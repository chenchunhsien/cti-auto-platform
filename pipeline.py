"""
pipeline.py
-----------
CTI 威脅情資自動化管線（純規則引擎，不使用 LLM）。

流程:
  1. 讀取 data/sync_state.json 的 high-water mark（無則回溯 N 小時）
  2. 呼叫 Luminar STIX 2.1 API 分頁取回增量物件
  3. 規則過濾：indicator + ipv4-addr + confidence>=90 + threat_score>=90
  4. Upsert 至 data/base_iocs.json（全量庫）；首次出現的 IP 另外累計進
     data/daily_iocs.json（台北時間「今日」桶，橫跨多次執行持續累加）
  5. 以「EDL 階梯式判定邏輯」從全量庫篩出 data/blocklist_edl.txt：
       條件 A（致命高危直通）：labels 命中高危關鍵字 AND threat_score>=95
                               AND last_seen 在 72 小時內（seen_count==1 亦可）
       條件 B（頑固威脅累計）：seen_count>=2 AND threat_score>=90
                               AND last_seen 在 7 天內
       符合任一條件即收錄；其餘 IP 僅留在 base_iocs.json 供查詢，不進 EDL。
  6. 回寫 high-water mark
  7. 自動 git add / commit / push 至遠端 main

用法:
  python pipeline.py                 # 正常增量同步
  python pipeline.py --no-push       # 不執行 git push
  python pipeline.py --full          # 忽略高水位線，強制回溯 DEFAULT_LOOKBACK_HOURS
  python pipeline.py --since-hours 72
  python pipeline.py --input sample.json   # 離線測試：讀本地 STIX bundle
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests
from dotenv import load_dotenv

from luminar_client import (
    FEED_IOC,
    FEED_LEAKED_CREDENTIALS,
    LuminarClient,
    LuminarEntitlementError,
    LuminarError,
)

# --------------------------------------------------------------------------- #
# 路徑與常數
# --------------------------------------------------------------------------- #
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
STATE_FILE = DATA_DIR / "sync_state.json"
BASE_IOCS_FILE = DATA_DIR / "base_iocs.json"
DAILY_IOCS_FILE = DATA_DIR / "daily_iocs.json"
EDL_FILE = DATA_DIR / "blocklist_edl.txt"
ASN_DICT_FILE = DATA_DIR / "asn_dict.json"

IPV4_PATTERN_RE = re.compile(
    r"ipv4-addr:value\s*=\s*'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)'",
    re.IGNORECASE,
)
IPV4_STRICT_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")

log = logging.getLogger("pipeline")


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #
def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


TAIPEI_TZ = timezone(timedelta(hours=8))


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def taipei_today_str() -> str:
    """台北時間（UTC+8）today 字串，作為 daily_iocs.json 的累計桶 key。"""
    return datetime.now(TAIPEI_TZ).strftime("%Y-%m-%d")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    """寬鬆解析 ISO8601 時間字串，失敗回傳 None（而非拋例外）。"""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def mask_secret(text: str, secret: Optional[str]) -> str:
    if secret and secret in text:
        return text.replace(secret, "****")
    return text


def env_str(key: str, default: str = "") -> str:
    return (os.getenv(key) or default).strip().strip('"').strip("'")


def env_int(key: str, default: int) -> int:
    raw = env_str(key)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        # utf-8-sig：容忍 Windows 工具（Out-File、記事本）寫入的 BOM
        with path.open("r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (ValueError, OSError) as exc:
        log.warning("讀取 %s 失敗（%s），改用預設值", path.name, exc)
        return default


def write_json(path: Path, payload: Any) -> None:
    """原子寫入，避免中途中斷造成檔案毀損。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    tmp.replace(path)


# --------------------------------------------------------------------------- #
# High-Water Mark
# --------------------------------------------------------------------------- #
def load_high_water_mark(lookback_hours: int, force_full: bool) -> Tuple[int, str]:
    """回傳 (起始 epoch 毫秒, 來源說明)。"""
    fallback = epoch_ms(datetime.now(timezone.utc) - timedelta(hours=lookback_hours))

    if force_full:
        return fallback, f"強制回溯 {lookback_hours} 小時（--full）"

    state = read_json(STATE_FILE, {})
    ts = state.get("last_successful_timestamp") if isinstance(state, dict) else None
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        ts = None

    if not ts or ts <= 0:
        return fallback, f"無高水位線，預設回溯 {lookback_hours} 小時"

    # 防呆：時間戳不可超過現在
    now_ms = epoch_ms(datetime.now(timezone.utc))
    if ts > now_ms:
        log.warning("高水位線 %s 位於未來，改用回溯值", ts)
        return fallback, f"高水位線異常，回溯 {lookback_hours} 小時"

    gap_h = (now_ms - ts) / 3_600_000
    return ts, f"沿用高水位線（距今 {gap_h:.1f} 小時，補抓停機期間資料）"


def save_high_water_mark(ts: int, stats: Dict[str, Any]) -> None:
    state = read_json(STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    state.update(
        {
            "last_successful_timestamp": int(ts),
            "last_successful_timestamp_utc": datetime.fromtimestamp(
                ts / 1000, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_run_utc": now_utc_iso(),
            "last_run_status": "success",
            "last_run_stats": stats,
        }
    )
    write_json(STATE_FILE, state)
    log.info("高水位線已更新 -> %s (%s)", ts, state["last_successful_timestamp_utc"])


def mark_run_failed(reason: str) -> None:
    state = read_json(STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    state.update(
        {
            "last_run_utc": now_utc_iso(),
            "last_run_status": "failed",
            "last_run_error": reason[:500],
        }
    )
    # 刻意「不」更新 last_successful_timestamp，下次執行才能重抓缺漏區間
    write_json(STATE_FILE, state)


# --------------------------------------------------------------------------- #
# STIX 解析與規則過濾
# --------------------------------------------------------------------------- #
def extract_ip(pattern: Optional[str]) -> Optional[str]:
    """由 STIX pattern 取出原始 IPv4（不做 defanging）。"""
    if not isinstance(pattern, str):
        return None
    match = IPV4_PATTERN_RE.search(pattern)
    if not match:
        return None
    ip = match.group("ip")
    if not IPV4_STRICT_RE.match(ip):
        return None
    octets = ip.split("/")[0].split(".")
    if any(not (0 <= int(o) <= 255) for o in octets):
        return None
    return ip


def flatten_extensions(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Luminar 把 score / asn / resolving_domains 等放在 extensions 的
    extension-definition--xxxx 子物件內，key 不固定，故攤平合併。
    """
    merged: Dict[str, Any] = {}
    ext = obj.get("extensions")
    if isinstance(ext, dict):
        for value in ext.values():
            if isinstance(value, dict):
                for k, v in value.items():
                    if v not in (None, "", [], {}) and k not in merged:
                        merged[k] = v
    # 部分來源會直接放在物件頂層
    for k in ("score", "threat_score", "asn", "resolving_domains", "collection_date"):
        if k not in merged and obj.get(k) not in (None, "", [], {}):
            merged[k] = obj[k]
    return merged


def to_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def as_list(value: Any) -> List[str]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def parse_indicators(
    objects: Iterable[Dict[str, Any]],
    min_confidence: float,
    min_threat_score: float,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """套用規則引擎，回傳 (通過的 IOC 清單, 統計)。"""
    stats = {
        "total_objects": 0,
        "indicators": 0,
        "ipv4_indicators": 0,
        "rejected_confidence": 0,
        "rejected_score": 0,
        "passed": 0,
    }
    results: List[Dict[str, Any]] = []

    for obj in objects:
        stats["total_objects"] += 1
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        stats["indicators"] += 1

        ip = extract_ip(obj.get("pattern"))
        if not ip:
            continue
        stats["ipv4_indicators"] += 1

        ext = flatten_extensions(obj)

        confidence = to_number(obj.get("confidence"))
        threat_score = to_number(ext.get("score"))
        if threat_score is None:
            threat_score = to_number(ext.get("threat_score"))

        if confidence is None or confidence < min_confidence:
            stats["rejected_confidence"] += 1
            continue
        if threat_score is None or threat_score < min_threat_score:
            stats["rejected_score"] += 1
            continue

        first_seen = obj.get("valid_from") or obj.get("created")
        last_seen = ext.get("collection_date") or obj.get("modified")

        results.append(
            {
                "ip": ip,  # 原始 IP，不做 defanging
                "confidence": int(confidence) if confidence.is_integer() else confidence,
                "threat_score": int(threat_score)
                if threat_score.is_integer()
                else threat_score,
                # STIX 2.1 indicator 無 labels 欄位（2.0 已棄用），改用
                # indicator_types 並併入 extensions.threat_types 以保留完整分類標籤
                "labels": merge_labels(
                    as_list(obj.get("labels")),
                    merge_labels(as_list(obj.get("indicator_types")), as_list(ext.get("threat_types"))),
                ),
                "asn": ext.get("asn"),
                "resolving_domains": as_list(ext.get("resolving_domains")),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "valid_until": obj.get("valid_until"),
                "stix_id": obj.get("id"),
            }
        )
        stats["passed"] += 1

    # 同一次批次可能有重複 IP，先行合併
    deduped: Dict[str, Dict[str, Any]] = {}
    for item in results:
        existing = deduped.get(item["ip"])
        if existing is None:
            deduped[item["ip"]] = item
            continue
        existing["labels"] = merge_labels(existing["labels"], item["labels"])
        existing["resolving_domains"] = merge_labels(
            existing["resolving_domains"], item["resolving_domains"]
        )
        existing["threat_score"] = max(existing["threat_score"], item["threat_score"])
        existing["confidence"] = max(existing["confidence"], item["confidence"])
        existing["last_seen"] = max_ts(existing["last_seen"], item["last_seen"])

    stats["unique_ips"] = len(deduped)
    return list(deduped.values()), stats


def merge_labels(old: Iterable[str], new: Iterable[str]) -> List[str]:
    """合併去重並保持穩定順序。"""
    seen: Dict[str, None] = {}
    for value in list(old or []) + list(new or []):
        if value:
            seen.setdefault(str(value), None)
    return list(seen.keys())


def max_ts(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """字串化 ISO8601 比較（同格式下字典序即時間序）。"""
    if not a:
        return b
    if not b:
        return a
    return a if a >= b else b


# --------------------------------------------------------------------------- #
# 本地儲存（Upsert）
# --------------------------------------------------------------------------- #
def load_base_iocs() -> Dict[str, Dict[str, Any]]:
    raw = read_json(BASE_IOCS_FILE, {})
    if isinstance(raw, dict) and isinstance(raw.get("iocs"), dict):
        return raw["iocs"]
    if isinstance(raw, dict):
        # 舊格式：頂層直接是 ip -> record
        return {k: v for k, v in raw.items() if isinstance(v, dict) and "ip" in v}
    return {}


def upsert_base_iocs(
    base: Dict[str, Dict[str, Any]], incoming: List[Dict[str, Any]]
) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    """
    Upsert 進全量庫。回傳 (counters, new_records)。

    new_records 是本次「首次出現」且剛寫入 base 的完整紀錄（seen_count=1），
    供 write_daily_iocs() 收集進 data/daily_iocs.json 的台北「今日」累計桶。
    既有 IP 只更新 last_seen/threat_score/confidence/labels 等欄位，不會
    重複計入 daily，因為它已經不是「新發現」。
    """
    counters = {"new": 0, "updated": 0}
    new_records: List[Dict[str, Any]] = []
    stamp = now_utc_iso()

    for item in incoming:
        ip = item["ip"]
        existing = base.get(ip)
        if existing is None:
            record = dict(item)
            record["seen_count"] = 1
            record["first_recorded"] = stamp
            record["last_updated"] = stamp
            base[ip] = record
            counters["new"] += 1
            new_records.append(record)
            continue

        existing["seen_count"] = int(existing.get("seen_count", 1)) + 1
        existing["last_seen"] = max_ts(existing.get("last_seen"), item.get("last_seen"))
        existing["labels"] = merge_labels(existing.get("labels", []), item["labels"])
        existing["resolving_domains"] = merge_labels(
            existing.get("resolving_domains", []), item["resolving_domains"]
        )
        existing["confidence"] = max(
            to_number(existing.get("confidence")) or 0, item["confidence"]
        )
        existing["threat_score"] = max(
            to_number(existing.get("threat_score")) or 0, item["threat_score"]
        )
        existing["confidence"] = int(existing["confidence"])
        existing["threat_score"] = int(existing["threat_score"])
        if item.get("asn"):
            existing["asn"] = item["asn"]
        if item.get("valid_until"):
            existing["valid_until"] = item["valid_until"]
        if item.get("first_seen"):
            existing["first_seen"] = existing.get("first_seen") or item["first_seen"]
        existing["last_updated"] = stamp
        counters["updated"] += 1

    return counters, new_records


def load_daily_bucket() -> Tuple[Dict[str, Dict[str, Any]], str]:
    """
    讀取 data/daily_iocs.json 目前的累計桶。
    若檔案記錄的日期不是台北時間的今天（或格式是舊版），視為空桶重新累積，
    確保「今日新增」跨日自動歸零，但同一天內多次執行會持續累加。
    """
    today = taipei_today_str()
    raw = read_json(DAILY_IOCS_FILE, {})
    if not isinstance(raw, dict):
        return {}, today
    meta = raw.get("meta") or {}
    iocs = raw.get("iocs")
    if meta.get("date_taipei") != today or not isinstance(iocs, dict):
        return {}, today
    return iocs, today


def write_daily_iocs(new_records: List[Dict[str, Any]], stats: Dict[str, Any]) -> None:
    """把本次首次出現的 IP 併入台北時間今日的累計桶，寫回 daily_iocs.json。"""
    bucket, today = load_daily_bucket()
    for record in new_records:
        bucket[record["ip"]] = record

    write_json(
        DAILY_IOCS_FILE,
        {
            "meta": {
                "generated_at": now_utc_iso(),
                "date_taipei": today,
                "count": len(bucket),
                "new_this_run": len(new_records),
                "run_stats": stats,
            },
            "iocs": bucket,
        },
    )
    log.info("今日新增累計（台北時間 %s）：%d 筆（本次新增 %d 筆）", today, len(bucket), len(new_records))


# --------------------------------------------------------------------------- #
# EDL 階梯式判定邏輯（Tiered Decision）
# --------------------------------------------------------------------------- #
HIGH_RISK_LABEL_KEYWORDS = (
    "c2", "ransomware", "apt", "cobaltstrike", "webshell", "trojan", "botnet",
)


def select_edl_candidates(
    base: Dict[str, Dict[str, Any]], now: datetime
) -> Tuple[List[str], Dict[str, int]]:
    """
    只有符合以下任一條件的 IP 才會寫入 blocklist_edl.txt：

      條件 A（致命高危直通）：
        labels 命中任一高危關鍵字 AND threat_score >= 95
        AND last_seen 在近 72 小時內（即使 seen_count == 1 也收錄）
      條件 B（頑固威脅累計）：
        seen_count >= 2 AND threat_score >= 90 AND last_seen 在近 7 天內

    其餘 IP（單次出現、無高危標籤、或已超過 7 天無活動）保留在
    base_iocs.json 供查詢，但不進入 EDL 阻斷清單。

    同時把判定結果以 record["edl_tier"] = "A" / "B" / None 寫回每筆
    base 紀錄（直接修改傳入的 dict），讓前端（docs/edl.html）能直接讀取
    「當初是依哪個條件被收錄」，不必自行以瀏覽器當下時間重新計算
    ——否則使用者晚點才打開頁面，72 小時 / 7 天的時間窗會跟著「現在」
    往後漂移，可能誤判成不符合任何條件。
    """
    window_a = now - timedelta(hours=72)
    window_b = now - timedelta(days=7)
    stats = {"condition_a": 0, "condition_b": 0, "excluded": 0}
    selected: List[str] = []

    for ip, record in base.items():
        labels_lower = [str(l).lower() for l in record.get("labels", []) or []]
        has_high_risk_label = any(
            keyword in label for label in labels_lower for keyword in HIGH_RISK_LABEL_KEYWORDS
        )
        threat_score = to_number(record.get("threat_score")) or 0
        seen_count = int(record.get("seen_count", 1) or 1)
        last_seen_dt = parse_iso(record.get("last_seen"))

        condition_a = (
            has_high_risk_label
            and threat_score >= 95
            and last_seen_dt is not None
            and last_seen_dt >= window_a
        )
        condition_b = (
            seen_count >= 2
            and threat_score >= 90
            and last_seen_dt is not None
            and last_seen_dt >= window_b
        )

        if condition_a:
            stats["condition_a"] += 1
            selected.append(ip)
            record["edl_tier"] = "A"
        elif condition_b:
            stats["condition_b"] += 1
            selected.append(ip)
            record["edl_tier"] = "B"
        else:
            stats["excluded"] += 1
            record["edl_tier"] = None

    selected.sort(key=lambda s: tuple(int(x) for x in s.split("/")[0].split(".")))
    return selected, stats


# --------------------------------------------------------------------------- #
# ASN 自動化查詢與動態字典擴充（策略 2）
# --------------------------------------------------------------------------- #
# 查詢來源：ARIN RDAP（/registry/autnum/{asn}）。實測發現 ARIN 的 RDAP 會
# 代理/鏡射其他 RIR（RIPE、APNIC、LACNIC 等）註冊的 ASN 資料，單一端點即可
# 涵蓋全球絕大多數 ASN，不需要依 RIR 分別查詢不同服務。
#
# 重要實測細節：
#   * Header 必須是 Accept: application/rdap+json——帶 application/json
#     會間歇性收到 HTTP 406（而非穩定失敗，容易誤判為暫時性錯誤）。
#   * 回應中的 vcardArray 結構化地址欄位（adr 的 value 陣列）在所有實測
#     案例中都是空字串，真正的地址只存在人類可讀的 "label" 自由格式文字
#     裡，且該文字最後一行通常是國家全名（如 "ITALY"）或已經是兩碼代號
#     （LACNIC 來源常見，如 "AR"）。沒有結構化欄位可直接取用。
#   * 單次查詢只給一個 holder/name，不含我們需要的分類（VPS/雲端/
#     防彈主機…），因此 type 由 classify_asn_type() 以關鍵字猜測。
#
# 真實資料顯示目前有 877 個不重複 ASN 不在字典裡，若一次全部查完單次
# 執行要花數分鐘、且可能被免費服務限流，因此設計成「每次執行最多新增
# N 筆」，靠多次排程執行逐步補齊（與高水位線增量追趕的精神一致）。
RDAP_HEADERS = {"Accept": "application/rdap+json"}
ASN_LOOKUP_TIMEOUT = 3
ASN_LOOKUP_DEFAULT_MAX_PER_RUN = 100
ASN_LOOKUP_DELAY_SECONDS = 0.15

# 常見國名/地區別名 -> ISO 兩碼代號，用來解析 RDAP label 自由格式文字。
# 覆蓋不到的國家會以 "--" 表示未知，不勉強塞入錯誤資料。
COUNTRY_NAME_TO_CODE = {
    "UNITED STATES": "US", "UNITED STATES OF AMERICA": "US", "USA": "US",
    "UNITED KINGDOM": "GB", "ENGLAND": "GB", "SCOTLAND": "GB", "WALES": "GB",
    "NORTHERN IRELAND": "GB", "GREAT BRITAIN": "GB",
    "MOLDOVA": "MD", "REPUBLIC OF MOLDOVA": "MD",
    "ITALY": "IT", "GERMANY": "DE", "FRANCE": "FR",
    "NETHERLANDS": "NL", "THE NETHERLANDS": "NL",
    "CHINA": "CN", "HONG KONG": "HK", "SINGAPORE": "SG", "JAPAN": "JP",
    "SOUTH KOREA": "KR", "KOREA, REPUBLIC OF": "KR", "REPUBLIC OF KOREA": "KR",
    "INDIA": "IN", "UKRAINE": "UA", "ROMANIA": "RO", "POLAND": "PL",
    "CZECH REPUBLIC": "CZ", "CZECHIA": "CZ", "BULGARIA": "BG",
    "SEYCHELLES": "SC", "PANAMA": "PA", "BRITISH VIRGIN ISLANDS": "VG",
    "CYPRUS": "CY", "BELIZE": "BZ", "CANADA": "CA", "AUSTRALIA": "AU",
    "BRAZIL": "BR", "SWITZERLAND": "CH", "SWEDEN": "SE", "FINLAND": "FI",
    "NORWAY": "NO", "DENMARK": "DK", "AUSTRIA": "AT", "BELGIUM": "BE",
    "SPAIN": "ES", "PORTUGAL": "PT", "IRELAND": "IE", "LUXEMBOURG": "LU",
    "LATVIA": "LV", "LITHUANIA": "LT", "ESTONIA": "EE", "HUNGARY": "HU",
    "SLOVAKIA": "SK", "SLOVENIA": "SI", "CROATIA": "HR", "GREECE": "GR",
    "TURKEY": "TR", "ISRAEL": "IL", "UNITED ARAB EMIRATES": "AE",
    "VIETNAM": "VN", "INDONESIA": "ID", "MALAYSIA": "MY", "THAILAND": "TH",
    "PHILIPPINES": "PH", "TAIWAN": "TW", "MEXICO": "MX", "ARGENTINA": "AR",
    "CHILE": "CL", "SOUTH AFRICA": "ZA", "EGYPT": "EG", "ICELAND": "IS",
    "KAZAKHSTAN": "KZ", "RUSSIAN FEDERATION": "RU", "RUSSIA": "RU",
}


def classify_asn_type(name: str) -> str:
    """
    依名稱關鍵字粗分類：
      bulletproof/alexhost -> 高危防彈主機
      cloud/vps            -> 雲端/VPS
      其餘                  -> 網路託管/ISP（預設）
    """
    lower = (name or "").lower()
    if "bulletproof" in lower or "alexhost" in lower:
        return "高危防彈主機"
    if "cloud" in lower or "vps" in lower:
        return "雲端/VPS"
    return "網路託管/ISP"


def resolve_country_code(candidate_lines: Iterable[str]) -> Optional[str]:
    """從多個候選文字行中找出可辨識的國家代碼，找不到回傳 None。"""
    for raw in candidate_lines:
        if not raw:
            continue
        text = str(raw).strip()
        if not text:
            continue
        if re.fullmatch(r"[A-Za-z]{2}", text):
            return text.upper()
        upper_text = text.upper()
        code = COUNTRY_NAME_TO_CODE.get(upper_text)
        if code:
            return code
        for name, mapped in COUNTRY_NAME_TO_CODE.items():
            if name in upper_text:
                return mapped
    return None


def _extract_rdap_address_labels(obj: Any) -> List[str]:
    """遞迴找出 RDAP 回應中所有 vcardArray 的地址 label 自由格式文字。"""
    labels: List[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "vcardArray":
                try:
                    for prop in value[1]:
                        if (
                            isinstance(prop, list)
                            and prop[0] == "adr"
                            and isinstance(prop[1], dict)
                            and prop[1].get("label")
                        ):
                            labels.append(prop[1]["label"])
                except (IndexError, TypeError):
                    continue
            else:
                labels.extend(_extract_rdap_address_labels(value))
    elif isinstance(obj, list):
        for item in obj:
            labels.extend(_extract_rdap_address_labels(item))
    return labels


def lookup_asn_via_rdap(
    asn: str, session: requests.Session
) -> Optional[Tuple[str, Optional[str]]]:
    """查 ARIN RDAP，回傳 (name, country_or_None)；查詢失敗回傳 None。"""
    url = f"https://rdap.arin.net/registry/autnum/{asn}"
    try:
        resp = session.get(url, headers=RDAP_HEADERS, timeout=ASN_LOOKUP_TIMEOUT)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None

    name = data.get("name")
    if not name or name.strip() == asn:
        name = f"AS{asn}"

    labels = _extract_rdap_address_labels(data)
    candidate_lines: List[str] = []
    for label in labels:
        lines = [ln.strip() for ln in str(label).split("\n") if ln.strip()]
        if lines:
            candidate_lines.append(lines[-1])
    country = resolve_country_code(candidate_lines)
    return name, country


def lookup_asn_via_ripestat(
    asn: str, session: requests.Session
) -> Optional[Tuple[str, Optional[str]]]:
    """RDAP 失敗時的備援：RIPEstat as-overview，只拿得到名稱，無國別。"""
    url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
    try:
        resp = session.get(url, timeout=ASN_LOOKUP_TIMEOUT)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        holder = resp.json().get("data", {}).get("holder")
    except ValueError:
        return None
    if not holder:
        return None
    return holder, None


def load_asn_dict() -> Dict[str, Dict[str, Any]]:
    raw = read_json(ASN_DICT_FILE, {})
    return raw if isinstance(raw, dict) else {}


def extract_asn_numbers(base: Dict[str, Dict[str, Any]]) -> Set[str]:
    """從全量庫每筆紀錄的 asn 欄位萃取純數字編號（與前端 extractAsnNumber 同邏輯）。"""
    numbers: Set[str] = set()
    for record in base.values():
        raw = record.get("asn")
        if raw is None:
            continue
        text = str(raw).strip()
        if not text:
            continue
        text = re.sub(r"^as\s*", "", text, flags=re.IGNORECASE)
        match = re.match(r"^(\d+)", text)
        if match:
            numbers.add(match.group(1))
    return numbers


def update_asn_dictionary(
    base: Dict[str, Dict[str, Any]], max_per_run: int
) -> Dict[str, int]:
    """
    找出全量庫中尚未收錄的 ASN，透過 RDAP（失敗則 RIPEstat 備援）查詢
    組織名稱與國別，寫回 data/asn_dict.json。

    為避免單次執行查詢上百個 ASN 導致管線跑太久或被免費服務限流，
    每次執行最多新增 max_per_run 筆，其餘留到下次排程執行繼續補齊。
    網路失敗的 ASN 不寫入字典（允許下次重試）；查詢成功但解析不出
    國別時，仍寫入並以 "--" 標示未知，避免每次都重查同一筆。
    """
    asn_dict = load_asn_dict()
    all_asns = extract_asn_numbers(base)
    unknown = sorted(all_asns - set(asn_dict.keys()), key=int)

    stats = {
        "total_distinct": len(all_asns),
        "already_known": len(all_asns) - len(unknown),
        "unknown_total": len(unknown),
        "queried": 0,
        "resolved": 0,
        "failed": 0,
        "deferred": max(0, len(unknown) - max_per_run),
    }

    if not unknown:
        log.info("ASN 字典：全部 %d 個不重複 ASN 皆已收錄，無需查詢", len(all_asns))
        return stats

    to_query = unknown[:max_per_run]
    log.info(
        "ASN 字典：發現 %d 個未收錄 ASN，本次處理 %d 筆（剩餘 %d 筆留待下次執行）",
        len(unknown), len(to_query), stats["deferred"],
    )

    changed = False
    with requests.Session() as session:
        for asn in to_query:
            stats["queried"] += 1
            result = lookup_asn_via_rdap(asn, session)
            if result is None:
                result = lookup_asn_via_ripestat(asn, session)

            if result is None:
                stats["failed"] += 1
                log.debug("ASN 字典：AS%s 查詢失敗，留待下次重試", asn)
                time.sleep(ASN_LOOKUP_DELAY_SECONDS)
                continue

            name, country = result
            asn_dict[asn] = {
                "name": name,
                "type": classify_asn_type(name),
                "country": country or "--",
            }
            changed = True
            stats["resolved"] += 1
            time.sleep(ASN_LOOKUP_DELAY_SECONDS)

    if changed:
        write_json(ASN_DICT_FILE, asn_dict)

    log.info(
        "ASN 字典：本次查詢 %d 筆，成功 %d 筆、失敗 %d 筆（留待重試），字典總計 %d 筆",
        stats["queried"], stats["resolved"], stats["failed"], len(asn_dict),
    )
    return stats


def write_outputs(
    base: Dict[str, Dict[str, Any]],
    edl_ips: List[str],
    edl_stats: Dict[str, int],
    stats: Dict[str, Any],
) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    stamp = now_utc_iso()

    scores = [to_number(r.get("threat_score")) or 0 for r in base.values()]
    avg_score = round(sum(scores) / len(scores), 2) if scores else 0

    write_json(
        BASE_IOCS_FILE,
        {
            "meta": {
                "generated_at": stamp,
                "total_ips": len(base),
                "avg_threat_score": avg_score,
                "min_confidence": stats.get("min_confidence"),
                "min_threat_score": stats.get("min_threat_score"),
                "edl_count": len(edl_ips),
                "edl_condition_a": edl_stats.get("condition_a", 0),
                "edl_condition_b": edl_stats.get("condition_b", 0),
                "source": "Luminar STIX 2.1",
            },
            "iocs": base,
        },
    )

    # EDL：純 IP 換行，供防火牆直接拉取（已經過階梯式判定篩選）
    EDL_FILE.write_text(
        "\n".join(edl_ips) + ("\n" if edl_ips else ""), encoding="utf-8"
    )

    log.info(
        "輸出完成：base_iocs=%d 筆, EDL=%d 行（條件A命中=%d, 條件B命中=%d, 未達標=%d）",
        len(base),
        len(edl_ips),
        edl_stats.get("condition_a", 0),
        edl_stats.get("condition_b", 0),
        edl_stats.get("excluded", 0),
    )


# --------------------------------------------------------------------------- #
# Git 自動推送
# --------------------------------------------------------------------------- #
def run_git(args: List[str], secret: Optional[str] = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        log.debug(
            "git %s -> rc=%s stderr=%s",
            mask_secret(" ".join(args), secret),
            proc.returncode,
            mask_secret((proc.stderr or "").strip(), secret),
        )
    return proc


def git_push(user: str, repo: str, pat: str, branch: str = "main") -> bool:
    """git add data/ → commit → push。無異動則跳過。"""
    if not (user and repo and pat):
        log.warning("GitHub 憑證不完整，略過自動推送")
        return False

    if not (ROOT / ".git").exists():
        log.info("尚未初始化 git repo，執行 git init")
        if run_git(["init"]).returncode != 0:
            log.error("git init 失敗，略過推送")
            return False
        run_git(["symbolic-ref", "HEAD", f"refs/heads/{branch}"])

    # 確保有 identity（CI / 排程環境常缺）
    if not run_git(["config", "user.email"]).stdout.strip():
        run_git(["config", "user.email", "cti-bot@local"])
    if not run_git(["config", "user.name"]).stdout.strip():
        run_git(["config", "user.name", "cti-auto-platform bot"])

    if run_git(["add", "data/"]).returncode != 0:
        log.error("git add 失敗")
        return False

    # 只檢查 data/ 是否有已暫存的異動
    if run_git(["diff", "--cached", "--quiet", "--", "data/"]).returncode == 0:
        log.info("data/ 無異動，略過 commit 與 push")
        return False

    message = f"chore(cti): sync IOCs {now_utc_iso()}"
    commit = run_git(["commit", "-m", message, "--", "data/"])
    if commit.returncode != 0:
        log.error("git commit 失敗: %s", (commit.stderr or commit.stdout).strip())
        return False
    log.info("已建立 commit: %s", message)

    # 直接把帶 PAT 的 URL 傳給 push，避免 token 落在 .git/config
    remote = f"https://{pat}@github.com/{user}/{repo}.git"
    push = run_git(["push", remote, f"HEAD:refs/heads/{branch}"], secret=pat)
    if push.returncode != 0:
        log.error(
            "git push 失敗: %s",
            mask_secret((push.stderr or push.stdout).strip(), pat),
        )
        return False

    log.info("已推送至 github.com/%s/%s (%s)", user, repo, branch)
    return True


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CTI 威脅情資自動化管線")
    p.add_argument("--no-push", action="store_true", help="不執行 git 自動推送")
    p.add_argument("--full", action="store_true", help="忽略高水位線，強制回溯")
    p.add_argument("--since-hours", type=int, help="自訂回溯時數（搭配 --full 使用）")
    p.add_argument("--input", help="離線測試：改讀本地 STIX JSON 檔（不呼叫 API）")
    p.add_argument(
        "--feed",
        choices=[FEED_IOC, FEED_LEAKED_CREDENTIALS],
        default=FEED_IOC,
        help="資料來源 feed（預設 ioc）",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument(
        "--no-asn-lookup",
        action="store_true",
        help="跳過 ASN 自動化查詢（離線測試/快速執行用）",
    )
    return p.parse_args()


def load_local_objects(path_str: str) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    path = Path(path_str)
    if not path.is_absolute():
        path = ROOT / path
    body = read_json(path, None)
    if body is None:
        raise SystemExit(f"無法讀取輸入檔: {path}")
    if isinstance(body, list):
        return [o for o in body if isinstance(o, dict)], None
    objects = LuminarClient._extract_objects(body)  # noqa: SLF001 - 共用解析邏輯
    latest = LuminarClient._extract_latest_timestamp(body)  # noqa: SLF001
    return objects, latest


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    load_dotenv(ROOT / ".env")

    min_conf = env_int("MIN_CONFIDENCE", 90)
    min_score = env_int("MIN_THREAT_SCORE", 90)
    lookback = args.since_hours or env_int("DEFAULT_LOOKBACK_HOURS", 24)

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    log.info("=" * 68)
    log.info("CTI Pipeline 啟動 | 門檻 confidence>=%s, threat_score>=%s", min_conf, min_score)

    start_ts, source_desc = load_high_water_mark(lookback, args.full)
    log.info(
        "增量起點: %s (%s) — %s",
        start_ts,
        datetime.fromtimestamp(start_ts / 1000, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%SZ"
        ),
        source_desc,
    )

    # ---- 1. 取資料 ----
    try:
        if args.input:
            log.info("離線模式：讀取 %s", args.input)
            objects, latest_ts = load_local_objects(args.input)
        else:
            client = LuminarClient(
                base_url=env_str("LUMINAR_BASE_URL", "https://cyberluminar.com"),
                realm=env_str("LUMINAR_REALM"),
                client_id=env_str("LUMINAR_CLIENT_ID"),
                client_secret=env_str("LUMINAR_CLIENT_SECRET"),
                token_path=env_str(
                    "LUMINAR_TOKEN_PATH", "/externalApi/v2/realm/{realm}/token"
                ),
                query_path=env_str("LUMINAR_QUERY_PATH", "/externalApi/v2/stix"),
                query_next_path=env_str(
                    "LUMINAR_QUERY_NEXT_PATH", "/externalApi/v2/stix/next"
                ),
                scope=env_str("LUMINAR_SCOPE", "externalAPI/stix.readonly"),
                # 官方文件建議 10、上限 100；實測 24h 視窗用 10 要數百頁才爬得完，
                # 改用上限值大幅減少來回次數；若遇 HTTP 408 請調低（FAQ 建議）。
                page_limit=env_int("PAGE_LIMIT", 100),
                scroll_duration=env_str("LUMINAR_SCROLL_DURATION", "2m"),
                max_pages=env_int("MAX_PAGES", 2000),
            )
            with client:
                objects, latest_ts = client.fetch_stix(start_ts, feed=args.feed)
    except LuminarEntitlementError as exc:
        log.error("查詢被拒: %s", exc)
        log.error(
            "請先確認 LUMINAR_SCOPE 是否正確送出（常見肇因是 Token 請求漏帶 scope），"
            "若已確認仍失敗才需要洽 Luminar 確認 client_id '%s' 的 dataSource 開通狀態。",
            env_str("LUMINAR_CLIENT_ID"),
        )
        mark_run_failed(str(exc))
        return 3
    except LuminarError as exc:
        log.error("擷取失敗: %s", exc)
        mark_run_failed(str(exc))
        return 2

    log.info("API 共取回 %d 個 STIX 物件", len(objects))

    # ---- 2. 規則過濾 ----
    daily, stats = parse_indicators(objects, min_conf, min_score)
    stats["min_confidence"] = min_conf
    stats["min_threat_score"] = min_score
    log.info(
        "過濾結果: indicators=%d, ipv4=%d, 通過=%d (unique %d), "
        "confidence不足=%d, score不足=%d",
        stats["indicators"],
        stats["ipv4_indicators"],
        stats["passed"],
        stats["unique_ips"],
        stats["rejected_confidence"],
        stats["rejected_score"],
    )

    # ---- 3. Upsert ----
    base = load_base_iocs()
    counters, new_records = upsert_base_iocs(base, daily)
    stats.update(counters)
    log.info("Upsert: 新增 %d, 更新 %d, 資料庫總計 %d", counters["new"], counters["updated"], len(base))

    write_daily_iocs(new_records, stats)

    # ---- 3.5 EDL 階梯式判定 ----
    edl_ips, edl_stats = select_edl_candidates(base, datetime.now(timezone.utc))

    # ---- 3.6 ASN 字典自動化查詢與擴充（策略 2） ----
    if args.no_asn_lookup:
        log.info("ASN 字典：已指定 --no-asn-lookup，跳過查詢")
    else:
        asn_max_per_run = env_int("ASN_LOOKUP_MAX_PER_RUN", ASN_LOOKUP_DEFAULT_MAX_PER_RUN)
        asn_stats = update_asn_dictionary(base, asn_max_per_run)
        stats["asn_dict"] = asn_stats

    write_outputs(base, edl_ips, edl_stats, stats)

    # ---- 4. 回寫高水位線 ----
    if latest_ts:
        save_high_water_mark(latest_ts, stats)
    else:
        # 本次未取得任何物件（已追上進度），以當前時間為準，避免下次重複查詢同一空窗
        fallback_ts = epoch_ms(datetime.now(timezone.utc))
        log.info("本次無新物件，改以當前時間 %s 作為高水位線", fallback_ts)
        save_high_water_mark(fallback_ts, stats)

    # ---- 5. Git push ----
    if args.no_push:
        log.info("--no-push 指定，略過 git 推送")
    else:
        git_push(
            env_str("GITHUB_USER"),
            env_str("GITHUB_REPO"),
            env_str("GITHUB_PAT"),
            env_str("GITHUB_BRANCH", "main"),
        )

    log.info("Pipeline 完成 ✔")
    log.info("=" * 68)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.warning("使用者中斷")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - 排程環境需記錄所有例外
        logging.getLogger("pipeline").exception("未預期錯誤: %s", exc)
        mark_run_failed(repr(exc))
        sys.exit(1)
