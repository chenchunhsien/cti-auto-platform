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
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from datetime import time as dt_time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

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
EDL_EXPORT_FILE = DATA_DIR / "edl_export.json"
EDL_RETIRED_FILE = DATA_DIR / "edl_retired.json"
EDL_RETIRED_TXT_FILE = DATA_DIR / "blocklist_edl_retired.txt"
EDL_EXPORT_META_FILE = DATA_DIR / "edl_export_meta.json"
# IOC收斂可觀測性報表（第一階段，見 rule_analysis.py）：只有加
# --emit-decision-detail 才會產出，預設不寫這兩個檔案。
DECISION_DETAIL_FILE = DATA_DIR / "decision_detail.json"
CIDR_AGGREGATION_REPORT_FILE = DATA_DIR / "cidr_aggregation_report.json"
ASN_DICT_FILE = DATA_DIR / "asn_dict.json"
EDL_RULES_FILE = ROOT / "docs" / "data" / "edl_rules.json"

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


def now_utc_iso_minus_days(days: float) -> str:
    """回傳『現在 - days 天』的 ISO8601 字串，供 seen_history 字串化比較用。"""
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def write_text_atomic(path: Path, content: str, encoding: str = "utf-8") -> None:
    """原子寫入純文字檔（審查後新增，2026-10-22；供blocklist_edl.txt／
    blocklist_edl_retired.txt這類直接供防火牆訂閱的TXT輸出使用），比照
    write_json()的「先寫入<檔名>.tmp、同目錄replace()」模式：

    - 同目錄替換：tmp是path.with_suffix()算出的同目錄檔名，確保
      replace()是同一個檔案系統內的原子rename，不會因為跨磁碟/跨檔案
      系統退化成非原子的copy+delete。
    - 編碼與換行符號：刻意沿用Path.write_text()預設的文字模式寫入
      （newline=None的universal newlines語意），不額外指定newline=""。
      已實測確認：現行 EDL_FILE.write_text(..., encoding="utf-8") 在
      Windows上會把字串裡的"\\n"轉成"\\r\\n"寫入磁碟（data/blocklist_
      edl.txt目前确实是CRLF），經tmp+replace()改寫後位元組輸出完全
      相同——這裡沒有引入任何編碼或換行符號的改變。
    - 空清單：呼叫端傳入的content本來就可能只有header、沒有任何IP列，
      這支函式對內容是什麼完全不關心，空清單情境下行為跟非空時一致，
      不需要特殊處理。
    - 例外處理與暫存檔清理：寫入.tmp或replace()任一步驟拋出例外時，
      一律清掉殘留的.tmp檔再重新拋出——這點比write_json()現有的實作
      更嚴謹（write_json()目前失敗時不會主動清理.tmp），因為這裡的
      輸出會被SYNC_COMMIT_PATHS整個目錄git add進public repo，殘留的
      .tmp檔案比data/底下其他內部分析報表的殘留風險更直接。不論哪個
      步驟失敗，正式檔案path在這支函式裡自始至終沒有被直接寫入或截斷
      過，只有replace()成功的那一刻才會整個換成新內容，所以失敗時
      path一定維持失敗前的原始內容，不會有「寫到一半」的半成品。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(content, encoding=encoding)
        tmp.replace(path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


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


def is_edl_today_new_bootstrapped() -> bool:
    """「今日/本次新增」(edl_first_added_date) 機制是否已經完成過一次性
    冷啟動初始化，記錄在 sync_state.json 裡（跟高水位線同一個狀態檔，
    沒有必要為了單一個布林旗標另開一個檔案）。"""
    state = read_json(STATE_FILE, {})
    return bool(isinstance(state, dict) and state.get("edl_today_new_bootstrap_done"))


def mark_edl_today_new_bootstrapped() -> None:
    state = read_json(STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    state["edl_today_new_bootstrap_done"] = True
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
            record["seen_history"] = [stamp]
            record["history_tracking_since"] = stamp
            base[ip] = record
            counters["new"] += 1
            new_records.append(record)
            continue

        existing["seen_count"] = int(existing.get("seen_count", 1)) + 1
        existing["last_seen"] = max_ts(existing.get("last_seen"), item.get("last_seen"))
        existing.setdefault("history_tracking_since", stamp)
        history = existing.setdefault("seen_history", [])
        history.append(stamp)
        cutoff = now_utc_iso_minus_days(HISTORY_RETENTION_DAYS)
        existing["seen_history"] = [h for h in history if h >= cutoff]
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
# EDL 四階過濾漏斗（4-Stage Filtering Funnel）
# --------------------------------------------------------------------------- #
# 第三階會用到的標籤集合（比對前統一轉小寫並 strip 前後空白）：
#
#   MUST_HAVE_TAGS   實質危害標籤 —— 命中任一項，具備「不被雜訊標籤剃除」
#                    的豁免權，但仍須通過較低的 Score>=85 門檻。
MUST_HAVE_TAGS = {
    "c2", "cnc", "command-and-control", "botnet", "cobalt-strike",
    "trojan", "ransomware", "exploit", "bruteforce",
    "stealer", "infostealer", "backdoor", "apt", "rce",
}

#   SCANNER_NOISE_TAGS 純探測/測繪雜訊標籤 —— 未命中 MUST_HAVE_TAGS 時，
#                      命中任一項即直接剃除（Shodan/Censys/Shadowserver
#                      等背景掃測雜訊，非真實攻擊來源）。
SCANNER_NOISE_TAGS = {
    "scanner", "scan", "probe", "reconnaissance", "crawler",
    "shodan", "censys", "shadowserver", "binaryedge", "net-systems-research",
}

# 第二階：時效窗口。通道A/C維持嚴格的24小時（STRICT_WINDOW_HOURS/
# FALLBACK_WINDOW_HOURS），通道B另外放寬到14天（PERSISTENCE_WINDOW_DAYS，
# 見下方「軌道3」常數區），三者各自獨立，不再共用同一道全域門檻——
# 舊版共用24小時門檻會讓「次數夠多但剛好超過24小時」的頑固攻擊者被
# 條件A/C的嚴格窗口提前擋在通道B門外，不合理。
STRICT_WINDOW_HOURS = 24

# 雙軌入榜門檻（軌道 1 與軌道 2/3 彼此獨立，各自判定、不疊加 AND）：
#   軌道 1（命中 MUST_HAVE_TAGS，即時實質危害）：score >= 85 即收錄，
#   出現 1 次也算數，不額外要求 confidence 或頻次。
MUST_HAVE_MIN_SCORE = 85

#   軌道 3（頑固攻擊者收斂通道，核心精神是「以頻次補足分數」）：未命中
#   軌道1、也未命中雜訊標籤、也未達軌道2(通道C)門檻時，只要近
#   PERSISTENCE_WINDOW_DAYS(14)天滾動視窗內高頻出現 seen_count_b >= 5
#   （見 compute_recent_seen_count()，基於 seen_history 時間戳記即時
#   計算，而非全時累計），且具備中高威脅度 score >= 88、confidence >= 80
#   即收錄——分數/信心門檻刻意低於軌道 2，讓「分數未達99頂級門檻，但
#   近期反覆探測」的節點能破格收錄；長期掛網但近14天已不活躍的IP會
#   自然淡出此軌道，避免全時累計無上限膨脹。
#   時效窗口（判定「最後活躍夠不夠近」）跟頻次計算窗口（判定「近期
#   累積出現次數夠不夠多」）刻意分開成兩個獨立常數，不再共用同一個
#   14天數字：頻次窗口維持14天（PERSISTENCE_WINDOW_DAYS，次數門檻5次
#   不變），但時效窗口收緊為7天（PERSISTENCE_RECENCY_WINDOW_DAYS）——
#   讓「14天內出現過5次，但最後一次活躍其實已經是8~14天前」這種近期
#   已經沒有實際動作的死魚級頑固IP，不會繼續卡在通道B；真正還在活躍
#   刺探的頑固來源，最後活躍時間自然會落在7天內。分數門檻維持
#   >=88分、刻意不設上限（98分只是先前文件裡的描述性文字，程式邏輯
#   從未真的封頂），避免分數剛好落在99分以上、但次數不足以進通道C
#   的高分IP被錯誤排除在通道B之外。
PERSISTENCE_RECENCY_WINDOW_DAYS = 7
PERSISTENCE_WINDOW_DAYS = 14
PERSISTENCE_MIN_SEEN_COUNT = 5
PERSISTENCE_MIN_SCORE = 88
PERSISTENCE_MIN_CONFIDENCE = 80

#   軌道 2（無標籤/未知標籤高確信威脅，通道C：高確信威脅通道，優先於
#   軌道3判定）：須同時滿足 score >= 99、confidence >= 90，「且」額外
#   套用與通道A/B相同的 24 小時時效窗口（FALLBACK_WINDOW_HOURS，對齊每日
#   同步排程週期，避免同步間隔期間窗口提前斷糧歸零）與近7天滾動視窗
#   出現次數（FALLBACK_MIN_SEEN_COUNT，同樣透過 compute_recent_seen_count()
#   計算）才收錄——以逼近滿分的 score>=99 取代原本的頻次門檻調升，在
#   維持次數門檻不變（3次，避免重現與軌道3門檻打平、通道C變死代碼的
#   問題）的前提下收斂總量，完全不影響通道A（通道A仍是 24 小時時效、
#   出現 1 次即收錄，不受本收緊影響）。
FALLBACK_WINDOW_HOURS = 24
FALLBACK_MIN_SEEN_COUNT = 3
FALLBACK_MIN_SCORE = 99
FALLBACK_MIN_CONFIDENCE = 90

# 通道B/C的出現次數改採滾動視窗而非全時累計，避免IP長期掛在
# base_iocs.json中造成seen_count無上限膨脹、也避免IP被重新分配後仍背著
# 舊主人的歷史次數。seen_history（每次同步觀測到即附加一筆時間戳記）保留
# HISTORY_RETENTION_DAYS天：通道B現在用到14天視窗(PERSISTENCE_WINDOW_DAYS)，
# 保留天數至少要能完整涵蓋最長的那個視窗才有意義，故由14天調高為30天，
# 預留緩衝空間，避免剛好卡在裁剪邊界讓14天視窗的最前緣被誤裁掉。
# 過渡期保護：剛導入本機制時沒有任何歷史時間戳記可用，若直接採用純滾動
# 視窗會讓通道B/C在轉換當下全部歸零；因此在每筆IP的歷史追蹤開始
# （history_tracking_since）未滿 TRANSITION_PERIOD_DAYS 天之前，以「全時
# 累計seen_count」當作下限（取兩者較大值），滿期後才改用純滾動視窗計數，
# 避免舊資料無限膨脹的問題在過渡期結束後完全回歸正軌。
HISTORY_RETENTION_DAYS = 30
TRANSITION_PERIOD_DAYS = 7
RECENT_WINDOW_DAYS = 7

# 第四階：同一 /24 網段內達標的高危 IP 數量 >= 此門檻時，整段聚合輸出
# 成一筆 /24 CIDR（取代個別 IP），避免單一機房的殭屍網路/掃描集中灌水。
# 調低門檻使聚合更積極觸發，搭配通道 B 收緊共同把清單收斂到合理規模。
CIDR_ROLLUP_THRESHOLD = 5

# ASN 節流：實測發現通道 B/C 常被單一大型 ISP/VPS 商（例如巴基斯坦
# CYBERNET、中國電信等）跨多個不同 /24 網段大量分散灌水，/24 聚合抓不到
# 這種「同 ASN 但不同網段」的洗版模式，因此另外在 ASN 層級節流：同一
# ASN 最多只保留分數最高、最後活躍時間最新的前 N 筆。只套用在通道 B/C，
# 不影響通道 A（即時實質危害），確保真正的 C2/殭屍網路直通不受影響。
ASN_THROTTLE_MAX_PER_ASN = 5

# 純觀測用常數（2026-10-22新增）：不是任何通道的選擇門檻，只用來在
# ASN節流統計裡額外標出「分數特別高、卻被節流排除」的IP，供事後稽核
# CIDR安全拒絕 x ASN節流互動情境時快速定位高風險案例。調整這個數字
# 不會影響任何EDL選擇結果，純粹改變統計報表裡「高分」的認定門檻。
ASN_THROTTLE_HIGH_SCORE_AUDIT_THRESHOLD = 95

PUBLIC_INFRA_RULES_FILE = ROOT / "docs" / "data" / "public_infra_rules.json"


def normalize_tags(labels: Iterable[Any]) -> Set[str]:
    """標籤正規化：轉小寫、strip 前後空白，供三層標籤決策樹比對用。"""
    result = set()
    for label in labels or []:
        text = str(label).strip().lower()
        if text:
            result.add(text)
    return result


def is_valid_public_ip(ip_str: str) -> bool:
    """
    第一階：RFC 規範與合規清洗。嚴格排除私有網段（RFC 1918）、組播
    （RFC 5771，224.0.0.0/4）、保留位址與環回位址等一切非法公網單播
    位址，從根本避免這類位址出現在防火牆黑名單裡。
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def compute_recent_seen_count(
    record: Dict[str, Any], now: datetime, window_days: int = RECENT_WINDOW_DAYS
) -> int:
    """
    計算通道判定用的「近window_days天出現次數」，取代舊有的全時累計
    seen_count。window_days預設RECENT_WINDOW_DAYS(7天，通道C與其餘顯示
    用途使用)；通道B改傳PERSISTENCE_WINDOW_DAYS(14天)算出自己專用的
    頻次，兩個通道各自的視窗長度不同，因此同一筆record會分別算兩次，
    不是只算一次共用。

    過渡期保護：若此IP的history_tracking_since距今未滿
    TRANSITION_PERIOD_DAYS天（代表seen_history才剛開始累積，或此IP是
    本機制上線前就已存在、尚未被任何一次新同步補上歷史時間戳記），
    則以「全時累計seen_count」當作下限（取兩者較大值），避免剛轉換時
    因為歷史時間戳記不足而被誤判成只出現1次；過渡期滿後才改用純粹的
    滾動視窗計數，讓長期掛網但近期不活躍的IP能自然淡出通道B/C。
    """
    history = record.get("seen_history") or []
    cutoff = now - timedelta(days=window_days)
    recent_count = sum(1 for h in history if (parse_iso(h) or now) >= cutoff)

    tracking_since = parse_iso(record.get("history_tracking_since"))
    legacy_count = int(record.get("seen_count", 1) or 1)
    if tracking_since is None or now - tracking_since < timedelta(days=TRANSITION_PERIOD_DAYS):
        return max(recent_count, legacy_count)
    return recent_count


def is_edl_candidate(
    labels_norm: Set[str],
    threat_score: float,
    confidence: float,
    last_seen_dt: Optional[datetime],
    seen_count_c: int,
    seen_count_b: int,
    now: datetime,
) -> Optional[str]:
    # seen_count_c/seen_count_b 參數語意：呼叫端須分別傳入
    # compute_recent_seen_count(record, now, window_days=RECENT_WINDOW_DAYS)
    # 與 compute_recent_seen_count(record, now, window_days=
    # PERSISTENCE_WINDOW_DAYS) 算出的滾動視窗出現次數（含過渡期下限
    # 保護），不是原始全時累計值。通道C跟通道B的頻次計算視窗長度不同
    # （7天 vs 14天），所以是兩個獨立的數字，不能共用同一個。
    """
    雙軌入榜 + 掃描雜訊排除時效架構，回傳 "A"（軌道1：即時實質危害）/
    "C"（軌道2 高確信威脅通道）/ "B"（軌道3 頑固攻擊者收斂通道）/
    None（剔除）。軌道之間彼此獨立判定，不是疊加 AND 的單一門檻；三個
    tier 各自代表不同的收錄理由，前端據此顯示對應徽章。

      【硬門檻：last_seen 必須有值】
        last_seen_dt 為 None（解析失敗或缺值）一律剔除（此函式不含 IP
        合法性檢查，由呼叫端先行套用 is_valid_public_ip() 這道硬門檻）。
        三條軌道「各自」還有自己的時效窗口，不共用同一道全域門檻。

      軌道 1（即時實質危害，具最高優先豁免權）：
        last_seen 須在 STRICT_WINDOW_HOURS（24小時）內，命中
        MUST_HAVE_TAGS 任一項，即使同時包含 scan 類標籤也不排除；只要
        threat_score >= 85 即收錄（"A"），出現 1 次也算數。

      雜訊攔截閥：
        未命中軌道 1，但命中 SCANNER_NOISE_TAGS 任一項 -> 直接剔除，
        不再進入軌道 2 / 3 判定。

      軌道 2（無標籤/未知標籤高確信威脅，通道C：高確信威脅通道，
      優先於軌道3判定）：
        last_seen 須在 FALLBACK_WINDOW_HOURS（24小時）內，且同時滿足
        threat_score >= FALLBACK_MIN_SCORE、confidence >=
        FALLBACK_MIN_CONFIDENCE、seen_count_c（近7天滾動視窗出現次數）
        >= FALLBACK_MIN_SEEN_COUNT 才收錄（"C"）。刻意排在軌道3（頑固
        攻擊者）之前判定：C的分數/信心門檻本就比B更高，若B先判定，只要
        B的次數門檻 <= C的次數門檻，所有同時滿足C條件的紀錄會先被B的
        較寬鬆門檻攔截走，讓C形同不可能命中的死代碼（2026-10-20發現的
        真實案例：B、C次數門檻一度被同步調到相等，C因此永遠收錄0筆）。
        C的「高分數/信心值優先判定」原則不應隨兩者次數門檻的相對大小
        而失效。

      軌道 3（頑固攻擊者收斂通道，以頻次補足分數，軌道2未命中才判定）：
        last_seen 須在 PERSISTENCE_RECENCY_WINDOW_DAYS（7天，判定「最後
        活躍夠不夠近」）內，且 seen_count_b（PERSISTENCE_WINDOW_DAYS，
        14天滾動視窗出現次數，窗口長度跟通道C的seen_count_c不同）>=
        PERSISTENCE_MIN_SEEN_COUNT、threat_score >= PERSISTENCE_MIN_SCORE
        （無上限）、confidence >= PERSISTENCE_MIN_CONFIDENCE 即收錄
        （"B"）——接住「次數夠多，但分數/信心值沒高到能走軌道2」的
        紀錄。時效窗口（7天）比頻次窗口（14天）更嚴格：頻次用較長的
        14天視窗累積「夠不夠頑固」，但若最後一次活躍其實已經是8~14天
        前，代表這支IP近期已經沒有實際動作，不該繼續被視為「現在仍
        頑固」而卡在通道B——這是2026-10-22調整後的設計，取代先前時效
        窗口跟頻次窗口共用同一個14天數字的版本。
    """
    if last_seen_dt is None:
        return None

    if labels_norm & MUST_HAVE_TAGS:
        is_recent_a = last_seen_dt >= now - timedelta(hours=STRICT_WINDOW_HOURS)
        return "A" if is_recent_a and threat_score >= MUST_HAVE_MIN_SCORE else None

    if labels_norm & SCANNER_NOISE_TAGS:
        return None

    is_recent_fallback = last_seen_dt >= now - timedelta(hours=FALLBACK_WINDOW_HOURS)
    if (
        is_recent_fallback
        and seen_count_c >= FALLBACK_MIN_SEEN_COUNT
        and threat_score >= FALLBACK_MIN_SCORE
        and confidence >= FALLBACK_MIN_CONFIDENCE
    ):
        return "C"

    is_recent_persistence = last_seen_dt >= now - timedelta(days=PERSISTENCE_RECENCY_WINDOW_DAYS)
    if (
        is_recent_persistence
        and seen_count_b >= PERSISTENCE_MIN_SEEN_COUNT
        and threat_score >= PERSISTENCE_MIN_SCORE
        and confidence >= PERSISTENCE_MIN_CONFIDENCE
    ):
        return "B"

    return None


def load_public_infra_matcher() -> Callable[[str, Any], bool]:
    """
    讀取「公用設施白名單」（docs/data/public_infra_rules.json），組出
    is_public_cloud(ip, asn) 比對函式，供 /24 聚合收斂的防誤殺判斷用：
    避免知名雲端/CDN 服務商（AWS/GCP/Azure/Cloudflare/Akamai 等）的網段
    被誤聚合成 /24 整段封鎖。

    讀取失敗或檔案不存在時，回傳一個永遠判斷 False 的函式——白名單只是
    這一階的「防呆保護」，不是 pipeline 的必要資料，缺檔不該讓整個
    EDL 產出流程中斷，只是退回「不受保護、可正常參與聚合」的安全預設。
    """
    rules = read_json(PUBLIC_INFRA_RULES_FILE, {})
    if not isinstance(rules, dict):
        rules = {}

    exact_ips = {
        e.get("ip") for e in (rules.get("exact_ips") or []) if isinstance(e, dict) and e.get("ip")
    }

    asn_whitelist: Set[str] = set()
    for entry in rules.get("asns") or []:
        if not isinstance(entry, dict):
            continue
        raw = str(entry.get("asn", "")).strip()
        digits = re.sub(r"^as\s*", "", raw, flags=re.IGNORECASE)
        if digits:
            asn_whitelist.add(digits)

    cidr_nets: List[ipaddress.IPv4Network] = []
    for group in rules.get("cdn_cidrs") or []:
        if not isinstance(group, dict):
            continue
        for cidr in group.get("cidrs") or []:
            try:
                cidr_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

    def is_public_cloud(ip: str, asn_raw: Any) -> bool:
        if ip in exact_ips:
            return True
        if asn_raw:
            digits_match = re.match(r"^(?:as)?\s*(\d+)", str(asn_raw).strip(), re.IGNORECASE)
            if digits_match and digits_match.group(1) in asn_whitelist:
                return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in cidr_nets)

    return is_public_cloud


def load_public_infra_cidr_ranges() -> Optional[List[ipaddress.IPv4Network]]:
    """
    專供 CIDR 聚合「安全檢查」使用（見 verify_cidr_safe_for_aggregation()）：
    回傳 docs/data/public_infra_rules.json 裡 cdn_cidrs 的網段清單。

    刻意不沿用 load_public_infra_matcher() 的失敗語意——那支函式用在
    舊的「/24聚合防呆保護」情境，缺檔時的安全預設是「不受保護、照常
    聚合」；但這支函式是用在新的「能不能安全聚合」這道硬性關卡，缺檔
    或解析失敗時必須回傳 None，讓呼叫端保守地視為「無法驗證」而拒絕
    聚合，不能沿用舊語意誤判成「沒有任何網段需要保護」。

    檔案『不存在』視為「目前沒有設定任何已知保護網段」（合法的空白名單
    狀態，回傳空列表，不是驗證失敗）；檔案存在但讀取/解析失敗，或內含
    無法解析的 CIDR 字串，才視為「無法可靠驗證」，回傳 None。
    """
    if not PUBLIC_INFRA_RULES_FILE.exists():
        return []
    try:
        with PUBLIC_INFRA_RULES_FILE.open("r", encoding="utf-8-sig") as fh:
            rules = json.load(fh)
    except (ValueError, OSError) as exc:
        log.warning(
            "讀取 %s 失敗（%s），CIDR聚合安全檢查無法驗證，保守起見視為不安全",
            PUBLIC_INFRA_RULES_FILE.name, exc,
        )
        return None
    if not isinstance(rules, dict):
        log.warning(
            "%s 格式異常（頂層不是物件），CIDR聚合安全檢查無法驗證，保守起見視為不安全",
            PUBLIC_INFRA_RULES_FILE.name,
        )
        return None

    cidr_nets: List[ipaddress.IPv4Network] = []
    for group in rules.get("cdn_cidrs") or []:
        if not isinstance(group, dict):
            continue
        for cidr in group.get("cidrs") or []:
            try:
                cidr_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning(
                    "%s 的 cdn_cidrs 內有無法解析的網段 %r，CIDR聚合安全檢查無法驗證，保守起見視為不安全",
                    PUBLIC_INFRA_RULES_FILE.name, cidr,
                )
                return None
    return cidr_nets


def verify_cidr_safe_for_aggregation(
    subnet: ipaddress.IPv4Network,
    member_ips: List[str],
    base: Dict[str, Dict[str, Any]],
    is_public_cloud: Callable[[str, Any], bool],
    protected_ranges: Optional[List[ipaddress.IPv4Network]],
) -> Tuple[bool, str]:
    """
    CIDR 聚合前的第二道安全關卡（保守策略：任何一項無法排除風險就直接
    判定不安全，退回輸出個別候選IP，不是「同一/24出現>=5筆候選就自動
    認定整段適合封鎖」）：

      1. 候選成員本身的 IP/ASN 是否命中白名單（沿用既有逐一比對）。
      2. 整個 /24 網段範圍是否跟已知公用雲端/CDN網段重疊——這一項涵蓋
         「網段裡其餘254個不是候選名單、我們沒有逐一資料可查的位址，
         但剛好屬於某個公用雲端/CDN供應商」的情況，不能只檢查候選
         成員本身。
      3. protected_ranges 為 None（代表白名單設定檔無法可靠讀取/解析）
         時，無從驗證前兩項，一律視為不安全。

    回傳 (是否安全可聚合, 原因說明)，不論通過或拒絕都附上文字，供
    rule_analysis.build_cidr_aggregation_report() 等報表直接引用。
    """
    if protected_ranges is None:
        return False, "public_infra_rules.json 無法讀取/解析，無法可靠驗證此網段，保守拒絕聚合"

    hit_members = [ip for ip in member_ips if is_public_cloud(ip, base.get(ip, {}).get("asn"))]
    if hit_members:
        return False, f"候選成員命中公用設施白名單: {sorted(hit_members)[:5]}"

    for protected_net in protected_ranges:
        if subnet.overlaps(protected_net):
            return False, f"/24網段與已知公用雲端/CDN網段重疊: {protected_net}"

    return True, "通過安全檢查：候選成員與整段網段範圍皆未命中已知白名單"


def extract_asn_number(raw: Any) -> Optional[str]:
    """取出 ASN 純數字編號（去除 AS 前綴），跟前端 extractAsnNumber()/
    count_asn_occurrences() 同邏輯，供 ASN 節流分組用。"""
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    text = re.sub(r"^as\s*", "", text, flags=re.IGNORECASE)
    match = re.match(r"^(\d+)", text)
    return match.group(1) if match else None


# tier 優先序：聚合後的代表 tier 取組內最高優先者（A > B > C），確保
# 混入任何通道A成員的聚合結果，在後續 ASN 節流階段仍被視為通道A豁免。
_TIER_RANK = {"A": 0, "B": 1, "C": 2}


def aggregate_to_cidr(
    candidates: List[Tuple[str, float, str, str]],
    base: Dict[str, Dict[str, Any]],
    is_public_cloud: Callable[[str, Any], bool],
    protected_ranges: Optional[List[ipaddress.IPv4Network]],
    threshold: int = CIDR_ROLLUP_THRESHOLD,
    rejected_subnet_reports: Optional[List[Dict[str, Any]]] = None,
) -> List[Tuple[str, float, str, str, Any, List[str]]]:
    """
    第四階之一（順序：先聚合、後節流，見 select_edl_candidates 的說明）：
    /24 CIDR 動態聚合收斂。將候選 IP 依 /24 網段分組；同一網段內候選
    數量 >= threshold 只是「有資格接受安全檢查」的前提，不是自動聚合的
    充分條件（2026-10-22 修正：保守策略，不再「同一/24出現>=5筆候選
    就自動認定整段適合封鎖」）——還要通過 verify_cidr_safe_for_
    aggregation() 的完整安全檢查（候選成員本身、以及整個/24範圍是否
    命中公用雲端/CDN白名單）才會真的聚合；沒通過安全檢查（含白名單
    設定檔無法可靠讀取的情況）一律退回輸出原始個別IP，不嘗試聚合。

    protected_ranges 由呼叫端傳入（通常是 load_public_infra_cidr_
    ranges() 的結果）：None 代表白名單設定檔無法可靠驗證，見
    verify_cidr_safe_for_aggregation() 的保守處理。

    rejected_subnet_reports（純觀測用，2026-10-22新增，見審查發現的
    「CIDR安全拒絕 x ASN節流」互動情境）：選填的可變list，若提供，
    函式會把「候選數達到threshold、但沒通過安全檢查」的每個網段，以
    {"subnet": 網段字串, "member_ips": 該組候選IP清單} 附加進去——這是
    明確的內部metadata（直接來自分組當下的判斷結果），不是靠事後字串
    猜測或推斷。刻意只在候選數「有資格」接受安全檢查、卻沒通過時才記錄
    （即真正被「拒絕聚合」的情況），不包含候選數原本就未達threshold、
    根本沒嘗試聚合的網段——兩者在統計意義上不同，不可混為一談。這個
    參數完全不影響 entries 的實際內容或聚合判斷本身，只是額外側録，
    預設None時函式行為跟加這個參數前完全一致。
    """
    groups: Dict[ipaddress.IPv4Network, List[Tuple[str, float, str, str]]] = defaultdict(list)
    for item in candidates:
        ip = item[0]
        # 防禦層（審查後新增）：/24分組語意僅定義於IPv4。f"{ip}/24"對IPv6
        # 位址仍能被ipaddress.ip_network()成功解析（/24是合法的IPv6前綴
        # 長度，但涵蓋範圍跟IPv4的/24完全不是一回事）。實測過（不是理論
        # 推測）：Python的IPv6Network.overlaps(IPv4Network)不會拋例外，
        # 而是直接回傳False（不同版本一律視為不重疊），這代表沒有命中
        # 個別白名單成員時，verify_cidr_safe_for_aggregation()會誤判為
        # 「安全」，靜默產生一個像`2001:d00::/24`這種對防火牆毫無意義的
        # 假CIDR聚合條目——比crash更隱蔽。真正會crash的地方在更下游：
        # select_edl_candidates()排序selected清單時假設每個字串都能拆成
        # IPv4四段式數字，遇到IPv6字串會丟ValueError。正常情況下呼叫端
        # （select_edl_candidates()／rule_analysis.py的候選蒐集迴圈）應該
        # 已經在候選入口排除IPv6，這裡是最後一道不依賴呼叫端自律的防線，
        # 不只是防呆assert：遇到非IPv4一律跳過分組、不納入聚合，並留下
        # 明確log可供追查，不會讓其餘IPv4候選的處理被中斷。
        if ipaddress.ip_address(ip).version != 4:
            log.warning(
                "aggregate_to_cidr() 收到非IPv4候選 %s，/24 CIDR聚合僅支援IPv4，"
                "已略過（呼叫端應在候選蒐集階段先行排除）",
                ip,
            )
            continue
        subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
        groups[subnet].append(item)

    entries: List[Tuple[str, float, str, str, Any, List[str]]] = []
    for subnet, items in groups.items():
        ips = [it[0] for it in items]
        is_safe = False
        if len(items) >= threshold:
            is_safe, _reason = verify_cidr_safe_for_aggregation(
                subnet, ips, base, is_public_cloud, protected_ranges
            )
        if is_safe:
            best_score = max(it[1] for it in items)
            best_last_seen = max((it[2] for it in items), default="")
            best_tier = min(items, key=lambda it: _TIER_RANK.get(it[3], 9))[3]
            rep_asn = base[ips[0]].get("asn")
            entries.append((str(subnet), best_score, best_last_seen, best_tier, rep_asn, ips))
        else:
            if len(items) >= threshold and rejected_subnet_reports is not None:
                rejected_subnet_reports.append({"subnet": str(subnet), "member_ips": list(ips)})
            for it in items:
                entries.append((it[0], it[1], it[2], it[3], base[it[0]].get("asn"), [it[0]]))
    return entries


def throttle_by_asn(
    candidates: List[Tuple[str, float, str, str, Any, List[str]]],
    max_per_asn: int = ASN_THROTTLE_MAX_PER_ASN,
) -> List[Tuple[str, float, str, str, Any, List[str]]]:
    """
    第四階之二：同一 ASN 最多保留「分數最高、最後活躍時間最新」的前 N
    筆條目，其餘剔除——因應通道 B/C 被單一大型 ISP/VPS 商跨多個不同
    /24 網段分散灌水的情況。通道 A（即時實質危害）不受此節流影響，
    一律保留；聚合後含通道A成員的 CIDR 條目，tier 已在 aggregate_to_
    cidr() 標記為 "A"，同樣豁免。

    刻意在 /24 聚合「之後」才執行（而非之前）：一個聚合後的 CIDR 條目
    只占用該 ASN 的 1 個名額，不論其背後涵蓋了多少個別 IP；若順序顛倒
    （節流在前、聚合在後），同一 ASN 底下、剛好也同屬一個 /24 的多台
    主機會在節流階段就被各自當成獨立名額消耗掉，浪費掉本該只需 1 個
    名額就能完整涵蓋的聚合機會，也可能讓原本可以靠聚合保留下來的 IP
    提早被節流剔除。
    """
    tier_a = [item for item in candidates if item[3] == "A"]
    others = [item for item in candidates if item[3] != "A"]

    groups: Dict[str, List[Tuple[str, float, str, str, Any, List[str]]]] = defaultdict(list)
    no_asn: List[Tuple[str, float, str, str, Any, List[str]]] = []
    for item in others:
        asn_num = extract_asn_number(item[4])
        if asn_num:
            groups[asn_num].append(item)
        else:
            no_asn.append(item)

    kept = list(no_asn)
    for items in groups.values():
        items.sort(key=lambda it: (it[1], it[2] or ""), reverse=True)
        kept.extend(items[:max_per_asn])

    return tier_a + kept


def select_edl_candidates(
    base: Dict[str, Dict[str, Any]], now: datetime, apply_today_new_bootstrap: bool = False
) -> Tuple[
    List[str],
    Dict[str, int],
    List[Tuple[str, float, str, str, Any, List[str]]],
    List[Tuple[str, str]],
]:
    """
    EDL 四階過濾漏斗（由嚴到寬依序套用）：

      第一階 RFC 規範與合規清洗：排除組播/私有/保留等非法公網單播位址。
      第二階 時效窗口：各通道各自獨立判定（見 is_edl_candidate()），
             通道A/C要求 last_seen 在24小時內，通道B放寬到14天內。
      第三階 雙軌入榜 + 掃描雜訊排除：見 is_edl_candidate()。
      第四階 先 /24 CIDR 動態聚合收斂、再 ASN 節流：見 aggregate_to_
             cidr() 與 throttle_by_asn()，輸出前再明確去重一次，確保
             blocklist_edl.txt 條目唯一、IP/CIDR 混編。

             順序刻意是「先聚合、後節流」：一個聚合後的 CIDR 條目只
             占用該 ASN 的 1 個節流名額，不論背後涵蓋多少個別 IP。
             若順序顛倒，同一 ASN 底下恰好同屬一個 /24 的多台主機會在
             節流階段就被各自當成獨立名額消耗掉，浪費掉本該只需 1 個
             名額就能完整涵蓋的聚合機會。

    同時把判定結果以 record["edl_tier"] = "A" / "B" / None 寫回每筆
    base 紀錄（直接修改傳入的 dict），讓前端能直接讀取「當初是依哪個
    條件被收錄」，不必自行以瀏覽器當下時間重新計算——聚合只是輸出格式
    上的壓縮，被聚合進 CIDR 的個別 IP 仍保留原本的 A/B 標記不變。同時
    寫回 record["edl_recent_seen_count_c"]（近7天滾動視窗次數，通道C
    判定用）、record["edl_recent_seen_count_b"]（近14天滾動視窗次數，
    通道B判定用，窗口長度跟通道C不同）、record["edl_recent_seen_count"]
    （向下相容的通用欄位，值跟著最終分配到的tier走）、
    record["edl_first_added_date"]（首次被收錄進EDL阻斷清單的台北時間
    日期，只在「上一輪不在榜上、這一輪新收錄」那一瞬間蓋成當天，往後
    持續留在榜上不會再更新）與 record["is_today_new"]（edl_first_added_
    date 是否等於今天），供前端「僅看今日/本次新增」篩選與匯出報表
    「判定說明」文字直接讀取使用。

    這套「比對上一輪有沒有在EDL裡」的判定方式刻意不看日曆日期、也不
    假設排程一定每天固定跑一次——維運架構是「每日開機才批次同步一次」
    （可能累積好幾天份、例如週末沒開機、週一才一次補抓），只要上一輪
    沒收錄、這一輪收錄了，不管中間隔了幾個日曆天都算「這次新增」，
    不會因為橫跨多天的批次同步而漏判。

    apply_today_new_bootstrap=True 時，會額外處理「這個欄位剛上線、
    所有現有EDL紀錄都還沒有 edl_first_added_date 可用」的一次性冷啟動
    情境：取目前EDL候選中最新一批的 first_seen 日期，把同一批的紀錄
    初始標記為今天新增，避免剛上線那次執行看起來永遠是0筆；呼叫端
    （main()）只在 is_edl_today_new_bootstrapped() 回傳 False 時傳
    True，且必須在這次執行成功寫出結果後呼叫
    mark_edl_today_new_bootstrapped()，確保這個邏輯一輩子只套用一次，
    之後全部改回純粹的「上一輪有沒有在榜上」差集判定。

    回傳四元組 (selected, stats, export_entries, retired_entries)：
    export_entries 是跟 selected 一一對應、尚未格式化成文字的聚合明細
    六元組（entry/score/last_seen/tier/asn/member_ips），供
    build_edl_export_rows() 組裝 CSV 匯出報表用；之所以延後到呼叫端
    另外組裝文字，是因為報表裡的「所屬ASN/ISP」欄位要查 ASN 字典，而
    ASN 字典在本函式執行完後、update_asn_dictionary() 才會補齊本輪新
    解析到的 ASN 名稱。retired_entries 是 (ip, 上一輪的tier) 二元組
    列表，列出「相較上一次執行基準，這一輪已經跌出EDL」的個別IP，供
    build_edl_retired_rows() 組裝「退場清單」CSV 報表用；只反映「上一輪
    到這一輪」這一次的差異，不是歷史上所有曾經退場過的IP。
    """
    stats = {
        "excluded_non_routable": 0,
        # 目前EDL候選判定、/24 CIDR聚合(aggregate_to_cidr()用
        # ip_network(f"{ip}/24")建構子網，/24在IPv6語意完全不同於IPv4，
        # 且IPv6Network跟protected_ranges裡的IPv4Network比較時
        # .overlaps()不會報錯、而是直接回傳False，可能讓安全檢查誤判、
        # 靜默產生無意義的假CIDR聚合條目)、以及最終輸出排序(假設每個
        # 字串都能拆成IPv4四段式數字，IPv6字串會讓排序丟出ValueError)
        # 都只支援IPv4。is_valid_public_ip()本身語意是「合法可路由公網
        # 位址」，刻意不侷限IPv4版本，因此IPv6的排除獨立計數、不跟
        # 「組播/私有/保留」的excluded_non_routable混在一起，方便未來
        # 若要支援IPv6時能準確定位這個邊界。
        "excluded_non_ipv4": 0,
        "excluded_scanner_noise": 0,
        "excluded_fallback_threshold": 0,
        "condition_a": 0,
        "condition_b": 0,
        "condition_c": 0,
        "whitelist_excluded": 0,
        "asn_throttle_excluded": 0,
        "cidr_rollup_subnets": 0,
        "cidr_rollup_ips_absorbed": 0,
        # ---- 以下為2026-10-22新增的純觀測統計（選項D：只加統計，不改變
        # 既有選擇結果），用來追蹤「CIDR聚合遭拒絕」與「ASN節流」兩個
        # 機制疊加時的實際影響範圍，見審查報告的互動情境分析。 ----
        # 候選IP數：通過白名單排除後、送進CIDR聚合前的候選總數，等同
        # len(candidates)；跟 condition_a+condition_b+condition_c 加總
        # 應該永遠相等，這裡額外明確命名一個欄位避免每次要手動加總。
        "pre_aggregation_candidate_count": 0,
        # 聚合後的EDL條目數：aggregate_to_cidr()輸出的entries數量（尚未
        # 經過ASN節流），CIDR條目跟個別IP條目都各算1筆「條目」。
        "post_aggregation_entry_count": 0,
        # CIDR聚合遭拒絕的網段組數：候選數達CIDR_ROLLUP_THRESHOLD、但
        # 沒通過verify_cidr_safe_for_aggregation()安全檢查的/24網段個數。
        "cidr_rejected_subnet_count": 0,
        # 上述被拒絕網段，背後涉及的候選IP總數（加總各網段的候選數）。
        "cidr_rejected_candidate_ip_count": 0,
        # ASN節流排除的「輸出條目數」：throttle_by_asn()丟棄的entries
        # 數量（len(aggregated)-len(throttled)），不是底層IP數——一個
        # 被丟棄的CIDR條目在這裡只算1筆，即使背後有多個IP。
        "asn_throttle_excluded_entries": 0,
        # ASN節流排除的「唯一IP數」：被丟棄的entries展開member_ips後的
        # 去重IP個數。跟既有的asn_throttle_excluded欄位算法完全相同
        # （保留舊欄位不動，這裡只是用更明確的名稱重複暴露一次，避免
        # 使用者誤以為asn_throttle_excluded是條目數而非IP數）。
        "asn_throttle_excluded_unique_ip_count": 0,
        # 上述被ASN節流排除的唯一IP裡，有多少筆同時也來自「CIDR聚合遭
        # 拒絕」的網段——這是本次新增統計的核心交叉歸因指標，直接回答
        # 審查報告提出的「CIDR安全拒絕是否真的排擠了其他候選」問題。
        "asn_throttle_excluded_from_rejected_cidr_count": 0,
        # 上述被ASN節流排除的唯一IP裡，有多少筆的threat_score達到
        # ASN_THROTTLE_HIGH_SCORE_AUDIT_THRESHOLD（純觀測門檻，非選擇
        # 門檻）——用來快速定位「分數很高卻被節流擠掉」的高風險個案。
        "asn_throttle_excluded_high_score_unique_ip_count": 0,
        # 最終唯一IP涵蓋數：經過CIDR聚合+ASN節流定案後，實際被blocklist_
        # edl.txt涵蓋到的「唯一IP位址」個數（CIDR條目會展開成員計算，
        # 不會因為CIDR跟個別IP條目同時存在而重複或漏算）。注意這個數字
        # 通常會大於等於最終輸出的「條目數」(len(selected))，因為1個
        # CIDR條目背後可能涵蓋多個IP。
        "final_unique_ip_coverage": 0,
    }

    candidates: List[Tuple[str, float, str, str]] = []

    today_str = taipei_today_str()

    # 提前到迴圈之前載入（而非像舊版留到CIDR聚合階段才載入）：白名單
    # 命中現在會在「第二階+第三階」判定當下就直接把tier打回None，不是
    # 只影響CIDR聚合的防呆保護，兩個判定都要用同一份白名單資料。
    is_public_cloud = load_public_infra_matcher()
    protected_cidr_ranges = load_public_infra_cidr_ranges()

    # 「退場(Retired)」判定用：記下每筆IP在本輪覆寫edl_tier之前的舊值
    # （即上一輪執行完、已經過CIDR聚合+ASN節流定案的最終狀態），本輪
    # 執行完畢後拿來跟「這輪最終還在不在EDL裡」比對，找出「上一輪還在
    # 榜上、這一輪完全跌出去」的IP——跟「今日/本次新增」是對稱的相反
    # 方向判定，刻意不另外維護一份快照檔案：data/base_iocs.json本身
    # 每輪執行都會把定案後的edl_tier持久化下來，下一輪讀回來的值就是
    # 現成的「前一次基準」，沒有必要為了同一件事再多存一份快照。
    previous_tier_by_ip: Dict[str, Optional[str]] = {}

    for ip, record in base.items():
        # 第一階
        previous_tier_by_ip[ip] = record.get("edl_tier")
        if not is_valid_public_ip(ip):
            stats["excluded_non_routable"] += 1
            record["edl_tier"] = None
            record["edl_first_added_date"] = None
            continue

        # IPv4/IPv6邊界：is_valid_public_ip()通過不代表可以進入後續的
        # /24 CIDR聚合與ASN節流——那兩道機制目前都只認得IPv4（見上方
        # stats["excluded_non_ipv4"]的註解）。這裡明確檢查並提前排除，
        # 不讓IPv6候選靜默流進候選清單、也不是靠下游聚合階段意外失敗
        # 來「順便」擋下。
        if ipaddress.ip_address(ip).version != 4:
            stats["excluded_non_ipv4"] += 1
            log.warning(
                "IP %s 是IPv6，目前EDL管線（CIDR聚合/ASN節流）僅支援IPv4，已排除於候選名單外",
                ip,
            )
            record["edl_tier"] = None
            record["edl_first_added_date"] = None
            continue

        labels_norm = normalize_tags(record.get("labels"))
        threat_score = to_number(record.get("threat_score")) or 0
        confidence = to_number(record.get("confidence")) or 0
        last_seen_dt = parse_iso(record.get("last_seen"))
        # 通道C跟通道B的頻次計算視窗長度不同(7天 vs 14天)，分開算、
        # 兩個欄位都存起來：edl_recent_seen_count_b 供「複合高危」標註
        # 等需要明確知道「這筆IP是否也符合通道B頻次」的場景直接讀取，
        # 不受最終被分到哪個tier影響。
        seen_count_c = compute_recent_seen_count(record, now, window_days=RECENT_WINDOW_DAYS)
        seen_count_b = compute_recent_seen_count(record, now, window_days=PERSISTENCE_WINDOW_DAYS)
        record["edl_recent_seen_count_c"] = seen_count_c
        record["edl_recent_seen_count_b"] = seen_count_b

        # 第二階 + 第三階
        # 判定前先記住「上一輪」的 edl_tier（還沒被這輪結果覆寫前的舊值），
        # 用來偵測這筆紀錄是不是「今天才剛跨過門檻、新加入EDL」。
        previous_tier = record.get("edl_tier")
        tier = is_edl_candidate(
            labels_norm, threat_score, confidence, last_seen_dt,
            seen_count_c, seen_count_b, now
        )

        # 2026-10-22 安全性修正：命中公用雲端/CDN白名單的IP，不論哪個
        # 通道判定出結果，一律不得輸出到正式EDL——先前的架構只拿
        # is_public_cloud() 做CIDR聚合的防呆保護，從未真的把白名單IP
        # 排除在blocklist_edl.txt之外，是真實存在的誤封風險缺口（見
        # rule_analysis.py 第一階段分析報告）。這裡在tier判定出來的
        # 當下就直接攔截，確保不管候選名單後續有沒有被CIDR聚合、ASN
        # 節流處理，白名單IP都不會進入candidates、不會出現在最終輸出。
        # 原始命中的tier仍保留在 edl_whitelist_excluded_tier 供稽核，
        # 不會因為被排除就讓這筆紀錄的歷史判定依據憑空消失。
        whitelist_hit = is_public_cloud(ip, record.get("asn"))
        if whitelist_hit and tier is not None:
            stats["whitelist_excluded"] += 1
            record["edl_whitelist_excluded_tier"] = tier
            tier = None
        else:
            record["edl_whitelist_excluded_tier"] = None
        record["edl_whitelist_match"] = whitelist_hit

        record["edl_tier"] = tier
        # edl_recent_seen_count：向下相容用的通用欄位，值跟著最終分配到
        # 的tier走（B用14天窗口的次數，其餘用7天窗口的次數）。
        record["edl_recent_seen_count"] = seen_count_b if tier == "B" else seen_count_c

        # 「今日新增」是EDL阻斷清單情境下的「今天這張清單比昨天多出來的
        # IP」，不是「IP本身今天才第一次被系統寫入」——條件B/C需要近7天
        # 累積到3~4次才會命中，若用「today新增」=「IP記錄今天才首次
        # 寫入(first_recorded)」，條件B/C永遠不可能是當天新建的紀錄，
        # 這個篩選就會對B/C恆為0筆。正確做法是比較「上一輪有沒有在EDL
        # 裡」：上一輪不在（previous_tier是None）、這一輪有收錄，不論是
        # 通道A當天空降的實質危害、還是通道B/C今天才剛好湊滿次數門檻，
        # 都算是「今天新入榜」，edl_first_added_date 只在這個瞬間蓋成
        # 今天，往後只要持續留在EDL裡就不再更新，確保它代表的是「最初
        # 那次入榜的日期」而非「最近一次被確認仍在榜上的日期」；一旦
        # 跌出EDL（tier變None）就清空，哪天重新回到榜上會被視為全新的
        # 一次入榜事件。
        if tier is not None:
            if previous_tier is None:
                record["edl_first_added_date"] = today_str
        else:
            record["edl_first_added_date"] = None
        # 供前端「僅看今日新增」篩選與匯出報表直接讀取使用。
        record["is_today_new"] = record.get("edl_first_added_date") == today_str

        if tier == "A":
            stats["condition_a"] += 1
            candidates.append((ip, threat_score, record.get("last_seen") or "", tier))
        elif tier == "B":
            stats["condition_b"] += 1
            candidates.append((ip, threat_score, record.get("last_seen") or "", tier))
        elif tier == "C":
            stats["condition_c"] += 1
            candidates.append((ip, threat_score, record.get("last_seen") or "", tier))
        elif labels_norm & SCANNER_NOISE_TAGS and not (labels_norm & MUST_HAVE_TAGS):
            stats["excluded_scanner_noise"] += 1
        else:
            stats["excluded_fallback_threshold"] += 1

    # 「今日/本次新增」一次性冷啟動 bootstrap（見函式docstring）：只在
    # 呼叫端明確表示「這個欄位還沒初始化過」時才做，且只處理這一批
    # 「上一輪本來就已經在榜上、所以沒被判定為新增」的既有紀錄——真正
    # 透過上面迴圈偵測到的新增（edl_first_added_date已經是today_str）
    # 不會被這裡影響到，不會重複處理。
    if apply_today_new_bootstrap:
        latest_batch_first_seen = max(
            (r.get("first_seen") for r in base.values() if r.get("edl_tier") and r.get("first_seen")),
            default=None,
        )
        if latest_batch_first_seen:
            for record in base.values():
                if (
                    record.get("edl_tier")
                    and record.get("first_seen") == latest_batch_first_seen
                    and not record.get("edl_first_added_date")
                ):
                    record["edl_first_added_date"] = today_str
                    record["is_today_new"] = True

    # 第四階之一：/24 CIDR 動態聚合收斂（公用雲端/CDN 白名單保護，防誤殺）
    # ——刻意在節流「之前」執行，見函式本身與上方說明。is_public_cloud/
    # protected_cidr_ranges 已在迴圈之前載入過，這裡沿用同一份，不重複
    # 讀檔。rejected_subnet_reports 純觀測用（見stats欄位說明），不影響
    # aggregate_to_cidr()本身的聚合判斷或輸出內容。
    stats["pre_aggregation_candidate_count"] = len(candidates)
    rejected_subnet_reports: List[Dict[str, Any]] = []
    aggregated = aggregate_to_cidr(
        candidates, base, is_public_cloud, protected_cidr_ranges,
        rejected_subnet_reports=rejected_subnet_reports,
    )
    stats["post_aggregation_entry_count"] = len(aggregated)
    stats["cidr_rejected_subnet_count"] = len(rejected_subnet_reports)
    stats["cidr_rejected_candidate_ip_count"] = sum(
        len(r["member_ips"]) for r in rejected_subnet_reports
    )
    # 攤平成一個IP集合，供節流之後交叉比對「被節流排除的IP裡，有哪些
    # 其實是來自CIDR聚合遭拒絕的網段」——明確的內部metadata（直接來自
    # aggregate_to_cidr()當下的分組判斷），不是事後用字串猜測或正規
    # 表示式反推。
    rejected_subnet_ip_set: Set[str] = set()
    for r in rejected_subnet_reports:
        rejected_subnet_ip_set.update(r["member_ips"])

    rollup_subnets = [e for e in aggregated if "/" in e[0]]
    stats["cidr_rollup_subnets"] = len(rollup_subnets)
    stats["cidr_rollup_ips_absorbed"] = len(candidates) - (len(aggregated) - len(rollup_subnets))

    # 第四階之二：ASN 節流（在聚合後執行，通道A不受影響，只節流通道B/C；
    # 聚合後的 CIDR 條目只占用 1 個節流名額，不論涵蓋多少個別IP）
    throttled = throttle_by_asn(aggregated)

    all_member_ips = set()
    for item in aggregated:
        all_member_ips.update(item[5])
    kept_member_ips = set()
    for item in throttled:
        kept_member_ips.update(item[5])
    stats["asn_throttle_excluded"] = len(all_member_ips) - len(kept_member_ips)

    # ---- 純觀測統計（選項D，不影響上面任何一行既有的選擇/輸出邏輯）----
    throttled_out_ips = all_member_ips - kept_member_ips
    stats["asn_throttle_excluded_entries"] = len(aggregated) - len(throttled)
    stats["asn_throttle_excluded_unique_ip_count"] = len(throttled_out_ips)
    stats["asn_throttle_excluded_from_rejected_cidr_count"] = len(
        throttled_out_ips & rejected_subnet_ip_set
    )
    stats["asn_throttle_excluded_high_score_unique_ip_count"] = sum(
        1 for ip in throttled_out_ips
        if (to_number(base.get(ip, {}).get("threat_score")) or 0)
        >= ASN_THROTTLE_HIGH_SCORE_AUDIT_THRESHOLD
    )
    stats["final_unique_ip_coverage"] = len(kept_member_ips)

    # 被節流剔除的個別 IP（含被剔除之聚合 CIDR 背後的全部成員 IP）不再
    # 進入最終名單，edl_tier 改回 None，避免前端誤判成仍在 EDL 內——
    # 跟成功留下的 CIDR 聚合不同，聚合只是換個呈現方式，節流則是真的
    # 排除，兩者對 edl_tier 的影響必須分開處理。edl_first_added_date/
    # is_today_new 也一併清空：這些IP實際上沒有真的留在最終EDL裡，
    # 不該繼續背著「首次入榜日期」，哪天真的被留下來才算重新入榜。
    for ip in all_member_ips - kept_member_ips:
        base[ip]["edl_tier"] = None
        base[ip]["edl_first_added_date"] = None
        base[ip]["is_today_new"] = False

    # 「退場」判定：上一輪有tier（previous_tier_by_ip不是None）、這一輪
    # 最終(已經過CIDR聚合+ASN節流定案)卻是None的IP，就是這次相較上一次
    # 基準跌出EDL的條目。刻意在這裡（CIDR/節流都處理完才算）判定，確保
    # 不管是「本來就沒再命中任何通道」還是「命中了但被節流踢出」都算數。
    retired_entries: List[Tuple[str, str]] = [
        (ip, prev_tier)
        for ip, prev_tier in previous_tier_by_ip.items()
        if prev_tier is not None and base.get(ip, {}).get("edl_tier") is None
    ]

    # 全域唯一性輸出：明確去重後才寫出，確保 blocklist_edl.txt 條目唯一
    # （IP 與 CIDR 混編時，純 IP 依四段數字排序、CIDR 依網路位址排序）
    final_entries = [item[0] for item in throttled]
    selected = list(dict.fromkeys(final_entries))
    selected.sort(key=lambda s: tuple(int(x) for x in s.split("/")[0].split(".")))

    # 供 build_edl_export_rows() 組裝 CSV 匯出用的完整聚合資訊（score/
    # last_seen/tier/asn/member_ips），依 selected 的順序與去重結果整理，
    # 確保匯出報表跟 blocklist_edl.txt 的條目完全一一對應。
    throttled_by_entry = {item[0]: item for item in throttled}
    export_entries = [throttled_by_entry[entry] for entry in selected]

    return selected, stats, export_entries, retired_entries


_CJK_RE = re.compile(r"[⺀-鿿豈-﫿　-〿]+")


def ascii_only_org_name(name: Optional[str]) -> str:
    """把 ASN 組織名稱清成純 ASCII：data/asn_dict.json 裡有少數手動預先
    維護的台灣/中國 ISP 條目混雜中文（例如「中國電信 ChinaNet」），其餘
    透過 RDAP/RIPEstat 查詢到的名稱本身已是純英文。一律先剔除 CJK
    統一表意文字／全形標點區段字元，再清掉因此留下的多餘空白與孤立
    括號，確保進到英文純文字匯出檔（TXT/CSV）的欄位不會殘留非ASCII
    字元；查無任何英文殘留時回傳空字串（寧可留白，不捏造內容）。"""
    if not name:
        return ""
    text = _CJK_RE.sub(" ", str(name))
    text = text.strip(" ()[]")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def resolve_asn_parts(asn_raw: Any, asn_dict: Dict[str, Dict[str, Any]]) -> Tuple[str, str]:
    """回傳 (asn, asn_org) 兩個獨立欄位，供英文純文字匯出檔
    （TXT/CSV）使用：asn 固定是 "ASxxxx" 格式，asn_org 是清過CJK字元
    的組織名稱（查無資料時兩者皆為空字串）。跟網頁UI沿用的合併顯示
    欄位（「ASxxxx 組織名稱」單一字串）分開維護，因為UI本身可以顯示
    中文，不受這次「匯出檔一律純英文」的要求限制。"""
    asn_num = extract_asn_number(asn_raw)
    if not asn_num:
        return "", ""
    entry = asn_dict.get(asn_num)
    name = entry.get("name") if isinstance(entry, dict) else None
    return f"AS{asn_num}", ascii_only_org_name(name)


def to_taipei_display(iso_value: Optional[str]) -> str:
    """把 ISO8601 UTC 時間字串轉成台北時間的易讀格式，供 CSV 匯出報表
    顯示用，避免使用者誤解UTC時間產生8小時時差落差；解析失敗或空值
    一律回傳「-」。

    若原始UTC時間的時分秒剛好都是0（例如 Luminar 的 first_seen 常只有
    日期精度、時間部分是補零佔位，不代表真的在當天0點發生），代表這個
    時間欄位本來就只有日期精度，直接轉成台北時間反而會顯示出一個
    「08:00:00」這種看起來很精確、實際上毫無意義的假時間，所以這種
    情況只輸出日期（YYYY-MM-DD，不受時區轉換影響日期本身，因為UTC
    0點加8小時仍是台北時間同一天）；其餘有實際時分秒精度的時間才轉成
    完整的 YYYY-MM-DD HH:MM:SS。"""
    dt = parse_iso(iso_value)
    if dt is None:
        return "-"
    if dt.time() == dt_time(0, 0, 0):
        return dt.astimezone(TAIPEI_TZ).strftime("%Y-%m-%d")
    return dt.astimezone(TAIPEI_TZ).strftime("%Y-%m-%d %H:%M:%S")


def to_taipei_iso8601(iso_value: Optional[str]) -> str:
    """把 ISO8601 UTC 時間字串轉成帶台北時區偏移量的 ISO8601
    （+08:00，而非 Z），供 EDL 純文字匯出檔（firewall訂閱用）的標頭
    時間戳使用，方便維運人員直接看懂本地時間，不必自行換算。"""
    dt = parse_iso(iso_value)
    if dt is None:
        return "-"
    return dt.astimezone(TAIPEI_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")


def build_trigger_reason(
    tier: str,
    is_cidr: bool,
    score: float,
    confidence: float,
    freq_b: int,
    freq_c: int,
    label_union: Set[str],
) -> str:
    """組出精簡版的入榜判定說明：只留純粹的判定依據上下文（分數/頻次/
    信心值等動態數字），不再加大寫分類代碼前綴——channel欄位本身已經
    單獨承載「這是哪個通道」的資訊，trigger_reason不需要重複一次。
    門檻數字一律讀程式碼裡的常數變數，不要寫死字面值，避免日後調整
    門檻時這裡忘記同步更新導致說明文字跟實際判定邏輯不一致。

    通道A若同時完整符合通道B/C各自的門檻（不是只命中其中一兩項數字，
    而是頻次/分數/信心值三者皆達標），直接把對應通道的完整判定文字
    接在後面（用 " | " 串接，依A→C→B的既定優先序排列），不再用抽象的
    COMPOSITE_ESCALATION代碼摘要——讓分析師直接看到兩段完整、各自站得
    住腳的判定依據，不必再回頭猜測代碼對應的實際數字。"""
    def channel_a_text() -> str:
        matched_tags = sorted(label_union & MUST_HAVE_TAGS) or sorted(label_union)
        tag_str = ", ".join(matched_tags) if matched_tags else "unknown"
        return f"Matched tag [{tag_str}] with score {score:g}"

    def channel_b_text() -> str:
        return (
            f"Observed {freq_b} hits within {PERSISTENCE_WINDOW_DAYS}d, "
            f"score {score:g}, conf {confidence:g}"
        )

    def channel_c_text() -> str:
        return f"Score {score:g} with {freq_c} hits in {RECENT_WINDOW_DAYS}d, conf {confidence:g}"

    if is_cidr:
        return f"Subnet rollup triggered by malicious entries in /24 block (representative_channel={tier})"
    if tier == "A":
        parts = [channel_a_text()]
        composite_c = (
            score >= FALLBACK_MIN_SCORE
            and confidence >= FALLBACK_MIN_CONFIDENCE
            and freq_c >= FALLBACK_MIN_SEEN_COUNT
        )
        composite_b = (
            freq_b >= PERSISTENCE_MIN_SEEN_COUNT
            and score >= PERSISTENCE_MIN_SCORE
            and confidence >= PERSISTENCE_MIN_CONFIDENCE
        )
        if composite_c:
            parts.append(channel_c_text())
        if composite_b:
            parts.append(channel_b_text())
        return " | ".join(parts)
    if tier == "B":
        return channel_b_text()
    # tier == "C"
    return channel_c_text()


def classify_retired_reason(
    ip: str,
    prev_tier: str,
    record: Dict[str, Any],
    now: datetime,
    is_public_cloud: Callable[[str, Any], bool],
) -> str:
    """針對跌出EDL門檻的IOC，動態比對這一輪的實際數值跟「上一輪所屬
    通道」的各項門檻，找出具體是哪一個條件先失守，組成英文結構化的
    退場原因。偵測順序：白名單命中（政策性排除，優先於其餘組織性因素
    判斷）> 時效過期 > 頻次不足 > 分數/信心值衰退 > 其餘（目前架構下
    唯一會落到這裡的情況是同一ASN節流上限擠掉——該IP其餘各項數值其實
    都還符合舊通道門檻，只是本輪ASN節流只保留同ASN分數最高的前
    ASN_THROTTLE_MAX_PER_ASN筆，這點目前的5種既定代碼沒有完全對應的
    選項，暫時沿用DROP_ASN_THROTTLED這個新增代碼，而非勉強套用語意
    不符的既定代碼）。"""
    threat_score = to_number(record.get("threat_score")) or 0
    confidence = to_number(record.get("confidence")) or 0
    last_seen_dt = parse_iso(record.get("last_seen"))

    if is_public_cloud(ip, record.get("asn")):
        return "REVOKED_WHITELIST_MATCH: Matched internal exception list or trusted infrastructure"

    if last_seen_dt is None:
        return "EXPIRED_INACTIVITY: Last-seen timestamp unavailable, exceeding observation window"

    if prev_tier == "A":
        window_hours = STRICT_WINDOW_HOURS
        if last_seen_dt < now - timedelta(hours=window_hours):
            days = (now - last_seen_dt).days
            return f"EXPIRED_INACTIVITY: Inactive for {days} days, exceeding {window_hours}h observation window"
        if threat_score < MUST_HAVE_MIN_SCORE:
            return f"DROP_SCORE_DEGRADED: Threat score reduced to {threat_score:g} (below {MUST_HAVE_MIN_SCORE} channel threshold)"
        return "DROP_SCORE_DEGRADED: No longer matches Channel A critical-threat tag criteria"

    if prev_tier == "B":
        seen_count_b = record.get("edl_recent_seen_count_b", 0)
        window_days = PERSISTENCE_RECENCY_WINDOW_DAYS
        if last_seen_dt < now - timedelta(days=window_days):
            days = (now - last_seen_dt).days
            return f"EXPIRED_INACTIVITY: Inactive for {days} days, exceeding {window_days}d observation window"
        if seen_count_b < PERSISTENCE_MIN_SEEN_COUNT:
            return f"DROP_FREQUENCY_INSUFFICIENT: Occurrence count fell to {seen_count_b} (<{PERSISTENCE_MIN_SEEN_COUNT} required for Channel B)"
        if threat_score < PERSISTENCE_MIN_SCORE or confidence < PERSISTENCE_MIN_CONFIDENCE:
            return f"DROP_SCORE_DEGRADED: Threat score/confidence reduced to {threat_score:g}/{confidence:g} (below channel threshold)"
        return "DROP_ASN_THROTTLED: Excluded by per-ASN retention cap (top 5 ranked entries kept)"

    if prev_tier == "C":
        seen_count_c = record.get("edl_recent_seen_count_c", 0)
        window_hours = FALLBACK_WINDOW_HOURS
        if last_seen_dt < now - timedelta(hours=window_hours):
            days = (now - last_seen_dt).days
            return f"EXPIRED_INACTIVITY: Inactive for {days} days, exceeding {window_hours}h observation window"
        if seen_count_c < FALLBACK_MIN_SEEN_COUNT:
            return f"DROP_FREQUENCY_INSUFFICIENT: Occurrence count fell to {seen_count_c} (<{FALLBACK_MIN_SEEN_COUNT} required for Channel C)"
        if threat_score < FALLBACK_MIN_SCORE or confidence < FALLBACK_MIN_CONFIDENCE:
            return f"DROP_SCORE_DEGRADED: Threat score/confidence reduced to {threat_score:g}/{confidence:g} (below channel threshold)"
        return "DROP_ASN_THROTTLED: Excluded by per-ASN retention cap (top 5 ranked entries kept)"

    return "DROP_SCORE_DEGRADED: No longer meets any channel threshold"


def build_edl_export_rows(
    export_entries: List[Tuple[str, float, str, str, Any, List[str]]],
    base: Dict[str, Dict[str, Any]],
    asn_dict: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    把 select_edl_candidates() 回傳的聚合明細，組裝成 docs 前端「CSV 情資
    匯出」用的報表列：每一列對應 blocklist_edl.txt 的一個條目（純 IP 或
    /24 CIDR 聚合皆有一列）。輸出全面採英文機器可讀格式（ip/domain/
    type/channel/threat_score/confidence/frequency/first_seen/
    last_seen/retired_at/retired_reason/trigger_reason/asn/asn_org
    這組跟 build_edl_retired_rows() 共用的統一欄位結構），不含任何
    中文字元，避免跨平台/SIEM/防火牆解析時的編碼問題。

    刻意延後到 select_edl_candidates() 之外才組裝（而非在裡面直接做），
    是因為「asn_org」要查 ASN 字典，必須等 update_asn_dictionary()
    補完本輪新解析到的 ASN 名稱之後才能拿到最新版本。

    注意：目前資料模型裡沒有獨立的「情報來源/feed」欄位（STIX資料本身
    沒有攜帶這項資訊），能取得的網路歸屬資訊只有 ASN/ISP，asn/asn_org
    呈現的是網路歸屬，不是情報來源本身。
    """
    rows: List[Dict[str, Any]] = []

    for entry, score, last_seen, tier, asn, member_ips in export_entries:
        is_cidr = "/" in entry
        members = [base[ip] for ip in member_ips if ip in base]

        confidences = [to_number(m.get("confidence")) or 0 for m in members]
        confidence = max(confidences) if confidences else 0
        first_seens = [m.get("first_seen") for m in members if m.get("first_seen")]
        first_seen = min(first_seens) if first_seens else None
        is_today_new = any(m.get("is_today_new") for m in members)
        label_union: Set[str] = set()
        domain_union: Set[str] = set()
        for m in members:
            label_union |= normalize_tags(m.get("labels"))
            domain_union.update(d for d in (m.get("resolving_domains") or []) if d)
        # 聚合後的CIDR條目背後可能橫跨多個不同ASN的成員IP（理論上少見，
        # /24多半同屬一個ASN，但保守取第一個代表值而非強制唯一假設）。
        asn_str, asn_org = resolve_asn_parts(asn, asn_dict)

        rep = base.get(entry, {}) if not is_cidr else {}
        freq_c = rep.get("edl_recent_seen_count_c", 0)
        freq_b = rep.get("edl_recent_seen_count_b", 0)
        frequency = freq_b if tier == "B" else freq_c
        trigger_reason = build_trigger_reason(tier, is_cidr, score, confidence, freq_b, freq_c, label_union)

        rows.append(
            {
                "entry": entry,
                "channel": tier,
                "threat_score": score,
                "confidence": confidence,
                "frequency": "" if is_cidr else frequency,
                "first_seen": to_taipei_iso8601(first_seen),
                "last_seen": to_taipei_iso8601(last_seen),
                "asn": asn_str,
                "asn_org": asn_org,
                "domains": sorted(domain_union),
                "labels": sorted(label_union),
                "is_today_new": is_today_new,
                "trigger_reason": trigger_reason,
                "retired_reason": "",
                "retired_at": "",
            }
        )

    return rows


def build_edl_retired_rows(
    retired_entries: List[Tuple[str, str]],
    base: Dict[str, Dict[str, Any]],
    asn_dict: Dict[str, Dict[str, Any]],
    now: datetime,
) -> List[Dict[str, Any]]:
    """
    把 select_edl_candidates() 回傳的 retired_entries，組裝成前端「退場
    清單」CSV 匯出報表用的列：退場IP一律是個別IP（不會是CIDR——CIDR只
    是最終輸出格式上的聚合產物，沒有自己獨立的退場生命週期，判斷退場
    與否一律回到背後的個別IP層級）。欄位結構刻意跟 build_edl_export_
    rows() 完全一致（同一組英文snake_case欄位），前端可以直接共用
    同一套CSV欄位排版/篩選邏輯，不必另外寫一份。
    """
    is_public_cloud = load_public_infra_matcher()
    rows: List[Dict[str, Any]] = []
    for ip, prev_tier in retired_entries:
        record = base.get(ip, {})
        labels_norm = normalize_tags(record.get("labels"))
        score = to_number(record.get("threat_score")) or 0
        confidence = to_number(record.get("confidence")) or 0
        asn_str, asn_org = resolve_asn_parts(record.get("asn"), asn_dict)
        domains = sorted({d for d in (record.get("resolving_domains") or []) if d})
        first_seen = record.get("first_seen")
        last_seen = record.get("last_seen")
        frequency = record.get(
            "edl_recent_seen_count_b" if prev_tier == "B" else "edl_recent_seen_count_c", 0
        )

        retired_reason = classify_retired_reason(ip, prev_tier, record, now, is_public_cloud)

        rows.append(
            {
                "entry": ip,
                "channel": prev_tier,
                "threat_score": score,
                "confidence": confidence,
                "frequency": frequency,
                "first_seen": to_taipei_iso8601(first_seen),
                "last_seen": to_taipei_iso8601(last_seen),
                "asn": asn_str,
                "asn_org": asn_org,
                "domains": domains,
                "labels": sorted(labels_norm),
                "is_today_new": False,
                "trigger_reason": "",
                "retired_reason": retired_reason,
                "retired_at": to_taipei_iso8601(now_utc_iso()),
            }
        )

    return rows


def build_edl_rules_snapshot() -> Dict[str, Any]:
    """
    把目前這版 EDL 四階過濾漏斗的所有門檻常數，整理成一份結構化
    snapshot，給前端「EDL 判定規則」頁籤直接讀取顯示。

    這份 JSON 是直接從程式碼裡的常數組出來的，每次 pipeline.py 執行都
    會重新產生——刻意不讓網頁另外手刻一份文字說明，避免跟實際程式碼
    的門檻脫鉤（這學期已經因為門檻反覆調整、手動維護的網頁文字數次
    跟不上程式碼異動）。要調整規則，只需要改這支檔案裡的常數，網頁會
    自動反映最新版本。

    2026-10-22第三輪更新（單一資料來源改造方案A）：docs/index.html的
    「EDL阻斷清單」頁籤（edlCriteriaPanel）最下方的CIDR/ASN/白名單說明
    footnote，現在由app.js的renderEdlCriteriaFootnote()從下面的
    edl_tab_summary欄位動態覆寫，不再是獨立手寫、容易脫鉤的靜態文字
    （docs/index.html裡仍保留同樣內容的靜態版本，只當作載入失敗時的
    fallback，兩邊文字理論上應該要一致——修改edl_tab_summary時記得
    一併檢查那段fallback文字）。注意：edl_tab_summary是刻意另外寫的
    精簡版本，用詞比下面stage3_channels/stage4_convergence給「EDL判定
    規則」頁籤用的逐階詳細說明更簡短，不是直接拼接那些欄位的文字。
    3張A/B/C門檻卡片本身（tier-block）維持原本寫死的HTML，這次沒有
    一併動態化。
    """
    return {
        "generated_at": now_utc_iso(),
        "stage1_ip_filter": {
            "name": "RFC 合規與 Bogon 清洗",
            "description": "依據 RFC 6890 / 5735 規範，嚴格剔除私有網段（RFC 1918）、組播"
            "（RFC 5771, 224.0.0.0/4）、環回位址（127.0.0.0/8）、Link-Local 及保留位址，"
            "確保清單僅包含具備實際路由效力之公網單播位址。",
        },
        "stage2_tags": {
            "must_have_tags": sorted(MUST_HAVE_TAGS),
            "must_have_tags_description": "實質危害標籤：命中任一項，具備「不被雜訊標籤剃除」的豁免權。",
            "scanner_noise_tags": sorted(SCANNER_NOISE_TAGS),
            "scanner_noise_tags_description": "純探測/測繪雜訊標籤：未命中 must_have_tags 時，命中任一項即直接剃除。",
        },
        "stage3_channels": {
            "A": {
                "name": "即時實質危害",
                "tier": "A",
                "window_hours": STRICT_WINDOW_HOURS,
                "min_score": MUST_HAVE_MIN_SCORE,
                "requires": "labels ∩ must_have_tags ≠ ∅",
                "min_seen_count": 1,
                "min_confidence": None,
                "description": "命中 must_have_tags 任一項，即使同時命中 scanner_noise_tags 也不剃除；"
                f"score >= {MUST_HAVE_MIN_SCORE} 即收錄，出現 1 次也算數，不限最後活躍時間窗以外的其他條件。",
            },
            "B": {
                "name": "頑固攻擊者收斂通道",
                "tier": "B",
                "window_hours": PERSISTENCE_RECENCY_WINDOW_DAYS * 24,
                "min_score": PERSISTENCE_MIN_SCORE,
                "min_confidence": PERSISTENCE_MIN_CONFIDENCE,
                "min_seen_count": PERSISTENCE_MIN_SEEN_COUNT,
                "description": "未命中條件 A 時：最後活躍在 "
                f"{PERSISTENCE_RECENCY_WINDOW_DAYS} 天內 且 近 {PERSISTENCE_WINDOW_DAYS} 天累積出現次數 >= "
                f"{PERSISTENCE_MIN_SEEN_COUNT} 次 且 威脅分數 >= {PERSISTENCE_MIN_SCORE} 分"
                f"（不設上限）且 信心值 >= {PERSISTENCE_MIN_CONFIDENCE} 分"
                "（定位：以量補質。頻次累積視窗（14天）比時效窗口（7天）更長，"
                f"鎖定單日分數未達頂級、但近{PERSISTENCE_WINDOW_DAYS}天內頻繁刺探 >= "
                f"{PERSISTENCE_MIN_SEEN_COUNT} 次、且最後活躍仍在近{PERSISTENCE_RECENCY_WINDOW_DAYS}天內"
                "的真正頑固 IP；若最後活躍已經是8天以上前，代表近期已無實際動作，"
                "會被視為退場，不再死纏爛打式地卡在通道B）。",
            },
            "C": {
                "name": "高確信威脅",
                "tier": "C",
                "window_hours": FALLBACK_WINDOW_HOURS,
                "min_score": FALLBACK_MIN_SCORE,
                "min_confidence": FALLBACK_MIN_CONFIDENCE,
                "min_seen_count": FALLBACK_MIN_SEEN_COUNT,
                "description": "未命中條件 A 時：最後活躍在 "
                f"{FALLBACK_WINDOW_HOURS} 小時內 且 近 7 天累積出現次數 >= {FALLBACK_MIN_SEEN_COUNT} "
                f"次 且 威脅分數 >= {FALLBACK_MIN_SCORE} 分 且 信心值 >= {FALLBACK_MIN_CONFIDENCE} 分"
                "（定位：以質補量。多方情資判定達"
                f" {FALLBACK_MIN_SCORE} 分極高危險者，無須等待累積至第"
                f" {PERSISTENCE_MIN_SEEN_COUNT} 天，活躍 >= {FALLBACK_MIN_SEEN_COUNT} "
                "次即提前破格入榜）。",
            },
        },
        "stage3b_whitelist_exclusion": {
            "name": "公用雲端/CDN 白名單排除",
            "order": "於 A/B/C 通道判定之後、CIDR 聚合與 ASN 節流之前套用",
            "applies_to": ["A", "B", "C"],
            "source": "docs/data/public_infra_rules.json",
            "description": "候選IP只要命中公用雲端/CDN白名單（完全比對IP、ASN，或落在官方公告的CDN "
            "CIDR網段），無論原本落在通道A、B或C，一律強制排除於EDL阻斷清單之外，不會以任何形式"
            "（個別IP或CIDR聚合條目）出現在blocklist_edl.txt；僅保留命中紀錄供稽核"
            "（edl_whitelist_match / edl_whitelist_excluded_tier），並轉移至「雲端公用清單」頁籤"
            "建議改以 Domain/URL 聯防，以免誤封鎖共用基礎設施導致合法業務中斷。",
        },
        "stage4_convergence": {
            "cidr_rollup": {
                "threshold": CIDR_ROLLUP_THRESHOLD,
                "whitelist_protected": True,
                "order": 1,
                "description": "（優先於 ASN 節流執行）同一 C 類子網（/24）內候選惡意 IP 達 "
                f"{CIDR_ROLLUP_THRESHOLD} 筆以上時，先初步判定可收斂為單一 CIDR 條目；正式聚合前"
                "另有一道安全檢查（verify_cidr_safe_for_aggregation）：只要該網段內任一候選成員IP"
                "本身命中白名單，或整個 /24 範圍與已知公用雲端/CDN CIDR"
                "（docs/data/public_infra_rules.json 的 cdn_cidrs）有重疊——即使沒有任何候選IP本身"
                "被列在白名單裡，也會判定不安全；若白名單設定檔讀取失敗或CIDR格式無法解析而無法"
                "驗證，一律保守視為不安全（fail-closed）。只要觸發以上任一項，該網段即不聚合，改為"
                "維持輸出網段內各候選IP的原貌（其中命中白名單的成員IP本身會依「公用雲端/CDN白名單"
                "排除」規則整體排除於EDL之外，不會以個別IP形式出現；其餘未命中白名單的候選IP則正常"
                "以個別IP條目輸出）。",
            },
            "asn_throttle": {
                "max_per_asn": ASN_THROTTLE_MAX_PER_ASN,
                "applies_to": ["B", "C"],
                "exempt": ["A"],
                "order": 2,
                "description": "（在 C 類子網聚合「之後」執行）條件B、條件C 合併計算：同一 ASN "
                f"最多保留分數最高、最後活躍時間最新的前 {ASN_THROTTLE_MAX_PER_ASN} 筆，其餘剔除；"
                "條件A（高危直通）完全不受此限制，同一 ASN 即使超過上限也全數收錄。一個聚合後的"
                "CIDR 條目只占用 1 個節流名額，不論背後涵蓋多少個別 IP，避免同網段主機浪費掉"
                "本該保留給其他網段的節流額度。",
            },
            "dedup": {
                "description": "寫入 blocklist_edl.txt 前以 dict.fromkeys() 明確去重，確保條目唯一。",
            },
        },
        "edl_tab_summary": {
            "description": "符合任一條件即收錄進 EDL 阻斷清單；命中純掃描雜訊標籤或落在組播/私有/"
            "保留網段者一律排除。候選IP命中公用雲端/CDN 白名單者，不論落在哪個通道，一律於候選"
            "階段強制排除於EDL之外。同一 C 類子網（/24）內候選惡意 IP 達 "
            f"{CIDR_ROLLUP_THRESHOLD} 筆以上時，須先通過安全檢查（確認候選成員本身與整個網段"
            "範圍皆未與受保護範圍重疊）才會收斂為單一 CIDR 條目；白名單設定檔無法讀取、無法解析，"
            "或安全檢查本身無法可靠完成驗證時，一律視為不安全、不允許該次聚合通過安全檢查，改為"
            "維持輸出網段內各個別IP。條件 B、條件 C 合併計算，同一 ASN 最多保留分數最高、最後"
            f"活躍時間最新的前 {ASN_THROTTLE_MAX_PER_ASN} 筆，未通過CIDR安全檢查而退回的個別IP"
            "一樣受此節流規則約束（條件 A 高危直通不受此限，同一 ASN 超過 "
            f"{ASN_THROTTLE_MAX_PER_ASN} 筆也全數收錄）。其餘情資保留在「全部情資庫」供查詢，"
            "不列入阻斷。",
        },
    }


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

    # 部分 RIR（實測如 APNIC）會在頂層直接給結構化的 country 欄位，
    # 比從 vcard 地址自由格式文字解析更可靠，優先採用；查無此欄位
    # （常見於 ARIN/RIPE 來源）才退回解析 vcard label 文字。
    top_country = data.get("country")
    if top_country and re.fullmatch(r"[A-Za-z]{2}", str(top_country).strip()):
        return name, str(top_country).strip().upper()

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


def count_asn_occurrences(base: Dict[str, Dict[str, Any]]) -> Counter:
    """
    統計全量庫每個 ASN 編號在幾筆紀錄中出現（與前端 extractAsnNumber
    同邏輯取純數字編號）。回傳次數而非單純集合，讓查詢配額受限時能
    優先處理「影響範圍最大」的未收錄 ASN，而非依編號大小這種與實際
    資料無關的順序。
    """
    counts: Counter = Counter()
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
            counts[match.group(1)] += 1
    return counts


def update_asn_dictionary(
    base: Dict[str, Dict[str, Any]], max_per_run: int
) -> Dict[str, int]:
    """
    找出全量庫中尚未收錄的 ASN，透過 RDAP（失敗則 RIPEstat 備援）查詢
    組織名稱與國別，寫回 data/asn_dict.json。

    為避免單次執行查詢上百個 ASN 導致管線跑太久或被免費服務限流，
    每次執行最多新增 max_per_run 筆，其餘留到下次排程執行繼續補齊。
    查詢順序依「該 ASN 在本次資料中出現的筆數」由多到少排列，確保
    配額有限時優先解析影響範圍最大的 ASN（出現次數相同則退回依編號
    由小到大排序，確保每次執行順序穩定、好追蹤進度）。
    網路失敗的 ASN 不寫入字典（允許下次重試）；查詢成功但解析不出
    國別時，仍寫入並以 "--" 標示未知，避免每次都重查同一筆。
    """
    asn_dict = load_asn_dict()
    asn_counts = count_asn_occurrences(base)
    all_asns = set(asn_counts.keys())
    unknown = sorted(
        all_asns - set(asn_dict.keys()),
        key=lambda asn: (-asn_counts[asn], int(asn)),
    )

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
    edl_export_rows: Optional[List[Dict[str, Any]]] = None,
    edl_retired_rows: Optional[List[Dict[str, Any]]] = None,
    baseline_at_iso: Optional[str] = None,
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
                "edl_condition_c": edl_stats.get("condition_c", 0),
                "source": "Luminar STIX 2.1",
            },
            "iocs": base,
        },
    )

    # EDL：純 IP/CIDR 換行，供防火牆直接拉取（已經過階梯式判定篩選）。
    # 頂部標頭統一用全英文的3行 "#" 中繼註解（Generated_At/
    # Baseline_Snapshot_At/Feed_Type），全部匯出檔案（TXT/CSV）共用同一套
    # 格式，方便下游工具統一解析；主流防火牆的 EDL 訂閱功能都會略過
    # "#" 開頭的行，不影響實際阻斷名單解析。
    #
    # 單檔原子性 vs. 兩檔一致性（審查後補充說明，2026-10-22）：下面
    # blocklist_edl.txt 與 blocklist_edl_retired.txt 各自透過write_text_
    # atomic()獨立原子寫入——保證「讀者不會讀到寫到一半的半成品檔案」，
    # 但兩個檔案**不是**用單一交易一起提交：如果process剛好在寫完
    # blocklist_edl.txt之後、寫blocklist_edl_retired.txt之前被中斷，
    # 磁碟上會暫時呈現「EDL本身已是這一輪最新結果、退場清單仍是上一輪
    # 舊內容」的不一致組合（反之不會發生，因為EDL永遠先寫）。這種落差
    # 會在下次成功執行時自動被下一輪的完整覆寫追平，不會累積或惡化，
    # 本輪刻意不引入兩檔合併成單一交易的複雜機制（例如兩者都先寫
    # tmp、最後才一起replace）來解決這個邊緣情況。
    edl_header = [
        f"# Generated_At: {to_taipei_iso8601(stamp)}",
        f"# Baseline_Snapshot_At: {to_taipei_iso8601(baseline_at_iso)}",
        "# Feed_Type: Active_IOCs",
    ]
    write_text_atomic(EDL_FILE, "\n".join(edl_header + edl_ips) + "\n")

    # EDL 匯出報表（供前端「匯出 IOC 情資 (.csv)」功能使用）：跟
    # blocklist_edl.txt 條目一一對應，額外附上人類可讀的判定說明文字，
    # 由 build_edl_export_rows() 組裝。
    if edl_export_rows is not None:
        write_json(EDL_EXPORT_FILE, edl_export_rows)

    # 退場清單（供前端「匯出 IOC 情資」全量模式一併產出 Retired 檔案
    # 使用）：只反映「上一輪到這一輪」這一次的差異，每輪執行都整份
    # 覆寫，不是歷史上所有曾經退場過的IP的累積清單。即使這輪沒有任何
    # IP退場（空陣列）也要覆寫成空陣列，否則前端會一直讀到上一輪的
    # 舊退場清單而誤判。
    if edl_retired_rows is not None:
        write_json(EDL_RETIRED_FILE, edl_retired_rows)

        # 純文字版退場清單，格式對齊 blocklist_edl.txt（純IP/CIDR逐行），
        # 供 Firewall 直接訂閱來解封（Unblock/Delist）這一輪跌出EDL的
        # 條目。退場清單只會是個別IP（見 build_edl_retired_rows() 說明：
        # CIDR沒有獨立退場生命週期），所以這裡不需要處理 CIDR 格式。
        # 0筆退場時仍要寫出檔案，只是只有標頭註解、沒有任何IP，避免
        # Firewall端讀到舊檔的過期內容。
        retired_header = [
            f"# Generated_At: {to_taipei_iso8601(stamp)}",
            f"# Baseline_Snapshot_At: {to_taipei_iso8601(baseline_at_iso)}",
            "# Feed_Type: Retired_IOCs",
        ]
        retired_ips = [r["entry"] for r in edl_retired_rows]
        write_text_atomic(EDL_RETIRED_TXT_FILE, "\n".join(retired_header + retired_ips) + "\n")

    # 匯出時間戳 meta（供前端匯出按鈕旁的輔助文字、以及匯出CSV檔頂部的
    # # 註解使用）：generated_at 是這一輪的產出時間；baseline_at 是上一輪
    # （也就是這輪退場比對基準）的產出時間，首次執行沒有上一輪可比對時
    # 為 None。
    if edl_export_rows is not None or edl_retired_rows is not None:
        write_json(EDL_EXPORT_META_FILE, {
            "generated_at": stamp,
            "baseline_at": baseline_at_iso,
        })

    log.info(
        "輸出完成：base_iocs=%d 筆, EDL=%d 行（通道A命中=%d, 通道B命中=%d, 通道C命中=%d, "
        "排除-非公開路由=%d, 排除-掃描雜訊=%d, 排除-未達兜底門檻=%d, "
        "ASN節流排除=%d 筆, /24聚合收斂=%d 段(吸收 %d 筆IP), 相較上次基準退場=%d 筆）",
        len(base),
        len(edl_ips),
        edl_stats.get("condition_a", 0),
        edl_stats.get("condition_b", 0),
        edl_stats.get("condition_c", 0),
        edl_stats.get("excluded_non_routable", 0),
        edl_stats.get("excluded_scanner_noise", 0),
        edl_stats.get("excluded_fallback_threshold", 0),
        edl_stats.get("asn_throttle_excluded", 0),
        edl_stats.get("cidr_rollup_subnets", 0),
        edl_stats.get("cidr_rollup_ips_absorbed", 0),
        len(edl_retired_rows) if edl_retired_rows is not None else 0,
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


#   同步本身產生的檔案，除了 data/ 之外還會寫 docs/data/edl_rules.json
#   （EDL 判定規則 snapshot，每次執行都重新產生，純粹是 pipeline.py 自己
#   的輸出，不像 docs/data/public_infra_rules.json 是另一條 GitHub Actions
#   自動化在維護）。先前曾發生只 commit data/、漏掉這個檔案，導致它一直
#   處於未暫存狀態，進而卡住下面的 git rebase（rebase 要求整個工作目錄
#   乾淨，不只是 data/ 乾淨），讓明明已經 commit 成功的同步結果因為 push
#   失敗而留在本機，所以把它併入同一個 commit 範圍。
SYNC_COMMIT_PATHS = ["data/", "docs/data/edl_rules.json"]


def git_push(user: str, repo: str, pat: str, branch: str = "main") -> bool:
    """git add 同步輸出路徑 → commit → push。無異動則跳過。"""
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

    if run_git(["add", *SYNC_COMMIT_PATHS]).returncode != 0:
        log.error("git add 失敗")
        return False

    # 只檢查同步輸出路徑是否有已暫存的異動
    if run_git(["diff", "--cached", "--quiet", "--", *SYNC_COMMIT_PATHS]).returncode == 0:
        log.info("同步輸出無異動，略過 commit 與 push")
        return False

    message = f"chore(cti): sync IOCs {now_utc_iso()}"
    commit = run_git(["commit", "-m", message, "--", *SYNC_COMMIT_PATHS])
    if commit.returncode != 0:
        log.error("git commit 失敗: %s", (commit.stderr or commit.stdout).strip())
        return False
    log.info("已建立 commit: %s", message)

    # 直接把帶 PAT 的 URL 傳給 push，避免 token 落在 .git/config
    remote = f"https://{pat}@github.com/{user}/{repo}.git"

    # 這台機器同時也是互動開發環境，工作目錄常常還留著其他未commit的
    # 手動改動（例如 docs/app.js、docs/index.html 正在開發中）。下面的
    # git rebase 要求整個工作目錄乾淨，這些跟本次同步無關的異動會讓
    # rebase 直接失敗、拖累整次自動推送——所以推送前先暫存它們，推送
    # 完（不論成功或失敗）一律還原，確保排程的自動推送不受互動開發期間
    # 的未提交改動影響。
    stash_needed = run_git(["status", "--porcelain"]).stdout.strip() != ""
    if stash_needed:
        stash = run_git(["stash", "push", "--include-untracked", "-m", "git_push() 暫存非同步輸出的未提交改動"])
        if stash.returncode != 0:
            log.error("git stash 失敗，中止推送避免弄丟工作目錄改動: %s", (stash.stderr or stash.stdout).strip())
            return False

    def restore_stash() -> None:
        if stash_needed:
            pop = run_git(["stash", "pop"])
            if pop.returncode != 0:
                log.error(
                    "git stash pop 失敗，未提交改動仍在 stash 裡，請手動執行 git stash pop: %s",
                    (pop.stderr or pop.stdout).strip(),
                )

    # 推送前先 fetch + rebase：本機排程（data/）與其他自動化，例如公用設施
    # 白名單的 GitHub Actions（docs/），都會各自提交到同一個 branch，彼此
    # 改動的檔案路徑不同，用 rebase 接上遠端最新 commit 再推送，避免遠端
    # 在這之間多了其他 commit 時被直接拒絕（non-fast-forward），導致這次
    # 的同步結果留在本機沒推上去。
    fetch = run_git(["fetch", remote, branch], secret=pat)
    if fetch.returncode == 0:
        rebase = run_git(["rebase", "FETCH_HEAD"])
        if rebase.returncode != 0:
            log.error(
                "rebase 失敗（可能跟遠端改動衝突），中止推送並還原: %s",
                mask_secret((rebase.stderr or rebase.stdout).strip(), pat),
            )
            run_git(["rebase", "--abort"])
            restore_stash()
            return False
    else:
        log.warning(
            "git fetch 失敗，略過 rebase 直接嘗試推送: %s",
            mask_secret((fetch.stderr or fetch.stdout).strip(), pat),
        )

    push = run_git(["push", remote, f"HEAD:refs/heads/{branch}"], secret=pat)
    if push.returncode != 0:
        log.error(
            "git push 失敗: %s",
            mask_secret((push.stderr or push.stdout).strip(), pat),
        )
        restore_stash()
        return False

    restore_stash()
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
    p.add_argument(
        "--emit-decision-detail",
        action="store_true",
        help="額外產出 data/decision_detail.json 與 data/cidr_aggregation_report.json"
             "（IOC收斂可觀測性報表，純觀測用途，不影響既有EDL判定/輸出結果）。"
             "預設關閉，正常排程同步不受影響；本機分析/除錯時可加上這個旗標。",
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
    # 搶在 load_base_iocs() 把舊檔覆寫前，先記下上一輪的 generated_at，
    # 作為這一輪「退場」比對基準時間戳（首次執行沒有上一輪時為 None）。
    _prev_raw = read_json(BASE_IOCS_FILE, {})
    baseline_at_iso = (
        _prev_raw.get("meta", {}).get("generated_at")
        if isinstance(_prev_raw, dict) else None
    )
    base = load_base_iocs()
    counters, new_records = upsert_base_iocs(base, daily)
    stats.update(counters)
    log.info("Upsert: 新增 %d, 更新 %d, 資料庫總計 %d", counters["new"], counters["updated"], len(base))

    write_daily_iocs(new_records, stats)

    # ---- 3.5 EDL 階梯式判定 ----
    # need_today_new_bootstrap：「今日/本次新增」欄位是否還沒做過一次性
    # 冷啟動初始化，只會是 True 一次，成功寫出結果後立刻標記完成。
    need_today_new_bootstrap = not is_edl_today_new_bootstrapped()
    now = datetime.now(timezone.utc)
    edl_ips, edl_stats, edl_export_entries, edl_retired_entries = select_edl_candidates(
        base, now, apply_today_new_bootstrap=need_today_new_bootstrap
    )

    # ---- 3.6 ASN 字典自動化查詢與擴充（策略 2） ----
    if args.no_asn_lookup:
        log.info("ASN 字典：已指定 --no-asn-lookup，跳過查詢")
    else:
        asn_max_per_run = env_int("ASN_LOOKUP_MAX_PER_RUN", ASN_LOOKUP_DEFAULT_MAX_PER_RUN)
        asn_stats = update_asn_dictionary(base, asn_max_per_run)
        stats["asn_dict"] = asn_stats

    # 刻意在 update_asn_dictionary() 之後才組裝匯出報表，確保「所屬ASN/
    # ISP」欄位用的是本輪執行補完之後的最新 ASN 字典。
    asn_dict = load_asn_dict()
    edl_export_rows = build_edl_export_rows(edl_export_entries, base, asn_dict)
    edl_retired_rows = build_edl_retired_rows(edl_retired_entries, base, asn_dict, now)

    write_outputs(base, edl_ips, edl_stats, stats, edl_export_rows, edl_retired_rows, baseline_at_iso)

    if need_today_new_bootstrap:
        mark_edl_today_new_bootstrapped()

    # ---- 3.7 EDL 判定規則 snapshot（供前端「EDL 判定規則」頁籤讀取）----
    write_json(EDL_RULES_FILE, build_edl_rules_snapshot())

    # ---- 3.8（選用）IOC收斂可觀測性報表：判定明細 + CIDR聚合評估 ----
    # 預設關閉，不影響正常排程同步的執行時間與輸出；本機分析/除錯時才
    # 加 --emit-decision-detail 開啟。在函式內才 import rule_analysis，
    # 避免跟 pipeline.py 形成模組層級的循環匯入（rule_analysis.py 本身
    # 會 import pipeline）。
    if args.emit_decision_detail:
        import rule_analysis as ra

        log.info("產出IOC收斂可觀測性報表（--emit-decision-detail）...")
        decision_detail_rows = ra.build_decision_detail_rows(base, now)
        write_json(DECISION_DETAIL_FILE, decision_detail_rows)
        cidr_report_rows = ra.build_cidr_aggregation_report(base, now)
        write_json(CIDR_AGGREGATION_REPORT_FILE, cidr_report_rows)
        log.info(
            "已寫出 %s（%d 筆）與 %s（%d 個網段）",
            DECISION_DETAIL_FILE.name, len(decision_detail_rows),
            CIDR_AGGREGATION_REPORT_FILE.name, len(cidr_report_rows),
        )

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
