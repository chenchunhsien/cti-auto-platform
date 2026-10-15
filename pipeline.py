"""
pipeline.py
-----------
CTI 威脅情資自動化管線（純規則引擎，不使用 LLM）。

流程:
  1. 讀取 data/sync_state.json 的 high-water mark（無則回溯 N 小時）
  2. 呼叫 Luminar STIX 2.1 API 分頁取回增量物件
  3. 規則過濾：indicator + ipv4-addr + confidence>=90 + threat_score>=90
  4. Upsert 至 data/base_iocs.json，並輸出 blocklist_edl.txt / daily_iocs.json
  5. 回寫 high-water mark
  6. 自動 git add / commit / push 至遠端 main

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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
                "labels": as_list(obj.get("labels")),  # 完整保留
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
) -> Dict[str, int]:
    counters = {"new": 0, "updated": 0}
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

    return counters


def write_outputs(
    base: Dict[str, Dict[str, Any]],
    daily: List[Dict[str, Any]],
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
                "source": "Luminar STIX 2.1",
            },
            "iocs": base,
        },
    )

    write_json(
        DAILY_IOCS_FILE,
        {
            "meta": {
                "generated_at": stamp,
                "count": len(daily),
                "run_stats": stats,
            },
            "iocs": daily,
        },
    )

    # EDL：純 IP 換行，供防火牆直接拉取
    ips = sorted(
        base.keys(),
        key=lambda s: tuple(int(x) for x in s.split("/")[0].split(".")),
    )
    EDL_FILE.write_text("\n".join(ips) + ("\n" if ips else ""), encoding="utf-8")

    log.info(
        "輸出完成：base_iocs=%d 筆, daily_iocs=%d 筆, EDL=%d 行",
        len(base),
        len(daily),
        len(ips),
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
                    "LUMINAR_TOKEN_PATH", "/externalApi/realm/{realm}/token"
                ),
                ioc_path=env_str("LUMINAR_IOC_PATH", "/externalApi/v2/stix"),
                leaks_path=env_str("LUMINAR_LEAKS_PATH", "/externalApi/stix"),
                page_limit=env_int("PAGE_LIMIT", 100),
                max_pages=env_int("MAX_PAGES", 500),
            )
            with client:
                objects, latest_ts = client.fetch_stix(start_ts, feed=args.feed)
    except LuminarEntitlementError as exc:
        log.error("帳號權限不足: %s", exc)
        log.error(
            "請洽 Luminar 支援窗口，確認 client_id '%s' 是否已開通 "
            "STIX IOC feed（/externalApi/v2/stix）。",
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
    counters = upsert_base_iocs(base, daily)
    stats.update(counters)
    log.info("Upsert: 新增 %d, 更新 %d, 資料庫總計 %d", counters["new"], counters["updated"], len(base))

    write_outputs(base, daily, stats)

    # ---- 4. 回寫高水位線 ----
    if latest_ts:
        save_high_water_mark(latest_ts, stats)
    else:
        # API 未回傳 latestTimestamp 時，以本次執行時間為準（避免重複抓取）
        fallback_ts = epoch_ms(datetime.now(timezone.utc))
        log.warning("API 未提供 latestTimestamp，改以當前時間 %s 作為高水位線", fallback_ts)
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
