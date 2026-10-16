"""
scripts/sync_public_infra.py
-----------------------------
從 5 大官方權威端點同步最新 IPv4 CIDR 網段，更新
docs/data/public_infra_rules.json 的 cdn_cidrs 欄位與 last_sync_time。

以 Python 3 標準庫（urllib / json / ipaddress）為主實作，HTTP 請求不依賴
requests。唯一的例外：SSL 憑證驗證改用 certifi 提供的 CA 憑證包，而非
Python/OpenSSL 在本機的預設信任庫——實測發現 Windows 上 Python 預設的
憑證路徑（ssl.get_default_verify_paths()）在這台機器上並不存在，導致
api.fastly.com 這類需要特定中繼憑證的網站驗證失敗（CERTIFICATE_VERIFY_
FAILED），但 Cloudflare/AWS/Google/Microsoft 恰好不受影響；改用 certifi
的憑證包（本來就是 requests 的相依套件，pipeline.py 已經間接安裝，這裡
不需要額外安裝）即可穩定解決，且比停用憑證驗證更安全。若執行環境沒有
certifi，會自動退回系統預設信任庫，不會整支腳本掛掉。

資料來源：
  Cloudflare   https://www.cloudflare.com/ips-v4           （純文字，一行一個 CIDR）
  Fastly       https://api.fastly.com/public-ip-list        （JSON，addresses 陣列）
  AWS          https://ip-ranges.amazonaws.com/ip-ranges.json（JSON，篩 service=="CLOUDFRONT"）
  Google Cloud https://www.gstatic.com/ipranges/goog.json   （JSON，prefixes[].ipv4Prefix）
  Microsoft365 https://endpoints.office.com/endpoints/worldwide?... （JSON，各 endpoint 的 ips[]）

安全/穩健設計（2026-10-16 強化版）：
  - HTTP 請求層：每次請求 timeout=15 秒，連線失敗/逾時最多重試 2 次
    （總共最多 3 次嘗試），重試之間間隔 2 秒，仍失敗才視為該廠商失敗。
  - 資料完整性校驗（Sanity Check / 熔斷機制）：每家廠商各自設定最低
    網段數門檻（見 THRESHOLDS），避免官方端點暫時性 500、反爬蟲攔截、
    或回應格式改版導致「成功收到回應但內容異常稀少」這種不會被一般
    例外處理捕捉到的靜默資料劣化。只要任何一家未達門檻，就視為整批
    同步失敗——**完全不寫入 docs/data/public_infra_rules.json**（連
    其他 4 家原本抓取成功的資料也一併不寫），寧可讓舊資料繼續用到
    下次同步成功，也不要讓任何一家的壞資料污染正式檔案。
  - 全有全無（all-or-nothing）寫入：只有 5 家全數通過門檻檢查，才會
    真的覆寫檔案與更新 last_sync_time；任何一家未通過，原檔案（含
    last_sync_time）一個位元都不會被動到，直接 sys.exit(1)。
  - 所有 CIDR 一律用 ipaddress.IPv4Network(..., strict=False) 驗證，
    驗證失敗的字串直接捨棄（不計入該廠商的筆數，也可能因此觸發門檻
    熔斷，這是刻意的設計——驗證失敗的筆數不該被計入「有效網段」）。

用法:
  python scripts/sync_public_infra.py
"""

from __future__ import annotations

import ipaddress
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = ROOT / "docs" / "data" / "public_infra_rules.json"

TAIPEI_TZ = timezone(timedelta(hours=8))
HTTP_TIMEOUT = 15
HTTP_MAX_RETRIES = 2
HTTP_RETRY_DELAY_SECONDS = 2.0
USER_AGENT = "cti-auto-platform-public-infra-sync/1.0"


def _build_ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


SSL_CONTEXT = _build_ssl_context()

MS365_ENDPOINT = (
    "https://endpoints.office.com/endpoints/worldwide"
    "?clientrequestid=b10c5ed1-bad1-4ac6-ae3e-1335ee274e71"
)

# 這些名稱必須跟 docs/app.js 的 WHITELIST_RULES[].name 完全一致，
# 前端是用字串完全比對（provider === rule.name）去配對 CIDR 清單。
PROVIDER_CLOUDFLARE = "Cloudflare"
PROVIDER_FASTLY = "Fastly"
PROVIDER_AWS = "Amazon Web Services (AWS)"
PROVIDER_GOOGLE = "Google Cloud Platform (GCP)"
PROVIDER_MS365 = "Microsoft 365 / Azure"

# 資料完整性校驗門檻：實測基準值 Cloudflare 15 / Fastly 21 / AWS 214 /
# Google 130 / Microsoft365 34 筆，門檻抓基準值的 6~7 成，容許官方日常
# 微幅增減網段，但抓不到「回應正常但內容被腰斬」這種異常。
THRESHOLDS: Dict[str, int] = {
    PROVIDER_CLOUDFLARE: 10,
    PROVIDER_FASTLY: 15,
    PROVIDER_AWS: 100,
    PROVIDER_GOOGLE: 80,
    PROVIDER_MS365: 20,
}


def http_get(url: str) -> bytes:
    """帶重試的 GET：連線失敗/逾時最多重試 HTTP_MAX_RETRIES 次才放棄。"""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    last_exc: Exception = RuntimeError("unreachable")  # 迴圈至少跑一次，一定會被覆寫
    for attempt in range(HTTP_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=SSL_CONTEXT) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt < HTTP_MAX_RETRIES:
                print(
                    f"    連線失敗（第 {attempt + 1} 次嘗試）：{exc}，"
                    f"{HTTP_RETRY_DELAY_SECONDS:.0f} 秒後重試",
                    file=sys.stderr,
                )
                time.sleep(HTTP_RETRY_DELAY_SECONDS)
    raise last_exc


def is_valid_ipv4_cidr(cidr: str) -> bool:
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False


def dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def fetch_cloudflare() -> List[str]:
    text = http_get("https://www.cloudflare.com/ips-v4").decode("utf-8")
    candidates = [line.strip() for line in text.splitlines() if line.strip()]
    return dedupe_keep_order([c for c in candidates if is_valid_ipv4_cidr(c)])


def fetch_fastly() -> List[str]:
    data = json.loads(http_get("https://api.fastly.com/public-ip-list"))
    candidates = data.get("addresses", []) if isinstance(data, dict) else []
    return dedupe_keep_order([c for c in candidates if is_valid_ipv4_cidr(c)])


def fetch_aws_cloudfront() -> List[str]:
    data = json.loads(http_get("https://ip-ranges.amazonaws.com/ip-ranges.json"))
    prefixes = data.get("prefixes", []) if isinstance(data, dict) else []
    candidates = [
        p.get("ip_prefix", "")
        for p in prefixes
        if isinstance(p, dict) and p.get("service") == "CLOUDFRONT"
    ]
    return dedupe_keep_order([c for c in candidates if is_valid_ipv4_cidr(c)])


def fetch_google() -> List[str]:
    data = json.loads(http_get("https://www.gstatic.com/ipranges/goog.json"))
    prefixes = data.get("prefixes", []) if isinstance(data, dict) else []
    candidates = [
        p.get("ipv4Prefix", "")
        for p in prefixes
        if isinstance(p, dict) and p.get("ipv4Prefix")
    ]
    return dedupe_keep_order([c for c in candidates if is_valid_ipv4_cidr(c)])


def fetch_microsoft365() -> List[str]:
    data = json.loads(http_get(MS365_ENDPOINT))
    candidates: List[str] = []
    for entry in data if isinstance(data, list) else []:
        if not isinstance(entry, dict):
            continue
        for ip in entry.get("ips") or []:
            if isinstance(ip, str) and is_valid_ipv4_cidr(ip):
                candidates.append(ip)
    return dedupe_keep_order(candidates)


PROVIDERS: List[Tuple[str, Callable[[], List[str]]]] = [
    (PROVIDER_CLOUDFLARE, fetch_cloudflare),
    (PROVIDER_FASTLY, fetch_fastly),
    (PROVIDER_AWS, fetch_aws_cloudfront),
    (PROVIDER_GOOGLE, fetch_google),
    (PROVIDER_MS365, fetch_microsoft365),
]


def fetch_all_providers() -> Dict[str, List[str]]:
    """抓取全部 5 家廠商，回傳 {provider: cidrs}；單一廠商例外只讓該家
    結果變空清單，不會中斷其他家的抓取（熔斷判斷留到抓完全部才做，
    這樣單次執行的日誌才能一次看到全部 5 家各自的實際筆數）。"""
    results: Dict[str, List[str]] = {}
    for provider_name, fetch_fn in PROVIDERS:
        try:
            cidrs = fetch_fn()
        except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
            print(f"[FAIL] {provider_name}: {exc}", file=sys.stderr)
            cidrs = []
        except Exception as exc:  # noqa: BLE001 - 單一來源的任何例外都不該中斷整支腳本
            print(f"[FAIL] {provider_name}: 未預期錯誤 {exc!r}", file=sys.stderr)
            cidrs = []
        results[provider_name] = cidrs
    return results


def run_sanity_check(results: Dict[str, List[str]]) -> List[str]:
    """回傳未達門檻的廠商清單；空清單代表全數通過。"""
    failed = []
    for provider_name, fetch_fn in PROVIDERS:
        count = len(results.get(provider_name, []))
        threshold = THRESHOLDS[provider_name]
        if count >= threshold:
            print(f"[OK] {provider_name}: {count} 筆 CIDR（門檻 >= {threshold}）")
        else:
            print(
                f"[!] ERROR: {provider_name} 抓取數量異常 ({count} 筆)，觸發保護機制中止寫入！",
                file=sys.stderr,
            )
            failed.append(provider_name)
    return failed


def main() -> int:
    if not RULES_FILE.exists():
        print(f"找不到 {RULES_FILE}，請先確認專案路徑正確", file=sys.stderr)
        return 1

    results = fetch_all_providers()
    failed_providers = run_sanity_check(results)

    if failed_providers:
        print(
            f"偵測到 {len(failed_providers)}/{len(PROVIDERS)} 家廠商未達最低安全門檻"
            f"（{', '.join(failed_providers)}）。"
            f"為保護既有資料完整性，完全不覆寫 {RULES_FILE}，"
            "原有 cdn_cidrs 與 last_sync_time 保持不變。",
            file=sys.stderr,
        )
        return 1

    # 走到這裡代表 5 家全數通過門檻，才讀取現有檔案並覆寫——刻意延後
    # 讀檔時機，避免「讀檔 -> 抓取失敗 -> 中途寫入半套資料」的時間差風險。
    with RULES_FILE.open("r", encoding="utf-8") as fh:
        rules = json.load(fh)

    rules["cdn_cidrs"] = [
        {"provider": provider_name, "cidrs": results[provider_name]}
        for provider_name, _ in PROVIDERS
    ]
    rules["last_sync_time"] = datetime.now(TAIPEI_TZ).strftime("%Y-%m-%dT%H:%M:%S+08:00")

    with RULES_FILE.open("w", encoding="utf-8") as fh:
        json.dump(rules, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    print(f"已更新 {RULES_FILE}（5/5 家全數通過門檻並成功同步）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
