"""
luminar_client.py
-----------------
Luminar (Cognyte) STIX 2.1 External API v2 客戶端。

依官方文件《Luminar External Client APIs v4.0 (2026-08)》實作，並經
2026-10-15 對 cyberluminar.com 實測確認：

  Token : POST {base}/externalApi/v2/realm/{realm}/token
          body (x-www-form-urlencoded): grant_type=client_credentials,
                client_id, client_secret, scope=<scope>
          scope 必填（官方文件 5.1.1.2），本專案使用
          "externalAPI/stix.readonly"。漏填會導致 JWT scope 為空，
          查詢 API 一律回 400 "Invalid limit size (0-100): null"
          （乍看像是 limit 參數錯誤，實際上是查詢權限問題）。

  首頁查詢 : POST {base}/externalApi/v2/stix
          body: {"dataSources": [<source>], "resultsPerPage": 1-100,
                 "timestamp": <Epoch 毫秒>, "duration": "<scroll 保活時間>"}
          dataSources 合法值: all, IOC, leakedRecords, cyberFeed,
                              vulnerability

  續頁查詢 : POST {base}/externalApi/v2/stix/next   <-- 官方文件 6.1.2
          body: {"nextPageToken": <token>}          （只帶這一個欄位！）

          實測教訓：若誤將 nextPageToken 疊加送回 /externalApi/v2/stix
          （而非官方指定的 /stix/next），伺服器會接受請求但分頁不會真正
          前進，重複回傳同一批資料（翻 150 頁仍卡住）。改用正確端點後
          每頁皆為新資料，問題消失。

  回應: {"nextPageToken": str|null, "totalHits": long,
        "latestTimestamp": <Epoch 毫秒>, "stix": [bundle, ...]}
        每個 bundle 才有 "objects" 陣列，需攤平收集。

高水位線策略:
  totalHits 對應的是「整個查詢範圍」的物件總數，可能高達百萬筆以上；
  實測發現 `latestTimestamp` 隨分頁推進極慢（每頁僅增加數十~數百毫秒），
  若回溯區間涵蓋數天，單次執行往往無法掃到「現在」。
  因此本模組改以本次實際取得物件的 modified / extensions.collection_date /
  valid_from / created 欄位取最大值作為高水位線，並允許「長時間斷線後
  的補抓分成多次排程執行逐步追上」——這是合理且預期中的行為，而非 bug。
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests

log = logging.getLogger("luminar")

TOKEN_TTL_SECONDS = 300
TOKEN_REFRESH_SKEW = 30

# dataSources 列舉（官方文件 6.1.1.3 + 伺服器端錯誤訊息實測確認）
DATA_SOURCE_IOC = "IOC"
DATA_SOURCE_LEAKED_RECORDS = "leakedRecords"
DATA_SOURCE_VULNERABILITY = "vulnerability"
DATA_SOURCE_CYBER_FEED = "cyberFeed"
DATA_SOURCE_ALL = "all"

# 對外相容別名（pipeline.py 使用這兩個名稱選擇 feed）
FEED_IOC = DATA_SOURCE_IOC
FEED_LEAKED_CREDENTIALS = DATA_SOURCE_LEAKED_RECORDS

# 官方文件建議值（6.1.1.3 Recommended: 10；FAQ: 408 逾時請調小 resultsPerPage）
RECOMMENDED_RESULTS_PER_PAGE = 10
MAX_RESULTS_PER_PAGE = 100


class LuminarError(RuntimeError):
    """Luminar API 相關錯誤。"""


class LuminarEntitlementError(LuminarError):
    """
    伺服器回報 'Invalid limit size (0-100): null'。

    實測發現最常見肇因是 Token 請求漏帶 scope=externalAPI/stix.readonly
    （JWT scope 為空，查詢端一律視為未授權並回報 limit=null）；
    其次才是帳號確實未開通該 dataSource。
    """


class LuminarClient:
    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        token_path: str = "/externalApi/v2/realm/{realm}/token",
        query_path: str = "/externalApi/v2/stix",
        query_next_path: str = "/externalApi/v2/stix/next",
        scope: str = "externalAPI/stix.readonly",
        page_limit: int = RECOMMENDED_RESULTS_PER_PAGE,
        scroll_duration: str = "2m",
        max_pages: int = 2000,
        timeout: int = 120,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_path = token_path
        self.query_path = query_path
        self.query_next_path = query_next_path
        self.scope = scope
        self.page_limit = max(1, min(int(page_limit), MAX_RESULTS_PER_PAGE))
        self.scroll_duration = scroll_duration
        self.max_pages = max_pages
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    # ------------------------------------------------------------------ #
    # Token 管理
    # ------------------------------------------------------------------ #
    @property
    def token_url(self) -> str:
        return self.base_url + self.token_path.format(realm=self.realm)

    @property
    def query_url(self) -> str:
        return self.base_url + self.query_path

    @property
    def query_next_url(self) -> str:
        return self.base_url + self.query_next_path

    def _token_is_valid(self) -> bool:
        return bool(self._token) and time.monotonic() < self._token_expiry

    def get_token(self, force: bool = False) -> str:
        """取得有效 Token；效期內直接回傳快取，否則重新申請。"""
        if not force and self._token_is_valid():
            return self._token  # type: ignore[return-value]

        log.info("申請新的 Luminar access token ...")
        try:
            resp = self.session.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": self.scope,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except requests.RequestException as exc:
            raise LuminarError(f"Token 請求連線失敗: {exc}") from exc

        if resp.status_code != 200:
            raise LuminarError(
                f"Token 請求失敗 HTTP {resp.status_code}: {resp.text[:300]}"
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise LuminarError(f"Token 回應非 JSON: {resp.text[:300]}") from exc

        token = body.get("access_token")
        if not token:
            raise LuminarError(f"Token 回應缺少 access_token: {body}")

        if not body.get("scope"):
            log.warning(
                "Token 回應的 scope 為空；查詢 API 可能會回報 "
                "'Invalid limit size (0-100): null'。請確認 LUMINAR_SCOPE 設定正確。"
            )

        ttl = int(body.get("expires_in") or TOKEN_TTL_SECONDS)
        self._token = token
        # 提早 TOKEN_REFRESH_SKEW 秒視為過期，避免長時間分頁拉取途中失效
        self._token_expiry = time.monotonic() + max(ttl - TOKEN_REFRESH_SKEW, 5)
        log.info("Token 取得成功，效期 %ss（提前 %ss 刷新），scope=%s",
                  ttl, TOKEN_REFRESH_SKEW, body.get("scope") or "(空)")
        return token

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------ #
    # HTTP
    # ------------------------------------------------------------------ #
    def _post(self, url: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """送出請求；遇 401 自動刷新 Token 重試一次。"""
        for attempt in (1, 2):
            try:
                resp = self.session.post(
                    url,
                    json=body,
                    headers=self._auth_headers(),
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except requests.RequestException as exc:
                raise LuminarError(f"POST {url} 連線失敗: {exc}") from exc

            if resp.status_code == 401 and attempt == 1:
                log.warning("收到 401，強制刷新 Token 後重試")
                self.get_token(force=True)
                continue

            if resp.status_code != 200:
                text = resp.text[:400]
                if "Invalid limit size" in text and ": null" in text:
                    raise LuminarEntitlementError(
                        "伺服器回報 limit 設定為 null："
                        "請確認 Token 請求有帶正確的 scope（LUMINAR_SCOPE），"
                        f"或洽 Luminar 確認帳號是否已開通此 dataSource (HTTP {resp.status_code}: {text})"
                    )
                if resp.status_code == 403:
                    raise LuminarError(
                        f"HTTP 403 Forbidden：本機 IP 可能未加入 Luminar 白名單，"
                        f"請洽 Luminar 確認。({text})"
                    )
                if resp.status_code == 408:
                    raise LuminarError(
                        f"HTTP 408 查詢逾時：請嘗試調小 resultsPerPage"
                        f"（官方建議 10）。({text})"
                    )
                raise LuminarError(f"POST {url} 失敗 HTTP {resp.status_code}: {text}")

            try:
                return resp.json()
            except ValueError as exc:
                raise LuminarError(f"回應非 JSON: {resp.text[:300]}") from exc

        raise LuminarError("重試後仍失敗")

    # ------------------------------------------------------------------ #
    # 回應解析
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_objects(body: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        攤平 {"stix": [{"type":"bundle","objects":[...]}, ...]} 結構。
        亦容錯支援舊版 / 其他包裝（objects / data 等直接在頂層的情況）。
        """
        if not isinstance(body, dict):
            return []

        bundles = body.get("stix")
        if isinstance(bundles, list):
            objects: List[Dict[str, Any]] = []
            for bundle in bundles:
                if isinstance(bundle, dict) and isinstance(bundle.get("objects"), list):
                    objects.extend(o for o in bundle["objects"] if isinstance(o, dict))
                elif isinstance(bundle, dict):
                    # 萬一 stix 陣列內直接就是物件而非 bundle
                    objects.append(bundle)
            return objects

        for key in ("objects", "data", "items", "results"):
            value = body.get(key)
            if isinstance(value, list):
                return [o for o in value if isinstance(o, dict)]
        return []

    @staticmethod
    def _extract_next_token(body: Dict[str, Any]) -> Optional[str]:
        if not isinstance(body, dict):
            return None
        value = body.get("nextPageToken")
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _extract_latest_timestamp(body: Dict[str, Any]) -> Optional[int]:
        """取回應中的 latestTimestamp 欄位，僅供診斷記錄用（見模組說明）。"""
        if not isinstance(body, dict):
            return None
        value = body.get("latestTimestamp")
        if value in (None, ""):
            return None
        try:
            ts = int(value)
        except (TypeError, ValueError):
            return None
        return ts * 1000 if 0 < ts < 10_000_000_000 else ts

    @staticmethod
    def _latest_from_objects(objects: Iterable[Dict[str, Any]]) -> Optional[int]:
        """
        以本次實際取得之物件（不限 indicator，所有型別都掃）的
        modified / extensions.collection_date / valid_from / created
        取最大值，作為真正可信的高水位線來源。
        """
        latest: Optional[int] = None

        def consider(raw: Any) -> None:
            nonlocal latest
            if not isinstance(raw, str) or not raw:
                return
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ms = int(dt.timestamp() * 1000)
            if latest is None or ms > latest:
                latest = ms

        for obj in objects:
            consider(obj.get("modified"))
            consider(obj.get("valid_from"))
            consider(obj.get("created"))
            ext = obj.get("extensions")
            if isinstance(ext, dict):
                for v in ext.values():
                    if isinstance(v, dict):
                        consider(v.get("collection_date"))

        return latest

    # ------------------------------------------------------------------ #
    # 公開 API
    # ------------------------------------------------------------------ #
    def fetch_stix(
        self, timestamp: int, feed: str = FEED_IOC
    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        """
        從指定時間戳（Epoch 毫秒）起抓取 STIX 物件。

        首頁 POST 至 query_path（/externalApi/v2/stix），續頁依官方文件
        6.1.2 改 POST 至 query_next_path（/externalApi/v2/stix/next），
        body 僅帶 nextPageToken。

        Args:
            timestamp: 起始時間戳，Epoch 毫秒（僅套用於第一頁請求）。
            feed: dataSources 值，預設 FEED_IOC（"IOC"）；
                  外洩憑證可用 FEED_LEAKED_CREDENTIALS（"leakedRecords"）。

        Returns:
            (objects, latest_timestamp_ms) —— latest_timestamp 由本次取得
            物件的 modified/collection_date 等欄位推導（見
            `_latest_from_objects`），而非信任伺服器的 latestTimestamp 欄位
            （理由見模組說明）。若本次未取得任何物件，回傳 None（呼叫端
            應以當前時間作為高水位線，詳見 pipeline.py）。
        """
        objects: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()
        api_latest_ts: Optional[int] = None
        next_token: Optional[str] = None
        total_hits: Any = None
        page = 0

        while page < self.max_pages:
            page += 1

            if page == 1:
                url = self.query_url
                body: Dict[str, Any] = {
                    "dataSources": [feed],
                    "resultsPerPage": self.page_limit,
                    "timestamp": int(timestamp),
                    "duration": self.scroll_duration,
                }
            else:
                # 官方文件 6.1.2：續頁走專屬端點，body 只帶 nextPageToken
                url = self.query_next_url
                body = {"nextPageToken": next_token}

            resp = self._post(url, body)

            if page == 1:
                api_latest_ts = self._extract_latest_timestamp(resp)

            page_objects = self._extract_objects(resp)
            new_objects = []
            for obj in page_objects:
                oid = obj.get("id")
                if oid and oid in seen_ids:
                    continue
                if oid:
                    seen_ids.add(oid)
                new_objects.append(obj)
            objects.extend(new_objects)

            next_token = self._extract_next_token(resp)
            total_hits = resp.get("totalHits")
            log.info(
                "第 %d 頁：本頁 %d 筆，新增 %d 筆（累計 %d / totalHits=%s），nextPageToken=%s",
                page, len(page_objects), len(new_objects), len(objects),
                total_hits, "有" if next_token else "無",
            )

            if not next_token or not page_objects:
                break
            if not new_objects:
                # 保險措施：若伺服器端仍回傳與已取得物件完全重複的內容，
                # 視為無新資料可抓，避免無窮迴圈消耗配額。
                log.info("本頁無新物件，視為已抓取完畢，停止分頁")
                break
        else:
            log.warning(
                "已達 max_pages=%d 上限（totalHits=%s），回溯區間資料量過大，"
                "本次僅部分抓取，下次排程將從本次高水位線繼續補抓",
                self.max_pages, total_hits,
            )

        local_latest = self._latest_from_objects(objects)
        now_ms = int(time.time() * 1000)
        if local_latest is not None and local_latest > now_ms:
            # 防呆：避免伺服器端異常未來時間戳把高水位線推過頭，漏掉後續資料
            local_latest = now_ms

        log.info(
            "高水位線來源比較：API latestTimestamp=%s，本地推導=%s（採用本地推導值）",
            api_latest_ts, local_latest,
        )
        return objects, local_latest

    # ------------------------------------------------------------------ #
    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "LuminarClient":
        return self

    def __exit__(self, *_exc: Iterable[Any]) -> None:
        self.close()
