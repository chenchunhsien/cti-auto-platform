"""
luminar_client.py
-----------------
Luminar (Cognyte) STIX 2.1 External API 客戶端。

端點（2026-10-15 對 cyberluminar.com 實測確認）:
  Token : POST {base}/externalApi/realm/{realm}/token      (expires_in = 300s)
  IOC   : POST {base}/externalApi/v2/stix                   (JSON body)
  Leaks : GET  {base}/externalApi/stix?timestamp=<秒>&limit=<n>

重要實測結論:
  * Token 效期 300 秒；本模組提早 30 秒自動刷新。
  * v1 的 timestamp 參數為 **Epoch 秒**（傳毫秒會回 HTTP 500）。
    本模組對外一律以毫秒為介面，送出前自動換算。
  * API 回應為標準 STIX bundle（type/id/objects），
    目前未回傳 nextPageToken 或 latestTimestamp，
    故高水位線改由物件的 modified/created 推導（見 latest_timestamp_from_objects）。
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

log = logging.getLogger("luminar")

TOKEN_TTL_SECONDS = 300
TOKEN_REFRESH_SKEW = 30

FEED_IOC = "ioc"
FEED_LEAKED_CREDENTIALS = "leaked_credentials"


class LuminarError(RuntimeError):
    """Luminar API 相關錯誤。"""


class LuminarEntitlementError(LuminarError):
    """帳號未開通該 feed（伺服器端授權問題，非程式錯誤）。"""


class LuminarClient:
    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        token_path: str = "/externalApi/realm/{realm}/token",
        ioc_path: str = "/externalApi/v2/stix",
        leaks_path: str = "/externalApi/stix",
        page_limit: int = 100,
        max_pages: int = 500,
        timeout: int = 300,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_path = token_path
        self.ioc_path = ioc_path
        self.leaks_path = leaks_path
        # v2 IOC feed 伺服器端限制 limit 介於 0-100
        self.page_limit = max(1, min(int(page_limit), 100))
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

        ttl = int(body.get("expires_in") or TOKEN_TTL_SECONDS)
        self._token = token
        # 提早 TOKEN_REFRESH_SKEW 秒視為過期，避免長時間分頁拉取途中失效
        self._token_expiry = time.monotonic() + max(ttl - TOKEN_REFRESH_SKEW, 5)
        log.info("Token 取得成功，效期 %ss（提前 %ss 刷新）", ttl, TOKEN_REFRESH_SKEW)
        return token

    def _auth_headers(self, json_body: bool = False) -> Dict[str, str]:
        headers = {"Authorization": f"Bearer {self.get_token()}"}
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    # ------------------------------------------------------------------ #
    # HTTP
    # ------------------------------------------------------------------ #
    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """送出請求；遇 401 自動刷新 Token 重試一次。"""
        for attempt in (1, 2):
            try:
                resp = self.session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=self._auth_headers(json_body is not None),
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except requests.RequestException as exc:
                raise LuminarError(f"{method} {url} 連線失敗: {exc}") from exc

            if resp.status_code == 401 and attempt == 1:
                log.warning("收到 401，強制刷新 Token 後重試")
                self.get_token(force=True)
                continue

            if resp.status_code != 200:
                text = resp.text[:400]
                # 伺服器端未替此 client_id 設定 feed limit → 帳號未開通
                if "Invalid limit size" in text and "null" in text:
                    raise LuminarEntitlementError(
                        "Luminar 帳號未開通 IOC feed：伺服器回報 limit 設定為 null "
                        f"(HTTP {resp.status_code}: {text})"
                    )
                raise LuminarError(f"{method} {url} 失敗 HTTP {resp.status_code}: {text}")

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
        """容錯解析：支援 bundle / objects / data 等常見包裝。"""
        if not isinstance(body, dict):
            return []
        for key in ("objects", "data", "stix", "items", "results"):
            value = body.get(key)
            if isinstance(value, list):
                return [o for o in value if isinstance(o, dict)]
            if isinstance(value, dict) and isinstance(value.get("objects"), list):
                return [o for o in value["objects"] if isinstance(o, dict)]
        return []

    @staticmethod
    def _extract_next_token(body: Dict[str, Any]) -> Optional[str]:
        if not isinstance(body, dict):
            return None
        for key in ("nextPageToken", "next_page_token", "nextToken", "next"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _extract_latest_timestamp(body: Dict[str, Any]) -> Optional[int]:
        """取回應中的 latestTimestamp（Epoch 毫秒）。目前 API 未提供，保留相容。"""
        if not isinstance(body, dict):
            return None
        for key in ("latestTimestamp", "latest_timestamp", "lastTimestamp"):
            value = body.get(key)
            if value in (None, ""):
                continue
            try:
                ts = int(value)
            except (TypeError, ValueError):
                continue
            # 秒 → 毫秒（10 位數視為秒）
            return ts * 1000 if ts < 10_000_000_000 else ts
        return None

    @staticmethod
    def latest_timestamp_from_objects(objects: Iterable[Dict[str, Any]]) -> Optional[int]:
        """
        API 未回傳 latestTimestamp 時，由物件的 modified/created/valid_from
        推導出最新時間戳（Epoch 毫秒），作為下次抓取的高水位線。
        """
        latest: Optional[int] = None
        for obj in objects:
            for field in ("modified", "created", "valid_from"):
                raw = obj.get(field)
                if not isinstance(raw, str):
                    continue
                try:
                    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ms = int(dt.timestamp() * 1000)
                if latest is None or ms > latest:
                    latest = ms
        return latest

    # ------------------------------------------------------------------ #
    # 公開 API
    # ------------------------------------------------------------------ #
    def fetch_stix(
        self, timestamp: int, feed: str = FEED_IOC
    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        """
        從指定時間戳（**Epoch 毫秒**）起抓取 STIX 物件。

        Args:
            timestamp: 起始時間戳，Epoch 毫秒。
            feed: FEED_IOC（v2，威脅指標）或 FEED_LEAKED_CREDENTIALS（v1，外洩憑證）。

        Returns:
            (objects, latest_timestamp_ms)
        """
        if feed == FEED_LEAKED_CREDENTIALS:
            return self._fetch_leaked_credentials(timestamp)
        return self._fetch_iocs(timestamp)

    def _fetch_iocs(self, timestamp_ms: int) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        """v2 IOC feed：POST + JSON body，依 nextPageToken 迴圈分頁。"""
        url = self.base_url + self.ioc_path
        objects: List[Dict[str, Any]] = []
        latest_ts: Optional[int] = None
        next_token: Optional[str] = None
        page = 0

        while page < self.max_pages:
            page += 1
            body: Dict[str, Any] = {
                "timestamp": int(timestamp_ms),
                "limit": self.page_limit,
            }
            if next_token:
                body["nextPageToken"] = next_token

            resp = self._request("POST", url, json_body=body)
            page_objects = self._extract_objects(resp)
            objects.extend(page_objects)

            page_latest = self._extract_latest_timestamp(resp)
            if page_latest is not None:
                latest_ts = page_latest if latest_ts is None else max(latest_ts, page_latest)

            next_token = self._extract_next_token(resp)
            log.info(
                "IOC 第 %d 頁：取得 %d 筆（累計 %d），nextPageToken=%s",
                page, len(page_objects), len(objects), "有" if next_token else "無",
            )

            if not next_token or not page_objects:
                break
        else:
            log.warning("已達 max_pages=%d 上限，可能尚有未取回資料", self.max_pages)

        if latest_ts is None:
            latest_ts = self.latest_timestamp_from_objects(objects)
        return objects, latest_ts

    def _fetch_leaked_credentials(
        self, timestamp_ms: int
    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        """v1 外洩憑證 feed：GET + timestamp 為 **Epoch 秒**。"""
        url = self.base_url + self.leaks_path
        # 對外介面為毫秒，此端點需要秒
        timestamp_s = int(timestamp_ms) // 1000

        resp = self._request(
            "GET", url, params={"timestamp": timestamp_s, "limit": self.page_limit}
        )
        objects = self._extract_objects(resp)
        log.info("Leaked-credentials feed：取得 %d 筆物件", len(objects))

        latest_ts = self._extract_latest_timestamp(resp)
        if latest_ts is None:
            latest_ts = self.latest_timestamp_from_objects(objects)
        return objects, latest_ts

    # ------------------------------------------------------------------ #
    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "LuminarClient":
        return self

    def __exit__(self, *_exc: Iterable[Any]) -> None:
        self.close()
