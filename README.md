# cti-auto-platform

CTI 威脅情資自動化管線與查詢系統 — 純規則引擎架構（不使用 LLM）。

從 Luminar STIX 2.1 API 增量擷取威脅指標，依雙門檻規則過濾後產出防火牆
EDL 阻斷清單，並自動推送至 GitHub，由 GitHub Pages 提供查詢介面。

---

## 架構

```
Luminar STIX 2.1 API
        │  (高水位線增量抓取)
        ▼
   pipeline.py  ──  規則引擎：indicator + ipv4-addr
        │                     confidence ≥ 90 且 threat_score ≥ 90
        ▼
   data/  base_iocs.json      累積資料庫（以 IP 為 key，Upsert）
          daily_iocs.json     本次增量
          blocklist_edl.txt   純 IP 清單（防火牆 EDL）
          sync_state.json     高水位線狀態
        │
        ▼  git push (PAT)
   GitHub ──> GitHub Pages ──> docs/index.html 查詢儀表板
```

## 檔案

| 檔案 | 用途 |
|------|------|
| `luminar_client.py` | Luminar API 客戶端；Token 快取/刷新、分頁 |
| `pipeline.py` | 主管線：抓取 → 過濾 → Upsert → 輸出 → git push |
| `docs/index.html`、`docs/app.js` | 靜態查詢儀表板（Bootstrap 5，深色主題） |
| `run_sync.ps1` | Windows 工作排程器進入點，日誌寫入 `sync.log` |
| `tests/sample_stix.json` | 離線回歸測試用的 STIX 樣本 |

---

## 安裝

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env    # 接著填入實際憑證
```

## 執行

```powershell
.\venv\Scripts\python.exe pipeline.py                      # 正常增量同步 + 自動推送
.\venv\Scripts\python.exe pipeline.py --no-push            # 不推送
.\venv\Scripts\python.exe pipeline.py --full --since-hours 72   # 忽略高水位線，回溯 72 小時
.\venv\Scripts\python.exe pipeline.py --input tests\sample_stix.json --no-push  # 離線測試
.\venv\Scripts\python.exe pipeline.py --feed leaked_credentials  # 改抓外洩憑證 feed
```

離職碼（exit code）：`0` 成功、`2` API 失敗、`3` 帳號未開通該 feed。

## 排程

Windows 工作排程器：

- 程式或指令碼：`powershell.exe`
- 引數：`-NoProfile -ExecutionPolicy Bypass -File "D:\cti-auto-platform\run_sync.ps1"`
- 起始位置：`D:\cti-auto-platform`

### 高水位線（High-Water Mark）

`data/sync_state.json` 記錄 `last_successful_timestamp`。每次從上次成功的時間點續抓，
因此週末/假日電腦關機、排程漏跑都不會造成資料缺口。執行**失敗時刻意不更新**此值，
下次執行會自動重抓缺漏區間。初次執行（無狀態檔）預設回溯 `DEFAULT_LOOKBACK_HOURS` 小時。

---

## Luminar API 實測筆記

> 以下為 2026-10-15 對 `cyberluminar.com` 實際打點確認的結果，與部分舊文件不符。

| 項目 | 實測結果 |
|------|----------|
| Token 端點 | `POST /externalApi/realm/{realm}/token`（client_credentials） |
| Token 效期 | `expires_in = 300` 秒；本專案提早 30 秒刷新 |
| IOC feed | `POST /externalApi/v2/stix`，JSON body，`limit` 範圍 0–100 |
| 外洩憑證 feed | `GET /externalApi/stix?timestamp=<秒>&limit=<n>` |
| **timestamp 單位** | v1 為 **Epoch 秒**（傳毫秒會回 HTTP 500）。本專案對外一律用毫秒，送出前自動換算 |
| 分頁 | 回應為標準 STIX bundle（`type`/`id`/`objects`），目前**未**回傳 `nextPageToken` 或 `latestTimestamp` |
| 高水位線來源 | 因上述緣故，改由物件的 `modified`/`created`/`valid_from` 推導最新時間戳 |

常見錯誤：

- `{"error":{"status":401,"identifier":"SESSION_TIMEOUT"}}` — 端點路徑錯誤（打到前端路由）
- `Invalid limit size (0-100): null` — 伺服器端未替該 `client_id` 設定 feed limit，
  即**帳號未開通該 feed**，需洽 Luminar 支援窗口開通，非程式問題

---

## 過濾規則

| 條件 | 值 |
|------|-----|
| 物件類型 | `type == "indicator"` |
| Pattern | 含 `ipv4-addr:value` |
| 信心值 | `confidence >= 90` |
| 威脅分數 | `extensions.*.score >= 90` |

欄位對應：`ip`（原始 IP，**不做 defanging**）、`confidence`、`threat_score`、
`labels`（完整保留）、`asn`、`resolving_domains`、
`first_seen`（`valid_from` → `created`）、`last_seen`（`collection_date` → `modified`）、`valid_until`。

Upsert 行為：相同 IP 再次出現時累計 `seen_count`、更新 `last_seen`、
合併 `labels` 與 `resolving_domains`、取 `confidence`/`threat_score` 較大值。

---

## GitHub Pages

Settings → Pages → Source 選 **Deploy from a branch**，branch `main`、資料夾 **`/ (root)`**。

> 前端以 `../data/base_iocs.json` 讀取資料，因此站台根目錄必須是 repo 根目錄。
> 若改成由 `/docs` 發佈，`data/` 會落在站台之外而讀不到
> （`docs/app.js` 內建多路徑 fallback，但仍以 root 發佈為準）。

頁面網址：`https://chenchunhsien.github.io/cti-auto-platform/docs/`

## 安全性

- `.env` 已列入 `.gitignore`，絕不進版控
- git push 時 PAT 直接以引數傳入，不寫入 `.git/config`，日誌中一律遮蔽
- 推送內容僅限 `data/` 下的過濾後 IP 清單
- **此 repo 為 public**：請勿將外洩憑證 feed 的內容寫入 `data/`
