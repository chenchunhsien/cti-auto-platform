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
.\venv\Scripts\python.exe pipeline.py --feed leakedRecords  # 改抓外洩憑證 feed
```

離職碼（exit code）：`0` 成功、`2` API 失敗、`3` 查詢被拒（通常是 scope 設定問題）。

## 排程

Windows 工作排程器：

- 程式或指令碼：`powershell.exe`
- 引數：`-NoProfile -ExecutionPolicy Bypass -File "D:\cti-auto-platform\run_sync.ps1"`
- 起始位置：`D:\cti-auto-platform`

### 高水位線（High-Water Mark）

`data/sync_state.json` 記錄 `last_successful_timestamp`。每次從上次成功的時間點續抓，
因此週末/假日電腦關機、排程漏跑都不會造成資料缺口。執行**失敗時刻意不更新**此值，
下次執行會自動重抓缺漏區間。初次執行（無狀態檔）預設回溯 `DEFAULT_LOOKBACK_HOURS` 小時。

此時間戳**不是**直接採信 Luminar API 回應的 `latestTimestamp`（原因見下方 API 筆記），
而是由 `luminar_client.py` 掃描本次實際取得物件的時間欄位自行推導，確保每次執行都能
真正往前推進。若斷線多日造成的回溯量極大（總筆數可能上看百萬），單次執行未必能一次
追上「現在」，可能需要**連續跑幾次排程才逐步補齊**——這是預期中的正常行為。

---

## Luminar API 實測筆記

> 依官方文件《Luminar External Client APIs v4.0（2026-08，Cognyte）》，並於
> 2026-10-15 對 `cyberluminar.com` 實際打點確認。在尚未取得官方文件、純靠錯誤訊息
> 反推 API 用法的階段，曾誤以為分頁續頁要把 `nextPageToken` 疊加送回
> `/externalApi/v2/stix`，導致分頁卡死、重複回傳同一批資料；取得官方文件後才發現
> 續頁其實要走專屬的 `/stix/next` 端點，問題隨之消失。以下是目前確認正確的用法。

| 項目 | 內容 |
|------|------|
| Token 端點 | `POST /externalApi/v2/realm/{realm}/token`（官方文件 5.1.1；注意是 v2，少了會回 401 SESSION_TIMEOUT） |
| Token body | `grant_type=client_credentials, client_id, client_secret, scope=<scope>`。`scope` 為必填欄位，漏填會導致 JWT scope 為空字串，查詢時一律回 `400 Invalid limit size (0-100): null`（這個錯誤訊息容易誤導成是 limit 參數錯誤或帳號未開通，實際上是 Token 沒有查詢權限）。本專案使用 `externalAPI/stix.readonly` |
| Token 效期 | `expires_in = 300` 秒；本專案提早 30 秒刷新 |
| 首頁查詢 | `POST /externalApi/v2/stix`（官方文件 6.1.1），body 需含 `dataSources`、`resultsPerPage`（1-100）、`timestamp`（Epoch 毫秒）、可選的 `duration`（scroll 保活時間，如 "2m"，預設 "30s"） |
| 續頁查詢 | `POST /externalApi/v2/stix/next`（官方文件 6.1.2），body 只帶 `nextPageToken` 一個欄位——這是先前分頁卡死的根本原因：誤將續頁送回 `/stix` 而非官方指定的 `/stix/next`，改對端點後問題消失 |
| dataSources 合法值 | all、IOC、leakedRecords、cyberFeed、vulnerability（官方文件 6.1.1.3） |
| resultsPerPage | 官方建議 10、上限 100。實測 10 在 24 小時回溯視窗下要爬數百頁才夠，本專案預設改用上限 100 以減少來回次數；若遇 HTTP 408 逾時，依官方 FAQ 建議調小 |
| 回應結構 | `nextPageToken`、`totalHits`、`latestTimestamp`、`stix`（bundle 陣列）。物件在每個 bundle 的 `objects` 陣列裡，需攤平收集 |
| latestTimestamp 不適合當高水位線 | 官方文件未說明其確切語意；實測發現在同一次 scroll 中隨分頁推進極慢（每頁僅增加數十到數百毫秒），而 totalHits 可能高達百萬筆以上，回溯區間涵蓋數天時單次執行往往無法掃到現在。本專案改用本次取得物件的 modified、extensions.collection_date、valid_from、created 欄位取最大值作為高水位線，確保每次執行都有真正進展 |
| 403 Forbidden | 本機 IP 未加入 Luminar 白名單（官方 FAQ） |
| 408 Request timeout | 查詢逾時，請調小 resultsPerPage（官方建議 10） |

---

## 過濾規則

| 條件 | 值 |
|------|-----|
| 物件類型 | `type == "indicator"` |
| Pattern | 含 `ipv4-addr:value` |
| 信心值 | `confidence >= 90` |
| 威脅分數 | `extensions.*.score >= 90` |

欄位對應：`ip`（原始 IP，**不做 defanging**）、`confidence`、`threat_score`、
`labels`、`asn`、`resolving_domains`、
`first_seen`（`valid_from` → `created`）、`last_seen`（`collection_date` → `modified`）、`valid_until`。

> **`labels` 欄位說明**：STIX 2.1 的 indicator 物件官方 schema 用的是 `indicator_types`
> （STIX 2.0 的 `labels` 已棄用），如 `malicious-activity`；部分 indicator 另在
> `extensions.*.threat_types` 帶有更細緻的分類（如 `phishing`、`resource-exploitation`），
> 也有部分帳號的實際資料確實帶有自訂 `labels`（如 `Honeypot`、`Scanner`）。
> 本專案將 `labels`、`indicator_types`、`threat_types` 三者合併去重存入 `labels`，
> 盡量保留所有可用的分類資訊。
>
> `asn`/`resolving_domains` 欄位則視資料來源而定，官方範例與部分實測資料中並未提供，
> 此時會是空值——這是上游資料本身未附帶，不代表程式有誤。

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
