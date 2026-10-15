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

此時間戳**不是**直接採信 Luminar API 回應的 `latestTimestamp`（該值經實測不可靠，見下方
API 筆記），而是由 `luminar_client.py` 掃描本次實際取得物件的時間欄位自行推導，
確保每次執行都能真正往前推進、追上最新資料。

---

## Luminar API 實測筆記

> 以下為 2026-10-15 對 `cyberluminar.com` 實際打點確認的結果。最初依文件猜測的端點
> （`/externalApi/realm/.../token`、GET `/externalApi/stix`、`limit` 參數）都走不通，
> 完整正確用法如下。

| 項目 | 實測結果 |
|------|----------|
| Token 端點 | `POST /externalApi/v2/realm/{realm}/token`（**注意 `v2`**，少了會回 401 SESSION_TIMEOUT） |
| Token body | `grant_type=client_credentials, client_id, client_secret, scope=externalAPI/stix.readonly` —— **`scope` 必填**，漏填會導致 JWT scope 為空字串，查詢時一律回 `400 Invalid limit size (0-100): null`（這個錯誤訊息容易誤導成「limit 參數錯誤」或「帳號未開通」，實際上是 Token 沒有查詢權限） |
| Token 效期 | `expires_in = 300` 秒；本專案提早 30 秒刷新 |
| 查詢端點 | `POST /externalApi/v2/stix`（IOC 與外洩憑證**共用同一端點**，靠 `dataSources` 參數切換） |
| 查詢 body（首頁） | `{"dataSources": ["IOC"], "resultsPerPage": 1-100, "timestamp": <Epoch 毫秒>}` |
| 查詢 body（續頁） | `{"dataSources": ["IOC"], "resultsPerPage": 1-100, "nextPageToken": <token>}` —— **續頁不可再帶 `timestamp`**，帶了會被忽略、等同重新從頭查 |
| `dataSources` 合法值 | `leakedRecords`, `all`, `vulnerability`, `IOC`, `cyberFeed`（伺服器錯誤訊息實測取得的完整列舉） |
| 回應結構 | `{"nextPageToken", "totalHits", "latestTimestamp", "stix": [bundle, ...]}`，**物件在每個 bundle 的 `objects` 陣列裡**，需攤平收集 |
| **`latestTimestamp` 不可信** | 連續執行幾乎不推進（實測連續 3 次只從 `...219331`→`...219454`→`...219570`，每次僅 +100 毫秒），拿來當高水位線會永遠卡住。本專案改用本次取得物件的 `modified`/`extensions.collection_date`/`valid_from`/`created` 取最大值作為高水位線，實測可正確推進到接近現在時間 |
| **分頁 bug** | `nextPageToken` 在無新資料時仍可能持續回傳非 null 值，並重複送出同一批物件（實測翻 150 頁仍卡在同一組 ~100 筆）。本專案改以「本頁有無新的物件 ID」為分頁終止條件，而非單純看 `nextPageToken` 是否存在 |

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

> **`labels` 欄位說明**：STIX 2.1 的 indicator 物件沒有 `labels`（STIX 2.0 已棄用該欄位），
> 實際分類資訊在 `indicator_types`（如 `malicious-activity`）與
> `extensions.*.threat_types`（如 `phishing`、`resource-exploitation`）。
> 本專案將兩者合併存入 `labels`，若未來資料來源真的帶有 `labels` 欄位也會一併保留。
> 同理，`asn`/`resolving_domains` 在目前的 Luminar IOC feed 中經常是空的——這是
> 上游資料本身未提供，不代表程式有誤。

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
