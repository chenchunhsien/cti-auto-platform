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
| `tests/sample_stix.json`、`tests/empty_stix.json` | 離線回歸測試用的 STIX 樣本 |
| `tests/test_*.py` | pytest 單元測試（見下方「測試」一節） |
| `requirements-dev.txt` | 測試用額外依賴（pytest），正式排程環境不需要安裝 |
| `rule_analysis.py` | IOC收斂可觀測性分析（判定明細、CIDR聚合評估、規則回測），見下方「可觀測性分析」一節 |
| `rule_backtest.py` | 規則回測CLI，純讀取比較現行/候選規則，不影響正式輸出 |

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

## 測試

`tests/` 下是純邏輯單元測試（不呼叫 Luminar API、不讀寫 `data/` 下的正式檔案），
涵蓋 EDL 四階過濾漏斗的每一階（IP合規清洗、三通道決策樹、CIDR聚合、ASN節流）、
今日新增／退場兩種差集判定、以及匯出報表的 `trigger_reason`/`retired_reason`
文字生成邏輯：

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements-dev.txt   # 只需執行一次
.\venv\Scripts\python.exe -m pytest tests/ -v
```

改動 `pipeline.py` 的判定邏輯（門檻數值、通道優先序、聚合/節流規則等）後，
建議先跑過這套測試再手動對真實資料做回歸驗證，能在幾秒內攔住大部分的邏輯
倒退（例如本次會話中真實發生過的「通道B/C判定順序死代碼」、「通道B時效窗口
誤收斂」等問題）。

## 可觀測性分析

`rule_analysis.py` 提供三種IOC收斂的可觀測性工具，第一階段**只產出分析報表，
不改變既有A/B/C門檻，也不改變正式EDL輸出結果**：所有會影響「誰被收錄進EDL」
的判斷，都直接重用 `pipeline.py` 裡正式管線實際使用的那幾個函式
（`is_edl_candidate` / `aggregate_to_cidr` / `throttle_by_asn`），不另外寫一份
門檻常數，避免兩邊日後分岔。

### 判定明細 + EDL排除原因

```powershell
.\venv\Scripts\python.exe pipeline.py --no-push --emit-decision-detail
```

額外產出兩個檔案（預設關閉，不加這個旗標完全不影響正常排程行為）：

| 檔案 | 內容 |
|------|------|
| `data/decision_detail.json` | 每筆IOC的完整判定明細：命中/未命中通道與具體原因、`threat_score`/`confidence`/`labels`、實際使用的時間窗、近7天與近14天出現次數、`exclusion_reason`（排除原因分類）。筆數等同整個情資庫，單檔可能數十MB，已列入 `.gitignore`，純本機分析用 |
| `data/cidr_aggregation_report.json` | 每個候選 `/24` 網段（不限最終是否真的聚合）的候選IP數、占網段比例、分數/信心值/通道分布、是否白名單保護、`safety_check_reason`（安全檢查通過/拒絕的具體原因）、聚合前後EDL條目數差異、`collateral_ips_if_aggregated`（若聚合成CIDR會一併涵蓋到的非候選位址數） |

`exclusion_reason` 的分類：`NOT_IOC_WORTHY`（不符合收斂條件）、
`SCANNER_NOISE_EXCLUDED`（命中掃描雜訊標籤）、
`WHITELIST_OR_PUBLIC_INFRA_PROTECTED`（命中公用雲端/CDN白名單而被排除）、
`AGGREGATED_INTO_CIDR`（併入CIDR網段，仍會被阻斷，只是不以個別IP身分出現）、
`ASN_THROTTLED`（被同ASN節流排除，未輸出）、
`OTHER_FORMAT_OR_SAFETY_CHECK`（非公開路由IP或缺少`last_seen`）。
**`exclusion_reason` 為 `None` 代表有被收錄，不代表「這筆IOC是安全的」**。

> **安全性修正記錄（2026-10-22）**：第一階段分析曾發現一個真實的誤封
> 風險缺口——當時 `is_public_cloud()`（公用雲端/CDN白名單比對）只影響
> CIDR聚合的防呆判斷，從未真的把任何IP排除在 `blocklist_edl.txt` 之外，
> 只是網頁前端把它過濾掉、歸類到「雲端公用清單」頁籤顯示，容易讓維運
> 人員誤以為它沒有被阻斷。**此缺口已在第二階段修正**：
> `select_edl_candidates()` 現在會在通道判定出結果的當下，直接檢查
> 白名單命中並把 `edl_tier` 打回 `None`，確保白名單IP不會輸出到正式
> `blocklist_edl.txt`；原始命中的通道保留在 `edl_whitelist_excluded_tier`
> 供稽核，`edl_whitelist_match` 則不論是否被排除都誠實記錄是否命中。
> 同時 CIDR聚合也加了 `verify_cidr_safe_for_aggregation()` 安全檢查：
> 同一 `/24` 候選數達門檻只是「有資格接受安全檢查」的前提，還要確認
> 候選成員本身、以及整個網段範圍都沒有跟已知白名單重疊才會真的聚合；
> 若白名單設定檔無法可靠讀取/解析，保守地視為不安全、退回輸出個別IP。

### 規則回測

```powershell
# 不覆寫任何門檻，結果應該跟現行規則完全一致（驗證回測機制本身可信）：
.\venv\Scripts\python.exe rule_backtest.py --now 2026-10-22T00:41:08+00:00

# 測試把通道A分數門檻從85調高到90的影響：
.\venv\Scripts\python.exe rule_backtest.py --candidate must_have_min_score=90

# 同時測試多個門檻、並把完整比較結果存成報表：
.\venv\Scripts\python.exe rule_backtest.py `
  --candidate persistence_min_seen_count=6 `
  --candidate fallback_min_score=97 `
  --output data/rule_backtest_report.json
```

`--candidate` 可用的門檻名稱見 `rule_analysis.DEFAULT_THRESHOLDS`（跟
`pipeline.py` 的真實常數一一對應）。回測模式**只讀取、不寫回**
`data/base_iocs.json` 或任何正式輸出檔案，也不會呼叫git——
`tests/test_rule_backtest.py` 有專門的子行程級測試，直接比對執行前後
`data/base_iocs.json`／`data/blocklist_edl.txt` 的位元組內容完全相同。

輸出包含：EDL條目數變化、各通道命中數變化、`/24`聚合吸收的IP數變化
（重複情報/同網段聚合的計數影響）、ASN節流排除數變化、CIDR聚合涵蓋的
非候選位址數變化。「已知惡意IOC保留率」這項指標目前固定略過並說明原因：
本系統沒有可靠的外部標記資料集可供驗證，捏造一個數字反而會誤導決策。

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
