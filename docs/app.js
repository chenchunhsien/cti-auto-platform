/* CTI 情資收斂與 EDL 聯防平台 — 前端邏輯（原生 JS，無框架） */
(function () {
  "use strict";

  // GitHub Pages 可能設定為 repo 根目錄或 /docs 子目錄為站台根，
  // 兩種情況下 data/ 的相對位置不同，因此依序嘗試。
  var IOC_CANDIDATES = ["../data/base_iocs.json", "./data/base_iocs.json", "/data/base_iocs.json"];
  var DAILY_CANDIDATES = ["../data/daily_iocs.json", "./data/daily_iocs.json", "/data/daily_iocs.json"];
  var ASN_DICT_CANDIDATES = ["../data/asn_dict.json", "./data/asn_dict.json", "/data/asn_dict.json"];
  // 公用雲端/CDN 白名單設定檔是前端自帶的靜態資源，放在 docs/data/ 底下
  // （跟 pipeline.py 產出、放在專案頂層 data/ 的其他檔案不同目錄），
  // 所以候選路徑不含 "../data/" 那一種。
  var PUBLIC_INFRA_CANDIDATES = ["./data/public_infra_rules.json", "/data/public_infra_rules.json"];
  // EDL 判定規則 snapshot：pipeline.py 每次執行都會重新產生，放在
  // docs/data/ 底下，跟 public_infra_rules.json 同一種候選路徑規則。
  var EDL_RULES_CANDIDATES = ["./data/edl_rules.json", "/data/edl_rules.json"];
  // EDL CSV 匯出報表：跟 base_iocs.json 同一層（data/），每次 pipeline.py
  // 執行都會重新產生，每一列對應 blocklist_edl.txt 的一個條目（純 IP 或
  // /24 CIDR 皆有一列），附上伺服器端組好的「判定說明」文字。
  var EDL_EXPORT_CANDIDATES = ["../data/edl_export.json", "./data/edl_export.json", "/data/edl_export.json"];
  // 退場清單：跟 edl_export.json 同一層、同時產生，只列出「相較上一次
  // 執行基準，這一輪已經跌出EDL」的個別IP，每輪執行整份覆寫（不是
  // 歷史累積）；沒有新退場的IP就是空陣列。
  var EDL_RETIRED_CANDIDATES = ["../data/edl_retired.json", "./data/edl_retired.json", "/data/edl_retired.json"];
  // 純文字版退場清單：跟 blocklist_edl.txt 同層，點「下載 Firewall EDL
  // 清單」時一併下載，不預先載入，點擊當下才 fetch。
  var EDL_RETIRED_TXT_CANDIDATES = ["../data/blocklist_edl_retired.txt", "./data/blocklist_edl_retired.txt", "/data/blocklist_edl_retired.txt"];
  // 匯出時間戳 meta：記錄這一輪產出時間與上一輪（退場比對基準）產出
  // 時間，供匯出按鈕旁輔助文字與CSV頂部 # 註解使用。
  var EDL_EXPORT_META_CANDIDATES = ["../data/edl_export_meta.json", "./data/edl_export_meta.json", "/data/edl_export_meta.json"];

  var PAGE_SIZE = 200;

  // 標籤家族常數：同一威脅概念的不同同義詞/別名，統一集中定義，避免各
  // 產業規則各自手動列舉時漏掉某個同義詞（例如只寫了 c2 卻漏了
  // command-and-control），日後標籤來源新增同義詞也只需改這裡一處。
  var FAMILY_C2 = ["c2", "command-and-control", "cnc", "cobalt-strike"];
  var FAMILY_EXPLOIT = ["exploit", "rce"];
  var FAMILY_STEALER = ["stealer", "infostealer"];
  var FAMILY_BRUTEFORCE = ["bruteforce", "brute-force"];

  // 攤平多個標籤家族陣列／個別標籤字串為單一、去重後的標籤清單，
  // 供下方 SECTOR_RULES 組裝各產業的完整標籤映射用。
  function sectorTags() {
    var seen = {};
    var out = [];
    for (var i = 0; i < arguments.length; i++) {
      var arg = arguments[i];
      var list = Array.isArray(arg) ? arg : [arg];
      list.forEach(function (t) {
        if (!seen[t]) { seen[t] = true; out.push(t); }
      });
    }
    return out;
  }

  // 產業別規則：目前服務之 6 大領域，驅動「產業別規則」頁籤的卡片內容，
  // 以及 EDL 頁籤「領域快篩」膠囊按鈕的標籤比對邏輯（單一事實來源，
  // 避免卡片內容跟篩選邏輯各寫一份日後對不上）。所有產業均納入
  // FAMILY_C2（C2/遠端控制為共通重大威脅基線），各自再疊加該產業
  // 特化的威脅標籤家族與個別標籤。
  var SECTOR_RULES = [
    {
      id: "gov_defense", name: "國安與政府機關", shortName: "國安/政府",
      targets: ["中央公務機關", "公務個資資料庫", "國防科研專案"],
      tags: sectorTags(
        ["apt", "espionage", "wiper", "phishing", "backdoor", "ransomware"],
        FAMILY_C2, FAMILY_EXPLOIT
      ),
      summary: "鎖定國家級威脅與間諜活動，APT 組織與破壞性攻擊（wiper）為主要風險。"
    },
    {
      id: "logistics_supplychain", name: "物流與倉儲供應鏈", shortName: "物流/倉儲",
      targets: ["陸運整合車隊", "自動化智慧倉儲", "供應鏈管理系統"],
      tags: sectorTags(
        ["ransomware", "phishing", "trojan", "botnet", "supply-chain", "backdoor"],
        FAMILY_C2, FAMILY_EXPLOIT, FAMILY_STEALER
      ),
      summary: "供應鏈攻擊與勒索軟體是物流業最主要的營運中斷風險。"
    },
    {
      id: "financial", name: "金融與支付", shortName: "金融/支付",
      targets: ["核心帳務主機", "數位網銀系統", "金流支付閘道"],
      tags: sectorTags(
        ["phishing", "banking-trojan", "credential-theft", "ransomware", "data-leak", "carding", "backdoor"],
        FAMILY_C2, FAMILY_EXPLOIT, FAMILY_BRUTEFORCE, FAMILY_STEALER
      ),
      summary: "針對帳戶憑證與交易系統的竊取型攻擊為主要威脅。"
    },
    {
      id: "telecom_network", name: "電信與通訊基礎", shortName: "電信/通訊",
      targets: ["核心網路維運", "骨幹網路基礎設施", "DNS 服務節點"],
      tags: sectorTags(
        ["ddos", "botnet", "dns-amplification", "ransomware"],
        FAMILY_C2, FAMILY_EXPLOIT, FAMILY_BRUTEFORCE
      ),
      summary: "大流量癱瘓攻擊（DDoS）與核心網路入侵為主要風險。"
    },
    {
      id: "healthcare", name: "醫療與生醫設施", shortName: "醫療/基礎",
      targets: ["關鍵公衛機構", "醫療 HIS/LIS 系統", "生醫資料中心"],
      tags: sectorTags(
        ["ransomware", "data-leak", "phishing", "trojan", "extortion", "critical-infrastructure", "backdoor"],
        FAMILY_C2, FAMILY_EXPLOIT, FAMILY_STEALER
      ),
      summary: "病患資料外洩與關鍵醫療設施中斷風險並存，勒索軟體衝擊尤其嚴重。"
    },
    {
      id: "retail_ecommerce", name: "零售通路與電商", shortName: "零售/電商",
      targets: ["連鎖門市 POS 系統", "大型電子商務平台", "會員身分認證平台"],
      tags: sectorTags(
        ["botnet", "ddos", "credential-stuffing", "carding", "magecart", "formjacking", "scraping", "ransomware"],
        FAMILY_C2, FAMILY_STEALER, FAMILY_BRUTEFORCE
      ),
      summary: "帳號盜用（credential stuffing）與自動化掃描攻擊為電商通路主要風險。"
    }
  ];
  var SECTOR_BY_ID = {};
  SECTOR_RULES.forEach(function (sector) {
    sector._tagSet = {};
    sector.tags.forEach(function (t) { sector._tagSet[t.toLowerCase()] = true; });
    SECTOR_BY_ID[sector.id] = sector;
  });

  // 「其他/未分類」：條件 B（頑固威脅）完全不限制標籤內容，所以 EDL 清單
  // 裡有不少紀錄的標籤（如 SuspiciousNetworkActivity、CommandInjection、
  // malicious-activity）不屬於任何一個產業的關鍵標籤。這個特殊選項讓
  // 使用者能單獨看到「6 個產業都比對不到」的這些紀錄，而不是只能看到
  // 「全部」或某個產業。
  var UNCATEGORIZED_SECTOR_ID = "__uncategorized__";
  var ALL_SECTOR_TAGS = {};
  SECTOR_RULES.forEach(function (sector) {
    Object.keys(sector._tagSet).forEach(function (t) { ALL_SECTOR_TAGS[t] = true; });
  });

  // 產業別快篩改為複選：選取的每個產業各自的關鍵標籤先聯集成一個集合，
  // 紀錄的標籤命中聯集中任一個即符合（同時符合其中任何一個選取的產業）。
  function buildSectorTagUnion(sectorIdSet) {
    var union = {};
    sectorIdSet.forEach(function (sid) {
      var sector = SECTOR_BY_ID[sid];
      if (!sector) return;
      Object.keys(sector._tagSet).forEach(function (t) { union[t] = true; });
    });
    return union;
  }

  function recordMatchesTagUnion(record, tagUnion) {
    return record.labels.some(function (l) { return tagUnion[String(l).toLowerCase()]; });
  }

  // 完全沒選（或選「全部」）回傳 true，代表不限制；否則依「選了哪些產業 /
  // 是否有選其他未分類」組合判斷。
  function recordMatchesSectorFilter(record, sectorIdSet) {
    if (!sectorIdSet || sectorIdSet.size === 0) return true;

    var wantsUncategorized = sectorIdSet.has(UNCATEGORIZED_SECTOR_ID);
    if (wantsUncategorized && !recordMatchesTagUnion(record, ALL_SECTOR_TAGS)) return true;

    var realSectorIds = new Set();
    sectorIdSet.forEach(function (sid) {
      if (sid !== UNCATEGORIZED_SECTOR_ID) realSectorIds.add(sid);
    });
    if (realSectorIds.size === 0) return false;
    return recordMatchesTagUnion(record, buildSectorTagUnion(realSectorIds));
  }

  var state = {
    raw: {                   // 各頁籤各自的完整資料（載入後不隨篩選變動）
      all: { meta: {}, list: [] },
      daily: { meta: {}, list: [] },
      edl: { meta: {}, list: [] },
      publicInfra: { meta: {}, list: [] }
    },
    activeTab: "edl",
    all: [],        // 目前作用中頁籤的資料
    view: [],       // 篩選後
    shown: 0,
    meta: {},
    // 每個頁籤各自獨立記住自己的排序狀態（key/dir/是否已被手動覆寫），
    // 而非共用同一組全域排序，避免「在 EDL 頁籤點過表頭後，切去其他
    // 頁籤、再回 EDL 下載」這種情境下排序互相污染。sortKey/sortDir 只是
    // 目前作用中頁籤的鏡射，方便既有 UI（排序下拉、表頭）讀寫。
    tabSort: {
      all:   { key: "threat_score", dir: -1, custom: false },
      daily: { key: "last_seen", dir: -1, custom: false },
      edl:   { key: "threat_score", dir: -1, custom: false },
      publicInfra: { key: "threat_score", dir: -1, custom: false }
    },
    sortKey: "threat_score",
    sortDir: -1,
    labelCounts: [],         // [{name, count}]，依總數排序
    selectedLabels: new Set(),  // 目前勾選的標籤（符合其中任一即顯示）
    edlTierFilter: { A: true, B: true, C: true },  // EDL 頁籤的階梯式判定篩選，預設 A+B+C 皆勾選
    edlSectorFilter: new Set(),  // EDL 頁籤的領域快篩（複選），空集合代表「全部 (All)」
    edlTodayNewFilter: false,  // EDL 頁籤「僅看今日/本次新增」勾選狀態
    edlRules: null,  // docs/data/edl_rules.json 的內容，供「EDL 判定規則」頁籤顯示
    edlExportRows: [],  // data/edl_export.json 的內容，供「匯出 IOC 情資 (.csv)」使用
    edlRetiredRows: [],  // data/edl_retired.json 的內容，供「匯出 IOC 情資」全量模式一併匯出退場清單使用
    edlExportMeta: { generated_at: null, baseline_at: null }  // data/edl_export_meta.json 的內容
  };

  // 各頁籤初始（未手動調整過）的主要排序欄位，供頁籤第一次載入與
  // 「清除條件」還原使用。
  var TAB_DEFAULT_PRIMARY = {
    all:   { key: "threat_score", dir: -1 },  // 全部情資庫：歷史威脅獵捕
    daily: { key: "last_seen", dir: -1 },     // 今日最新發現：當日最新感知
    edl:   { key: "threat_score", dir: -1 },  // EDL 阻斷清單：活體攻擊優先阻斷
    publicInfra: { key: "threat_score", dir: -1 }  // 雲端公用清單：沿用威脅分數優先
  };

  // 標準 SOC 次要排序順位：不論主要排序欄位選哪一個（無論是頁籤預設，
  // 或使用者從下拉選單/點表頭手動改選的任何欄位），當主要欄位打平時，
  // 一律依這個順位依序 tie-break（已選為主要欄位的那一項會被跳過）。
  // 這避免了「主要欄位打平就直接 return 0」導致看似同分/同時間的列
  // 之間順序混亂的問題。
  var CANONICAL_TIEBREAK_ORDER = [
    { key: "threat_score", dir: -1 },
    { key: "last_seen", dir: -1 },
    { key: "confidence", dir: -1 },
    { key: "seen_count", dir: -1 }
  ];

  var $ = function (id) { return document.getElementById(id); };

  // ---------------------------------------------------------------- 工具
  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function fmtDate(value) {
    if (!value) return "—";
    var d = new Date(value);
    if (isNaN(d.getTime())) return esc(String(value).slice(0, 19));
    // 固定以 UTC+8（台北時間）顯示，不受瀏覽者所在時區影響
    return d.toLocaleString("sv-SE", {
      timeZone: "Asia/Taipei",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit"
    });
  }

  // 同 fmtDate，但保留到秒——公用設施白名單頁籤的同步時間需要秒數精度，
  // 其餘頁籤沿用 fmtDate 的分鐘精度即可，兩者分開避免互相牽動。
  function fmtDateTimeSeconds(value) {
    if (!value) return "—";
    var d = new Date(value);
    if (isNaN(d.getTime())) return esc(String(value).slice(0, 19));
    return d.toLocaleString("sv-SE", {
      timeZone: "Asia/Taipei",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit"
    });
  }

  // 按鈕下方的「退場比對基準」標示：跟左側「最後同步時間」刻意區隔開——
  // 這裡顯示的是「上一輪」（也就是這一輪退場判定拿來比較的基準）產出
  // 時間，不是這一輪本身的時間，純顯示不會因為點擊下載/匯出而改變。
  // 下載/匯出按鈕下方的單一時間標示：只讀取 pipeline.py 最近一次同步
  // 產出的時間戳記，點擊下載/匯出純粹下載檔案，不會改變這個時間。
  function renderEdlExportMetaHint() {
    var meta = state.edlExportMeta || {};
    var el = $("edlExportMetaHint");
    if (!el) return;
    var text = meta.generated_at ? fmtDate(meta.generated_at) : "—";
    el.textContent = "資料更新時間：" + text + " (UTC+8)";
  }

  // ISO-8601 帶台北時區偏移量（+08:00，非 Z）——供 EDL 純文字匯出檔
  // （firewall訂閱用）的標頭時間戳使用，跟 pipeline.py 端 blocklist_edl_
  // retired.txt 的標頭時間格式對齊，方便維運人員直接看懂本地時間。
  function toTaipeiIso8601(value) {
    if (!value) return "-";
    var d = new Date(value);
    if (isNaN(d.getTime())) return "-";
    var parts = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Taipei",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false
    }).formatToParts(d);
    var map = {};
    parts.forEach(function (p) { map[p.type] = p.value; });
    return map.year + "-" + map.month + "-" + map.day + "T" +
      map.hour + ":" + map.minute + ":" + map.second + "+08:00";
  }

  function ipKey(ip) {
    var parts = String(ip).split("/")[0].split(".");
    if (parts.length !== 4) return 0;
    return parts.reduce(function (acc, p) { return acc * 256 + (parseInt(p, 10) || 0); }, 0);
  }

  // ---------------------------------------------------------- 公用雲端/CDN 白名單
  // 命中這份白名單的情資會被排除在 EDL 建議阻斷數之外，改列進「雲端公用
  // 清單」頁籤，避免誤封共用的 DNS/CDN/雲端基礎設施波及其他客戶。
  var PUBLIC_INFRA = {
    exactIpMap: {}, asnMap: {}, cidrRanges: [],
    cdnGroups: [], exactIpsRaw: [], lastSyncTime: null  // 載入前的預設空值，避免白名單頁籤在資料到位前渲染出錯
  };

  function extractAsnNum(rawAsn) {
    if (rawAsn == null) return null;
    var s = String(rawAsn).trim();
    if (!s) return null;
    s = s.replace(/^as\s*/i, "");
    var match = s.match(/^(\d+)/);
    return match ? match[1] : null;
  }

  // 用純算術（非位元運算）算出 CIDR 的位址範圍，避免 JS 位元運算子把
  // 數值視為 32-bit 帶號整數、在靠近 2^31 以上的位址算錯的問題。
  function cidrToRange(cidr) {
    var parts = cidr.split("/");
    var base = ipKey(parts[0]);
    var bits = parseInt(parts[1], 10);
    var size = Math.pow(2, 32 - (isNaN(bits) ? 32 : bits));
    var networkBase = Math.floor(base / size) * size;
    return { start: networkBase, end: networkBase + size - 1 };
  }

  function loadPublicInfraRules(data) {
    (data.exact_ips || []).forEach(function (item) {
      if (item && item.ip) PUBLIC_INFRA.exactIpMap[item.ip] = item.name || item.ip;
    });
    (data.asns || []).forEach(function (item) {
      if (item && item.asn) PUBLIC_INFRA.asnMap[item.asn.toUpperCase()] = item.name || item.asn;
    });
    (data.cdn_cidrs || []).forEach(function (group) {
      (group.cidrs || []).forEach(function (cidr) {
        var range = cidrToRange(cidr);
        range.provider = group.provider;
        range.cidr = cidr;
        PUBLIC_INFRA.cidrRanges.push(range);
      });
    });
    // 保留原始分組資料，供「公用設施白名單」頁籤渲染網段統計徽章與
    // 可展開 CIDR 清單使用（比對邏輯本身用上面攤平的 cidrRanges 就夠，
    // 這裡額外存一份是純粹為了畫面呈現）。
    PUBLIC_INFRA.cdnGroups = data.cdn_cidrs || [];
    PUBLIC_INFRA.exactIpsRaw = data.exact_ips || [];
    // 這個欄位是為了讓未來的自動同步腳本（週期性向官方 API 拉取最新
    // CIDR/ASN 後覆寫本檔）有固定位置可寫入「最後同步時間」，供前端
    // 顯示資料新鮮度；目前是手動填入，尚未接自動化腳本。
    PUBLIC_INFRA.lastSyncTime = data.last_sync_time || null;
  }

  // 命中任一條件（完全比對 IP / ASN / CDN CIDR 網段）即視為公用設施，
  // 回傳 {type, name} 說明命中哪一條規則；完全沒命中回傳 null。
  function matchPublicInfra(record) {
    var ipOnly = String(record.ip).split("/")[0];

    if (PUBLIC_INFRA.exactIpMap[ipOnly]) {
      return { type: "exact_ip", name: PUBLIC_INFRA.exactIpMap[ipOnly] };
    }

    var asnNum = extractAsnNum(record.asn);
    if (asnNum && PUBLIC_INFRA.asnMap["AS" + asnNum]) {
      return { type: "asn", name: PUBLIC_INFRA.asnMap["AS" + asnNum] };
    }

    var ipInt = ipKey(ipOnly);
    for (var i = 0; i < PUBLIC_INFRA.cidrRanges.length; i++) {
      var range = PUBLIC_INFRA.cidrRanges[i];
      if (ipInt >= range.start && ipInt <= range.end) {
        return { type: "cdn_cidr", name: range.provider + " " + range.cidr };
      }
    }

    return null;
  }

  function toArray(value) {
    if (value == null) return [];
    return Array.isArray(value) ? value : [value];
  }

  // ---------------------------------------------------------------- 載入
  function fetchFirstAvailable(candidates, asJson) {
    var index = 0;
    function attempt() {
      if (index >= candidates.length) {
        return Promise.reject(new Error("找不到資料檔，已嘗試：" + candidates.join(", ")));
      }
      var url = candidates[index++];
      return fetch(url, { cache: "no-store" })
        .then(function (res) {
          if (!res.ok) throw new Error("HTTP " + res.status);
          return asJson ? res.json() : res.text();
        })
        .then(function (data) { return { url: url, data: data }; })
        .catch(attempt);
    }
    return attempt();
  }

  function normalize(payload) {
    var meta = (payload && payload.meta) || {};
    var raw = (payload && payload.iocs) || payload || {};
    var list = [];

    if (Array.isArray(raw)) {
      list = raw.slice();
    } else {
      Object.keys(raw).forEach(function (key) {
        var record = raw[key];
        if (record && typeof record === "object") {
          if (!record.ip) record.ip = key;
          list.push(record);
        }
      });
    }

    list.forEach(function (r) {
      r.labels = toArray(r.labels);
      r.resolving_domains = toArray(r.resolving_domains);
      r.threat_score = Number(r.threat_score) || 0;
      r.confidence = Number(r.confidence) || 0;
      r.seen_count = Number(r.seen_count) || 1;
      r._search = [
        r.ip,
        asnSearchText(r.asn),  // 涵蓋原始 ASN 代號與字典組織名稱/類型/國別
        r.labels.join(" "),
        r.resolving_domains.join(" ")
      ].join(" ").toLowerCase();
    });

    return { meta: meta, list: list };
  }

  function load() {
    $("tableBody").innerHTML =
      '<tr><td colspan="9" class="text-center py-5 muted">載入中 …</td></tr>';

    // pipeline.py 自動查詢擴充的 ASN 字典；尚未產生或載入失敗時
    // 容錯跳過，沿用 asn_dict.js 內建的靜態基礎字典即可。
    // 刻意讓字典先載入完成才處理 IOC 清單：normalize() 會在載入當下
    // 就算出 _search 比對字串，若字典晚到，動態解析出的組織名稱將
    // 無法被搜尋比對到。字典檔遠小於 base_iocs.json，先後載入對整體
    // 載入時間影響可忽略。
    var asnDictPromise = fetchFirstAvailable(ASN_DICT_CANDIDATES, true)
      .then(function (result) { mergeAsnDict(result.data); })
      .catch(function () { /* 沒有動態字典也不影響其餘功能 */ });

    // 公用雲端/CDN 白名單是前端自帶的靜態設定檔，載入失敗不應影響其餘
    // 功能（只是雲端公用清單會是空的、EDL 也就不會排除任何東西）。
    var publicInfraPromise = fetchFirstAvailable(PUBLIC_INFRA_CANDIDATES, true)
      .then(function (result) { loadPublicInfraRules(result.data); })
      .catch(function () { /* 沒有設定檔就不做白名單過濾 */ });

    // EDL 判定規則 snapshot：只有切到「EDL 判定規則」頁籤才需要，載入
    // 失敗不影響其餘功能（頁籤會顯示空狀態訊息）。
    var edlRulesPromise = fetchFirstAvailable(EDL_RULES_CANDIDATES, true)
      .then(function (result) {
        state.edlRules = result.data;
        renderEdlCriteriaFootnote();
      })
      .catch(function () {
        state.edlRules = null;
        // 不呼叫renderEdlCriteriaFootnote()：保留docs/index.html裡原本
        // 寫死的靜態文字當fallback，避免載入失敗時footnote變成空白。
      });

    // EDL CSV 匯出報表：只有按「匯出 IOC 情資 (.csv)」才會用到，載入
    // 失敗不影響其餘功能（按鈕點了會提示尚未就緒）。
    var edlExportPromise = fetchFirstAvailable(EDL_EXPORT_CANDIDATES, true)
      .then(function (result) { state.edlExportRows = Array.isArray(result.data) ? result.data : []; })
      .catch(function () { state.edlExportRows = []; });

    // 退場清單：同樣只有匯出時才用到，載入失敗（或檔案還不存在）就當作
    // 沒有任何退場紀錄，不影響「匯出 IOC 情資」按鈕的其餘功能。
    var edlRetiredPromise = fetchFirstAvailable(EDL_RETIRED_CANDIDATES, true)
      .then(function (result) { state.edlRetiredRows = Array.isArray(result.data) ? result.data : []; })
      .catch(function () { state.edlRetiredRows = []; });

    // 匯出時間戳 meta：同樣只有匯出時才用到，載入失敗就顯示「—」。
    var edlExportMetaPromise = fetchFirstAvailable(EDL_EXPORT_META_CANDIDATES, true)
      .then(function (result) {
        state.edlExportMeta = (result.data && typeof result.data === "object")
          ? result.data : { generated_at: null, baseline_at: null };
      })
      .catch(function () { state.edlExportMeta = { generated_at: null, baseline_at: null }; });

    var allPromise = asnDictPromise.then(function () {
      return fetchFirstAvailable(IOC_CANDIDATES, true).then(function (result) {
        state.raw.all = normalize(result.data);
      });
    });

    // daily_iocs.json 在尚未產生任何新資料前可能不存在，容錯回傳空集合
    var dailyPromise = asnDictPromise.then(function () {
      return fetchFirstAvailable(DAILY_CANDIDATES, true)
        .then(function (result) { return normalize(result.data); })
        .catch(function () { return { meta: {}, list: [] }; })
        .then(function (normalized) { state.raw.daily = normalized; });
    });

    Promise.all([allPromise, dailyPromise, asnDictPromise, publicInfraPromise, edlRulesPromise, edlExportPromise, edlRetiredPromise, edlExportMetaPromise])
      .then(function () {
        // EDL 頁籤不另外抓檔，直接從全量庫篩出 edl_tier 已標記的紀錄
        // （edl_tier 由 pipeline.py 的三層標籤決策邏輯於同步當下寫入，
        // 避免前端用瀏覽器當下時間重算導致兜底門檻的 24 小時時間窗漂移）。
        // 公用雲端/CDN 白名單比對（matchPublicInfra()）對「全部情資庫」
        // 每一筆紀錄都執行、一律標記，不只限於已經符合 EDL 條件的候選
        // 名單——這樣「雲端公用清單」頁籤能完整呈現所有命中公用設施的
        // 情資，而不是只有「原本差點被 EDL 誤判」的子集合。命中白名單的
        // 紀錄同時會被排除在 EDL 清單之外，避免誤封共用基礎設施。
        state.raw.all.list.forEach(function (r) {
          var match = matchPublicInfra(r);
          if (match) r._publicInfraMatch = match;
        });
        var edlList = state.raw.all.list.filter(function (r) {
          return (r.edl_tier === "A" || r.edl_tier === "B" || r.edl_tier === "C") && !r._publicInfraMatch;
        });
        var publicInfraList = state.raw.all.list.filter(function (r) {
          return !!r._publicInfraMatch;
        });
        state.raw.edl = { meta: state.raw.all.meta, list: edlList };
        state.raw.publicInfra = { meta: state.raw.all.meta, list: publicInfraList };

        updateTabBadges();
        renderEdlExportMetaHint();
        switchTab(state.activeTab);
      })
      .catch(function (err) {
        $("tableBody").innerHTML =
          '<tr><td colspan="9" class="text-center py-5 text-danger">' +
          "無法載入 base_iocs.json：" + esc(err.message) +
          '<br><span class="muted small">請先執行 pipeline.py 產生資料，或確認 GitHub Pages 發佈路徑。</span>' +
          "</td></tr>";
      });
  }

  function updateTabBadges() {
    $("tabAllBadge").textContent = state.raw.all.list.length.toLocaleString();
    $("tabDailyBadge").textContent = state.raw.daily.list.length.toLocaleString();
    $("tabEdlBadge").textContent = state.raw.edl.list.length.toLocaleString();
    $("tabPublicInfraBadge").textContent = state.raw.publicInfra.list.length.toLocaleString();
  }

  var TAB_LABELS = {
    all: "收錄總 IP 數",
    daily: "今日新增 IP 數",
    edl: "EDL 阻斷 IP 數",
    publicInfra: "雲端公用 IP 數"
  };

  function switchTab(tab) {
    if (tab !== "sectors" && tab !== "whitelist" && tab !== "edlRules" && !state.raw[tab]) tab = "all";
    state.activeTab = tab;

    $("tabAllBtn").classList.toggle("active", tab === "all");
    $("tabDailyBtn").classList.toggle("active", tab === "daily");
    $("tabEdlBtn").classList.toggle("active", tab === "edl");
    $("tabSectorsBtn").classList.toggle("active", tab === "sectors");
    $("tabPublicInfraBtn").classList.toggle("active", tab === "publicInfra");
    $("tabWhitelistBtn").classList.toggle("active", tab === "whitelist");
    $("tabEdlRulesBtn").classList.toggle("active", tab === "edlRules");

    var isSectors = tab === "sectors";
    var isPublicInfra = tab === "publicInfra";
    var isWhitelist = tab === "whitelist";
    var isEdlRules = tab === "edlRules";
    var isStaticTab = isSectors || isWhitelist || isEdlRules;
    $("sectorsPanel").hidden = !isSectors;
    $("whitelistPanel").hidden = !isWhitelist;
    $("edlRulesPanel").hidden = !isEdlRules;
    $("resultsPanel").hidden = (isStaticTab || isPublicInfra);
    $("publicInfraResultsPanel").hidden = !isPublicInfra;
    $("publicInfraPanel").hidden = !isPublicInfra;
    $("statsRow").hidden = (tab === "edl" || isStaticTab || isPublicInfra);
    $("searchRow").hidden = (tab === "edl" || isStaticTab);
    // 產業別規則／公用設施白名單完全不需要查詢列，整個外層容器隱藏，
    // 避免 searchRow 和 edlTierFilterRow 都隱藏後留下一條空白橫條
    $("queryBarPanel").hidden = isStaticTab;
    // 雲端公用清單頁籤精簡查詢列：只留搜尋框 + 清除條件，標籤下拉與
    // 排序下拉都不需要（表格欄位本來就不顯示 labels，排序固定依威脅分數）
    $("labelFilterCol").hidden = isPublicInfra;
    $("sortSelectCol").hidden = isPublicInfra;
    $("edlCriteriaPanel").hidden = (tab !== "edl");
    $("edlTierFilterRow").hidden = (tab !== "edl");
    $("edlSyncCompact").hidden = (tab !== "edl");
    // 右上角「下載 Firewall EDL 清單」只在 EDL 頁籤有意義，其餘頁籤一律隱藏
    $("edlLink").hidden = (tab !== "edl");
    $("edlCsvExportBtn").hidden = (tab !== "edl");
    $("edlExportMetaHint").hidden = (tab !== "edl");

    // 產業別規則／公用設施白名單都是靜態對照表，不走 IOC 資料的
    // 篩選/排序/統計流程
    if (isSectors) {
      renderSectorsPanel();
      return;
    }
    if (isWhitelist) {
      renderWhitelistPanel();
      return;
    }
    if (isEdlRules) {
      renderEdlRulesPanel();
      return;
    }

    var bucket = state.raw[tab];
    state.all = bucket.list;
    state.meta = bucket.meta;
    $("statTotalLabel").textContent = TAB_LABELS[tab] || TAB_LABELS.all;

    // 切換頁籤時，把目前作用中的排序鏡射成該頁籤自己記住的排序狀態
    var ts = state.tabSort[tab];
    state.sortKey = ts.key;
    state.sortDir = ts.dir;
    if (tab !== "edl" && !isPublicInfra) {
      var opt = document.querySelector('#sortSelect option[value="' + state.sortKey + '"]');
      if (opt) $("sortSelect").value = state.sortKey;
    }

    buildLabelOptions();
    renderStats();
    applyFilters();
  }

  // ---------------------------------------------------------------- 產業別規則
  function sectorCardHtml(sector) {
    var targetBadges = sector.targets.map(function (t) {
      return '<span class="badge-target">' + esc(t) + "</span>";
    }).join("");
    var tagBadges = sector.tags.map(function (t) {
      return '<span class="tag tag-amber">' + esc(t) + "</span>";
    }).join("");
    return (
      '<div class="sector-card sector-card-amber">' +
        '<div class="sector-card-title">' + esc(sector.name) +
          '<span class="sector-card-id">(' + esc(sector.id) + ")</span></div>" +
        '<div>' +
          '<span class="sector-card-label">防護標的</span>' +
          '<div class="sector-card-badges">' + targetBadges + "</div>" +
        "</div>" +
        '<div>' +
          '<span class="sector-card-label">關鍵標籤</span>' +
          '<div class="sector-card-badges">' + tagBadges + "</div>" +
        "</div>" +
        '<div class="sector-card-summary">' + esc(sector.summary) + "</div>" +
      "</div>"
    );
  }

  function renderSectorsPanel() {
    $("sectorsGrid").innerHTML = SECTOR_RULES.map(sectorCardHtml).join("");
  }

  // ---------------------------------------------------------------- 公用設施白名單規則
  // 靜態規則定義卡片（比照產業別規則卡片樣式），說明「雲端公用清單」頁籤
  // 判定邏輯依據的廠商/ASN/官方同步來源，純文件用途，不驅動實際比對
  // 邏輯（實際比對邏輯讀 docs/data/public_infra_rules.json，見 matchPublicInfra()）。
  var WHITELIST_RULES = [
    {
      name: "Cloudflare",
      asns: ["AS13335", "AS209242"],
      source: "https://www.cloudflare.com/ips-v4",
      summary: "保護全球 Anycast CDN 節點與 1.1.1.1 公用 DNS。",
      showCidrSection: true
    },
    {
      name: "Fastly",
      asns: ["AS54113"],
      source: "https://api.fastly.com/public-ip-list",
      summary: "保護關鍵 SaaS 服務與開源套件庫。",
      showCidrSection: true
    },
    {
      name: "Amazon Web Services (AWS)",
      asns: ["AS16509", "AS14618"],
      source: "AWS IP Ranges（篩選 CLOUDFRONT）",
      summary: "涵蓋服務：CloudFront CDN。",
      showCidrSection: true
    },
    {
      name: "Google Cloud Platform (GCP)",
      asns: ["AS15169", "AS396982"],
      source: "https://www.gstatic.com/ipranges/goog.json",
      summary: "涵蓋服務：Google Core & GCP 網段、8.8.8.8 公用 DNS。",
      showCidrSection: true
    },
    {
      name: "Microsoft 365 / Azure",
      asns: ["AS8075", "AS8068"],
      source: "Microsoft 365 Worldwide IP Web Service",
      summary: "涵蓋服務：M365 全球通訊端點。",
      showCidrSection: true
    },
    {
      name: "公用 DNS 服務 (Public DNS)",
      asns: [],
      isDns: true,
      source: null,
      summary: "避免阻斷各企業內部之核心 DNS 解析節點。"
    }
  ];

  // 可展開/收合的 CIDR 清單區塊。資料實際有無來自 docs/data/
  // public_infra_rules.json（見 loadPublicInfraRules 存的 cdnGroups），
  // 目前只有 Cloudflare、Fastly 有收錄實際網段，AWS/GCP/Microsoft
  // 目前僅做 ASN 比對、尚無 CIDR 清單——沒有資料時誠實顯示說明文字，
  // 不假造網段內容。
  function cidrBlockHtml(cidrs) {
    // 沒有資料就什麼都不畫——scripts/sync_public_infra.py 正式同步後，
    // 5 家廠商都會有真實 CIDR，這裡不再寫死「尚未同步」之類的提示文字；
    // 若未來真的遇到某家完全沒資料（例如全新廠商還沒跑過同步），就單純
    // 不顯示這個區塊，不誤導使用者。
    if (!cidrs || !cidrs.length) return "";

    var preview = cidrs.slice(0, 3).map(function (c) {
      return '<span class="tag">' + esc(c) + "</span>";
    }).join("");
    var expandLabel = "展開全部 " + cidrs.length + " 筆 CIDR ⯆";
    var collapseLabel = "收合 CIDR 清單 ⯅";
    var fullText = cidrs.join("\n");
    return (
      '<div class="cidr-block mt-2">' +
        '<div class="sector-card-badges mb-2">' + preview + "</div>" +
        '<button type="button" class="btn btn-sm btn-outline-info cidr-toggle-btn" ' +
          'data-expand-label="' + esc(expandLabel) + '" data-collapse-label="' + esc(collapseLabel) + '">' +
          esc(expandLabel) +
        "</button>" +
        '<div class="cidr-full-list mt-2" hidden>' +
          '<div class="d-flex justify-content-end mb-1">' +
            '<button type="button" class="btn btn-sm btn-outline-secondary cidr-copy-btn">複製全部</button>' +
          "</div>" +
          '<pre class="cidr-codebox" data-cidr-text>' + esc(fullText) + "</pre>" +
        "</div>" +
      "</div>"
    );
  }

  function findCidrGroup(providerName) {
    var groups = PUBLIC_INFRA.cdnGroups || [];
    for (var i = 0; i < groups.length; i++) {
      if (groups[i].provider === providerName) return groups[i];
    }
    return null;
  }

  function whitelistCardHtml(rule) {
    var asnBadges = (rule.asns || []).map(function (a) {
      return '<span class="tag tag-emerald">' + esc(a) + "</span>";
    }).join("");

    var ipBadges = "";
    if (rule.isDns) {
      // 公用 DNS 卡片直接讀取 public_infra_rules.json 的 exact_ips，
      // 確保清單跟實際用於比對的資料永遠一致、不會漏列或手key漏打。
      ipBadges = (PUBLIC_INFRA.exactIpsRaw || []).map(function (item) {
        return '<span class="tag tag-emerald">' + esc(item.ip) + "（" + esc(item.name) + "）</span>";
      }).join("");
    } else {
      ipBadges = (rule.ips || []).map(function (ip) {
        return '<span class="tag tag-emerald">' + esc(ip) + "</span>";
      }).join("");
    }

    var cidrGroup = rule.showCidrSection ? findCidrGroup(rule.name) : null;
    var cidrs = cidrGroup ? cidrGroup.cidrs : null;
    var countBadge = (cidrs && cidrs.length)
      ? ' <span class="badge bg-success" style="font-size:.68rem;">已同步 ' + cidrs.length + " 個 IPv4 網段</span>"
      : "";

    var sourceLine = "";
    if (rule.source) {
      var sourceContent = /^https?:\/\//.test(rule.source)
        ? '<a href="' + esc(rule.source) + '" target="_blank" rel="noopener noreferrer">' + esc(rule.source) + "</a>"
        : esc(rule.source);
      sourceLine = '<div class="sector-card-summary">官方同步來源：' + sourceContent + "</div>";
    }

    return (
      '<div class="sector-card sector-card-emerald">' +
        '<div class="sector-card-title">' + esc(rule.name) + countBadge + "</div>" +
        (asnBadges
          ? '<div><span class="sector-card-label">涵蓋 ASN</span>' +
            '<div class="sector-card-badges">' + asnBadges + "</div></div>"
          : "") +
        (ipBadges
          ? '<div><span class="sector-card-label">涵蓋 IP</span>' +
            '<div class="sector-card-badges">' + ipBadges + "</div></div>"
          : "") +
        sourceLine +
        '<div class="sector-card-summary">' + esc(rule.summary) + "</div>" +
        (rule.showCidrSection ? cidrBlockHtml(cidrs) : "") +
      "</div>"
    );
  }

  function renderWhitelistPanel() {
    $("whitelistGrid").innerHTML = WHITELIST_RULES.map(whitelistCardHtml).join("");
    $("whitelistSyncTime").textContent = PUBLIC_INFRA.lastSyncTime
      ? "最後同步時間 (UTC+8)：" + fmtDateTimeSeconds(PUBLIC_INFRA.lastSyncTime)
      : "最後同步時間 (UTC+8)：—";
  }

  // ---------------------------------------------------------------- EDL 判定規則頁籤
  // 內容完全來自 docs/data/edl_rules.json（pipeline.py 每次執行都重新產
  // 生），不在前端另外手刻一份門檻文字——避免像先前「EDL 判定條件說明」
  // 卡片那樣，門檻在程式碼裡調整好幾輪後，手寫文案忘記同步更新。
  // 通道A/B/C 卡片頂部飾條：A=Crimson紅／B=Amber橘／C=Violet紫，呼應
  // 表格裡的 tag-tier-a/b/c 徽章色，讓規則頁籤跟實際資料的通道配色一致。
  var EDL_CHANNEL_CARD_CLASS = { A: "sector-card-crimson", B: "sector-card-amber", C: "sector-card-violet" };

  // 時效窗口數值 >24小時且能整除24時（如通道B的336小時=14天），改用
  // 「X 天內」顯示更直覺；24小時以內（通道A/C）維持原本的「小時」顯示。
  function formatWindowHours(hours) {
    if (hours == null) return "—";
    if (hours > 24 && hours % 24 === 0) return (hours / 24) + " 天內";
    return hours + " 小時內";
  }

  function edlChannelCardHtml(key, ch) {
    if (!ch) return "";
    var rows = [];
    rows.push(["時效窗口", formatWindowHours(ch.window_hours)]);
    if (ch.min_seen_count != null) rows.push(["最低出現次數", "≥ " + ch.min_seen_count + " 次"]);
    if (ch.min_score != null) rows.push(["最低威脅分數", "≥ " + ch.min_score]);
    if (ch.min_confidence != null) rows.push(["最低信心值", "≥ " + ch.min_confidence]);

    var rowsHtml = rows.map(function (r) {
      return '<div class="d-flex justify-content-between small py-1" style="border-bottom:1px solid var(--cti-border);">' +
        '<span class="muted">' + esc(r[0]) + "</span><span class=\"fw-bold\">" + esc(String(r[1])) + "</span></div>";
    }).join("");

    var cardClass = "sector-card " + (EDL_CHANNEL_CARD_CLASS[key] || "sector-card-cyan");
    return (
      '<div class="' + cardClass + '">' +
        '<div class="sector-card-title">' +
          '<span class="tag tag-tier-' + esc(key.toLowerCase()) + '">通道' + esc(key) + "</span> " + esc(ch.name) +
        "</div>" +
        '<div class="mt-2">' + rowsHtml + "</div>" +
        '<div class="sector-card-summary mt-2">' + esc(ch.description) + "</div>" +
      "</div>"
    );
  }

  function edlTagListCardHtml(title, tags, description) {
    var badges = (tags || []).map(function (t) {
      return '<span class="tag">' + esc(t) + "</span>";
    }).join("");
    return (
      '<div class="sector-card sector-card-cyan">' +
        '<div class="sector-card-title">' + esc(title) + "</div>" +
        '<div class="sector-card-badges">' + badges + "</div>" +
        '<div class="sector-card-summary mt-2">' + esc(description) + "</div>" +
      "</div>"
    );
  }

  function edlConvergenceCardHtml(title, description) {
    return (
      '<div class="sector-card sector-card-cyan">' +
        '<div class="sector-card-title">' + esc(title) + "</div>" +
        '<div class="sector-card-summary">' + esc(description) + "</div>" +
      "</div>"
    );
  }

  // EDL阻斷清單頁籤最下方的CIDR/ASN/白名單說明（審查後新增，2026-10-22
  // 第三輪）：單一資料來源改造方案A——只把這一段footnote改成動態從
  // edl_rules.json的edl_tab_summary欄位取得（pipeline.py的build_edl_
  // rules_snapshot()新增的專屬精簡欄位，用詞比「EDL判定規則」頁籤的
  // 逐階詳細說明更簡短，適合這裡的footnote版面），不動3張A/B/C卡片的
  // 版面與樣式。資料缺失或載入失敗時，完全不touch這個元素，讓
  // docs/index.html裡原本寫死的靜態文字繼續當fallback顯示，不會出現
  // 空白區塊。
  function renderEdlCriteriaFootnote() {
    var el = document.getElementById("edlCriteriaFootnote");
    if (!el) return;
    var rules = state.edlRules;
    var summary = rules && rules.edl_tab_summary && rules.edl_tab_summary.description;
    if (!summary) return;
    el.textContent = summary;
  }

  function renderEdlRulesPanel() {
    var rules = state.edlRules;
    if (!rules) {
      $("edlRulesContent").innerHTML =
        '<div class="panel p-4 text-center muted">尚未載入 EDL 判定規則（docs/data/edl_rules.json 可能尚未產生）。</div>';
      $("edlRulesSyncTime").textContent = "";
      return;
    }

    $("edlRulesSyncTime").textContent = rules.generated_at
      ? "規則版本時間 (UTC+8)：" + fmtDateTimeSeconds(rules.generated_at)
      : "";

    var cards = [];
    var s1 = rules.stage1_ip_filter;
    if (s1) cards.push(edlConvergenceCardHtml(s1.name, s1.description));

    var s2 = rules.stage2_tags;
    if (s2) {
      cards.push(edlTagListCardHtml(
        "實質危害標籤 (MUST_HAVE_TAGS)", s2.must_have_tags, s2.must_have_tags_description
      ));
      cards.push(edlTagListCardHtml(
        "掃描雜訊標籤 (SCANNER_NOISE_TAGS)", s2.scanner_noise_tags, s2.scanner_noise_tags_description
      ));
    }

    var s3 = rules.stage3_channels || {};
    cards.push(edlChannelCardHtml("A", s3.A));
    cards.push(edlChannelCardHtml("B", s3.B));
    cards.push(edlChannelCardHtml("C", s3.C));

    // 白名單排除卡片：審查後新增（2026-10-22）。stage3b_whitelist_
    // exclusion 是pipeline.py後來才加入edl_rules.json的新區塊，舊版
    // 快取檔案可能沒有這個欄位——用if保護，缺欄位時單純不產生這張卡片
    // ，不影響其餘卡片正常渲染（維持既有的「缺資料不中斷整個頁籤」
    // 原則）。順序排在A/B/C通道卡片之後、CIDR聚合卡片之前，對應實際
    // 判定順序（通道判定完才套用白名單排除，早於CIDR聚合/ASN節流）。
    var s3b = rules.stage3b_whitelist_exclusion;
    if (s3b) {
      cards.push(edlConvergenceCardHtml(s3b.name || "公用雲端/CDN 白名單排除", s3b.description));
    }

    // 第四階卡片依實際執行順序排列：先 /24 聚合、後 ASN 節流、最後去重
    var s4 = rules.stage4_convergence;
    if (s4) {
      if (s4.cidr_rollup) {
        cards.push(edlConvergenceCardHtml(
          "① CIDR 收斂（門檻 ≥ " + s4.cidr_rollup.threshold + " 筆）", s4.cidr_rollup.description
        ));
      }
      if (s4.asn_throttle) {
        cards.push(edlConvergenceCardHtml(
          "② ASN 節流（上限 " + s4.asn_throttle.max_per_asn + " 筆／ASN）", s4.asn_throttle.description
        ));
      }
      if (s4.dedup) {
        cards.push(edlConvergenceCardHtml("③ 全域去重", s4.dedup.description));
      }
    }

    $("edlRulesContent").innerHTML = '<div class="sectors-grid">' + cards.join("") + "</div>";
  }

  function renderSectorPills() {
    var allPill = '<span class="sector-pill" data-sector="">全部 (All)</span>';
    var sectorPills = SECTOR_RULES.map(function (sector) {
      return '<span class="sector-pill" data-sector="' + esc(sector.id) + '">' +
        esc(sector.shortName) + "</span>";
    }).join("");
    var uncategorizedPill = '<span class="sector-pill" data-sector="' + UNCATEGORIZED_SECTOR_ID +
      '">其他/未分類</span>';
    $("sectorPillGroup").innerHTML = allPill + sectorPills + uncategorizedPill;
    updateSectorPillUI();
  }

  // 「全部」在複選集合為空時顯示為選中；其餘產業各自依是否在集合內顯示選中
  function updateSectorPillUI() {
    var selected = state.edlSectorFilter;
    $("sectorPillGroup").querySelectorAll(".sector-pill").forEach(function (el) {
      var sectorId = el.getAttribute("data-sector");
      var active = sectorId ? selected.has(sectorId) : selected.size === 0;
      el.classList.toggle("active", active);
    });
  }

  // ---------------------------------------------------------------- 篩選
  function buildLabelOptions() {
    var counts = {};
    state.all.forEach(function (r) {
      r.labels.forEach(function (label) {
        counts[label] = (counts[label] || 0) + 1;
      });
    });

    var names = Object.keys(counts).sort(function (a, b) {
      return counts[b] - counts[a] || a.localeCompare(b);
    });
    state.labelCounts = names.map(function (name) {
      return { name: name, count: counts[name] };
    });

    // 資料重新載入後，先前勾選但已不存在的標籤要移除
    var valid = new Set(names);
    state.selectedLabels.forEach(function (l) {
      if (!valid.has(l)) state.selectedLabels.delete(l);
    });

    renderLabelMenu();
    updateLabelButton();
    $("statLabels").textContent = names.length.toLocaleString();
  }

  function renderLabelMenu() {
    var query = ($("labelFilterSearch").value || "").trim().toLowerCase();
    var list = $("labelFilterList");
    var items = state.labelCounts.filter(function (item) {
      return !query || item.name.toLowerCase().indexOf(query) !== -1;
    });

    if (!items.length) {
      list.innerHTML = '<div class="label-filter-empty">沒有符合的標籤</div>';
      return;
    }

    list.innerHTML = items.map(function (item, idx) {
      var checked = state.selectedLabels.has(item.name) ? "checked" : "";
      var id = "lblChk" + idx + "_" + item.name.length;
      return (
        '<label class="label-filter-item" for="' + id + '">' +
          '<input type="checkbox" id="' + id + '" data-label="' + esc(item.name) + '" ' + checked + ' />' +
          '<span class="name">' + esc(item.name) + "</span>" +
          '<span class="count">' + item.count + "</span>" +
        "</label>"
      );
    }).join("");
  }

  function updateLabelButton() {
    var n = state.selectedLabels.size;
    var text;
    if (n === 0) text = "全部標籤 (labels)";
    else if (n === 1) text = Array.from(state.selectedLabels)[0];
    else text = "已選 " + n + " 個標籤";
    $("labelFilterBtnText").textContent = text;
    $("labelFilterSelectedCount").textContent = n ? ("已勾選 " + n + " 項") : " ";
  }

  function applyFilters() {
    var isEdlTab = state.activeTab === "edl";
    var isPublicInfraTab = state.activeTab === "publicInfra";
    // EDL 頁籤沒有搜尋框/標籤篩選 UI，一律不套用，只用階梯式判定篩選；
    // 雲端公用清單頁籤保留搜尋框，但沒有標籤篩選 UI。
    var query = isEdlTab ? "" : $("searchBox").value.trim().toLowerCase();
    var selected = (isEdlTab || isPublicInfraTab) ? new Set() : state.selectedLabels;
    var tierFilter = state.edlTierFilter;
    var sectorFilter = state.edlSectorFilter;
    var todayNewOnly = isEdlTab && state.edlTodayNewFilter;

    state.view = state.all.filter(function (r) {
      if (isEdlTab && !tierFilter[r.edl_tier]) return false;
      if (isEdlTab && !recordMatchesSectorFilter(r, sectorFilter)) return false;
      if (todayNewOnly && !r.is_today_new) return false;
      if (selected.size && !r.labels.some(function (l) { return selected.has(l); })) return false;
      if (query && r._search.indexOf(query) === -1) return false;
      return true;
    });

    sortView();
    state.shown = 0;
    if (isPublicInfraTab) {
      renderPublicInfraTable();
    } else {
      $("tableBody").innerHTML = "";
      renderMore();
    }

    var tierNarrowed = isEdlTab && !(tierFilter.A && tierFilter.B && tierFilter.C);
    $("statFiltered").textContent =
      (query || selected.size || tierNarrowed || todayNewOnly)
        ? "符合條件 " + state.view.length.toLocaleString() + " 筆"
        : " ";

    if (isEdlTab) {
      $("edlTierFilterCount").textContent =
        "符合條件：" + state.view.length.toLocaleString() +
        " 筆 (總量 " + state.raw.edl.list.length.toLocaleString() + " 筆)";
    }
  }

  // 依單一欄位比較兩筆紀錄，回傳負/零/正數（標準 comparator 慣例）
  // 時間欄位只截斷到「分鐘」精度再比較：後端寫入時同一批次的紀錄
  // last_seen/first_seen 往往只差幾毫秒（寫入處理順序造成，不具代表
  // 任何「誰比較新」的實質意義），但畫面上 (fmtDate) 只顯示到分鐘。
  // 若用完整毫秒精度比較，兩筆紀錄幾乎不可能真的打平，次要排序
  // （威脅分數等）就永遠排不到比較的機會——這正是「畫面上顯示同一
  // 分鐘，但分數卻亂序」的根因。改成分鐘精度比較後，真正同一分鐘的
  // 紀錄才會被視為打平，進而交給次要欄位排序。
  function truncateToMinute(epochMs) {
    return epochMs ? Math.floor(epochMs / 60000) * 60000 : 0;
  }

  function compareByKey(a, b, key, dir) {
    var x = a[key], y = b[key];
    if (key === "ip") { x = ipKey(x); y = ipKey(y); }
    else if (key === "first_seen" || key === "last_seen") {
      x = truncateToMinute(Date.parse(x) || 0);
      y = truncateToMinute(Date.parse(y) || 0);
    } else if (typeof x === "string" || typeof y === "string") {
      x = String(x == null ? "" : x); y = String(y == null ? "" : y);
      return x.localeCompare(y) * dir;
    }
    return x === y ? 0 : (x > y ? dir : -dir);
  }

  // 排序鏈 = 目前的主要排序欄位（頁籤預設，或使用者手動選的任何欄位）
  // + 標準次要排序順位（扣掉已經是主要欄位的那一項）。不論主要欄位是
  // 什麼，次要 tie-break 永遠都在，不會有「只有兩種預設模式才有
  // fallback、其餘排序方式退化成單欄位」的落差。
  function buildSortChain(tab) {
    var ts = state.tabSort[tab];
    var chain = [{ key: ts.key, dir: ts.dir }];
    CANONICAL_TIEBREAK_ORDER.forEach(function (entry) {
      if (entry.key !== ts.key) chain.push(entry);
    });
    return chain;
  }

  function sortRows(rows, chain) {
    rows.sort(function (a, b) {
      for (var i = 0; i < chain.length; i++) {
        var cmp = compareByKey(a, b, chain[i].key, chain[i].dir);
        if (cmp !== 0) return cmp;
      }
      return 0;
    });
  }

  function sortView() {
    sortRows(state.view, buildSortChain(state.activeTab));
  }

  // ---------------------------------------------------------------- EDL 匯出
  // 匯出清單依「目前的篩選結果」產生（階梯式判定 A/B + 領域快篩），內容
  // （IP 集合）預設 A+B 皆勾選、領域為「全部」時等同 pipeline.py 產生的
  // 靜態全量檔；排序則對齊 EDL 頁籤目前畫面上的排序（標準 SOC 預設：
  // threat_score → last_seen → confidence 皆降冪，或使用者手動覆寫的排序）。
  function buildEdlExportText() {
    var tierFilter = state.edlTierFilter;
    var sectorFilter = state.edlSectorFilter;
    var rows = state.raw.edl.list.filter(function (r) {
      if (!tierFilter[r.edl_tier]) return false;
      if (!recordMatchesSectorFilter(r, sectorFilter)) return false;
      return true;
    });

    sortRows(rows, buildSortChain("edl"));

    // 標頭 Generated_At 讀的是 pipeline.py 最近一次同步產出的時間戳記
    // （state.edlExportMeta.generated_at），不是瀏覽器點擊下載當下的
    // 時間——這份檔案的內容本來就是那次同步定案的結果，不該因為使用者
    // 晚點才按下下載鍵，就讓標頭顯示一個其實沒有重新運算過的新時間。
    // 標頭格式統一跟 pipeline.py 產出的純文字/CSV 匯出檔對齊：全英文
    // 3行 Generated_At/Baseline_Snapshot_At/Feed_Type。
    var meta = state.edlExportMeta || {};
    var header = [
      "# Generated_At: " + toTaipeiIso8601(meta.generated_at),
      "# Baseline_Snapshot_At: " + toTaipeiIso8601(meta.baseline_at),
      "# Feed_Type: Active_IOCs"
    ];
    var ipLines = rows.map(function (r) { return r.ip; });
    return header.concat(ipLines).join("\n") + "\n";
  }

  function downloadEdlExport() {
    var text = buildEdlExportText();
    var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "blocklist_edl.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // 退場(Retired)純文字清單：pipeline.py 每輪產出的現成靜態檔，內容已
  // 含標頭註解，前端原樣下載即可，不像 blocklist_edl.txt 需要依畫面上
  // 的通道/產業別篩選動態組字串——退場名單語意是「這些IP要解封」，
  // 不該受畫面篩選影響而漏推送部分解封項目。
  function downloadEdlRetiredTxt() {
    fetchFirstAvailable(EDL_RETIRED_TXT_CANDIDATES, false)
      .then(function (result) {
        var blob = new Blob([result.data], { type: "text/plain;charset=utf-8" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "blocklist_edl_retired.txt";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      })
      .catch(function (err) {
        console.warn("退場清單(blocklist_edl_retired.txt)下載失敗：", err);
      });
  }

  // CSV 欄位依 RFC 4180 一律加雙引號並跳脫內部雙引號，不管內容是否
  // 真的含逗號/換行——trigger_reason/retired_reason 文字裡可能夾雜
  // 「,」「|」等符號，一律加引號最保險，Excel 開啟也不受影響。
  function csvField(value) {
    return '"' + String(value == null ? "" : value).replace(/"/g, '""') + '"';
  }

  // CSV 匯出資料來源是 data/edl_export.json（跟 blocklist_edl.txt 條目
  // 一一對應，IP/CIDR 混編，已含伺服器端組好的英文結構化判定說明），
  // 不是 state.raw.edl.list（那是逐筆 IP 的畫面瀏覽用資料、未經過 /24
  // 聚合）——兩者刻意分開：TXT 下載維持既有行為給防火牆訂閱，CSV 匯出
  // 呈現跟正式 blocklist_edl.txt 完全對齊的聚合後條目。套用的篩選條件
  // （通道A/B/C、產業別、今日/本次新增）跟畫面上的 EDL 篩選列完全連動。
  function buildEdlCsvExportRows() {
    var tierFilter = state.edlTierFilter;
    var sectorFilter = state.edlSectorFilter;
    var todayNewOnly = state.edlTodayNewFilter;
    return state.edlExportRows.filter(function (r) {
      if (!tierFilter[r.channel]) return false;
      if (!recordMatchesSectorFilter(r, sectorFilter)) return false;
      if (todayNewOnly && !r.is_today_new) return false;
      return true;
    });
  }

  // 退場清單（data/edl_retired.json）：只列出「相較上一次執行基準，這
  // 一輪已經跌出EDL」的個別IP，每輪執行整份覆寫。跟現行有效清單一樣
  // 套用通道A/B/C、產業別篩選，但沒有「今日/本次新增」這個維度可套用
  // ——退場清單只在「僅看今日/本次新增」沒勾選的全量匯出模式下才會
  // 一併產出，呼叫端（downloadEdlCsvExport）已經處理這個互斥邏輯。
  function buildEdlRetiredCsvExportRows() {
    var tierFilter = state.edlTierFilter;
    var sectorFilter = state.edlSectorFilter;
    return state.edlRetiredRows.filter(function (r) {
      if (!tierFilter[r.channel]) return false;
      if (!recordMatchesSectorFilter(r, sectorFilter)) return false;
      return true;
    });
  }

  function csvLinesToBlob(lines) {
    var csvText = lines.join("\r\n") + "\r\n";
    // 開頭加 BOM（String.fromCharCode(0xFEFF)）對齊 utf-8-sig，確保 Excel
    // 開啟繁體中文判定說明時不會顯示亂碼。
    return new Blob([String.fromCharCode(0xFEFF) + csvText], { type: "text/csv;charset=utf-8" });
  }

  function triggerBlobDownload(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // 兩個CSV檔案統一欄位結構（snake_case全英文），確保下游工具用同一套
  // 解析邏輯就能讀兩種檔案：ip/domain/type/channel/threat_score/
  // confidence/frequency/first_seen/last_seen/retired_at/
  // retired_reason/trigger_reason/asn/asn_org。IP檔一列對應一個
  // blocklist_edl.txt條目（domain欄位留空）；Domain檔則依網域展開（ip
  // 欄位放該網域對應解析到的IP）。
  // Active/Added 跟 Retired 兩種情境的欄位結構刻意不同：前者是「目前
  // 為什麼在榜上」，需要完整的判定上下文；後者只在乎「這筆是誰、為何
  // 離開」，其餘欄位（channel/score/asn等）此刻都已經不是這筆記錄的
  // 現況，混進同一張表只會製造誤解，所以乾脆砍到只剩識別值跟退場原因。
  var ACTIVE_IP_HEADER = [
    "ip", "channel", "trigger_reason", "threat_score", "confidence",
    "frequency", "first_seen", "last_seen", "domain", "asn", "asn_org"
  ];
  var ACTIVE_DOMAIN_HEADER = [
    "domain", "channel", "trigger_reason", "threat_score", "confidence",
    "frequency", "first_seen", "last_seen"
  ];
  var RETIRED_IP_HEADER = ["ip", "retired_reason"];
  var RETIRED_DOMAIN_HEADER = ["domain", "retired_reason"];

  // 檔案一（Active/Added 情境）：IP阻斷清單——跟畫面上的EDL筆數1:1對應，
  // 不展開；domain欄位列出這個IP關聯到的網域（多顆以逗號分隔），沒有
  // 關聯網域則輸出空字串。
  function buildActiveIpCsvLines(rows) {
    var lines = [ACTIVE_IP_HEADER.map(csvField).join(",")];
    rows.forEach(function (r) {
      var domainField = (r.domains || []).join(", ");
      lines.push([
        csvField(r.entry), csvField(r.channel), csvField(r.trigger_reason),
        csvField(r.threat_score), csvField(r.confidence), csvField(r.frequency),
        csvField(r.first_seen), csvField(r.last_seen), csvField(domainField),
        csvField(r.asn), csvField(r.asn_org)
      ].join(","));
    });
    return lines;
  }

  // 檔案二（Active/Added 情境）：Domain威脅清單——只收錄有解析網域的
  // 條目，每個網域展開成獨立一列，並對FQDN做全域去重。trigger_reason
  // 不重複IP那一欄已經有的判定規則/分數門檻文字，改成單純標註這個
  // 網域是關聯到哪個/哪些IP（"via IP x.x.x.x"，多顆IP以逗號分隔）——
  // 同一網域如果掛在多個IP底下，要先掃過全部列把關聯IP蒐集完整，才能
  // 組出正確的逗號列表，不能像之前只看第一次遇到時那一個IP。channel/
  // threat_score等其餘欄位仍取第一次遇到時所屬的那筆IP列資訊為代表。
  function buildActiveDomainCsvLines(rows) {
    var lines = [ACTIVE_DOMAIN_HEADER.map(csvField).join(",")];
    var order = [];
    var ipsByDomain = {};
    var repByDomain = {};
    var displayByDomain = {};
    rows.forEach(function (r) {
      (r.domains || []).forEach(function (domain) {
        var key = domain.toLowerCase();
        if (!ipsByDomain[key]) {
          ipsByDomain[key] = [];
          repByDomain[key] = r;
          displayByDomain[key] = domain;
          order.push(key);
        }
        if (ipsByDomain[key].indexOf(r.entry) === -1) {
          ipsByDomain[key].push(r.entry);
        }
      });
    });
    order.forEach(function (key) {
      var r = repByDomain[key];
      var ips = ipsByDomain[key];
      var triggerReason = ips.length ? "via IP " + ips.join(", ") : (r.trigger_reason || "");
      lines.push([
        csvField(displayByDomain[key]), csvField(r.channel), csvField(triggerReason),
        csvField(r.threat_score), csvField(r.confidence), csvField(r.frequency),
        csvField(r.first_seen), csvField(r.last_seen)
      ].join(","));
    });
    return lines;
  }

  // 檔案三（Retired 情境）：退場IP清單——只保留識別值跟退場原因。
  function buildRetiredIpCsvLines(rows) {
    var lines = [RETIRED_IP_HEADER.map(csvField).join(",")];
    rows.forEach(function (r) {
      lines.push([csvField(r.entry), csvField(r.retired_reason)].join(","));
    });
    return lines;
  }

  // 檔案四（Retired 情境）：退場Domain清單——同樣只保留識別值跟退場
  // 原因，網域展開/去重邏輯跟 Active 版本一致。
  function buildRetiredDomainCsvLines(rows) {
    var lines = [RETIRED_DOMAIN_HEADER.map(csvField).join(",")];
    var seen = {};
    rows.forEach(function (r) {
      (r.domains || []).forEach(function (domain) {
        var key = domain.toLowerCase();
        if (seen[key]) return;
        seen[key] = true;
        lines.push([csvField(domain), csvField(r.retired_reason)].join(","));
      });
    });
    return lines;
  }

  // 同一個「匯出 IOC 情資」按鈕，依「僅看今日/本次新增」勾選狀態分兩種
  // 情境（不拆成獨立按鈕、不另外排程，單次點擊內一次算完）：
  //   情境A：未勾選（全量匯出）→ 當前有效IP/Domain + 相較上次基準的
  //          退場IP/Domain，共四個檔案。
  //   情境B：勾選了 → 只匯出本次新增的IP/Domain，不產出退場檔案
  //          （退場是「跌出清單」，跟「今日新增」在語意上互斥，勾選
  //          「只看新增」時混入退場清單沒有意義）。
  // 四個檔案之間用 setTimeout 錯開觸發，避免瀏覽器把連續多個下載當成
  // 快速連點擋下。
  // 在每個匯出CSV頂部加上3行全英文 # 註解（跟 pipeline.py 產出的純文字
  // 檔統一格式），標示產出時間、退場比對基準時間、以及這份檔案屬於
  // 哪一種feed（Active/Added/Retired），方便下游工具自動分類處理。
  function withExportTimestampComments(lines, feedType) {
    var meta = state.edlExportMeta || {};
    var header = [
      "# Generated_At: " + toTaipeiIso8601(meta.generated_at),
      "# Baseline_Snapshot_At: " + toTaipeiIso8601(meta.baseline_at),
      "# Feed_Type: " + feedType
    ];
    return header.concat(lines);
  }

  function downloadEdlCsvExport() {
    var rows = buildEdlCsvExportRows();

    // 台北日期字串取自 daily_iocs.json 的 meta.date_taipei（伺服器端算好
    // 的「今天」基準，跟「僅看今日/本次新增」篩選用的是同一套定義），避免
    // 瀏覽器用使用者裝置的本地時區另外推算出不一致的日期。
    var dateStr = (state.raw.daily.meta.date_taipei || "").replace(/-/g, "") || "unknown";
    var suffix = state.edlTodayNewFilter ? "TodayNew_" + dateStr : dateStr;
    var feedType = state.edlTodayNewFilter ? "Added_IOCs" : "Active_IOCs";

    triggerBlobDownload(csvLinesToBlob(withExportTimestampComments(buildActiveIpCsvLines(rows), feedType)), "Luminar_IOC_IP_" + suffix + ".csv");
    setTimeout(function () {
      triggerBlobDownload(csvLinesToBlob(withExportTimestampComments(buildActiveDomainCsvLines(rows), feedType)), "Luminar_IOC_Domain_" + suffix + ".csv");
    }, 150);

    if (state.edlTodayNewFilter) return;  // 情境B：到此為止，不產出退場檔案

    var retiredRows = buildEdlRetiredCsvExportRows();
    setTimeout(function () {
      triggerBlobDownload(csvLinesToBlob(withExportTimestampComments(buildRetiredIpCsvLines(retiredRows), "Retired_IOCs")), "Luminar_IOC_IP_Retired_" + dateStr + ".csv");
    }, 300);
    setTimeout(function () {
      triggerBlobDownload(csvLinesToBlob(withExportTimestampComments(buildRetiredDomainCsvLines(retiredRows), "Retired_IOCs")), "Luminar_IOC_Domain_Retired_" + dateStr + ".csv");
    }, 450);
  }

  // ---------------------------------------------------------------- 繪製
  function scoreClass(score) {
    return score >= 95 ? "score-pill score-crit" : "score-pill score-high";
  }

  function rowHtml(r) {
    var tierTag = "";
    if (r.edl_tier === "A") tierTag = '<span class="tag tag-tier-a">高危直通</span>';
    else if (r.edl_tier === "B") tierTag = '<span class="tag tag-tier-b">頑固威脅</span>';
    else if (r.edl_tier === "C") tierTag = '<span class="tag tag-tier-c">高確信</span>';

    var labels = tierTag + r.labels.slice(0, 6).map(function (l) {
      return '<span class="tag">' + esc(l) + "</span>";
    }).join("");
    if (r.labels.length > 6) {
      labels += '<span class="tag">+' + (r.labels.length - 6) + "</span>";
    }

    var domains = r.resolving_domains.slice(0, 3).map(esc).join("<br>");
    if (r.resolving_domains.length > 3) {
      domains += '<br><span class="muted">+' + (r.resolving_domains.length - 3) + " more</span>";
    }

    return "<tr>" +
      '<td class="ip-cell">' + esc(r.ip) + "</td>" +
      '<td><span class="' + scoreClass(r.threat_score) + '">' + r.threat_score + "</span></td>" +
      "<td>" + r.confidence + "</td>" +
      "<td>" + (labels || '<span class="muted">—</span>') + "</td>" +
      '<td class="muted small">' + formatASN(r.asn) + "</td>" +
      '<td class="domain-list">' + (domains || "—") + "</td>" +
      '<td class="muted small">' + fmtDate(r.first_seen) + "</td>" +
      '<td class="muted small">' + fmtDate(r.last_seen) + "</td>" +
      '<td class="text-center">' + r.seen_count + "</td>" +
      "</tr>";
  }

  function renderMore() {
    var slice = state.view.slice(state.shown, state.shown + PAGE_SIZE);

    if (!state.view.length) {
      $("tableBody").innerHTML =
        '<tr><td colspan="9" class="text-center py-5 muted">沒有符合條件的情資</td></tr>';
      $("rowInfo").textContent = "0 筆";
      $("btnMore").classList.add("d-none");
      return;
    }

    $("tableBody").insertAdjacentHTML("beforeend", slice.map(rowHtml).join(""));
    state.shown += slice.length;

    $("rowInfo").textContent =
      "顯示 " + state.shown.toLocaleString() + " / " + state.view.length.toLocaleString() + " 筆";
    $("btnMore").classList.toggle("d-none", state.shown >= state.view.length);
  }

  // 雲端公用清單頁籤專用的精簡表格渲染（5 欄，無分頁——預期筆數不多）
  function publicInfraRowHtml(r) {
    var domains = r.resolving_domains.length
      ? r.resolving_domains.map(esc).join("<br>")
      : '<span class="muted">—</span>';
    var ruleName = r._publicInfraMatch
      ? esc(r._publicInfraMatch.name)
      : '<span class="muted">—</span>';
    return "<tr>" +
      '<td class="ip-cell">' + esc(r.ip) + "</td>" +
      '<td class="muted small">' + ruleName + "</td>" +
      '<td class="domain-list">' + domains + "</td>" +
      '<td><span class="' + scoreClass(r.threat_score) + '">' + r.threat_score + "</span></td>" +
      '<td class="muted small">' + fmtDate(r.last_seen) + "</td>" +
      "</tr>";
  }

  function renderPublicInfraTable() {
    if (!state.view.length) {
      $("publicInfraTableBody").innerHTML =
        '<tr><td colspan="5" class="text-center py-5 muted">沒有符合條件的情資</td></tr>';
      $("publicInfraRowInfo").textContent = "0 筆";
      return;
    }
    $("publicInfraTableBody").innerHTML = state.view.map(publicInfraRowHtml).join("");
    $("publicInfraRowInfo").textContent = "共 " + state.view.length.toLocaleString() + " 筆";
  }

  // 匯出目前畫面上（已套用搜尋篩選）的非空解析網域，去重、一行一個
  function buildPublicInfraDomainExportText() {
    var seen = {};
    var domains = [];
    state.view.forEach(function (r) {
      (r.resolving_domains || []).forEach(function (d) {
        var domain = String(d || "").trim();
        if (domain && !seen[domain]) {
          seen[domain] = true;
          domains.push(domain);
        }
      });
    });
    return domains.join("\n") + (domains.length ? "\n" : "");
  }

  function downloadPublicInfraDomains() {
    var text = buildPublicInfraDomainExportText();
    var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "public_infra_malicious_domains.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function renderStats() {
    var total = state.all.length;
    $("statTotal").textContent = total.toLocaleString();

    // 同步時間與 EDL 阻斷數是全系統層級指標，不隨頁籤切換，固定讀全量庫 meta
    var globalMeta = state.raw.all.meta || {};
    var synced = globalMeta.generated_at;
    $("statSync").textContent = synced ? fmtDate(synced) : "—";
    $("statSyncLocal").textContent = " ";
    $("statSyncEdl").textContent = synced ? fmtDate(synced) : "—";

    // 直接用後端算出的 globalMeta.edl_count——這是 pipeline.py 經過四階
    // 過濾漏斗（RFC清洗 / 24h時效 / 標籤決策樹 / /24 CIDR 聚合收斂）後，
    // 實際會寫進 blocklist_edl.txt 的最終行數，才是真正會部署到防火牆
    // 的筆數。改版前曾改用「前端個別紀錄數」是因為當時後端還沒有聚合，
    // 兩者剛好相等；加入 /24 聚合後，後端數字才是正確答案（聚合後筆數
    // 必然 <= 個別紀錄數，改回用個別紀錄數會讓畫面顯示比實際部署量更大
    // 的誤導數字）。
    $("statEdl").textContent = (globalMeta.edl_count || 0).toLocaleString();
  }

  // ---------------------------------------------------------------- 事件
  function debounce(fn, wait) {
    var timer;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(fn, wait);
    };
  }

  function toggleLabelMenu(forceOpen) {
    var menu = $("labelFilterMenu");
    var open = forceOpen != null ? forceOpen : menu.hidden;
    menu.hidden = !open;
    if (open) {
      $("labelFilterSearch").value = "";
      renderLabelMenu();
      setTimeout(function () { $("labelFilterSearch").focus(); }, 0);
    }
  }

  function bind() {
    $("tabAllBtn").addEventListener("click", function () { switchTab("all"); });
    $("tabDailyBtn").addEventListener("click", function () { switchTab("daily"); });
    $("tabEdlBtn").addEventListener("click", function () { switchTab("edl"); });
    $("tabSectorsBtn").addEventListener("click", function () { switchTab("sectors"); });
    $("tabPublicInfraBtn").addEventListener("click", function () { switchTab("publicInfra"); });
    $("tabWhitelistBtn").addEventListener("click", function () { switchTab("whitelist"); });
    $("tabEdlRulesBtn").addEventListener("click", function () { switchTab("edlRules"); });

    // CIDR 展開/收合 + 複製全部，用事件代理綁在固定不變的 #whitelistGrid
    // 上，renderWhitelistPanel() 每次重繪 innerHTML 都不需要重新綁定。
    $("whitelistGrid").addEventListener("click", function (e) {
      var toggleBtn = e.target.closest(".cidr-toggle-btn");
      if (toggleBtn) {
        var block = toggleBtn.closest(".cidr-block");
        var fullList = block.querySelector(".cidr-full-list");
        var wasHidden = fullList.hidden;
        fullList.hidden = !wasHidden;
        toggleBtn.textContent = wasHidden
          ? toggleBtn.getAttribute("data-collapse-label")
          : toggleBtn.getAttribute("data-expand-label");
        return;
      }
      var copyBtn = e.target.closest(".cidr-copy-btn");
      if (copyBtn) {
        var pre = copyBtn.closest(".cidr-full-list").querySelector("[data-cidr-text]");
        var text = pre.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            var original = copyBtn.textContent;
            copyBtn.textContent = "已複製！";
            setTimeout(function () { copyBtn.textContent = original; }, 1500);
          }).catch(function () { /* 剪貼簿權限被拒時靜默失敗，使用者仍可手動選取文字複製 */ });
        }
      }
    });
    $("btnExportPublicInfraDomains").addEventListener("click", downloadPublicInfraDomains);

    $("sectorPillGroup").addEventListener("click", function (e) {
      var pill = e.target.closest(".sector-pill");
      if (!pill) return;
      var sectorId = pill.getAttribute("data-sector");

      if (!sectorId) {
        // 點「全部」：清空複選，回到不限制
        state.edlSectorFilter.clear();
      } else {
        // 複選：點一下切換該產業是否加入篩選集合
        if (state.edlSectorFilter.has(sectorId)) state.edlSectorFilter.delete(sectorId);
        else state.edlSectorFilter.add(sectorId);
      }
      updateSectorPillUI();
      applyFilters();
    });

    $("searchBox").addEventListener("input", debounce(applyFilters, 180));

    $("labelFilterBtn").addEventListener("click", function (e) {
      e.stopPropagation();
      toggleLabelMenu();
    });
    $("labelFilterMenu").addEventListener("click", function (e) {
      e.stopPropagation();
    });
    $("labelFilterSearch").addEventListener("input", renderLabelMenu);
    $("labelFilterList").addEventListener("change", function (e) {
      var target = e.target;
      if (!target || target.type !== "checkbox") return;
      var label = target.getAttribute("data-label");
      if (target.checked) state.selectedLabels.add(label);
      else state.selectedLabels.delete(label);
      updateLabelButton();
      applyFilters();
    });
    $("labelFilterClear").addEventListener("click", function () {
      state.selectedLabels.clear();
      updateLabelButton();
      renderLabelMenu();
      applyFilters();
    });
    document.addEventListener("click", function () {
      toggleLabelMenu(false);
    });

    $("sortSelect").addEventListener("change", function () {
      var ts = state.tabSort[state.activeTab];
      ts.key = this.value;
      ts.dir = this.value === "ip" ? 1 : -1;
      ts.custom = true;
      state.sortKey = ts.key;
      state.sortDir = ts.dir;
      applyFilters();
    });
    $("btnMore").addEventListener("click", renderMore);
    $("btnReset").addEventListener("click", function () {
      $("searchBox").value = "";
      state.selectedLabels.clear();
      updateLabelButton();
      renderLabelMenu();
      var tab = state.activeTab;
      var defaultEntry = TAB_DEFAULT_PRIMARY[tab];
      state.tabSort[tab] = { key: defaultEntry.key, dir: defaultEntry.dir, custom: false };
      state.sortKey = defaultEntry.key;
      state.sortDir = defaultEntry.dir;
      var opt = document.querySelector('#sortSelect option[value="' + state.sortKey + '"]');
      if (opt) $("sortSelect").value = state.sortKey;
      state.edlTierFilter = { A: true, B: true, C: true };
      $("tierFilterA").checked = true;
      $("tierFilterB").checked = true;
      $("tierFilterC").checked = true;
      state.edlTodayNewFilter = false;
      $("tierFilterTodayNew").checked = false;
      state.edlSectorFilter.clear();
      updateSectorPillUI();
      applyFilters();
    });

    $("tierFilterA").addEventListener("change", function () {
      state.edlTierFilter.A = this.checked;
      applyFilters();
    });
    $("tierFilterB").addEventListener("change", function () {
      state.edlTierFilter.B = this.checked;
      applyFilters();
    });
    $("tierFilterC").addEventListener("change", function () {
      state.edlTierFilter.C = this.checked;
      applyFilters();
    });
    $("tierFilterTodayNew").addEventListener("change", function () {
      state.edlTodayNewFilter = this.checked;
      applyFilters();
    });
    $("edlLink").addEventListener("click", function (e) {
      e.preventDefault();
      downloadEdlExport();
      setTimeout(downloadEdlRetiredTxt, 150);
    });
    $("edlCsvExportBtn").addEventListener("click", function () {
      downloadEdlCsvExport();
    });

    document.querySelectorAll("th[data-sort]").forEach(function (th) {
      th.addEventListener("click", function () {
        var key = th.getAttribute("data-sort");
        var tab = state.activeTab;
        var ts = state.tabSort[tab];
        // 已經是手動模式且點的是同一欄位才切換升降冪，否則採用該欄位的預設方向
        ts.dir = (ts.custom && ts.key === key) ? -ts.dir : (key === "ip" ? 1 : -1);
        ts.key = key;
        ts.custom = true;
        state.sortKey = ts.key;
        state.sortDir = ts.dir;
        if (tab !== "edl") {
          var opt = document.querySelector('#sortSelect option[value="' + key + '"]');
          if (opt) $("sortSelect").value = key;
        }
        applyFilters();
      });
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") toggleLabelMenu(false);
      if (e.key === "/" && document.activeElement !== $("searchBox")) {
        e.preventDefault();
        $("searchBox").focus();
      }
    });
  }

  bind();
  renderSectorPills();
  load();
})();
