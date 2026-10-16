/* CTI 情資收斂與 EDL 聯防平台 — 前端邏輯（原生 JS，無框架） */
(function () {
  "use strict";

  // GitHub Pages 可能設定為 repo 根目錄或 /docs 子目錄為站台根，
  // 兩種情況下 data/ 的相對位置不同，因此依序嘗試。
  var IOC_CANDIDATES = ["../data/base_iocs.json", "./data/base_iocs.json", "/data/base_iocs.json"];
  var DAILY_CANDIDATES = ["../data/daily_iocs.json", "./data/daily_iocs.json", "/data/daily_iocs.json"];
  var ASN_DICT_CANDIDATES = ["../data/asn_dict.json", "./data/asn_dict.json", "/data/asn_dict.json"];

  var PAGE_SIZE = 200;

  // 產業別規則：目前服務之 6 大領域，驅動「產業別規則」頁籤的卡片內容，
  // 以及 EDL 頁籤「領域快篩」膠囊按鈕的標籤比對邏輯（單一事實來源，
  // 避免卡片內容跟篩選邏輯各寫一份日後對不上）。
  var SECTOR_RULES = [
    {
      id: "gov_defense", name: "國安與政府機關", shortName: "國安/政府",
      targets: ["中央公務機關", "公務個資資料庫", "國防科研專案"],
      tags: ["apt", "espionage", "c2", "wiper", "exploit", "phishing"],
      summary: "鎖定國家級威脅與間諜活動，APT 組織與破壞性攻擊（wiper）為主要風險。"
    },
    {
      id: "logistics_supplychain", name: "物流與倉儲供應鏈", shortName: "物流/倉儲",
      targets: ["陸運整合車隊", "自動化智慧倉儲", "供應鏈管理系統"],
      tags: ["ransomware", "phishing", "trojan", "botnet", "supply-chain"],
      summary: "供應鏈攻擊與勒索軟體是物流業最主要的營運中斷風險。"
    },
    {
      id: "financial", name: "金融與支付", shortName: "金融/支付",
      targets: ["核心帳務主機", "數位網銀系統", "金流支付閘道"],
      tags: ["phishing", "banking-trojan", "credential-theft", "ransomware", "stealer"],
      summary: "針對帳戶憑證與交易系統的竊取型攻擊為主要威脅。"
    },
    {
      id: "telecom_network", name: "電信與通訊基礎", shortName: "電信/通訊",
      targets: ["核心網路維運", "骨幹網路基礎設施", "DNS 服務節點"],
      tags: ["ddos", "botnet", "dns-amplification", "c2", "exploit"],
      summary: "大流量癱瘓攻擊（DDoS）與核心網路入侵為主要風險。"
    },
    {
      id: "healthcare", name: "醫療與生醫設施", shortName: "醫療/基礎",
      targets: ["關鍵公衛機構", "醫療 HIS/LIS 系統", "生醫資料中心"],
      tags: ["ransomware", "data-leak", "phishing", "trojan", "extortion", "critical-infrastructure"],
      summary: "病患資料外洩與關鍵醫療設施中斷風險並存，勒索軟體衝擊尤其嚴重。"
    },
    {
      id: "retail_ecommerce", name: "零售通路與電商", shortName: "零售/電商",
      targets: ["連鎖門市 POS 系統", "大型電子商務平台", "會員身分認證平台"],
      tags: ["botnet", "ddos", "credential-stuffing", "carding", "brute-force", "scanner"],
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
      edl: { meta: {}, list: [] }
    },
    activeTab: "all",
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
      edl:   { key: "threat_score", dir: -1, custom: false }
    },
    sortKey: "threat_score",
    sortDir: -1,
    labelCounts: [],         // [{name, count}]，依總數排序
    selectedLabels: new Set(),  // 目前勾選的標籤（符合其中任一即顯示）
    edlTierFilter: { A: true, B: true },  // EDL 頁籤的階梯式判定篩選，預設 A+B 皆勾選
    edlSectorFilter: new Set()  // EDL 頁籤的領域快篩（複選），空集合代表「全部 (All)」
  };

  // 各頁籤初始（未手動調整過）的主要排序欄位，供頁籤第一次載入與
  // 「清除條件」還原使用。
  var TAB_DEFAULT_PRIMARY = {
    all:   { key: "threat_score", dir: -1 },  // 全部情資庫：歷史威脅獵捕
    daily: { key: "last_seen", dir: -1 },     // 今日最新發現：當日最新感知
    edl:   { key: "threat_score", dir: -1 }   // EDL 阻斷清單：活體攻擊優先阻斷
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

  function ipKey(ip) {
    var parts = String(ip).split("/")[0].split(".");
    if (parts.length !== 4) return 0;
    return parts.reduce(function (acc, p) { return acc * 256 + (parseInt(p, 10) || 0); }, 0);
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

    Promise.all([allPromise, dailyPromise, asnDictPromise])
      .then(function () {
        // EDL 頁籤不另外抓檔，直接從全量庫篩出 edl_tier 已標記的紀錄
        // （edl_tier 由 pipeline.py 的階梯式判定邏輯於同步當下寫入，
        // 避免前端用瀏覽器當下時間重算導致 72 小時 / 7 天時間窗漂移）
        var edlList = state.raw.all.list.filter(function (r) {
          return r.edl_tier === "A" || r.edl_tier === "B";
        });
        state.raw.edl = { meta: state.raw.all.meta, list: edlList };

        updateTabBadges();
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
  }

  var TAB_LABELS = {
    all: "收錄總 IP 數",
    daily: "今日新增 IP 數",
    edl: "EDL 阻斷 IP 數"
  };

  function switchTab(tab) {
    if (tab !== "sectors" && !state.raw[tab]) tab = "all";
    state.activeTab = tab;

    $("tabAllBtn").classList.toggle("active", tab === "all");
    $("tabDailyBtn").classList.toggle("active", tab === "daily");
    $("tabEdlBtn").classList.toggle("active", tab === "edl");
    $("tabSectorsBtn").classList.toggle("active", tab === "sectors");

    var isSectors = tab === "sectors";
    $("sectorsPanel").hidden = !isSectors;
    $("resultsPanel").hidden = isSectors;
    $("statsRow").hidden = (tab === "edl" || isSectors);
    $("searchRow").hidden = (tab === "edl" || isSectors);
    $("edlCriteriaPanel").hidden = (tab !== "edl");
    $("edlTierFilterRow").hidden = (tab !== "edl");
    $("edlSyncCompact").hidden = (tab !== "edl");

    // 產業別規則頁籤是靜態對照表，不走 IOC 資料的篩選/排序/統計流程
    if (isSectors) {
      renderSectorsPanel();
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
    if (tab !== "edl") {
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
      return '<span class="tag">' + esc(t) + "</span>";
    }).join("");
    return (
      '<div class="sector-card">' +
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
    // EDL 頁籤沒有搜尋框/標籤篩選 UI，一律不套用，只用階梯式判定篩選
    var query = isEdlTab ? "" : $("searchBox").value.trim().toLowerCase();
    var selected = isEdlTab ? new Set() : state.selectedLabels;
    var tierFilter = state.edlTierFilter;
    var sectorFilter = state.edlSectorFilter;

    state.view = state.all.filter(function (r) {
      if (isEdlTab && !tierFilter[r.edl_tier]) return false;
      if (isEdlTab && !recordMatchesSectorFilter(r, sectorFilter)) return false;
      if (selected.size && !r.labels.some(function (l) { return selected.has(l); })) return false;
      if (query && r._search.indexOf(query) === -1) return false;
      return true;
    });

    sortView();
    state.shown = 0;
    $("tableBody").innerHTML = "";
    renderMore();

    var tierNarrowed = isEdlTab && !(tierFilter.A && tierFilter.B);
    $("statFiltered").textContent =
      (query || selected.size || tierNarrowed)
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
    return rows.map(function (r) { return r.ip; }).join("\n") + (rows.length ? "\n" : "");
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

  // ---------------------------------------------------------------- 繪製
  function scoreClass(score) {
    return score >= 95 ? "score-pill score-crit" : "score-pill score-high";
  }

  function rowHtml(r) {
    var tierTag = "";
    if (r.edl_tier === "A") tierTag = '<span class="tag tag-tier-a">高危直通</span>';
    else if (r.edl_tier === "B") tierTag = '<span class="tag tag-tier-b">頑固威脅</span>';

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

  function renderStats() {
    var total = state.all.length;
    $("statTotal").textContent = total.toLocaleString();

    var avg = 0;
    if (total) {
      avg = state.all.reduce(function (s, r) { return s + r.threat_score; }, 0) / total;
    }
    $("statAvgScore").textContent = total ? Number(avg).toFixed(1) : "—";

    // 同步時間與 EDL 阻斷數是全系統層級指標，不隨頁籤切換，固定讀全量庫 meta
    var globalMeta = state.raw.all.meta || {};
    var synced = globalMeta.generated_at;
    $("statSync").textContent = synced ? fmtDate(synced) : "—";
    $("statSyncLocal").textContent = " ";
    $("statSyncEdl").textContent = synced ? fmtDate(synced) : "—";

    var edlCount = globalMeta.edl_count;
    $("statEdl").textContent = (edlCount != null) ? Number(edlCount).toLocaleString() : "—";
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
    $("btnRefresh").addEventListener("click", load);
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
      state.edlTierFilter = { A: true, B: true };
      $("tierFilterA").checked = true;
      $("tierFilterB").checked = true;
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
    $("edlLink").addEventListener("click", function (e) {
      e.preventDefault();
      downloadEdlExport();
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
