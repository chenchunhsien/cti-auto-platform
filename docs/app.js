/* CTI 威脅情資查詢平台 — 前端邏輯（原生 JS，無框架） */
(function () {
  "use strict";

  // GitHub Pages 可能設定為 repo 根目錄或 /docs 子目錄為站台根，
  // 兩種情況下 data/ 的相對位置不同，因此依序嘗試。
  var IOC_CANDIDATES = ["../data/base_iocs.json", "./data/base_iocs.json", "/data/base_iocs.json"];
  var DAILY_CANDIDATES = ["../data/daily_iocs.json", "./data/daily_iocs.json", "/data/daily_iocs.json"];
  var EDL_CANDIDATES = ["../data/blocklist_edl.txt", "./data/blocklist_edl.txt", "/data/blocklist_edl.txt"];

  var PAGE_SIZE = 200;

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
    sortKey: "threat_score",
    sortDir: -1,
    labelCounts: [],         // [{name, count}]，依總數排序
    selectedLabels: new Set()  // 目前勾選的標籤（符合其中任一即顯示）
  };

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
        r.asn,
        r.labels.join(" "),
        r.resolving_domains.join(" ")
      ].join(" ").toLowerCase();
    });

    return { meta: meta, list: list };
  }

  function load() {
    $("tableBody").innerHTML =
      '<tr><td colspan="9" class="text-center py-5 muted">載入中 …</td></tr>';

    var allPromise = fetchFirstAvailable(IOC_CANDIDATES, true).then(function (result) {
      state.raw.all = normalize(result.data);
    });

    // daily_iocs.json 在尚未產生任何新資料前可能不存在，容錯回傳空集合
    var dailyPromise = fetchFirstAvailable(DAILY_CANDIDATES, true)
      .then(function (result) { return normalize(result.data); })
      .catch(function () { return { meta: {}, list: [] }; })
      .then(function (normalized) { state.raw.daily = normalized; });

    Promise.all([allPromise, dailyPromise])
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

    // EDL 下載連結指向第一個可用位置
    fetchFirstAvailable(EDL_CANDIDATES, false)
      .then(function (result) {
        var link = $("edlLink");
        link.href = result.url;
        link.setAttribute("download", "blocklist_edl.txt");
      })
      .catch(function () {
        $("edlLink").classList.add("disabled");
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
    if (!state.raw[tab]) tab = "all";
    state.activeTab = tab;

    var bucket = state.raw[tab];
    state.all = bucket.list;
    state.meta = bucket.meta;

    $("tabAllBtn").classList.toggle("active", tab === "all");
    $("tabDailyBtn").classList.toggle("active", tab === "daily");
    $("tabEdlBtn").classList.toggle("active", tab === "edl");
    $("statTotalLabel").textContent = TAB_LABELS[tab] || TAB_LABELS.all;

    buildLabelOptions();
    renderStats();
    applyFilters();
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
    var query = $("searchBox").value.trim().toLowerCase();
    var selected = state.selectedLabels;

    state.view = state.all.filter(function (r) {
      if (selected.size && !r.labels.some(function (l) { return selected.has(l); })) return false;
      if (query && r._search.indexOf(query) === -1) return false;
      return true;
    });

    sortView();
    state.shown = 0;
    $("tableBody").innerHTML = "";
    renderMore();

    $("statFiltered").textContent =
      (query || selected.size)
        ? "符合條件 " + state.view.length.toLocaleString() + " 筆"
        : " ";
  }

  function sortView() {
    var key = state.sortKey;
    var dir = state.sortDir;
    state.view.sort(function (a, b) {
      var x = a[key], y = b[key];
      if (key === "ip") { x = ipKey(x); y = ipKey(y); }
      else if (key === "first_seen" || key === "last_seen") {
        x = Date.parse(x) || 0; y = Date.parse(y) || 0;
      } else if (typeof x === "string" || typeof y === "string") {
        x = String(x == null ? "" : x); y = String(y == null ? "" : y);
        return x.localeCompare(y) * dir;
      }
      return x === y ? 0 : (x > y ? dir : -dir);
    });
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
      '<td class="muted small">' + esc(r.asn || "—") + "</td>" +
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
      state.sortKey = this.value;
      state.sortDir = this.value === "ip" ? 1 : -1;
      applyFilters();
    });
    $("btnMore").addEventListener("click", renderMore);
    $("btnRefresh").addEventListener("click", load);
    $("btnReset").addEventListener("click", function () {
      $("searchBox").value = "";
      state.selectedLabels.clear();
      updateLabelButton();
      renderLabelMenu();
      $("sortSelect").value = "threat_score";
      state.sortKey = "threat_score";
      state.sortDir = -1;
      applyFilters();
    });

    document.querySelectorAll("th[data-sort]").forEach(function (th) {
      th.addEventListener("click", function () {
        var key = th.getAttribute("data-sort");
        state.sortDir = state.sortKey === key ? -state.sortDir : (key === "ip" ? 1 : -1);
        state.sortKey = key;
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
  load();
})();
