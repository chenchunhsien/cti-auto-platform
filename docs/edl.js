/* EDL 阻斷清單檢視頁 — 前端邏輯（原生 JS，無框架） */
(function () {
  "use strict";

  var BASE_CANDIDATES = ["../data/base_iocs.json", "./data/base_iocs.json", "/data/base_iocs.json"];
  var EDL_TXT_CANDIDATES = ["../data/blocklist_edl.txt", "./data/blocklist_edl.txt", "/data/blocklist_edl.txt"];

  var state = {
    rows: [],   // 豐富化後的完整清單（未篩選）
    view: [],   // 搜尋篩選後
    sortKey: "threat_score",
    sortDir: -1
  };

  var $ = function (id) { return document.getElementById(id); };

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function toArray(value) {
    if (value == null) return [];
    return Array.isArray(value) ? value : [value];
  }

  function fmtDate(value) {
    if (!value) return "—";
    var d = new Date(value);
    if (isNaN(d.getTime())) return esc(String(value).slice(0, 19));
    // 固定以 UTC+8（台北時間）顯示，與情資總覽頁一致
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

  function parseEdlText(text) {
    return String(text || "")
      .split(/\r?\n/)
      .map(function (line) { return line.trim(); })
      .filter(function (line) { return line.length > 0; });
  }

  function buildBaseMap(payload) {
    var raw = (payload && payload.iocs) || payload || {};
    var map = Object.create(null);

    if (Array.isArray(raw)) {
      raw.forEach(function (record) {
        if (record && record.ip) map[record.ip] = record;
      });
    } else {
      Object.keys(raw).forEach(function (key) {
        var record = raw[key];
        if (record && typeof record === "object") {
          if (!record.ip) record.ip = key;
          map[key] = record;
        }
      });
    }
    return map;
  }

  function enrichRow(ip, baseMap) {
    var record = baseMap[ip];
    if (!record) {
      // EDL 清單引用的 IP 理論上都存在於 base_iocs.json；
      // 真的找不到時仍顯示該筆，其餘欄位留白，避免整頁因單筆資料缺漏而中斷。
      return {
        ip: ip, threat_score: 0, confidence: 0, labels: [], resolving_domains: [],
        asn: null, last_seen: null, first_seen: null, seen_count: 1, edl_tier: null,
        _search: ip.toLowerCase()
      };
    }
    var labels = toArray(record.labels);
    var asn = record.asn;
    return {
      ip: ip,
      threat_score: Number(record.threat_score) || 0,
      confidence: Number(record.confidence) || 0,
      labels: labels,
      resolving_domains: toArray(record.resolving_domains),
      asn: asn,
      last_seen: record.last_seen,
      first_seen: record.first_seen,
      seen_count: Number(record.seen_count) || 1,
      edl_tier: record.edl_tier || null,
      _search: [ip, asn, labels.join(" ")].join(" ").toLowerCase()
    };
  }

  function load() {
    $("tableBody").innerHTML =
      '<tr><td colspan="7" class="text-center py-5 muted">載入中 …</td></tr>';

    var edlPromise = fetchFirstAvailable(EDL_TXT_CANDIDATES, false)
      .then(function (result) {
        var link = $("edlLink");
        link.href = result.url;
        link.setAttribute("download", "blocklist_edl.txt");
        return parseEdlText(result.data);
      });

    var basePromise = fetchFirstAvailable(BASE_CANDIDATES, true)
      .then(function (result) { return buildBaseMap(result.data); });

    Promise.all([edlPromise, basePromise])
      .then(function (results) {
        var ipList = results[0];
        var baseMap = results[1];
        state.rows = ipList.map(function (ip) { return enrichRow(ip, baseMap); });
        renderStats();
        applyFilter();
      })
      .catch(function (err) {
        $("tableBody").innerHTML =
          '<tr><td colspan="7" class="text-center py-5 text-danger">' +
          "無法載入 EDL 資料：" + esc(err.message) +
          '<br><span class="muted small">請先執行 pipeline.py 產生資料，或確認 GitHub Pages 發佈路徑。</span>' +
          "</td></tr>";
      });
  }

  function renderStats() {
    var total = state.rows.length;
    var tierA = 0, tierB = 0;
    state.rows.forEach(function (r) {
      if (r.edl_tier === "A") tierA++;
      else if (r.edl_tier === "B") tierB++;
    });
    $("statEdlTotal").textContent = total.toLocaleString();
    $("statTierA").textContent = tierA.toLocaleString();
    $("statTierB").textContent = tierB.toLocaleString();
  }

  // ---------------------------------------------------------------- 篩選 / 排序 / 繪製
  function applyFilter() {
    var query = $("searchBox").value.trim().toLowerCase();
    state.view = state.rows.filter(function (r) {
      return !query || r._search.indexOf(query) !== -1;
    });
    sortView();
    render();
  }

  function sortView() {
    var key = state.sortKey;
    var dir = state.sortDir;
    state.view.sort(function (a, b) {
      var x = a[key], y = b[key];
      if (key === "ip") { x = ipKey(x); y = ipKey(y); }
      else if (key === "last_seen") {
        x = Date.parse(x) || 0; y = Date.parse(y) || 0;
      } else if (typeof x === "string" || typeof y === "string") {
        x = String(x == null ? "" : x); y = String(y == null ? "" : y);
        return x.localeCompare(y) * dir;
      }
      return x === y ? 0 : (x > y ? dir : -dir);
    });
  }

  function tierBadge(tier) {
    if (tier === "A") return '<span class="tier-badge tier-a">高危直通</span>';
    if (tier === "B") return '<span class="tier-badge tier-b">頑固威脅</span>';
    return '<span class="muted small">—</span>';
  }

  function scoreClass(score) {
    return score >= 95 ? "score-pill score-crit" : "score-pill score-high";
  }

  function rowHtml(r) {
    var labels = r.labels.slice(0, 4).map(function (l) {
      return '<span class="tag">' + esc(l) + "</span>";
    }).join("");
    if (r.labels.length > 4) {
      labels += '<span class="tag">+' + (r.labels.length - 4) + "</span>";
    }

    return "<tr>" +
      '<td class="ip-cell">' + esc(r.ip) + "</td>" +
      "<td>" + tierBadge(r.edl_tier) + "</td>" +
      '<td><span class="' + scoreClass(r.threat_score) + '">' + r.threat_score + "</span></td>" +
      "<td>" + (labels || '<span class="muted">—</span>') + "</td>" +
      '<td class="muted small">' + esc(r.asn || "—") + "</td>" +
      '<td class="muted small">' + fmtDate(r.last_seen) + "</td>" +
      '<td class="text-center">' + r.seen_count + "</td>" +
      "</tr>";
  }

  function render() {
    if (!state.view.length) {
      $("tableBody").innerHTML =
        '<tr><td colspan="7" class="text-center py-5 muted">沒有符合條件的 IP</td></tr>';
      $("rowInfo").textContent = "0 筆";
      return;
    }
    $("tableBody").innerHTML = state.view.map(rowHtml).join("");
    $("rowInfo").textContent =
      "顯示 " + state.view.length.toLocaleString() + " / " + state.rows.length.toLocaleString() + " 筆";
  }

  // ---------------------------------------------------------------- 複製到剪貼簿
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    // 舊瀏覽器 fallback
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        document.body.removeChild(ta);
      }
    });
  }

  function flashFeedback(el) {
    el.classList.add("show");
    setTimeout(function () { el.classList.remove("show"); }, 1800);
  }

  // ---------------------------------------------------------------- 事件
  function debounce(fn, wait) {
    var timer;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(fn, wait);
    };
  }

  function bind() {
    $("searchBox").addEventListener("input", debounce(applyFilter, 180));

    document.querySelectorAll("th[data-sort]").forEach(function (th) {
      th.addEventListener("click", function () {
        var key = th.getAttribute("data-sort");
        state.sortDir = state.sortKey === key ? -state.sortDir : (key === "ip" ? 1 : -1);
        state.sortKey = key;
        sortView();
        render();
      });
    });

    $("btnCopyUrl").addEventListener("click", function () {
      copyText($("subscribeUrl").value).then(function () {
        flashFeedback($("copyUrlFeedback"));
      });
    });

    $("btnCopyAll").addEventListener("click", function () {
      var allIps = state.rows.map(function (r) { return r.ip; }).join("\n");
      copyText(allIps).then(function () {
        flashFeedback($("copyAllFeedback"));
      });
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "/" && document.activeElement !== $("searchBox")) {
        e.preventDefault();
        $("searchBox").focus();
      }
    });
  }

  bind();
  load();
})();
