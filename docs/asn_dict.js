/* ASN 易讀化字典 — 前端自建對照表（方案 A）
   涵蓋常見雲端/VPS主機商、CDN/網路防護商、台灣主要 ISP、亞太主要電信。
   由 app.js 透過全域 window.formatASN / window.asnSearchText 呼叫使用。 */
(function (global) {
  "use strict";

  var ASN_MAP = {
    // 雲端與 VPS 主機商
    "14061":  { name: "DigitalOcean",             type: "VPS主機",     country: "US" },
    "16276":  { name: "OVHcloud",                 type: "主機託管",    country: "FR" },
    "20473":  { name: "Vultr (Constant)",          type: "VPS主機",     country: "US" },
    "63949":  { name: "Linode (Akamai)",          type: "雲端主機",    country: "US" },
    "24940":  { name: "Hetzner Online",           type: "伺服器託管",  country: "DE" },
    "51167":  { name: "Contabo GmbH",             type: "VPS主機",     country: "DE" },
    "16509":  { name: "Amazon AWS",               type: "公有雲",      country: "US" },
    "14618":  { name: "Amazon AWS",               type: "公有雲",      country: "US" },
    "15169":  { name: "Google Cloud",             type: "公有雲",      country: "US" },
    "8075":   { name: "Microsoft Azure",          type: "公有雲",      country: "US" },
    "31898":  { name: "Oracle Cloud",             type: "公有雲",      country: "US" },
    "45102":  { name: "Alibaba Cloud (阿里雲)",    type: "公有雲",      country: "CN" },
    "132203": { name: "Tencent Cloud (騰訊雲)",    type: "公有雲",      country: "CN" },

    // CDN 與網路防護商
    "13335":  { name: "Cloudflare",               type: "CDN/Proxy",   country: "US" },
    "20940":  { name: "Akamai",                   type: "CDN加速",     country: "US" },

    // 台灣主要 ISP
    "3462":   { name: "中華電信 HiNet",           type: "台灣/ISP",       country: "TW" },
    "4780":   { name: "遠傳電信 NCIC",            type: "台灣/ISP",       country: "TW" },
    "9924":   { name: "台灣大哥大 TWM",           type: "台灣/ISP",       country: "TW" },
    "18049":  { name: "凱擘大寬頻 kbro",          type: "台灣/有線電視", country: "TW" },
    "18182":  { name: "中嘉寬頻 Homeplus",        type: "台灣/有線電視", country: "TW" },

    // 亞太主要電信
    "4134":   { name: "中國電信 ChinaNet",        type: "電信骨幹",    country: "CN" },
    "4837":   { name: "中國聯通 China Unicom",    type: "電信骨幹",    country: "CN" },
    "9808":   { name: "中國移動 China Mobile",    type: "電信骨幹",    country: "CN" },
    "4766":   { name: "Korea Telecom (KT)",       type: "韓國/ISP",     country: "KR" }
  };

  function escHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // 容錯取出 ASN 數字：移除開頭 AS/as 字樣與空白後，取開頭連續數字。
  // 可處理 "AS14061"、"AS205100 F3 Netze e.V." 與純數字 202412 三種常見格式。
  function extractAsnNumber(rawAsn) {
    if (rawAsn == null) return null;
    var s = String(rawAsn).trim();
    if (!s) return null;
    s = s.replace(/^as\s*/i, "");
    var match = s.match(/^(\d+)/);
    return match ? match[1] : null;
  }

  function formatASN(rawAsn) {
    if (rawAsn == null || String(rawAsn).trim() === "") {
      return '<span class="text-secondary">—</span>';
    }

    var asnNumber = extractAsnNumber(rawAsn);

    if (asnNumber && ASN_MAP[asnNumber]) {
      var item = ASN_MAP[asnNumber];
      return (
        '<div>' +
          '<span class="fw-bold text-light">' + escHtml(item.name) + '</span>' +
          '<span class="badge bg-secondary ms-1" style="font-size: 0.75rem;">' + escHtml(item.type) + '</span>' +
        '</div>' +
        '<div class="text-secondary small" style="font-size: 0.75rem;">' +
          'AS' + asnNumber + ' &middot; ' + escHtml(item.country) +
        '</div>'
      );
    }

    if (asnNumber) {
      return (
        '<div><span class="text-light">AS' + asnNumber + '</span></div>' +
        '<div class="text-secondary small" style="font-size: 0.75rem;">其他/未收錄組織</div>'
      );
    }

    // 無法從原始字串解析出 AS 編號（罕見格式），保留原文字避免資訊消失
    return (
      '<div><span class="text-light">' + escHtml(String(rawAsn).trim()) + '</span></div>' +
      '<div class="text-secondary small" style="font-size: 0.75rem;">其他/未收錄組織</div>'
    );
  }

  // 供搜尋欄位比對用：同時涵蓋原始代號（14061 / AS14061）與字典的
  // 組織名稱、類型、國別（DigitalOcean / HiNet / VPS / AWS ...）。
  function asnSearchText(rawAsn) {
    if (rawAsn == null) return "";
    var raw = String(rawAsn).trim();
    if (!raw) return "";

    var parts = [raw];
    var asnNumber = extractAsnNumber(rawAsn);
    if (asnNumber) {
      parts.push("as" + asnNumber, asnNumber);
      var item = ASN_MAP[asnNumber];
      if (item) parts.push(item.name, item.type, item.country);
    }
    return parts.join(" ").toLowerCase();
  }

  global.ASN_MAP = ASN_MAP;
  global.formatASN = formatASN;
  global.asnSearchText = asnSearchText;
})(window);
