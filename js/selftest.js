(function(global) {
  'use strict';

  function runSelftest() {
    if (typeof document === "undefined") return;
    const $ = id => document.getElementById(id);

    try {
      const sample = (global.PKCS7Constants && global.PKCS7Constants.SAMPLE_B64) || global.SAMPLE_B64;
      const wrapped = sample.replace(/(.{72})/g, "$1\n");
      const res = global.doParse(wrapped, false);
      const out = [];
      global.treeLines(res.root, 0, out);

      document.title = "SELFTEST OK nodes=" + res.count + " certs=" + res.certs.length +
        " root=" + (res.root.role || res.root.tagName) +
        " ct=" + (res.root.kids[0] ? res.root.kids[0].preview : "?") +
        " inner=" + (res.root.kids[1] && res.root.kids[1].kids[0] ? res.root.kids[1].kids[0].role : "?");

      const pre = document.createElement("pre");
      pre.id = "selftest-out";
      pre.textContent = out.slice(0, 200).join("\n");
      document.body.appendChild(pre);

      try {
        $("btnSample").click();
        const rows = document.querySelectorAll(".trow").length;
        const hexSpans = document.querySelectorAll("#hex .hx").length;
        const cards = document.querySelectorAll(".card").length;
        const statusTxt = $("status").textContent;
        const firstRow = document.querySelector(".trow");
        if (firstRow) firstRow.click();
        const detailsLen = $("details").textContent.length;
        const th0 = document.documentElement.getAttribute("data-theme");
        $("btnTheme").click();
        const th1 = document.documentElement.getAttribute("data-theme");
        $("btnTheme").click();
        const th2 = document.documentElement.getAttribute("data-theme");

        document.title += " | UI rows=" + rows + " hx=" + hexSpans + " cards=" + cards +
          " det=" + detailsLen + " status='" + statusTxt + "'" +
          " theme=" + th0 + "->" + th1 + "->" + th2;

        try {
          const certSum = res.certs[0];
          if (certSum) {
            const der = global.CUR_BYTES.slice(certSum.node.start, certSum.node.end);
            global.PKCS7App.setMode("x509");
            global.PKCS7App.runXParse(der, true);
            const xrows = document.querySelectorAll("#xview tr").length;
            const xtreeRows = document.querySelectorAll("#xtree .trow").length;
            const xstatus = $("statusX").textContent;
            const xtxt = document.getElementById("xview").textContent;
            const keysOk = xtxt.indexOf("2048 bits") !== -1 ? "1" : "0";
            global.PKCS7App.setMode("pkcs7");
            const restored = $("tree").querySelectorAll(".trow").length;
            document.title += " | X509 rows=" + xrows + " xtree=" + xtreeRows + " xstatus='" + xstatus + "' keys2048=" + keysOk + " back2pkcs7rows=" + restored;
          }
        } catch (e3) {
          document.title += " | X509_FAIL " + e3.message;
        }

        try {
          const splOK = ($("vsplitP") && $("vsplitX") && $("hsplit") && $("hsplit2")) ? "ok" : "missing";
          $("btnClear").click();
          const disp = getComputedStyle($("status")).display;
          $("btnSample").click();
          const rows2 = document.querySelectorAll(".trow").length;
          document.title += " | spl=" + splOK + " emptyStatusDisp=" + disp + " rowsAfterReparse=" + rows2;
        } catch (e4) {
          document.title += " | SPL_FAIL " + e4.message;
        }
      } catch (e2) {
        document.title += " | UI_FAIL " + e2.message;
      }
    } catch (err) {
      document.title = "SELFTEST FAIL " + err.message;
      const pre = document.createElement("pre");
      pre.id = "selftest-out";
      pre.textContent = "FAIL " + err.message + "\n" + (err.stack || "");
      document.body.appendChild(pre);
    }
  }

  const selftestModule = {
    run: runSelftest
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = selftestModule;
  }
  global.PKCS7Selftest = selftestModule;

  if (typeof location !== 'undefined' && location.hash === "#selftest") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", runSelftest);
    } else {
      runSelftest();
    }
  }
})(typeof window !== 'undefined' ? window : global);
