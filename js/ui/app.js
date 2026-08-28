(function(global) {
  'use strict';

  if (typeof document === "undefined") return;

  const $ = id => document.getElementById(id);

  let MODE = "pkcs7";
  let SELNODE = null;

  const WSSTATE = {
    pkcs7: { host: "tree", bytes: null, root: null, sel: null, certs: [] },
    x509: { host: "xtree", bytes: null, root: null, sel: null, certs: [] }
  };

  function setStatus(msg, ok) {
    const el = $("status");
    if (!el) return;
    el.textContent = msg;
    el.className = ok ? "ok" : "err";
  }

  function setStatusX(msg, ok) {
    const el = $("statusX");
    if (!el) return;
    el.textContent = msg;
    el.className = ok ? "ok" : "err";
  }

  function handleSelectNode(node, rowEl) {
    SELNODE = node;
    document.querySelectorAll(".trow.sel").forEach(e => e.classList.remove("sel"));
    if (rowEl) rowEl.classList.add("sel");
    const details = $("details");
    const detailPath = $("detailPath");
    if (details) details.textContent = global.describeNode(node);
    if (detailPath) detailPath.textContent = global.pathOf(node);
    global.PKCS7HexViewer.highlightRange(node.start, node.end);
  }

  function renderAll() {
    const state = WSSTATE[MODE];
    const host = $(state.host);
    if (!host) return;
    global.PKCS7TreeView.renderTree(host, global.CUR_ROOT, handleSelectNode, () => renderAll(), SELNODE);
  }

  function selectByNode(node) {
    global.PKCS7TreeView.selectByNode(node, global.CUR_ROOT, renderAll, handleSelectNode);
  }

  function runParse(input, isBinary) {
    try {
      const res = global.doParse(input, isBinary);
      SELNODE = null;
      global.CUR_ROOT = res.root;
      global.CUR_ROOT.open = true;
      for (const c of global.CUR_ROOT.kids) c.open = true;
      const ci = global.CUR_ROOT.kids.find(c => c.role === "content [0] EXPLICIT");
      if (ci) for (const c of ci.kids) c.open = true;

      WSSTATE.pkcs7.bytes = global.CUR_BYTES;
      WSSTATE.pkcs7.root = global.CUR_ROOT;
      WSSTATE.pkcs7.sel = null;
      WSSTATE.pkcs7.certs = res.certs;

      renderAll();
      global.PKCS7CertView.renderCerts(res.certs, sum => {
        $("tabBtnAsn1").click();
        selectByNode(sum.node);
      }, sum => {
        const der = global.CUR_BYTES.slice(sum.node.start, sum.node.end);
        setMode("x509");
        runXParse(der, true);
      });

      global.PKCS7HexViewer.buildHex(global.CUR_BYTES);

      let trailing = "";
      if (res.root.end < res.size) {
        trailing = " | note: extra data after first structure (from byte " + res.root.end + ")";
      }
      setStatus("Parsed " + res.size + " bytes | " + res.count + " ASN.1 nodes" + (res.certs.length ? " | " + res.certs.length + " certificate(s)" : "") + trailing, true);
    } catch (err) {
      setStatus("ERROR: " + err.message, false);
      const tree = $("tree");
      if (tree) tree.innerHTML = '<div class="hint">Parse failed - see status message above.</div>';
    }
  }

  function runXParse(input, isBinary) {
    try {
      const res = global.doParse(input, isBinary);
      if (res.root.role !== "Certificate") {
        setStatusX("Input is not an X.509 certificate (detected: " + (res.root.role || res.root.tagName) + ").", false);
        const xv = $("xview");
        if (xv) xv.innerHTML = '<div class="hint">Input parsed, but it is not an X.509 certificate.</div>';
        return;
      }
      SELNODE = null;
      WSSTATE.x509.bytes = global.CUR_BYTES;
      WSSTATE.x509.root = res.root;
      WSSTATE.x509.sel = null;
      WSSTATE.x509.certs = res.certs;

      res.root.open = true;
      for (const c of res.root.kids) c.open = true;

      global.PKCS7CertView.buildXView(res.certs[0] || {}, res.root, global.CUR_BYTES);
      renderAll();
      global.PKCS7HexViewer.buildHex(global.CUR_BYTES);

      let extra = res.root.end < res.size ? " (note: " + (res.size - res.root.end) + " extra bytes after the certificate ignored)" : "";
      setStatusX("Parsed certificate - " + res.size + " bytes, " + res.count + " ASN.1 nodes" + extra, true);
    } catch (err) {
      setStatusX("ERROR: " + err.message, false);
      const xv = $("xview");
      if (xv) xv.innerHTML = '<div class="hint">Parse failed - see status message above.</div>';
    }
  }

  function setMode(m) {
    if (MODE === m) return;
    WSSTATE[MODE].bytes = global.CUR_BYTES;
    WSSTATE[MODE].root = global.CUR_ROOT;
    WSSTATE[MODE].sel = SELNODE;
    WSSTATE[MODE].certs = global.CERTS;

    MODE = m;
    const st = WSSTATE[m];
    global.CUR_BYTES = st.bytes;
    global.CUR_ROOT = st.root;
    global.CERTS = st.certs || [];
    SELNODE = st.sel;

    $("modePkcs7").classList.toggle("active", m === "pkcs7");
    $("modeX509").classList.toggle("active", m === "x509");
    $("wsPkcs7").classList.toggle("active", m === "pkcs7");
    $("wsX509").classList.toggle("active", m === "x509");

    global.PKCS7HexViewer.clearHighlight();

    if (st.root) {
      renderAll();
      global.PKCS7HexViewer.buildHex(global.CUR_BYTES);
      if (SELNODE) {
        $("details").textContent = global.describeNode(SELNODE);
        $("detailPath").textContent = global.pathOf(SELNODE);
        global.PKCS7HexViewer.highlightRange(SELNODE.start, SELNODE.end);
      }
    }
  }

  function looksBinary(buf) {
    let ctrl = 0;
    const n = Math.min(buf.length, 4096);
    for (let i = 0; i < n; i++) {
      const c = buf[i];
      if ((c < 32 && c !== 9 && c !== 10 && c !== 13) || c === 127) ctrl++;
    }
    return n > 0 && (ctrl / n > 0.02);
  }

  function wireDrop(wrapEl, ta, run) {
    if (!wrapEl || !ta) return;
    wrapEl.addEventListener("dragover", e => {
      e.preventDefault();
      wrapEl.style.opacity = "0.6";
    });
    wrapEl.addEventListener("dragleave", () => {
      wrapEl.style.opacity = "1";
    });
    wrapEl.addEventListener("drop", e => {
      e.preventDefault();
      wrapEl.style.opacity = "1";
      const f = e.dataTransfer.files && e.dataTransfer.files[0];
      if (!f) return;
      const rd = new FileReader();
      rd.onload = () => {
        const buf = new Uint8Array(rd.result);
        if (looksBinary(buf)) {
          ta.value = "(binary file loaded: " + f.name + ", " + buf.length + " bytes)";
          run(buf, true);
        } else {
          const text = new TextDecoder().decode(buf);
          ta.value = text;
          run(text, false);
        }
      };
      rd.readAsArrayBuffer(f);
    });
  }

  function initApp() {
    global.PKCS7Theme.initTheme();
    global.PKCS7Splitter.initSplitters();

    $("btnTheme").addEventListener("click", () => {
      global.PKCS7Theme.toggleTheme();
    });

    $("modePkcs7").addEventListener("click", () => setMode("pkcs7"));
    $("modeX509").addEventListener("click", () => setMode("x509"));

    $("btnParse").addEventListener("click", () => {
      const t = $("input").value;
      if (!t.trim()) {
        setStatus("nothing to parse", false);
        return;
      }
      runParse(t, false);
    });

    $("btnClear").addEventListener("click", () => {
      $("input").value = "";
      $("tree").innerHTML = '<div class="hint">Paste input on the left and press Parse.</div>';
      $("certs").innerHTML = '<div class="hint">No certificate information yet.</div>';
      $("certCount").textContent = "";
      $("details").textContent = "Select a node to inspect it.";
      $("detailPath").textContent = "";
      $("hex").textContent = "";
      $("hexNote").textContent = "";
      SELNODE = null;
      WSSTATE.pkcs7 = { host: "tree", bytes: null, root: null, sel: null, certs: [] };
      if (MODE === "pkcs7") {
        global.CUR_BYTES = null;
        global.CUR_ROOT = null;
        global.CERTS = [];
      }
      global.PKCS7HexViewer.clearHighlight();
      setStatus("", true);
    });

    $("btnSample").addEventListener("click", () => {
      const sample = (global.PKCS7Constants && global.PKCS7Constants.SAMPLE_B64) || global.SAMPLE_B64;
      const wrapped = sample.replace(/(.{72})/g, "$1\n");
      $("input").value = wrapped;
      runParse(wrapped, false);
    });

    $("btnCopy").addEventListener("click", () => {
      if (!global.CUR_ROOT) {
        setStatus("nothing parsed yet", false);
        return;
      }
      const out = [];
      global.treeLines(global.CUR_ROOT, 0, out);
      navigator.clipboard.writeText(out.join("\n")).then(
        () => setStatus("tree copied to clipboard", true),
        () => setStatus("clipboard copy failed", false)
      );
    });

    $("tabBtnAsn1").addEventListener("click", () => {
      $("tabBtnAsn1").classList.add("active");
      $("tabBtnCerts").classList.remove("active");
      $("tabAsn1").classList.add("active");
      $("tabCerts").classList.remove("active");
    });

    $("tabBtnCerts").addEventListener("click", () => {
      $("tabBtnCerts").classList.add("active");
      $("tabBtnAsn1").classList.remove("active");
      $("tabCerts").classList.add("active");
      $("tabAsn1").classList.remove("active");
    });

    $("btnXParse").addEventListener("click", () => {
      const t = $("xinput").value;
      if (!t.trim()) {
        setStatusX("nothing to parse", false);
        return;
      }
      runXParse(t, false);
    });

    $("btnXClear").addEventListener("click", () => {
      $("xinput").value = "";
      $("xview").innerHTML = '<div class="hint">Paste a certificate on the left and press Parse.</div>';
      WSSTATE.x509 = { host: "xtree", bytes: null, root: null, sel: null, certs: [] };
      if (MODE === "x509") {
        global.CUR_BYTES = null;
        global.CUR_ROOT = null;
        SELNODE = null;
        global.CERTS = [];
        global.PKCS7HexViewer.clearHighlight();
        $("hex").textContent = "";
        $("hexNote").textContent = "";
        $("details").textContent = "Select a node to inspect it.";
        $("detailPath").textContent = "";
      }
      setStatusX("", true);
    });

    $("btnXSample").addEventListener("click", () => {
      const sampleCert = (global.PKCS7Constants && global.PKCS7Constants.SAMPLE_CERT_B64) || global.SAMPLE_CERT_B64;
      const w = sampleCert.replace(/(.{72})/g, "$1\n");
      $("xinput").value = w;
      runXParse(w, false);
    });

    wireDrop($("inputWrap"), $("input"), (a, b) => runParse(a, b));
    wireDrop($("xinputWrap"), $("xinput"), (a, b) => runXParse(a, b));

    if (/x509/.test(location.hash)) {
      setMode("x509");
      $("btnXSample").click();
    } else if (/demo|sample/.test(location.hash)) {
      $("btnSample").click();
    }

    if (location.hash === "#selftest" && global.PKCS7Selftest) {
      global.PKCS7Selftest.run();
    }
  }

  const appModule = {
    initApp,
    runParse,
    runXParse,
    setMode,
    selectByNode
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = appModule;
  }
  global.PKCS7App = appModule;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initApp);
  } else {
    initApp();
  }
})(typeof window !== 'undefined' ? window : global);
