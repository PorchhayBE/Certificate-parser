(function(global) {
  'use strict';

  let HEXH = [];
  let HEXA = [];
  let HEXLEN = 0;
  let SELSPANSH = [];
  let SELSPANSA = [];

  function clearHighlight() {
    for (const s of SELSPANSH) s.classList.remove("on");
    for (const s of SELSPANSA) s.classList.remove("on");
    SELSPANSH = [];
    SELSPANSA = [];
  }

  function highlightRange(start, end) {
    clearHighlight();
    const a = Math.max(0, start), b = Math.min(HEXLEN, end);
    for (let i = a; i < b; i++) {
      if (HEXH[i]) {
        HEXH[i].classList.add("on");
        SELSPANSH.push(HEXH[i]);
      }
      if (HEXA[i]) {
        HEXA[i].classList.add("on");
        SELSPANSA.push(HEXA[i]);
      }
    }
    if (SELSPANSH.length) {
      SELSPANSH[0].scrollIntoView({ block: "nearest" });
    }
  }

  function buildHex(bytes) {
    const $ = id => document.getElementById(id);
    const host = $("hex");
    const note = $("hexNote");
    if (!host) return;

    if (!bytes || !bytes.length) {
      host.textContent = "";
      if (note) note.textContent = "";
      HEXH = [];
      HEXA = [];
      HEXLEN = 0;
      clearHighlight();
      return;
    }

    const MAX = 131072;
    HEXLEN = Math.min(bytes.length, MAX);
    if (note) {
      note.textContent = bytes.length + " bytes" + (bytes.length > MAX ? " - showing first " + MAX : "");
    }
    host.textContent = "";
    HEXH = new Array(bytes.length);
    HEXA = new Array(bytes.length);
    const frag = document.createDocumentFragment();

    for (let off = 0; off < HEXLEN; off += 16) {
      const row = document.createElement("div");
      row.className = "hexrow";
      const o = document.createElement("span");
      o.className = "hexoff";
      o.textContent = off.toString(16).padStart(8, "0") + "  ";
      row.appendChild(o);

      for (let i = 0; i < 16; i++) {
        const idx = off + i;
        if (idx < HEXLEN) {
          const hx = document.createElement("span");
          hx.className = "hx";
          hx.textContent = bytes[idx].toString(16).padStart(2, "0");
          HEXH[idx] = hx;
          row.appendChild(hx);
          row.appendChild(document.createTextNode(" "));
        } else {
          row.appendChild(document.createTextNode("   "));
        }
        if (i === 7) row.appendChild(document.createTextNode(" "));
      }

      row.appendChild(document.createTextNode(" "));
      for (let i = 0; i < 16; i++) {
        const idx = off + i;
        if (idx < HEXLEN) {
          const c = bytes[idx];
          const sp = document.createElement("span");
          sp.className = "as";
          sp.textContent = (c >= 32 && c < 127) ? String.fromCharCode(c) : "|";
          HEXA[idx] = sp;
          row.appendChild(sp);
        } else {
          row.appendChild(document.createTextNode(" "));
        }
      }
      frag.appendChild(row);
    }
    host.appendChild(frag);
  }

  const hexViewerModule = {
    clearHighlight,
    highlightRange,
    buildHex,
    getHexLength: () => HEXLEN
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = hexViewerModule;
  }
  global.PKCS7HexViewer = hexViewerModule;
})(typeof window !== 'undefined' ? window : global);
