(function(global) {
  'use strict';

  function keyDetails(spki, customBytes) {
    const bytes = customBytes || global.CUR_BYTES;
    if (!bytes) return null;
    try {
      const algOid = global.decodeOID(global.contentBytes(spki.kids[0].kids[0], bytes));
      const bs = spki.kids[1];
      const raw = bytes.subarray(bs.contentStart, bs.contentEnd);
      if (raw.length && raw[0] === 0) {
        const inner = global.readTLV(raw, 1, raw.length, 0);
        if (algOid === "1.2.840.113549.1.1.1" && inner.num === 16 && inner.kids.length >= 2) {
          const nb = inner.kids[0], eb = inner.kids[1];
          let mod = raw.subarray(nb.contentStart, nb.contentEnd);
          if (mod.length && mod[0] === 0) mod = mod.subarray(1);
          const exp = raw.subarray(eb.contentStart, eb.contentEnd);
          const modHex = global.toHex(mod);
          const modShort = modHex.length > 96 ? modHex.slice(0, 96) + "... (" + mod.length + " bytes)" : modHex;
          return [
            "Algorithm: RSA",
            "Key size: " + global.rsaBitsFromSpki(bs) + " bits",
            "Exponent: " + global.intText(exp),
            "Modulus: " + modShort
          ];
        }
        if (algOid === "1.2.840.10045.2.1") {
          const params = spki.kids[0].kids[1];
          const curve = params && params.cls === (global.CLS_UNIVERSAL || 0) && params.num === 6
            ? global.d0(params, bytes)
            : "(explicit parameters)";
          return [
            "Algorithm: EC public key",
            "Curve: " + curve,
            "Public point: " + global.toHex(raw.subarray(1), 96)
          ];
        }
        return ["Public key bytes: " + global.toHex(raw, 96)];
      }
    } catch (e) {}
    return null;
  }

  async function fillFps(bytes) {
    const $ = id => document.getElementById(id);
    let s256 = "unavailable (requires secure context)", s1 = s256;
    try {
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        const [d256, d1] = await Promise.all([
          window.crypto.subtle.digest("SHA-256", bytes),
          window.crypto.subtle.digest("SHA-1", bytes)
        ]);
        const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0").toUpperCase()).join(":");
        s256 = hex(d256);
        s1 = hex(d1);
      }
    } catch (e) {}
    const a = $("fps256"), b = $("fps1");
    if (a) a.textContent = s256;
    if (b) b.textContent = s1;
  }

  function renderCerts(certs, onSelectCertNode, onOpenInX509) {
    const $ = id => document.getElementById(id);
    const host = $("certs");
    const certCount = $("certCount");
    if (!host) return;

    if (certCount) certCount.textContent = certs.length ? "(" + certs.length + ")" : "";
    host.textContent = "";

    if (!certs.length) {
      host.innerHTML = '<div class="hint">No certificates found in this message.</div>';
      return;
    }

    for (const sum of certs) {
      const card = document.createElement("div");
      card.className = "card";

      const h = document.createElement("h3");
      h.textContent = sum.subjectCN || sum.subject || "(certificate)";

      const tb = document.createElement("table");
      const add = (k, v) => {
        if (!v) return;
        const tr = document.createElement("tr");
        const a = document.createElement("td");
        a.textContent = k;
        const b = document.createElement("td");
        b.textContent = v;
        tr.appendChild(a);
        tr.appendChild(b);
        tb.appendChild(tr);
      };

      add("Subject", sum.subject);
      add("Issuer", sum.issuer);
      add("Serial", sum.serial);
      add("Signature", sum.sigAlg);
      add("Public key", sum.keyAlg);
      add("Valid", (sum.notBefore || "?") + " -> " + (sum.notAfter || "?"));

      card.appendChild(h);
      card.appendChild(tb);

      const open = document.createElement("button");
      open.textContent = "Open in X.509 viewer";
      open.style.marginTop = "8px";
      open.addEventListener("click", ev => {
        ev.stopPropagation();
        if (typeof onOpenInX509 === 'function') {
          onOpenInX509(sum);
        }
      });
      card.appendChild(open);

      card.addEventListener("click", () => {
        if (typeof onSelectCertNode === 'function') {
          onSelectCertNode(sum);
        }
      });

      host.appendChild(card);
    }
  }

  function buildXView(sum, root, customBytes) {
    const $ = id => document.getElementById(id);
    const v = $("xview");
    if (!v) return;
    v.textContent = "";

    const curBytes = customBytes || global.CUR_BYTES;
    let serialNode = null, spki = null, versionNode = null;
    const exts = [];

    (function rec(n) {
      if (n.role === "serialNumber" && !serialNode) serialNode = n;
      if (n.role === "subjectPublicKeyInfo" && !spki) spki = n;
      if (n.role === "version [0] EXPLICIT" && !versionNode) versionNode = n;
      if (n._ext) exts.push(n._ext);
      for (const c of n.kids) rec(c);
    })(root);

    const mkPanel = title => {
      const p = document.createElement("div");
      p.className = "panel";
      const h = document.createElement("h3");
      h.textContent = title;
      p.appendChild(h);
      v.appendChild(p);
      return p;
    };

    const mkTable = p => {
      const t = document.createElement("table");
      t.className = "xtable";
      p.appendChild(t);
      return t;
    };

    const addRow = (t, k, val) => {
      const tr = document.createElement("tr");
      const a = document.createElement("td");
      a.textContent = k;
      const b = document.createElement("td");
      if (typeof val === "string") b.textContent = val;
      else b.appendChild(val);
      tr.appendChild(a);
      tr.appendChild(b);
      t.appendChild(tr);
      return b;
    };

    const p1 = mkPanel("Certificate information");
    const t1 = mkTable(p1);
    addRow(t1, "Version", versionNode && versionNode.kids[0] ? versionNode.kids[0].preview : "v1");
    if (sum.serial) addRow(t1, "Serial number", serialNode ? sum.serial + "  (0x" + global.toHex(global.contentBytes(serialNode, curBytes)) + ")" : sum.serial);
    if (sum.sigAlg) addRow(t1, "Signature algorithm", sum.sigAlg);
    if (sum.subject) addRow(t1, "Subject", sum.subject);
    if (sum.issuer) addRow(t1, "Issuer", sum.issuer);
    if (sum.notBefore) addRow(t1, "Valid from", sum.notBefore);
    if (sum.notAfter) addRow(t1, "Valid to", sum.notAfter);

    const p2 = mkPanel("Public key");
    const t2 = mkTable(p2);
    if (sum.keyAlg) addRow(t2, "Summary", sum.keyAlg);
    const kd = spki ? keyDetails(spki, curBytes) : null;
    if (kd) {
      for (const line of kd) {
        const i = line.indexOf(": ");
        addRow(t2, line.slice(0, i), line.slice(i + 2));
      }
    }

    const p3 = mkPanel("Fingerprints (SHA over certificate DER)");
    const t3 = mkTable(p3);
    const b256 = addRow(t3, "SHA-256", "computing...");
    b256.className = "fp";
    b256.id = "fps256";
    const b1 = addRow(t3, "SHA-1", "computing...");
    b1.className = "fp";
    b1.id = "fps1";
    fillFps(curBytes);

    if (exts.length) {
      const p4 = mkPanel("Extensions (" + exts.length + ")");
      const t4 = mkTable(p4);
      for (const e of exts) {
        const tr = document.createElement("tr");
        const a = document.createElement("td");
        a.textContent = e.name + (e.critical ? " (critical)" : "");
        const b = document.createElement("td");
        b.textContent = e.decoded || "";
        tr.appendChild(a);
        tr.appendChild(b);
        t4.appendChild(tr);
      }
    }

    const p5 = mkPanel("ASN.1 structure - click a node for details + hex below");
    const tv = document.createElement("div");
    tv.className = "tree";
    tv.id = "xtree";
    p5.appendChild(tv);
  }

  const certViewModule = {
    keyDetails,
    fillFps,
    renderCerts,
    buildXView
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = certViewModule;
  }
  global.PKCS7CertView = certViewModule;
})(typeof window !== 'undefined' ? window : global);
