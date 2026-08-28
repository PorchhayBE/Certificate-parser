(function(global) {
  'use strict';

  const asciiDec = new TextDecoder("ascii");

  function nameToString(node) {
    const parts = [];
    const clsUniv = global.CLS_UNIVERSAL || 0;
    for (const rdn of node.kids || []) {
      for (const atv of rdn.kids || []) {
        const t = atv.kids[0], v = atv.kids[1];
        let nm = null, val = "";
        if (t && t.cls === clsUniv && t.num === 6) {
          const d = global.decodeOID(global.contentBytes(t));
          nm = global.oidName(d) || d;
        }
        if (v) {
          const b = global.contentBytes(v);
          val = global.isMostlyPrintable(b) && global.bytesToString(b) != null
            ? global.bytesToString(b)
            : global.toHex(b, 32);
        }
        if (nm) parts.push(nm + "=" + val);
      }
    }
    return parts.join(", ");
  }

  function cnFromName(nameNode) {
    for (const rdn of nameNode.kids || []) {
      for (const atv of rdn.kids || []) {
        const t = atv.kids[0], v = atv.kids[1];
        if (t && t.num === 6 && global.decodeOID(global.contentBytes(t)) === "2.5.4.3" && v) {
          const b = global.contentBytes(v);
          if (global.isMostlyPrintable(b)) {
            const s = global.bytesToString(b);
            if (s) return s;
          }
        }
      }
    }
    return null;
  }

  function rsaBitsFromSpki(bitstrNode) {
    try {
      const bs = global.CUR_BYTES.subarray(bitstrNode.contentStart, bitstrNode.contentEnd);
      if (bs.length < 2 || bs[0] !== 0) return null;
      const seq = global.readTLV(bs, 1, bs.length, 0);
      if (seq.num !== 16 || !seq.kids.length || seq.kids[0].num !== 2) return null;
      const nb = seq.kids[0];
      const mod = bs.subarray(nb.contentStart, nb.contentEnd);
      let bits = mod.length * 8, lz = 0;
      while (lz < mod.length && mod[lz] === 0) {
        lz++;
        bits -= 8;
      }
      if (lz < mod.length) {
        let m = mod[lz];
        while (!(m & 0x80)) {
          m <<= 1;
          bits--;
        }
      }
      return bits > 0 ? bits : null;
    } catch (e) {
      return null;
    }
  }

  function decodeExtValue(oid, inner) {
    switch (oid) {
      case "2.5.29.19": { // BasicConstraints
        let s = "CA:" + (inner.kids[0] && global.contentBytes(inner.kids[0]).length && global.contentBytes(inner.kids[0])[0] ? "TRUE" : "FALSE");
        if (inner.kids[1]) s += ", pathlen=" + global.intText(global.contentBytes(inner.kids[1]));
        return s;
      }
      case "2.5.29.15": { // KeyUsage
        const b = global.contentBytes(inner);
        if (b.length < 2) return "";
        const names = [
          "digitalSignature", "nonRepudiation", "keyEncipherment",
          "dataEncipherment", "keyAgreement", "keyCertSign",
          "cRLSign", "encipherOnly", "decipherOnly"
        ];
        const bits = [];
        for (let i = 0; i < (b.length - 1) * 8; i++) {
          if (b[1 + (i >> 3)] & (0x80 >> (i & 7))) {
            bits.push(names[i] || ("bit " + i));
          }
        }
        return bits.join(", ") || "(empty)";
      }
      case "2.5.29.17": { // SubjectAltName
        const parts = [];
        for (const g of inner.kids) {
          const cb = global.contentBytes(g);
          if (g.num === 2) parts.push("DNS: " + asciiDec.decode(cb));
          else if (g.num === 1) parts.push("email: " + asciiDec.decode(cb));
          else if (g.num === 7) parts.push("IP: " + [...cb].join("."));
          else if (g.num === 4 && g.kids[0]) parts.push("DirName: " + nameToString(g.kids[0]));
          else if (g.num === 6) parts.push("URI: " + asciiDec.decode(cb));
          else parts.push("[tag " + g.num + "] " + global.toHex(cb, 24));
        }
        return parts.join(",  ");
      }
      case "2.5.29.14": // SubjectKeyIdentifier
        return global.toHex(global.contentBytes(inner));
      case "2.5.29.37": // ExtendedKeyUsage
        return inner.kids.map(k => {
          try {
            return global.d0(k);
          } catch (e) {
            return "?";
          }
        }).join(",  ");
      case "2.5.29.35": { // AuthorityKeyIdentifier
        const kid0 = inner.kids[0];
        return kid0 ? "keyid: " + global.toHex(global.contentBytes(kid0)) : "(present)";
      }
      case "2.5.29.31": { // CRLDistributionPoints
        const parts = [];
        for (const dp of inner.kids) {
          for (const gn of dp.kids) {
            for (const u of gn.kids) {
              if (u.num === 6) parts.push("URI: " + asciiDec.decode(global.contentBytes(u)));
            }
          }
        }
        return parts.join(",  ") || "(present)";
      }
      default:
        return null;
    }
  }

  function labelExtension(ext) {
    ext.role = "Extension";
    const k = ext.kids;
    const clsUniv = global.CLS_UNIVERSAL || 0;
    let ename = null, eoid = null, crit = false;

    if (k.length && k[0].cls === clsUniv && k[0].num === 6) {
      const d = global.decodeOID(global.contentBytes(k[0]));
      eoid = d;
      ename = global.oidName(d) || d;
      global.mark(k[0], "extnID", d + (global.oidName(d) ? " (" + global.oidName(d) + ")" : ""));
    } else if (k.length) {
      global.walk(k[0]);
    }

    let vi = 1;
    if (k[vi] && k[vi].cls === clsUniv && k[vi].num === 1) {
      crit = global.contentBytes(k[vi])[0] !== 0;
      global.mark(k[vi], "critical", crit ? "TRUE" : "FALSE");
      vi++;
    }

    if (k[vi] && k[vi].cls === clsUniv && k[vi].num === 4) {
      k[vi].role = "extnValue";
      k[vi].extName = ename;
      global.walk(k[vi]);
      try {
        const inner = global.readTLV(global.CUR_BYTES, k[vi].contentStart, k[vi].contentEnd, 0);
        const dec = decodeExtValue(eoid, inner);
        k[vi]._ext = {
          name: ename || eoid || "?",
          critical: crit,
          decoded: dec != null ? dec : (inner.tagName + " " + global.previewOf(inner))
        };
        k[vi].preview = (ename ? ename + ": " : "") + inner.tagName + " " + global.previewOf(inner);
      } catch (e) {}
    }
  }

  function labelCertificate(node) {
    node.role = "Certificate";
    const k = node.kids;
    const tbs = k[0], sig = k[1], sigv = k[2];
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;

    if (sig) global.labelAlgorithm(sig, "signatureAlgorithm");
    if (sigv) global.mark(sigv, "signatureValue");

    const sum = { node };
    if (tbs) {
      tbs.role = "TBSCertificate";
      const f = tbs.kids;
      let i = 0;
      if (f[i] && f[i].cls === clsCtx && f[i].num === 0 && f[i].constructed) {
        f[i].role = "version [0] EXPLICIT";
        const iv = f[i].kids[0];
        if (iv && iv.cls === clsUniv && iv.num === 2) {
          global.mark(iv, "version", "v" + (global.intToBig(global.contentBytes(iv)) + 1n).toString());
        } else if (iv) {
          global.walk(iv);
        }
        i++;
      }
      if (f[i] && f[i].cls === clsUniv && f[i].num === 2) {
        global.mark(f[i], "serialNumber", global.intText(global.contentBytes(f[i])));
        sum.serial = f[i].preview;
        i++;
      }
      if (f[i] && f[i].cls === clsUniv && f[i].num === 16) {
        global.labelAlgorithm(f[i], "tbsSignature");
        sum.sigAlg = f[i].kids[0] ? f[i].kids[0].preview : null;
        i++;
      }
      if (f[i] && f[i].cls === clsUniv && f[i].num === 16) {
        f[i].role = "issuer";
        global.labelName(f[i]);
        sum.issuer = cnFromName(f[i]) || f[i].preview;
        i++;
      }
      if (f[i] && f[i].cls === clsUniv && f[i].num === 16 && f[i].kids.length === 2) {
        const v = f[i];
        v.role = "validity";
        if (v.kids[0]) {
          global.mark(v.kids[0], "notBefore", global.decodeTime(v.kids[0], global.contentBytes(v.kids[0])));
          sum.notBefore = v.kids[0].preview;
        }
        if (v.kids[1]) {
          global.mark(v.kids[1], "notAfter", global.decodeTime(v.kids[1], global.contentBytes(v.kids[1])));
          sum.notAfter = v.kids[1].preview;
        }
        i++;
      }
      if (f[i] && f[i].cls === clsUniv && f[i].num === 16) {
        f[i].role = "subject";
        global.labelName(f[i]);
        sum.subject = cnFromName(f[i]) || f[i].preview;
        i++;
      }
      if (f[i] && f[i].cls === clsUniv && f[i].num === 16 && f[i].kids.length === 2 && f[i].kids[0].num === 16 && f[i].kids[1].num === 3) {
        const spki = f[i];
        spki.role = "subjectPublicKeyInfo";
        global.labelAlgorithm(spki.kids[0], "publicKey");
        global.mark(spki.kids[1], "subjectPublicKey");
        const bits = rsaBitsFromSpki(spki.kids[1]);
        sum.keyAlg = (spki.kids[0].kids[0] ? spki.kids[0].kids[0].preview : null) + (bits ? (" " + bits + " bits") : "");
        i++;
      }
      for (; i < f.length; i++) {
        const c = f[i];
        if (c.cls === clsCtx && c.num === 3 && c.constructed) {
          c.role = "extensions [3] EXPLICIT";
          const inner = c.kids[0];
          if (inner && inner.cls === clsUniv && inner.num === 16) {
            inner.role = "extensions";
            for (const e of inner.kids) labelExtension(e);
          } else {
            global.walk(c);
          }
        } else {
          global.walk(c);
        }
      }
    }
    if (global.CERTS) {
      global.CERTS.push(sum);
    }
  }

  function looksLikeCertificate(node) {
    const clsUniv = global.CLS_UNIVERSAL || 0;
    if (!(node.cls === clsUniv && node.num === 16 && node.kids.length === 3)) return false;
    const [tbs, sig, sigv] = node.kids;
    return !!(tbs && tbs.num === 16 && tbs.constructed && sig && sig.num === 16 && sigv && sigv.num === 3 &&
      tbs.kids.length >= 6 &&
      tbs.kids.some(x => x.num === 16 && x.kids.length === 2 && x.kids[0].num === 16 && x.kids[1].num === 3));
  }

  const x509Labels = {
    nameToString,
    cnFromName,
    rsaBitsFromSpki,
    decodeExtValue,
    labelExtension,
    labelCertificate,
    looksLikeCertificate
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = x509Labels;
  }
  Object.assign(global, x509Labels);
})(typeof window !== 'undefined' ? window : global);
