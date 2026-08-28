(function(global) {
  'use strict';

  function labelAlgorithm(node, hint) {
    node.role = hint ? ("AlgorithmIdentifier (" + hint + ")") : "AlgorithmIdentifier";
    const k = node.kids;
    for (const c of k) {
      global.walk(c);
      if (c.cls === (global.CLS_UNIVERSAL || 0) && c.num === 6) c.role = "algorithm";
      else c.role = "parameters";
    }
  }

  function labelName(node) {
    node.role = "Name";
    const parts = [];
    for (const rdn of node.kids) {
      rdn.role = "RDN";
      for (const atv of rdn.kids) {
        atv.role = "AttributeTypeAndValue";
        const t = atv.kids[0], v = atv.kids[1];
        let nm = null, val = "";
        if (t && t.cls === (global.CLS_UNIVERSAL || 0) && t.num === 6) {
          const d = global.decodeOID(global.contentBytes(t));
          nm = global.oidName(d) || d;
          global.mark(t, "type");
        }
        if (v) {
          global.walk(v);
          v.role = "value";
          const cb = global.contentBytes(v);
          val = global.isMostlyPrintable(cb) && global.bytesToString(cb) != null
            ? global.bytesToString(cb)
            : global.toHex(cb, 32);
        }
        if (nm) parts.push(nm + "=" + val);
      }
    }
    node.preview = parts.join(", ");
  }

  function labelAttr(attr) {
    const k = attr.kids;
    if (!k.length) {
      global.walk(attr);
      return;
    }
    attr.role = "Attribute";
    let aname = null;
    if (k[0] && k[0].cls === (global.CLS_UNIVERSAL || 0) && k[0].num === 6) {
      const d = global.decodeOID(global.contentBytes(k[0]));
      const attrNames = (global.PKCS7Constants && global.PKCS7Constants.ATTR_NAMES) || global.ATTR_NAMES || {};
      aname = attrNames[d] || global.oidName(d) || d;
    }
    attr.attrName = aname;
    if (k[0]) {
      const d = global.decodeOID(global.contentBytes(k[0]));
      global.mark(k[0], "attrType", d + " (" + aname + ")");
    }
    if (k[1]) {
      k[1].role = aname || "attrValues";
      global.walk(k[1]);
    }
  }

  function labelAttrsSet(setNode, label) {
    setNode.role = label;
    for (const a of setNode.kids) labelAttr(a);
  }

  function labelIssuerSerial(seq) {
    seq.role = "IssuerAndSerialNumber";
    const k = seq.kids;
    if (k[0]) {
      k[0].role = "issuer";
      labelName(k[0]);
    }
    if (k[1]) {
      global.mark(k[1], "serialNumber", global.intText(global.contentBytes(k[1])));
    }
  }

  function labelSid(sid) {
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;
    if (sid.cls === clsUniv && sid.num === 16) {
      sid.role = "sid";
      labelIssuerSerial(sid);
      sid.role = "sid: IssuerAndSerialNumber";
    } else if (sid.cls === clsCtx && sid.constructed) {
      sid.role = "sid: SubjectKeyIdentifier [0]";
      for (const c of sid.kids) global.walk(c);
    } else {
      global.walk(sid);
    }
  }

  function looksLikeAttrs(node) {
    const clsUniv = global.CLS_UNIVERSAL || 0;
    return node.kids.every(a => a.cls === clsUniv && a.num === 16 && a.kids.length >= 2 && a.kids[0].num === 6);
  }

  function labelSignerInfo(si) {
    si.role = "SignerInfo";
    const k = si.kids;
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;
    let i = 0;
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 2) {
      global.mark(k[i], "version", "v" + global.intText(global.contentBytes(k[i])));
      i++;
    }
    if (i < k.length) {
      labelSid(k[i]);
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 16) {
      labelAlgorithm(k[i], "digest");
      i++;
    }
    if (i < k.length && k[i].cls === clsCtx && k[i].constructed && looksLikeAttrs(k[i])) {
      labelAttrsSet(k[i], "signedAttrs [0]");
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 16) {
      labelAlgorithm(k[i], "signature");
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 4) {
      global.mark(k[i], "signature");
      i++;
    }
    if (i < k.length && k[i].cls === clsCtx && k[i].constructed && looksLikeAttrs(k[i])) {
      labelAttrsSet(k[i], "unsignedAttrs [1]");
      i++;
    }
    for (; i < k.length; i++) global.walk(k[i]);
  }

  function labelEncap(enc) {
    enc.role = "encapContentInfo";
    const k = enc.kids;
    if (k.length) global.mark(k[0], "eContentType", global.d0(k[0]));
    if (k[1]) {
      k[1].role = "eContent [0] EXPLICIT";
      for (const c of k[1].kids) global.walk(c);
    }
  }

  function labelECI(eci) {
    eci.role = "encryptedContentInfo";
    const k = eci.kids;
    const clsUniv = global.CLS_UNIVERSAL || 0;
    let i = 0;
    if (i < k.length) {
      global.mark(k[i], "contentType", global.d0(k[i]));
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 16) {
      labelAlgorithm(k[i], "contentEncryption");
      i++;
    }
    if (i < k.length) {
      global.mark(k[i], "encryptedContent [0] IMPLICIT");
      i++;
    }
    for (; i < k.length; i++) global.walk(k[i]);
  }

  function labelRecipientInfos(setNode) {
    setNode.role = "recipientInfos";
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;
    for (const ri of setNode.kids) {
      ri.role = "RecipientInfo";
      const k = ri.kids;
      let i = 0;
      if (i < k.length && k[i].cls === clsUniv && k[i].num === 2) {
        global.mark(k[i], "version", "v" + global.intText(global.contentBytes(k[i])));
        i++;
      }
      if (i < k.length) {
        const rid = k[i];
        if (rid.cls === clsUniv && rid.num === 16) {
          rid.role = "rid: IssuerAndSerialNumber";
          labelIssuerSerial(rid);
          rid.role = "rid: IssuerAndSerialNumber";
        } else if (rid.cls === clsCtx && rid.constructed) {
          rid.role = "rid: SubjectKeyIdentifier [0]";
          for (const c of rid.kids) global.walk(c);
        } else {
          global.walk(rid);
        }
        i++;
      }
      if (i < k.length && k[i].cls === clsUniv && k[i].num === 16) {
        labelAlgorithm(k[i], "keyEncryption");
        i++;
      }
      if (i < k.length && k[i].cls === clsUniv && k[i].num === 4) {
        global.mark(k[i], "encryptedKey");
        i++;
      }
      for (; i < k.length; i++) global.walk(k[i]);
    }
  }

  function labelSignedData(n) {
    n.role = "signedData";
    const k = n.kids;
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;
    let i = 0;
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 2) {
      global.mark(k[i], "version", "v" + global.intText(global.contentBytes(k[i])));
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 17) {
      k[i].role = "digestAlgorithms";
      for (const a of k[i].kids) labelAlgorithm(a, "digest");
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 16) {
      labelEncap(k[i]);
      i++;
    }
    for (; i < k.length; i++) {
      const c = k[i];
      if (c.cls === clsCtx && c.num === 0 && c.constructed) {
        c.role = "certificates [0]";
        for (const cc of c.kids) global.annotate(cc);
      } else if (c.cls === clsCtx && c.num === 1 && c.constructed) {
        c.role = "crls [1]";
        for (const cc of c.kids) global.annotate(cc);
      } else if (c.cls === clsUniv && c.num === 17) {
        c.role = "signerInfos";
        for (const si of c.kids) labelSignerInfo(si);
      } else {
        global.walk(c);
      }
    }
  }

  function labelEnvelopedData(n) {
    n.role = "envelopedData";
    const k = n.kids;
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;
    let i = 0;
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 2) {
      global.mark(k[i], "version", "v" + global.intText(global.contentBytes(k[i])));
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 17) {
      labelRecipientInfos(k[i]);
      i++;
    }
    for (; i < k.length; i++) {
      const c = k[i];
      if (c.cls === clsUniv && c.num === 16 && c.kids.length && c.kids[0].cls === clsUniv && c.kids[0].num === 6) {
        labelECI(c);
      } else if (c.cls === clsCtx && c.num === 1) {
        labelAttrsSet(c, "unprotectedAttrs [1]");
      } else {
        global.walk(c);
      }
    }
  }

  function labelSignedAndEnveloped(n) {
    n.role = "signedAndEnvelopedData";
    const k = n.kids;
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;
    let i = 0;
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 2) {
      global.mark(k[i], "version", "v" + global.intText(global.contentBytes(k[i])));
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 17) {
      labelRecipientInfos(k[i]);
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 17) {
      k[i].role = "digestAlgorithms";
      for (const a of k[i].kids) labelAlgorithm(a, "digest");
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 16) {
      labelEncap(k[i]);
      i++;
    }
    for (; i < k.length; i++) {
      const c = k[i];
      if (c.cls === clsCtx && c.num === 0) {
        c.role = "certificates [0]";
        for (const cc of c.kids) global.annotate(cc);
      } else if (c.cls === clsUniv && c.num === 17) {
        c.role = "signerInfos";
        for (const si of c.kids) labelSignerInfo(si);
      } else {
        global.walk(c);
      }
    }
  }

  function labelDigestedData(n) {
    n.role = "digestedData";
    const k = n.kids;
    const clsUniv = global.CLS_UNIVERSAL || 0;
    let i = 0;
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 2) {
      global.mark(k[i], "version", "v" + global.intText(global.contentBytes(k[i])));
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 16) {
      labelAlgorithm(k[i], "digest");
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 16) {
      labelEncap(k[i]);
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 4) {
      global.mark(k[i], "digest");
      i++;
    }
    for (; i < k.length; i++) global.walk(k[i]);
  }

  function labelEncryptedData(n) {
    n.role = "encryptedData";
    const k = n.kids;
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;
    let i = 0;
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 2) {
      global.mark(k[i], "version", "v" + global.intText(global.contentBytes(k[i])));
      i++;
    }
    if (i < k.length && k[i].cls === clsUniv && k[i].num === 16 && k[i].kids.length && k[i].kids[0].num === 6) {
      labelECI(k[i]);
      i++;
    }
    if (i < k.length && k[i].cls === clsCtx && k[i].num === 1) {
      labelAttrsSet(k[i], "unprotectedAttrs [1]");
      i++;
    }
    for (; i < k.length; i++) global.walk(k[i]);
  }

  const cmsLabels = {
    labelAlgorithm,
    labelName,
    labelAttr,
    labelAttrsSet,
    labelIssuerSerial,
    labelSid,
    looksLikeAttrs,
    labelSignerInfo,
    labelEncap,
    labelECI,
    labelRecipientInfos,
    labelSignedData,
    labelEnvelopedData,
    labelSignedAndEnveloped,
    labelDigestedData,
    labelEncryptedData
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = cmsLabels;
  }
  Object.assign(global, cmsLabels);
})(typeof window !== 'undefined' ? window : global);
