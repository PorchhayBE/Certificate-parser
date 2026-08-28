(function(global) {
  'use strict';

  global.NODECOUNT = 0;
  global.CERTS = [];
  global.CUR_BYTES = null;
  global.CUR_ROOT = null;

  function previewOf(node) {
    const curBytes = global.CUR_BYTES;
    const c = (curBytes && node.contentStart < node.contentEnd)
      ? curBytes.subarray(node.contentStart, node.contentEnd)
      : new Uint8Array(0);

    const clsUniv = global.CLS_UNIVERSAL || 0;
    const strTags = (global.PKCS7Constants && global.PKCS7Constants.STR_TAGS) || global.STR_TAGS || new Set();

    switch (node.cls) {
      case clsUniv:
        switch (node.num) {
          case 1:
            return c.length ? (c[0] ? "TRUE" : "FALSE") : "";
          case 2:
          case 10:
            return global.intText(c);
          case 3: {
            if (!c.length) return "";
            return ((c.length - 1) * 8 - c[0]) + " bits";
          }
          case 4: {
            if (global.isMostlyPrintable(c)) {
              const t = global.bytesToString(c);
              if (t != null) return JSON.stringify(t.length > 96 ? t.slice(0, 96) + "..." : t);
            }
            return "<" + c.length + " bytes>";
          }
          case 5:
            return "";
          case 6: {
            const d = global.decodeOID(c);
            const nm = global.oidName(d);
            return d + (nm ? " (" + nm + ")" : "");
          }
          case 23:
          case 24:
            return global.decodeTime(node, c);
          default:
            if (strTags.has(node.num)) {
              const t = global.bytesToString(c);
              return t != null ? JSON.stringify(t.length > 96 ? t.slice(0, 96) + "..." : t) : "<" + c.length + " bytes>";
            }
            return c.length ? "<" + c.length + " bytes>" : "";
        }
      default:
        return c.length ? "<" + c.length + " bytes>" : "";
    }
  }

  function walk(node) {
    global.NODECOUNT++;
    node.preview = previewOf(node);
    for (const c of node.kids) walk(c);
  }

  function mark(node, role, preview) {
    if (role) node.role = role;
    walk(node);
    if (preview != null) node.preview = preview;
  }

  function isKnownContentType(oidStr) {
    return /^1\.2\.840\.113549\.1\.7\.\d+$/.test(oidStr) ||
      /^1\.2\.840\.113549\.1\.9\.16\.1\.\d+$/.test(oidStr);
  }

  function looksLikeContentInfo(node) {
    const clsUniv = global.CLS_UNIVERSAL || 0;
    const clsCtx = global.CLS_CONTEXT || 2;
    if (!(node.cls === clsUniv && node.num === 16 && node.kids.length >= 2 && node.kids.length <= 2)) return false;
    const [oid, ctx] = node.kids;
    if (!(oid.cls === clsUniv && oid.num === 6)) return false;
    if (!(ctx.cls === clsCtx && ctx.num === 0 && ctx.constructed && ctx.kids.length === 1)) return false;
    let d;
    try {
      d = global.decodeOID(global.contentBytes(oid));
    } catch (e) {
      return false;
    }
    return isKnownContentType(d);
  }

  const CONTENT_DISPATCH = {
    "signedData": (...args) => global.labelSignedData(...args),
    "envelopedData": (...args) => global.labelEnvelopedData(...args),
    "signedAndEnvelopedData": (...args) => global.labelSignedAndEnveloped(...args),
    "digestedData": (...args) => global.labelDigestedData(...args),
    "encryptedData": (...args) => global.labelEncryptedData(...args)
  };

  function annotate(node) {
    global.NODECOUNT++;
    if (looksLikeContentInfo(node)) {
      node.role = "ContentInfo";
      const [oid, ctx] = node.kids;
      const d = global.decodeOID(global.contentBytes(oid));
      const nm = global.oidName(d) || d;
      global.mark(oid, "contentType", nm);
      global.mark(ctx, "content [0] EXPLICIT");
      const inner = ctx.kids[0];
      if (inner) {
        const fn = CONTENT_DISPATCH[nm];
        if (fn) fn(inner);
        else annotate(inner);
      }
      return;
    }
    if (global.looksLikeCertificate(node)) {
      global.labelCertificate(node);
      return;
    }
    node.preview = previewOf(node);
    for (const c of node.kids) annotate(c);
  }

  const annotator = {
    previewOf,
    walk,
    mark,
    isKnownContentType,
    looksLikeContentInfo,
    CONTENT_DISPATCH,
    annotate
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = annotator;
  }
  Object.assign(global, annotator);
})(typeof window !== 'undefined' ? window : global);
