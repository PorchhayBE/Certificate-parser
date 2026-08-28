(function(global) {
  'use strict';

  const utf8dec = new TextDecoder("utf-8", { fatal: true });
  const asciiDec = new TextDecoder("ascii");

  function toHex(bytes, max) {
    if (!bytes) return "";
    const lim = max == null ? bytes.length : Math.min(bytes.length, max);
    let s = "";
    for (let i = 0; i < lim; i++) {
      s += bytes[i].toString(16).padStart(2, "0");
    }
    if (lim < bytes.length) s += "...";
    return s;
  }

  function contentBytes(node, customBytes) {
    const bytes = customBytes || global.CUR_BYTES;
    if (!bytes || node.contentStart == null || node.contentEnd == null) return new Uint8Array(0);
    return bytes.subarray(node.contentStart, node.contentEnd);
  }

  function intToBig(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    let v = BigInt("0x" + (hex || "0"));
    if (bytes.length && (bytes[0] & 0x80)) {
      v -= 1n << BigInt(bytes.length * 8);
    }
    return v;
  }

  function intText(bytes) {
    if (!bytes || bytes.length === 0) return "0";
    return intToBig(bytes).toString();
  }

  function bytesToString(bytes) {
    if (!bytes || bytes.length === 0) return "";
    try {
      return utf8dec.decode(bytes);
    } catch (e) {
      return null;
    }
  }

  function fmtDate(y, mo, d, h, mi, s) {
    const dt = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
    if (isNaN(dt)) return "invalid date";
    return dt.toISOString().replace("T", " ").replace(/(\.\d+)?Z$/, " UTC");
  }

  function decodeTime(node, bytes) {
    const raw = asciiDec.decode(bytes);
    let m;
    if (node.num === 23) { // UTCTime
      m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?\s*(Z|[+-]\d{4})?$/.exec(raw);
      if (!m) return raw;
      let yy = parseInt(m[1], 10);
      yy += yy < 50 ? 2000 : 1900;
      return fmtDate(yy, +m[2], +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
    }
    // GeneralizedTime
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:[.,]\d+)?(Z|[+-]\d{4})?$/.exec(raw);
    if (!m) return raw;
    return fmtDate(+m[1], +m[2], +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  }

  function isMostlyPrintable(bytes) {
    if (!bytes || !bytes.length) return false;
    const lim = Math.min(bytes.length, 256);
    for (let i = 0; i < lim; i++) {
      const c = bytes[i];
      if (!(c === 9 || c === 10 || c === 13 || (c >= 32 && c < 126))) return false;
    }
    return true;
  }

  const utils = {
    toHex,
    contentBytes,
    intToBig,
    intText,
    bytesToString,
    fmtDate,
    decodeTime,
    isMostlyPrintable
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = utils;
  }
  Object.assign(global, utils);
})(typeof window !== 'undefined' ? window : global);
