(function(global) {
  'use strict';

  function decodeOID(b) {
    const AsnErrorCtor = global.AsnError || Error;
    if (!b || b.length === 0) throw new AsnErrorCtor("empty OBJECT IDENTIFIER");
    const out = [];
    let val = 0;
    for (let i = 0; i < b.length; i++) {
      const x = b[i];
      val = val * 128 + (x & 0x7f);
      if (!(x & 0x80)) {
        if (out.length === 0) {
          if (val < 40) out.push(0, val);
          else if (val < 80) out.push(1, val - 40);
          else {
            const a1 = Math.min(2, (val / 40) | 0);
            out.push(a1, val - a1 * 40);
          }
        } else {
          out.push(val);
        }
        val = 0;
      }
    }
    return out.join(".");
  }

  function oidName(dotted) {
    const table = (global.PKCS7Constants && global.PKCS7Constants.OID_NAMES) || global.OID_NAMES || {};
    return table[dotted] || null;
  }

  function d0(node, curBytes) {
    const bytes = curBytes || global.CUR_BYTES;
    const content = bytes.subarray(node.contentStart, node.contentEnd);
    const d = decodeOID(content);
    const nm = oidName(d);
    return d + (nm ? " (" + nm + ")" : "");
  }

  const oidsModule = { decodeOID, oidName, d0 };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = oidsModule;
  }
  global.decodeOID = decodeOID;
  global.oidName = oidName;
  global.d0 = d0;
})(typeof window !== 'undefined' ? window : global);
