(function(global) {
  'use strict';

  class AsnError extends Error {
    constructor(msg, offset) {
      super(msg + (offset != null ? " (at byte offset " + offset + ")" : ""));
      this.offset = offset;
    }
  }

  class AsnNode {
    constructor() {
      this.parent = null;
      this.cls = 0;
      this.constructed = false;
      this.num = 0;
      this.start = 0;
      this.headerLen = 0;
      this.contentStart = 0;
      this.contentEnd = 0;
      this.end = 0;
      this.indefinite = false;
      this.kids = [];
      this.role = null;
      this.preview = "";
      this.extName = null;
      this.attrName = null;
      this.open = false;
    }

    get tagName() {
      const utag = (global.PKCS7Constants && global.PKCS7Constants.UTAG) || global.UTAG || {};
      const clsUniv = (global.PKCS7Constants && global.PKCS7Constants.CLS_UNIVERSAL != null)
        ? global.PKCS7Constants.CLS_UNIVERSAL
        : (global.CLS_UNIVERSAL != null ? global.CLS_UNIVERSAL : 0);

      if (this.cls !== clsUniv) {
        return "[" + this.num + "]";
      }
      return utag[this.num] || ("UNIVERSAL-" + this.num);
    }

    get tagClassLabel() {
      return ["UNIVERSAL", "APPLICATION", "CONTEXT", "PRIVATE"][this.cls] || "UNKNOWN";
    }
  }

  const asnNodeModule = { AsnError, AsnNode };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = asnNodeModule;
  }
  global.AsnError = AsnError;
  global.AsnNode = AsnNode;
})(typeof window !== 'undefined' ? window : global);
