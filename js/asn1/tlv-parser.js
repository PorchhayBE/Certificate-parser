(function(global) {
  'use strict';

  const NodeClass = global.AsnNode || (typeof require !== 'undefined' ? require('./asn-node').AsnNode : null);
  const ErrorClass = global.AsnError || (typeof require !== 'undefined' ? require('./asn-node').AsnError : null);

  function readTLV(bytes, pos, end, depth) {
    const AsnNodeCtor = global.AsnNode || NodeClass;
    const AsnErrorCtor = global.AsnError || ErrorClass;

    if (depth > 64) throw new AsnErrorCtor("nesting too deep (>64)", pos);
    if (pos + 2 > end) throw new AsnErrorCtor("truncated: need tag+length", pos);
    
    const n = new AsnNodeCtor();
    n.start = pos;
    const b0 = bytes[pos++];
    n.cls = b0 >>> 6;
    n.constructed = !!(b0 & 0x20);
    n.num = b0 & 0x1f;

    if (n.num === 0x1f) {
      let acc = 0, count = 0;
      for (;;) {
        if (pos >= end) throw new AsnErrorCtor("truncated in multi-byte tag", pos);
        const b = bytes[pos++];
        acc = acc * 128 + (b & 0x7f);
        count++;
        if (!(b & 0x80)) break;
        if (count > 5) throw new AsnErrorCtor("multi-byte tag too long", pos);
      }
      n.num = acc;
    }

    if (pos >= end) throw new AsnErrorCtor("truncated before length", pos);
    const lb = bytes[pos++];
    let len = -1;
    if (lb < 0x80) {
      len = lb;
    } else if (lb === 0x80) {
      if (!n.constructed) throw new AsnErrorCtor("indefinite length used with primitive encoding", pos);
      n.indefinite = true;
    } else {
      const cnt = lb & 0x7f;
      if (cnt > 6) throw new AsnErrorCtor("length field too large (" + cnt + " bytes)", pos);
      if (pos + cnt > end) throw new AsnErrorCtor("truncated length field", pos);
      len = 0;
      for (let i = 0; i < cnt; i++) len = len * 256 + bytes[pos + i];
      pos += cnt;
    }

    n.headerLen = pos - n.start;
    n.contentStart = pos;

    if (n.indefinite) {
      let p = pos;
      for (;;) {
        if (p + 2 <= end && bytes[p] === 0 && bytes[p + 1] === 0) {
          n.contentEnd = p;
          p += 2;
          break;
        }
        if (p >= end) throw new AsnErrorCtor("truncated: missing EOC for indefinite length", p);
        const ch = readTLV(bytes, p, end, depth + 1);
        ch.parent = n;
        n.kids.push(ch);
        p = ch.end;
      }
      n.end = p;
    } else {
      n.contentEnd = n.contentStart + len;
      if (n.contentEnd > end) throw new AsnErrorCtor("value length " + len + " exceeds available data", n.contentStart);
      if (n.constructed) {
        let p = n.contentStart;
        while (p < n.contentEnd) {
          const ch = readTLV(bytes, p, n.contentEnd, depth + 1);
          ch.parent = n;
          n.kids.push(ch);
          p = ch.end;
        }
      }
      n.end = n.contentEnd;
    }
    return n;
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { readTLV };
  }
  global.readTLV = readTLV;
})(typeof window !== 'undefined' ? window : global);
