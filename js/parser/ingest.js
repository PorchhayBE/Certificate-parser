(function(global) {
  'use strict';

  function b64ToBytes(str) {
    const clean = str.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) throw new Error("not valid Base64");
    const core = clean.replace(/=+$/, "");
    const padded = core + "=".repeat((4 - core.length % 4) % 4);
    
    // Support browser atob and Node.js Buffer
    if (typeof atob === 'function') {
      const bin = atob(padded);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } else if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(padded, 'base64'));
    } else {
      throw new Error("Base64 decoder not available in this environment");
    }
  }

  function extractPemBlocks(text) {
    const re = /-----BEGIN ([^-][A-Za-z0-9 ]*?)-----([\s\S]*?)-----END \1-----/g;
    const chunks = [];
    let m, found = false;
    while ((m = re.exec(text))) {
      found = true;
      chunks.push(b64ToBytes(m[2]));
    }
    if (!found) throw new Error("PEM markers found but no decodable blocks");
    return chunks;
  }

  function plausibleTagByte(b) {
    return (b & 0xC0) === 0 || (b >= 0xA0 && b <= 0xBF);
  }

  function hexToBytes(text) {
    const t = text.replace(/[\s,:]/g, "");
    if (!/^[0-9a-fA-F]+$/.test(t) || t.length % 2 !== 0) throw new Error("not valid hex");
    const out = new Uint8Array(t.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(t.substr(i * 2, 2), 16);
    }
    return out;
  }

  function concatBytes(arrs) {
    let total = 0;
    for (const a of arrs) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }

  function ingest(text) {
    const t = text.trim();
    if (!t) throw new Error("input is empty");
    if (t.includes("-----BEGIN")) return concatBytes(extractPemBlocks(t));
    if (/^[0-9a-fA-F\s,:]+$/.test(t)) {
      const probe = t.replace(/[\s,:]/g, "");
      if (probe.length % 2 === 0 && probe.length >= 2 && plausibleTagByte(parseInt(probe.substr(0, 2), 16))) {
        return hexToBytes(t);
      }
    }
    return b64ToBytes(t);
  }

  const ingestModule = {
    b64ToBytes,
    extractPemBlocks,
    plausibleTagByte,
    hexToBytes,
    concatBytes,
    ingest
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = ingestModule;
  }
  Object.assign(global, ingestModule);
})(typeof window !== 'undefined' ? window : global);
