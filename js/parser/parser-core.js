(function(global) {
  'use strict';

  function pathOf(node) {
    const names = [];
    let n = node;
    while (n) {
      names.unshift(n.role || n.tagName);
      n = n.parent;
    }
    return names.join(" > ");
  }

  function treeLines(node, depth, out) {
    const pad = "  ".repeat(depth);
    let s = pad + node.tagName;
    if (node.role) s += "  [" + node.role + "]";
    if (node.preview) s += "  " + node.preview;
    out.push(s);
    for (const c of node.kids) treeLines(c, depth + 1, out);
  }

  function certSummaryLines(sum) {
    const L = [];
    if (sum.subject) L.push("Subject : " + sum.subject);
    if (sum.issuer) L.push("Issuer  : " + sum.issuer);
    if (sum.serial) L.push("Serial  : " + sum.serial);
    if (sum.sigAlg) L.push("Sig alg : " + sum.sigAlg);
    if (sum.keyAlg) L.push("Pub key : " + sum.keyAlg);
    if (sum.notBefore || sum.notAfter) L.push("Validity: " + (sum.notBefore || "?") + "  ->  " + (sum.notAfter || "?"));
    return L;
  }

  function describeNode(node, curBytes, certsList) {
    const bytes = curBytes || global.CUR_BYTES;
    const certs = certsList || global.CERTS || [];
    const L = [];
    L.push("Path: " + pathOf(node));
    L.push("");
    L.push("Offset: " + node.start + " .. " + node.end + "   (header " + node.headerLen + " B" + (node.indefinite ? ", BER indefinite" : "") + ", content " + (node.contentEnd - node.contentStart) + " B)");
    L.push("Tag: " + node.tagClassLabel + " " + (node.constructed ? "constructed" : "primitive") + " #" + node.num + "  " + node.tagName);
    if (node.role) L.push("Role: " + node.role);
    if (bytes) {
      L.push("Header bytes: " + global.toHex(bytes.subarray(node.start, Math.min(node.start + node.headerLen, bytes.length))));
    }
    if (node.preview) L.push("Value: " + node.preview);
    const clen = node.contentEnd - node.contentStart;
    if (clen > 0 && bytes) {
      const c = bytes.subarray(node.contentStart, node.contentEnd);
      if (clen <= 512) L.push("Content (" + clen + " B): " + global.toHex(c));
      else L.push("Content (first 512 of " + clen + " B): " + global.toHex(c, 512));
    }
    const sum = certs.find(s => s.node === node);
    if (sum) {
      L.push("");
      L.push("- Certificate -");
      L.push(...certSummaryLines(sum));
    }
    if (node.attrName) {
      L.push("");
      L.push("Attribute: " + node.attrName);
    }
    return L.join("\n");
  }

  function doParse(input, isBinary) {
    const bytes = isBinary ? input : global.ingest(input);
    global.CUR_BYTES = bytes;
    global.CUR_ROOT = null;
    global.NODECOUNT = 0;
    global.CERTS = [];
    global.CUR_ROOT = global.readTLV(bytes, 0, bytes.length, 0);
    global.annotate(global.CUR_ROOT);
    return {
      root: global.CUR_ROOT,
      count: global.NODECOUNT,
      size: bytes.length,
      certs: global.CERTS,
      bytes: bytes
    };
  }

  const parserCore = {
    pathOf,
    treeLines,
    certSummaryLines,
    describeNode,
    doParse
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = parserCore;
  }
  Object.assign(global, parserCore);
})(typeof window !== 'undefined' ? window : global);
