'use strict';

const assert = require('assert');

// Set up global environment for modules
const globalContext = global;

require('../js/constants.js');
require('../js/asn1/asn-node.js');
require('../js/asn1/tlv-parser.js');
require('../js/asn1/oids.js');
require('../js/asn1/utils.js');
require('../js/pkcs7/cms-labels.js');
require('../js/pkcs7/x509-labels.js');
require('../js/pkcs7/annotate.js');
require('../js/parser/ingest.js');
require('../js/parser/parser-core.js');

console.log("=== Running PKCS#7 & X.509 Parser Tests ===");

// Test 1: Ingest Base64
{
  console.log("Test 1: Ingest Base64 / PEM / Hex");
  const b64 = global.SAMPLE_B64;
  const bytesFromB64 = global.ingest(b64);
  assert.ok(bytesFromB64 instanceof Uint8Array, "Must return Uint8Array");
  assert.ok(bytesFromB64.length > 0, "Must not be empty");

  const pem = `-----BEGIN PKCS7-----\n${b64}\n-----END PKCS7-----`;
  const bytesFromPem = global.ingest(pem);
  assert.strictEqual(bytesFromPem.length, bytesFromB64.length, "PEM payload should match Base64 length");

  const hex = "3006020101020102"; // SEQUENCE { INTEGER 1, INTEGER 2 }
  const bytesFromHex = global.ingest(hex);
  assert.strictEqual(bytesFromHex.length, 8, "Hex should decode to 8 bytes");
  console.log("  [PASS] Ingestion tests passed.");
}

// Test 2: Parse Sample PKCS#7 SignedData
{
  console.log("Test 2: Parse Sample PKCS#7 SignedData");
  const res = global.doParse(global.SAMPLE_B64, false);
  assert.ok(res.root, "Root node must be present");
  assert.strictEqual(res.root.role, "ContentInfo", "Root role should be ContentInfo");
  assert.ok(res.count > 30, `Expected >30 nodes, got ${res.count}`);
  assert.strictEqual(res.certs.length, 1, "Should detect 1 embedded certificate");

  const cert = res.certs[0];
  assert.strictEqual(cert.subject, "PKCS7 Demo", "Cert subject matches");
  assert.strictEqual(cert.issuer, "PKCS7 Demo", "Cert issuer matches");
  assert.ok(cert.serial, "Cert serial should be present");
  assert.ok(cert.keyAlg.includes("2048 bits"), `Expected 2048 bits RSA key, got: ${cert.keyAlg}`);

  const lines = [];
  global.treeLines(res.root, 0, lines);
  assert.ok(lines.length > 30, "Generated tree lines");
  console.log(`  [PASS] PKCS#7 parsed successfully: ${res.count} nodes, ${res.certs.length} certs.`);
}

// Test 3: Parse Sample X.509 Certificate
{
  console.log("Test 3: Parse Standalone X.509 Certificate");
  const res = global.doParse(global.SAMPLE_CERT_B64, false);
  assert.strictEqual(res.root.role, "Certificate", "Root role should be Certificate");
  assert.strictEqual(res.certs.length, 1, "Should have 1 certificate summary");

  const cert = res.certs[0];
  assert.strictEqual(cert.subject, "X509 Viewer Demo");
  assert.strictEqual(cert.issuer, "X509 Viewer Demo");
  assert.ok(cert.keyAlg.includes("2048 bits"), `Public key: ${cert.keyAlg}`);

  const desc = global.describeNode(res.root);
  assert.ok(desc.includes("Path: Certificate"), "Describe node contains path");
  console.log("  [PASS] Standalone X.509 certificate parsed successfully.");
}

// Test 4: OID Decoder & Error handling
{
  console.log("Test 4: OID Decoder & Error Handling");
  // RSA Encryption OID: 1.2.840.113549.1.1.1 -> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
  const rsaOidBytes = new Uint8Array([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]);
  const decodedOid = global.decodeOID(rsaOidBytes);
  assert.strictEqual(decodedOid, "1.2.840.113549.1.1.1", "Decodes RSA OID accurately");
  assert.strictEqual(global.oidName(decodedOid), "rsaEncryption", "Lookups OID name");

  // Error case: truncated data
  assert.throws(() => {
    global.readTLV(new Uint8Array([0x30, 0x82, 0x01]), 0, 3, 0);
  }, /truncated/i, "Throws on truncated TLV");
  console.log("  [PASS] OID decoder and error handling verified.");
}

console.log("\nALL TESTS PASSED SUCCESSFULLY! \u2714\n");
