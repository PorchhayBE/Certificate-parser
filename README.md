# PKCS#7 / CMS ASN.1 Parser & X.509 Certificate Viewer

A fast, client-side, dependency-free PKCS#7 (CMS RFC 5652) ASN.1 parser and X.509 certificate viewer.

## Features

- **PKCS#7 / CMS Parsing**: Full support for `SignedData`, `EnvelopedData`, `SignedAndEnvelopedData`, `DigestedData`, and `EncryptedData`.
- **X.509 Certificate Viewer**: Formatted breakdown of Subject, Issuer, Validity, Serial number, RSA/EC Public Key algorithms, and X.509 v3 Extensions (`SAN`, `KeyUsage`, `BasicConstraints`, `AuthorityKeyIdentifier`, `CRLDistributionPoints`, `EKU`).
- **Flexible Input Formats**: Automatically detects PEM headers, raw Base64 strings, Hex byte streams, or drag-and-drop `.p7b`, `.pem`, `.cer`, `.der` binary files.
- **Interactive ASN.1 Tree**: Expand/collapse nested constructed sequences, with universal/context-specific tag badges and human-readable roles.
- **Synchronized Hex Viewer**: Real-time byte-range highlighting when selecting any node in the ASN.1 tree or certificate structure.
- **Dark / Light Theme**: Built-in responsive theme switcher with OS color scheme preference detection.
- **Zero Build Step**: Runs directly in any browser (via `file://` or HTTP server) without bundlers.

## Project Structure

```
certificate-parser/
├── index.html                 # Main application entry point
├── pkcs7-parser.html          # Compatible alias entry point
├── css/
│   ├── main.css               # CSS aggregator import
│   ├── theme.css              # Dark/light CSS color variables
│   ├── layout.css             # Pane layout, splitters, responsive breakpoints
│   ├── components.css         # Header, tabs, buttons, textareas, status pills
│   ├── tree.css               # ASN.1 hierarchy tree styles, badges, twisties
│   ├── certs.css              # Certificate summary cards & table panels
│   └── hex.css                # Hex dump and synchronized byte selection styles
├── js/
│   ├── constants.js           # ASN.1 tags, OID tables, test sample payloads
│   ├── asn1/
│   │   ├── asn-node.js        # AsnNode & AsnError data classes
│   │   ├── tlv-parser.js      # Recursive TLV decoder (BER/DER & indefinite length)
│   │   ├── oids.js            # Base-128 variable OID decoder and lookup
│   │   └── utils.js           # Primitives (BigInt, time decoding, UTF8/hex conversion)
│   ├── pkcs7/
│   │   ├── cms-labels.js      # RFC 5652 semantic annotators
│   │   ├── x509-labels.js     # RFC 5280 certificate & extension annotators
│   │   └── annotate.js        # High-level dispatcher and preview generator
│   ├── parser/
│   │   ├── ingest.js          # Input decoder (PEM, Base64, Hex, Binary)
│   │   └── parser-core.js     # Parser coordinator and text descriptor
│   └── ui/
│       ├── theme.js           # Theme manager
│       └── splitter.js        # Draggable pane splitters
└── .github/
    └── workflows/
        └── deploy.yml         # GitHub Actions deployment to GitHub Pages
```

## GitHub Pages Deployment

This project is configured to automatically build and host on GitHub Pages using GitHub Actions (`.github/workflows/deploy.yml`).

To enable GitHub Pages:
1. Go to repository **Settings** > **Pages**
2. Set **Source** under *Build and deployment* to **`GitHub Actions`**
3. The site will be published at `https://porchhaybe.github.io/Certificate-parser/`
