(function(global) {
  'use strict';

  const SAMPLE_B64 =
    "MIIFNAYJKoZIhvcNAQcCoIIFJTCCBSECAQExCzAJBgUrDgMCGgUAME8GCSqGSIb3DQEHAaBCBEBI" +
    "ZWxsbyBmcm9tIG9wZW5jb2RlISBUaGlzIGlzIGEgc2FtcGxlIFBLQ1MjNyBzaWduZWREYXRhIG1l" +
    "c3NhZ2UuoIIDSDCCA0QwggIsoAMCAQICEHmEgSKjB2CDQBJpbIC7crIwDQYJKoZIhvcNAQELBQAw" +
    "NTELMAkGA1UEBhMCVVMxETAPBgNVBAoMCG9wZW5jb2RlMRMwEQYDVQQDDApQS0NTNyBEZW1vMB4X" +
    "DTI2MDgyNjAwMDI1M1oXDTI3MDgyNjAwMTI1M1owNTELMAkGA1UEBhMCVVMxETAPBgNVBAoMCG9w" +
    "ZW5jb2RlMRMwEQYDVQQDDApQS0NTNyBEZW1vMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC" +
    "AQEAoV5wnrQJ+Q9KBZsF09N9WL8/bIMvBEpmQ6DGa9ic7MdAxMzcZensDShjA+/Fbs2pC6j9T6e7" +
    "cFhecmfSxS9htrIwe7M15/eqvPTGvNWgAd8yTXr6MEhWAdRqP4tEfIO9dGsOO3pLT5aPRZBWi2Vn" +
    "KcYAHftXaIEDBidJjvv43k6RKZQQSa4np/7pqYkac4Ht1f39aYnTOAacPxIw5nHoPHCn1UP3zjU6" +
    "KQyeYJPAzgrcODoHjLghFh8tfvTcGFd91giBlw+FVUG91OS1nTxfPRPV/9Pqoskexdx6fAl8STbh" +
    "P9ozssuguNeI3DmWXYaCu262rOpGlKksskXNO3oCeQIDAQABo1AwTjAOBgNVHQ8BAf8EBAMCBaAw" +
    "HQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBTeMeObrZ6eDQlKfwjqkQy5" +
    "BJHgNDANBgkqhkiG9w0BAQsFAAOCAQEAKmjfhc34a6kIvbOyY2Cdzam1X9EfnEI4fP6GODOCiNzP" +
    "jsQBTl9w7O6sZ9SSPfqcPQZd+e+N6bcmPVDrIbWu2l6vDli0xd82iWE1YMFEEI3N4afI9fJW3T/+" +
    "Rxr2dMxnuWWjNU5nsI7fDCDf2TqslGr1ZkUkM0C/GgoCKARU3jwEbvUWN9O3ezEaiB6wdjEZ1tSs" +
    "oGrOO6o/h4WhgCPIYxer8uZsDasGwO4n7OwA0jImuleUP99tQ0bShcHC/WQO41EfHYOAHoOXgiRf" +
    "LZEbvG1HMd5uJcsDEEHylb7rVN4t3sG1jFgXRM4SebglZlNfwPacC6IZdx3XvpKvgwNMKjGCAXAw" +
    "ggFsAgEBMEkwNTELMAkGA1UEBhMCVVMxETAPBgNVBAoMCG9wZW5jb2RlMRMwEQYDVQQDDApQS0NT" +
    "NyBEZW1vAhB5hIEiowdgg0ASaWyAu3KyMAkGBSsOAwIaBQAwDQYJKoZIhvcNAQEBBQAEggEAXK+K" +
    "Ks6648H/v22Gky3xHQfdvrSFq+XRd5tnlYBSvIqzYs8jLnbXTMnpnql0Nd3wQryjaxiRk5lS/svg" +
    "85pSL22cFnI0iV7bHegvwRGAdMGqSMU4HZWGZf/S6D8oFupdWF5Ij4+XhNZjmjKmbY5i2YAFFM0G" +
    "JNt5ZwRgmuH9zavPOFiAGd3FR/sm4Ejm/B/10LZLRovcc+49LCzadzZQcClP+qKpcGqPIigCsXFQ" +
    "lFIjPeTJtwz+qGH9DiSIJIPnJYcTne8fMBt+WBvHD/QTkUEpQAbU/3yQmXvXVIry4XcBUn7fYd4G" +
    "b6ZxQOLI9jvCErxb2p5G+NR50ArXUrnjzg==";

  const SAMPLE_CERT_B64 =
    "MIIDdjCCAl6gAwIBAgIQN6Uub+F6Z6JAnhSYbzIplzANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQG" +
    "EwJVUzERMA8GA1UECgwIb3BlbmNvZGUxGTAXBgNVBAMMEFg1MDkgVmlld2VyIERlbW8wHhcNMjYw" +
    "ODI2MDE0MTMxWhcNMjcwODI2MDE1MTMyWjA7MQswCQYDVQQGEwJVUzERMA8GA1UECgwIb3BlbmNv" +
    "ZGUxGTAXBgNVBAMMEFg1MDkgVmlld2VyIERlbW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" +
    "AoIBAQCZpAgC1f1/zkZoMSEN5LiTKrdm3L6lNoxPmiupoX/RirTjMXpEqoDyNK3uVdOGTxIwcOr4" +
    "mINbFpSeicYRRfaD4i6ar3SQnyRGTKewqfEmChsNvL0k8TucBzABw33MwvT+tFawax3XY+Pyf+2E" +
    ""/Wd7W9jrmsjgvkk1tKY1XlRJA8Q8X63XUIsgA4OVq8joceip5tV5R8EOdjnS9AaDYj31y+VkkPcL" +
    "LNemegXiEQ6gVTeY8lSQOsLwfsKhdSnWlue21DCMIGJHDQ/39EElHBqRp5h7zqfkhrPI0mIew4sU" +
    "H5Kf1rhhBiv105k/qk/fFhtsUgvyPSZtYViDkTz97bYFAgMBAAGjdjB0MA4GA1UdDwEB/wQEAwIF" +
    "oDAkBgNVHREEHTAbghNkZW1vLm9wZW5jb2RlLmxvY2FshwR/AAABMB0GA1UdJQQWMBQGCCsGAQUF" +
    "BwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUlGXMG6OcrmtUzoD1D1TL5GxpcAswDQYJKoZIhvcNAQEL" +
    "BQADggEBACJML2URnxIkHC776R2KZty/DiWmCKr3JAbltop3o84SSF/934w8oEpT9SDY079uq9zT" +
    "XmyZasaxYGgQSAO6eRtIc9izTohz77u9AnK9rd1e0mOc4gyQQ6S0GQNjmB6kL0uWpNZFPibfto6g" +
    "UFpCOVcbUpX9ci0eh4ZyV061lnbGwRtypL1FkiTvG6DKMThWK3wmcCJuKnq1dgu0wt3rVPfhP5/u" +
    "v3h//v+0RDtUReYWSzWF7d5x13gyazlIafLp2dT9mpzjW/jQzmKwp7SdqrkeyJx5mLzJPbX0/d8X" +
    "S//vLUmwdCmJ5u+tH7e8GnNWSuR93nvZR/hGc6Wgj7pPFdc=";

  const CLS_UNIVERSAL = 0;
  const CLS_APPLICATION = 1;
  const CLS_CONTEXT = 2;
  const CLS_PRIVATE = 3;

  const UTAG = {
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT STRING",
    4: "OCTET STRING",
    5: "NULL",
    6: "OBJECT IDENTIFIER",
    7: "ObjectDescriptor",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    11: "EMBEDDED PDV",
    12: "UTF8String",
    13: "RELATIVE-OID",
    16: "SEQUENCE",
    17: "SET",
    18: "NumericString",
    19: "PrintableString",
    20: "TeletexString",
    21: "VideotexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime",
    25: "GraphicString",
    26: "VisibleString",
    27: "GeneralString",
    28: "UniversalString",
    29: "CHARACTER STRING",
    30: "BMPString"
  };

  const OID_NAMES = {
    "1.2.840.113549.1.7.1": "data",
    "1.2.840.113549.1.7.2": "signedData",
    "1.2.840.113549.1.7.3": "envelopedData",
    "1.2.840.113549.1.7.4": "signedAndEnvelopedData",
    "1.2.840.113549.1.7.5": "digestedData",
    "1.2.840.113549.1.7.6": "encryptedData",
    "1.2.840.113549.1.9.16.1.2": "authenticatedData (id-ct-authData)",
    "1.2.840.113549.1.9.16.1.4": "timestampedData (id-ct-DTInfo)",
    "1.2.840.113549.1.9.3": "contentType",
    "1.2.840.113549.1.9.4": "messageDigest",
    "1.2.840.113549.1.9.5": "signingTime",
    "1.2.840.113549.1.9.6": "counterSignature",
    "1.2.840.113549.1.9.7": "challengePassword",
    "1.2.840.113549.1.9.13": "signingDescription",
    "1.2.840.113549.1.9.14": "extensionRequest",
    "1.2.840.113549.1.9.15": "smimeCapabilities",
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.2.840.113549.2.2": "md2",
    "1.2.840.113549.2.4": "md4",
    "1.2.840.113549.2.5": "md5",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.5": "sha512-224",
    "2.16.840.1.101.3.4.2.6": "sha512-256",
    "2.16.840.1.101.3.4.2.7": "sha3-224",
    "2.16.840.1.101.3.4.2.8": "sha3-256",
    "2.16.840.1.101.3.4.2.9": "sha3-384",
    "2.16.840.1.101.3.4.2.10": "sha3-512",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.7": "rsa-OAEP (rsaesOaep)",
    "1.2.840.113549.1.1.8": "id-RSASSA-PSS",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.3.1": "dhKeyAgreement",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10045.3.1.7": "secp256r1 (prime256v1)",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "2.16.840.1.101.3.4.1.2": "aes128-CBC",
    "2.16.840.1.101.3.4.1.5": "aes128-wrap",
    "2.16.840.1.101.3.4.1.6": "aes128-GCM",
    "2.16.840.1.101.3.4.1.22": "aes192-CBC",
    "2.16.840.1.101.3.4.1.25": "aes192-wrap",
    "2.16.840.1.101.3.4.1.26": "aes192-GCM",
    "2.16.840.1.101.3.4.1.42": "aes256-CBC",
    "2.16.840.1.101.3.4.1.45": "aes256-wrap",
    "2.16.840.1.101.3.4.1.46": "aes256-GCM",
    "1.2.840.113549.3.2": "rc2-CBC",
    "1.2.840.113549.3.4": "rc4",
    "1.2.840.113549.3.7": "des-EDE3-CBC (3DES)",
    "1.3.6.1.4.1.311.2.1.3": "spcIndirectDataContext (Authenticode)",
    "1.3.6.1.4.1.311.10.3.12": "SPC_STATEMENT_TYPE (Authenticode)",
    "1.3.6.1.5.5.7.3.1": "id-kp-serverAuth",
    "1.3.6.1.5.5.7.3.2": "id-kp-clientAuth",
    "1.3.6.1.5.5.7.3.3": "id-kp-codeSigning",
    "1.3.6.1.5.5.7.3.4": "id-kp-emailProtection",
    "1.3.6.1.5.5.7.3.8": "id-kp-timeStamping",
    "1.3.6.1.5.5.7.3.9": "id-kp-OCSPSigning",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "1.3.6.1.5.5.7.48.1": "ocsp",
    "1.3.6.1.5.5.7.48.2": "caIssuers",
    "2.5.4.3": "CN",
    "2.5.4.4": "SN (surname)",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.42": "GN (givenName)",
    "2.5.4.17": "postalCode",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
    "2.5.29.9": "subjectDirectoryAttributes",
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.17": "subjectAltName",
    "2.5.29.18": "issuerAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.20": "cRLNumber",
    "2.5.29.28": "issuingDistributionPoint",
    "2.5.29.30": "nameConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.36": "policyConstraints",
    "2.5.29.37": "extendedKeyUsage",
    "2.5.29.46": "freshestCRL"
  };

  const ATTR_NAMES = {
    "1.2.840.113549.1.9.3": "contentType",
    "1.2.840.113549.1.9.4": "messageDigest",
    "1.2.840.113549.1.9.5": "signingTime",
    "1.2.840.113549.1.9.6": "counterSignature",
    "1.2.840.113549.1.9.7": "challengePassword",
    "1.2.840.113549.1.9.13": "signingDescription",
    "1.2.840.113549.1.9.14": "extensionRequest",
    "1.2.840.113549.1.9.15": "smimeCapabilities",
    "1.3.6.1.4.1.311.2.1.4": "SPC_SP_OPUS_INFO (Authenticode)",
    "1.3.6.1.4.1.311.10.3.12": "SPC_STATEMENT_TYPE (Authenticode)"
  };

  const STR_TAGS = new Set([12, 18, 19, 20, 21, 22, 25, 26, 27, 30]);

  const constants = {
    SAMPLE_B64,
    SAMPLE_CERT_B64,
    CLS_UNIVERSAL,
    CLS_APPLICATION,
    CLS_CONTEXT,
    CLS_PRIVATE,
    UTAG,
    OID_NAMES,
    ATTR_NAMES,
    STR_TAGS
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = constants;
  }
  global.PKCS7Constants = constants;
  // Also expose on global scope for backwards compatibility
  Object.assign(global, constants);
})(typeof window !== 'undefined' ? window : global);
