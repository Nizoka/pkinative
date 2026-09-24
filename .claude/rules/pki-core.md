---
paths:
  - "src/asn1/**"
  - "src/pem/**"
  - "src/oid/**"
  - "src/x509/**"
---
<!-- GENERATED from .github/instructions/pki-core.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# PKI Core Standards

## Normative references
| Area | Standard | Sections that decide behaviour |
|---|---|---|
| BER/DER | ITU-T X.690 (02/2021) | §8 basic rules, §10 DER restrictions, §11 CER/DER common restrictions |
| Certificate profile | RFC 5280 | §4.1 basic fields, §4.2 extensions, Appendix A ASN.1 modules |
| PEM | RFC 7468 | §2 general considerations, §3 ABNF (strict and lax), §5 certificates |
| Names | RFC 4514 | §2 string representation of distinguished names |
| Algorithms | RFC 3279, RFC 4055, RFC 5480, RFC 8410, RFC 9814 | parameters of RSA, RSA-PSS, EC, EdDSA, ML-DSA keys |
| IP in names | RFC 5280 §4.2.1.6 / §4.2.1.10 | 4 or 16 octets; doubled with a mask in name constraints |

## Decoder policy
- `encodingRules: 'der'` (default) refuses: indefinite length, non-minimal length, constructed strings,
  non-minimal high tag numbers, BOOLEAN other than `0x00`/`0xFF`, non-minimal INTEGER, BIT STRING with non-zero
  padding bits, trailing data after the root TLV (unless `allowTrailingData`)
- `encodingRules: 'ber'` accepts indefinite lengths and constructed strings, and emits a diagnostic the first time
- Every node keeps its absolute `offset`, `headerLength` and `contentLength`, so `bytes` of any node re-encodes
  byte-identically under DER — signatures cover exactly those bytes

## Time policy
- UTCTime: `YYMMDDHHMMSSZ`; years 50–99 map to 1950–1999, 00–49 to 2000–2049 (RFC 5280 §4.1.2.5.1)
- GeneralizedTime: `YYYYMMDDHHMMSSZ`; DER forbids a trailing zero in a fraction and requires `Z`
- Out-of-range fields (month 13, day 31 in April, hour 24, second 60) throw `PKI_ASN1_TIME_INVALID`
- Years before 1970 and after 2038 are ordinary values: use `setUTCFullYear`, never `Date.UTC` with two digits

## X.509 policy
- A structural violation of the RFC 5280 ASN.1 module throws `PkiCertificateError`
- A profile violation that real issuers commit (serial too long, PrintableString with `*`, GeneralizedTime before
  2050) is a diagnostic, recorded on `certificate.diagnostics` with its RFC section
- A recognised extension whose value does not match its ASN.1 definition throws `PKI_X509_EXTENSION_MALFORMED`;
  `decodeExtensions: false` defers that decision to the caller
- An unknown extension is kept raw (`kind: 'unknown'`); an unknown *critical* extension also raises a diagnostic
- `x509/` parses and nothing more: it never verifies a signature, never writes a structure and never builds or
  validates a chain. Verification lives in `crypto/`, creation in `build/`, and **path validation does not exist
  yet** (0.5) — never imply otherwise in a name or a doc comment
- `build/` writes what `x509/` reads, and the two are held together by one rule: every structure a recipe or a
  test builds is parsed back with `onDiagnostic`, and **zero diagnostics** is the assertion. A builder whose
  output its own reader complains about has written what someone else's reader will refuse
- Any builder input that must match a parsed object byte for byte takes DER and is named `…Der` (`issuerDer`,
  `subjectDer`): a name re-encoded from its decoded attributes does not reproduce a TeletexString, and a chain
  whose two names differ by one octet is a chain nothing will build

## Module boundaries
- `asn1/` knows nothing of certificates; `x509/` reaches bytes only through `asn1/`. The structural encoders
  (`encodeAlgorithmIdentifier`, `encodeDistinguishedName`, `encodeExtensions`, …) live in `build/` for the same
  reason — a certificate structure is not an ASN.1 primitive
- Neither `crypto/` nor `build/` imports `x509/`: the verifier consumes already-parsed data, the builder writes
  bytes, and `tests/tools/verify-bundle.test.ts` proves on the artefact that neither ships the parser
- `x509/` does not import `oid/` (the name registry is tree-shaken data); it keeps its own internal OID constants
- `pem/` does not import `asn1/`: PEM is a text envelope, not a decoder of its content
- `x509/` does not import `pem/` and exports no PEM entry point (as Go separates `encoding/pem` from `crypto/x509`):
  callers compose `decodePem(text, { label: 'CERTIFICATE' })` with `parseCertificate`, shown in `recipes/pem-bundle.ts`
