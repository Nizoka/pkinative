# Choosing a PKI library

> **Choose pkinative to read certificates strictly with nothing else installed; choose another library today if you need to validate chains or sign.** This guide says which, with the facts behind it and the milestone that closes each gap.

## What pkinative 0.1 does

- Parses every field and every standard extension of an RFC 5280 certificate, with profile concerns as diagnostics.
- Decodes and encodes DER (and BER on request), PEM and OIDs, with typed errors and CWE-tagged limits.
- Computes certificate fingerprints, synchronously or through Web Crypto.
- Runs unchanged on Node.js ≥ 22, browsers, Deno, Bun and Workers, with zero runtime dependencies.

`docs/data/surfaces.json` lists each capability with the exports that provide it and the version that brought it.

## What it does not do yet

| You need | pkinative | Until then |
|---|---|---|
| Verify a certificate's signature | 0.3, through Web Crypto | @peculiar/x509 or pkijs, which verify through Web Crypto |
| Create a CSR or a certificate | 0.3, signed by a Web Crypto key | @peculiar/x509 |
| Validate a path, check CRL or OCSP | 0.5 | pkijs; on Node.js, `node:crypto.X509Certificate` plus your TLS stack |
| Parse or build CMS, verify timestamps | 0.7 | pkijs |
| Read PKCS#8 or PKCS#12 | 0.8, PKCS#12 under PBES2 only | pkijs, node-forge — and for a legacy `.p12`, `openssl pkcs12 -legacy` to convert it |

## The alternatives, by the facts

Read from the npm registry on 2026-09-19 ([docs/data/comparison-2026-09-19.json](../data/comparison-2026-09-19.json)):

| Library | Runtime dependencies | Types bundled | ES modules | Weekly downloads |
|---|---|---|---|---|
| node-forge 1.4.0 | 0 | no | no | 27.6 M |
| asn1js 3.0.10 | 3 | yes | yes | 13.7 M |
| @peculiar/x509 2.1.0 | 11 | yes | yes | 8.2 M |
| pkijs 3.4.0 | 6 | yes | yes | 6.8 M |
| jsrsasign 11.1.5 | 0 | no | no | 1.0 M |
| micro509 0.14.0 | 0 | yes | yes | 59 |

node-forge and jsrsasign implement RSA and elliptic curves in JavaScript; pkinative will not, and leaves that arithmetic to Web Crypto. asn1js, pkijs and @peculiar/x509 are typed and modern, and bring their dependency trees with them.

## When pkinative is the right choice

- You read certificates from untrusted sources — uploads, network peers, logs — and want the parser to refuse ambiguous encodings and bound its resources.
- You ship to browsers or edge runtimes and count every dependency and every kilobyte: a certificate parser bundle is about 55 KB minified, checked by `npm run verify:bundle`.
- You build tools that must display every field of a certificate, including the ones other parsers skip.
- You drive a library from an AI agent and want machine-readable codes, diagnostics and an API manifest.
