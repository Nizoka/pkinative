# pkinative

**Read the certificates your software trusts — strictly, safely, on every runtime, without a single dependency.**

![Zero runtime dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![TypeScript strict mode](https://img.shields.io/badge/TypeScript-strict-blue)
![Conformance: x509-limbo and Wycheproof](https://img.shields.io/badge/conformance-x509--limbo%20%2B%20Wycheproof-blueviolet)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Zero runtime dependencies. 100% TypeScript. One API across Node.js ≥ 22, browsers, Deno, Bun and Workers. The third library of the *native* family, under the engineering doctrine of [pdfnative](https://github.com/Nizoka/pdfnative) and [zipnative](https://github.com/Nizoka/zipnative).

> **Status: 0.2 — pre-1.0, not on npm.** Versions below 1.0.0 are git tags with an attested release tarball, and the first npm publication is 1.0.0 ([ROADMAP.md](ROADMAP.md)). 0.1 reads certificates; it does not verify signatures or validate chains yet.

## Why pkinative?

The JavaScript ecosystem parses certificates with node-forge, pkijs, asn1js and @peculiar/x509 — tens of millions of weekly downloads between them, pre-ES2015 code or dependency chains, and a history of ASN.1 parser advisories. pkinative starts from the other end:

- **Strict by default.** DER is decoded as X.690 §10–11 requires: two encodings of one value is an ambiguity an attacker can exploit, so it is refused, not guessed at. BER is an explicit option.
- **Safe on hostile input.** Every loop runs under a named, CWE-tagged, caller-configurable limit; nesting is iterative; every failure is a typed error with a stable code — never a `TypeError`.
- **Complete.** Every RFC 5280 extension decoded to its ASN.1 module, every GeneralName form, every DirectoryString type, RFC 4514 names, RSA, EC, EdDSA, XDH and ML-DSA keys.
- **Honest about profiles.** What real issuers get wrong — a 21-octet serial, an explicit DEFAULT, a non-critical name constraint — is a diagnostic with its RFC section, not a crash and not silence.
- **No cryptography it should not own.** pkinative never implements signing, key generation or arithmetic on secret material; verification arrives through Web Crypto.
- **Held to external corpora.** A blocking conformance gate runs x509-limbo and Wycheproof, pinned by commit and checksum, and cross-checks every result against OpenSSL.
- **Agent-pilotable.** Machine-readable error codes, a diagnostics channel, [`llms.txt`](llms.txt), a generated [API manifest](docs/assets/api.json), and a human-in-the-loop AI governance policy.

## How it compares

Registry facts only, read on 2026-09-19 ([docs/data/comparison-2026-09-19.json](docs/data/comparison-2026-09-19.json)).

| Library | Latest | Runtime dependencies | Types bundled | ES modules | Scope |
|---|---|---|---|---|---|
| **pkinative** | 0.1.0 (git tag) | **0** | yes | yes | ASN.1, PEM, OIDs, complete X.509 reading; creation and verification through Web Crypto from 0.3 |
| node-forge | 1.4.0 | 0 | no | no | Broad: ASN.1, X.509, TLS, its own RSA and ciphers in JavaScript |
| asn1js | 3.0.10 | 3 | yes | yes | ASN.1 BER/DER codec |
| @peculiar/x509 | 2.1.0 | 11 | yes | yes | X.509 over Web Crypto, on the @peculiar/asn1 schema stack |
| pkijs | 3.4.0 | 6 | yes | yes | Broad PKI over asn1js and Web Crypto: X.509, CRL, OCSP, CMS, timestamps |
| jsrsasign | 11.1.5 | 0 | no | no | Broad: ASN.1, X.509, JWS, its own RSA and ECDSA in JavaScript |
| micro509 | 0.14.0 | 0 | yes | yes | Small X.509 toolkit, pre-1.0 |

Choose pkinative to **read** certificates strictly with nothing else installed; choose pkijs or @peculiar/x509 today if you need path validation, CMS or signing before pkinative's 0.5 and 0.7 milestones ([choose guide](docs/guides/choose.md)).

## Installation

pkinative 0.1 is not on npm. Install the tarball attached to the GitHub release — built from the tag, run through the full gate, installed as a test and attested with Sigstore build provenance by [release-assets.yml](.github/workflows/release-assets.yml):

```bash
npm install https://github.com/Nizoka/pkinative/releases/download/v0.2.0/pkinative-0.2.0.tgz
gh attestation verify pkinative-0.2.0.tgz --repo Nizoka/pkinative   # optional: check where it was built
```

A plain git install (`github:Nizoka/pkinative#v0.1.0`) does not work: `dist/` is not committed. Node.js ≥ 22, current browsers, Deno, Bun and Cloudflare Workers run the same build; the package has `browser`, `import` and `require` conditions and no runtime dependency.

## Quick start

Read every certificate of a PEM text and print what a person checks first:

```ts
import { computeFingerprint, decodePem, formatDistinguishedName, formatFingerprint, getExtension, parseCertificate } from 'pkinative';

export function describeCertificates(pemText: string): string[] {
    const lines: string[] = [];
    for (const { bytes } of decodePem(pemText, { label: 'CERTIFICATE' })) {
        const cert = parseCertificate(bytes);
        const names = getExtension(cert, 'subjectAltName')?.names ?? [];
        const iso = (ms: number): string => new Date(ms).toISOString();
        lines.push(
            `subject: ${formatDistinguishedName(cert.subject)}`,
            `issuer:  ${formatDistinguishedName(cert.issuer)}`,
            `valid:   ${iso(cert.validity.notBefore.epochMilliseconds)} → ${iso(cert.validity.notAfter.epochMilliseconds)}`,
            `names:   ${names.map((n) => (n.kind === 'dNSName' ? n.value : n.kind)).join(', ')}`,
            `sha-256: ${formatFingerprint(computeFingerprint(bytes, 'SHA-256'))}`,
        );
    }
    return lines;
}
```

This block is [recipes/quick-start.ts](recipes/quick-start.ts), executed on every test run against the letsencrypt.org certificate. The [quick start guide](docs/guides/quickstart.md) goes further: extensions, diagnostics, `strict`, limits and errors. Every public export, with its signature and the errors it throws, is listed in [docs/assets/api.json](docs/assets/api.json).

## What you get

| Area | Exports |
|---|---|
| Certificates | `parseCertificate`, `getExtension`, `decodeExtensionValue`, `formatDistinguishedName` — every RFC 5280 field and standard extension |
| PEM | `decodePem` (strict or lax RFC 7468, optionally restricted to one label), `encodePem` |
| ASN.1 | `decodeAsn1`, `decodeAsn1Sequence`, typed readers (BOOLEAN, INTEGER, NULL, BIT STRING, OCTET STRING, OBJECT IDENTIFIER, eight string types, both time types), DER encoders, `encodeAsn1Node` (byte-identical re-encoding) |
| OIDs | `encodeOid`, `decodeOid`, `isValidOid`, `getOidName` over a registry of 300+ names |
| Fingerprints | `computeFingerprint`, `computeFingerprintAsync` (Web Crypto), `formatFingerprint` |
| Errors and limits | `PkiError`, `PkiEncodingError`, `PkiCertificateError`, `PkiLimitError`, `DEFAULT_PKI_LIMITS` |

pkinative has 127 public exports. There is deliberately no PEM-to-certificate shortcut: `decodePem` and `parseCertificate` compose, as Go's `encoding/pem` and `crypto/x509` do, so the certificate parser carries no PEM code ([recipes/pem-bundle.ts](recipes/pem-bundle.ts)).

## Security model

Every certificate, PEM text and DER blob is attacker-controlled. Eleven named limits (`maxDepth`, `maxNodes`, `maxExtensions`, …) bound every loop, each with its CWE; structural failures throw a `PkiError` subclass with a stable `code`, and conformance concerns go to a diagnostics channel (`onDiagnostic`, or `strict: true` to refuse them). No `eval`, no I/O, no dynamic import in the engine, and no secret-dependent cryptography in TypeScript. Details: [SECURITY.md](SECURITY.md) and the [security guide](docs/guides/security.md).

## Conformance

A blocking gate ([conformance guide](docs/guides/conformance.md)) runs the built package over corpora pinned by commit and SHA-256:

- **x509-limbo** — all 30 361 unique x509-limbo certificates parse, or are refused only where every limbo case using them expects failure; 564 certificates refused, each held to a reviewed baseline. Every certificate re-encodes byte for byte, and every parsed one agrees with OpenSSL on serial, validity, CA flag and fingerprint.
- **Wycheproof** — all 1 530 Wycheproof ECDSA vectors on P-256, P-384 and P-521: every valid signature decodes, every encoding defect is refused.

## Known limitations

- No signature verification before 0.3, no path validation, CRL or OCSP before 0.5, no CMS before 0.7 ([ROADMAP.md](ROADMAP.md)).
- Internationalized names are not converted: a non-ASCII octet in an IA5String name is refused, not guessed (0.5).
- The Certificate Transparency SCT list is kept in its TLS encoding, not decoded.
- The SHA implementations are synchronous TypeScript over public data; `computeFingerprintAsync` uses Web Crypto when the host has it.

## What pkinative will NOT do

No runtime dependency. No TypeScript implementation of signing, key generation or modular arithmetic on secrets. No filesystem, network or process access inside the engine. No lenient decoder that silently accepts what the standard forbids. No PEM parsing inside the certificate parser.

## Ecosystem

- [pdfnative](https://github.com/Nizoka/pdfnative) — the mother project; its PAdES and LTV signature stack is where pkinative comes from, and will run on it from 0.7.
- [zipnative](https://github.com/Nizoka/zipnative) — the sibling whose error vocabulary, limits and conformance-gate patterns pkinative inherits.

## Development

```bash
npm ci --ignore-scripts
npm run gate:fast        # typecheck, lint, tests, documentation checks
npm run gate             # the CI profile
npm run conformance:fetch && npx tsx scripts/gate.ts --publish --require-all
```

[CONTRIBUTING.md](CONTRIBUTING.md) has the conventions and the release procedure; [AGENTS.md](AGENTS.md) is the brief for AI coding agents, who work under a human-in-the-loop policy ([.github/AGENT_RULES.md](.github/AGENT_RULES.md)).

## Origin

pkinative grew out of the X.509 and CMS code pdfnative wrote for PDF signatures. An audit found that code useful but not reusable as it stood — a signed-shift length bug, recursion without a bound, extensions silently lost after an `issuerUniqueID`, and pure-JavaScript RSA and ECDSA that are not constant-time. pkinative keeps the ideas, rewrites the parser, and leaves the secret-dependent arithmetic to Web Crypto.

## License

[MIT](LICENSE) © Nizoka — Plika
