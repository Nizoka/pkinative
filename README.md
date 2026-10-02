# pkinative

**Read, verify and build the certificates your software trusts — strictly, safely, on every runtime, without a single dependency.**

![Zero runtime dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![TypeScript strict mode](https://img.shields.io/badge/TypeScript-strict-blue)
![Conformance: x509-limbo, Wycheproof and NIST PKITS](https://img.shields.io/badge/conformance-x509--limbo%20%2B%20Wycheproof%20%2B%20NIST%20PKITS-blueviolet)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Zero runtime dependencies. 100% TypeScript. One API for every runtime with Web Crypto: tested in CI on Node.js 22 on Linux, Windows and macOS and on Node.js 24 on Linux, with a Deno, a Bun and a headless Chromium smoke test; other Web Crypto runtimes, such as Cloudflare Workers, are expected to work and are not tested in CI. The third library of the *native* family, under the engineering doctrine of [pdfnative](https://github.com/Nizoka/pdfnative) and [zipnative](https://github.com/Nizoka/zipnative).

> **Status: 1.0 — stable, on npm.** The public API, the error codes and the reason codes follow semantic versioning: a minor release only adds, and a removal or an incompatible change waits for the next major ([ROADMAP.md](ROADMAP.md), [SECURITY.md §Compatibility promise](SECURITY.md#compatibility-promise)). Versions below 1.0.0 are git tags only — source snapshots of each milestone, never released on GitHub or npm.

pkinative reads certificates and verifies them the whole way: signatures, RFC 5280 §6 paths, CRL and OCSP revocation, host names and key purposes. It reads, builds and verifies CMS SignedData and RFC 3161 timestamps, opens PKCS#8 keys and PKCS#12 files into non-extractable Web Crypto keys, and creates certificates and certification requests — with Web Crypto doing every signature.

## Why pkinative?

The JavaScript ecosystem parses certificates with node-forge, pkijs, asn1js and @peculiar/x509 — tens of millions of weekly downloads between them, pre-ES2015 code or dependency chains, and a history of ASN.1 parser advisories. pkinative starts from the other end:

- **Strict by default.** DER's length, tag, constructed-string, BOOLEAN, INTEGER and BIT STRING rules (X.690 §8, §10, §11.1–11.2.1) are refused, not guessed at: two encodings of one value is an ambiguity an attacker can exploit. The departures from §11.2.2, §11.5 and §11.6 that real issuers commit — trailing zero bits in a named bit list, an explicit DEFAULT, an unsorted SET OF — are diagnostics, refused under `strict: true`. BER is an explicit option.
- **Safe on hostile input.** Every loop runs under a named, CWE-tagged, caller-configurable limit; nesting is iterative; every failure is a typed error with a stable code — never a `TypeError`.
- **Complete.** Every RFC 5280 extension decoded to its ASN.1 module, every GeneralName form, every DirectoryString type, RFC 4514 names, RSA, EC, EdDSA, XDH and ML-DSA keys.
- **Honest about profiles.** What real issuers get wrong — a 21-octet serial, an explicit DEFAULT, a non-critical name constraint — is a diagnostic with its RFC section, not a crash and not silence.
- **Verdicts that explain themselves.** A chain, a signed message, a timestamp or a PKCS#12 file comes back as a report carrying every reason it was refused, each a stable code with its clause, never an exception for a problem with the input.
- **No cryptography it should not own.** pkinative never implements signing, key generation or arithmetic on secret material; every signature is created and verified through Web Crypto, with your key.
- **Held to external corpora.** A blocking conformance gate runs x509-limbo, Wycheproof and NIST PKITS, pinned by commit and checksum, holds the parser to the pinned text of RFC 5280 clause by clause, and cross-checks the serial number, validity, CA flag and fingerprint of every parsed certificate against OpenSSL.
- **Agent-pilotable.** Machine-readable error codes, a diagnostics channel, [`llms.txt`](llms.txt), a generated [API manifest](docs/assets/api.json), and a human-in-the-loop AI governance policy.

## How it compares

Registry facts only, read on 2026-09-19 ([docs/data/comparison-2026-09-19.json](docs/data/comparison-2026-09-19.json)).

| Library | Latest | Runtime dependencies | Types bundled | ES modules | Scope |
|---|---|---|---|---|---|
| **pkinative** | 1.0 (npm) | **0** | yes | yes | ASN.1, PEM, OIDs, X.509, path validation with CRL and OCSP, CMS and RFC 3161, PKCS#8 and PKCS#12 under PBES2; every signature through Web Crypto |
| node-forge | 1.4.0 | 0 | no | no | Broad: ASN.1, X.509, TLS, its own RSA and ciphers in JavaScript |
| asn1js | 3.0.10 | 3 | yes | yes | ASN.1 BER/DER codec |
| @peculiar/x509 | 2.1.0 | 11 | yes | yes | X.509 over Web Crypto, on the @peculiar/asn1 schema stack |
| pkijs | 3.4.0 | 6 | yes | yes | Broad PKI over asn1js and Web Crypto: X.509, CRL, OCSP, CMS, timestamps |
| jsrsasign | 11.1.5 | 0 | no | no | Broad: ASN.1, X.509, JWS, its own RSA and ECDSA in JavaScript |
| micro509 | 0.14.0 | 0 | yes | yes | Small X.509 toolkit, pre-1.0 |

Choose pkinative for strict, dependency-free PKI with every refusal explained by a stable code; choose another tool for what it will never do — legacy PKCS#12, DSA, network fetching, key generation — each a recorded decision ([choose guide](docs/guides/choose.md)).

## Installation

pkinative is on npm, published by [publish.yml](.github/workflows/publish.yml) from the tagged commit, after the full gate, with npm provenance:

```bash
npm install pkinative
npm audit signatures   # optional: verify the registry signatures and provenance of what you installed
```

Every GitHub release also carries that same tarball, fetched back from the registry, and a CycloneDX SBOM, both attested with Sigstore build provenance:

```bash
npm install https://github.com/Nizoka/pkinative/releases/download/v1.0.0/pkinative-1.0.0.tgz
gh attestation verify pkinative-1.0.0.tgz --repo Nizoka/pkinative   # optional: check where it was built
```

A plain git install (`github:Nizoka/pkinative#v1.0.0`) does not work: `dist/` is not committed. Every runtime runs the same build; the package has `browser`, `import` and `require` conditions and no runtime dependency.

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

This block is [recipes/quick-start.ts](recipes/quick-start.ts), executed on every test run against the letsencrypt.org certificate. The [quick start guide](docs/guides/quickstart.md) goes further: extensions, diagnostics, `strict`, limits and errors; the [use cases](docs/guides/use-cases.md) go the whole way, from a chain verdict to a timestamped signature. Every public export, with its signature and the errors it throws, is listed in [docs/assets/api.json](docs/assets/api.json).

## What you get

| Area | Exports |
|---|---|
| The one-call verdict | `verifyCertificateChain` — path building, RFC 5280 §6 validation, host name, key purpose and revocation in one report that lists every reason at once ([use cases](docs/guides/use-cases.md#just-tell-me-whether-to-accept-this-certificate)) |
| Certificates | `parseCertificate`, `getExtension`, `decodeExtensionValue`, `formatDistinguishedName` — every RFC 5280 field and standard extension |
| Signature verification | `verifyCertificateSignature`, `verifySelfSignature`, `canVerify` — one signature against one issuer key, through Web Crypto; `PkiCryptoError` when it could not be checked, never when it failed |
| Creation | `createCertificate`, `createCertificationRequest` (PKCS#10), `canSign` — signed by a Web Crypto key or an `ExternalSigner`; the structural encoders `encodeDistinguishedName`, `encodeExtensions`, `encodeSubjectAltName`, `encodeKeyUsage`, `KEY_USAGE_BITS`, `encodeSubjectPublicKeyInfo` and the rest |
| Paths | `buildCertificatePath`, `validateCertificatePath` — RFC 5280 §6 with name constraints and the policy tree |
| Host names and purposes | `checkServerName`, `matchDnsName` (RFC 6125), `checkExtendedKeyUsage`, `KEY_PURPOSES`, `ANY_EXTENDED_KEY_USAGE` |
| Revocation | CRLs: `parseCertificateList`, `findRevocation`, `verifyCrlSignature`, `checkRevocation` (delta lists and scopes included); OCSP: `createOcspRequest`, `encodeOcspCertId`, `parseOcspResponse`, `verifyOcspSignature`, `checkOcspStatus`, `OCSP_NONCE_OID` — you fetch, pkinative judges |
| CMS and timestamps | `createSignedData` (a Web Crypto key or an `ExternalSigner` such as an HSM), `verifySignedData`, `parseSignedData`, `verifySignerInfoSignature`, `addUnsignedAttribute`; RFC 3161 `createTimeStampRequest`, `parseTimeStampResponse`, `parseTimeStampToken`, `parseTstInfo`, `verifyTimeStampToken`, `addTimeStampToken`; `PkiCmsError` ([use cases](docs/guides/use-cases.md#sign-a-message-and-verify-one-the-whole-way)) |
| Private keys and PKCS#12 | `openPkcs12` (one call: MAC, SafeContents, certificates, keys), `parsePkcs12`, `verifyPkcs12Mac`, `openSafeContents`; PKCS#8 `parsePrivateKeyInfo`, `parseEncryptedPrivateKeyInfo`, `importPrivateKey`, `decryptPrivateKey` — keys unwrapped into non-extractable Web Crypto handles, PBES2 only; `canDecrypt`, `PkiKeyError` ([use cases](docs/guides/use-cases.md#private-keys-and-pkcs12)) |
| PEM | `decodePem` (strict or lax RFC 7468, optionally restricted to one label), `encodePem` |
| ASN.1 | `decodeAsn1`, `decodeAsn1Sequence`; the typed readers `readBoolean`, `readInteger`, `readSmallInteger`, `readNull`, `readBitString`, `readOctetString`, `readObjectIdentifier`, `readString` (eight string types) and `readTime` (both time types); DER encoders (`encodeSequence`, `encodeInteger`, `encodeTlv`, …); `encodeAsn1Node` (byte-identical re-encoding) |
| OIDs | `encodeOid`, `decodeOid`, `isValidOid`, `getOidName` over a registry of 300+ names |
| Fingerprints and key identifiers | `computeFingerprint`, `computeFingerprintAsync` (Web Crypto), `formatFingerprint`, `computeKeyIdentifier` |
| Errors and limits | `PkiError` and its six subclasses — `PkiEncodingError`, `PkiCertificateError`, `PkiLimitError`, `PkiCryptoError`, `PkiCmsError`, `PkiKeyError` — each with a stable `code` ([error guide](docs/guides/errors.md)); `DEFAULT_PKI_LIMITS` |

pkinative has 284 public exports. There is deliberately no PEM-to-certificate shortcut: `decodePem` and `parseCertificate` compose, as Go's `encoding/pem` and `crypto/x509` do, so the certificate parser carries no PEM code ([recipes/pem-bundle.ts](recipes/pem-bundle.ts)).

## Security model

Every certificate, PEM text and DER blob is attacker-controlled. Twenty-two named limits (`maxDepth`, `maxNodes`, `maxExtensions`, …) bound every loop, each with its CWE; structural failures throw a `PkiError` subclass with a stable `code`, conformance concerns go to a diagnostics channel (`onDiagnostic`, or `strict: true` to refuse them), and a judgement — a chain, a message, a timestamp, a key file — returns its reasons in a report. No `eval`, no I/O, no dynamic import in the engine, and no secret-dependent cryptography in TypeScript. Details: [SECURITY.md](SECURITY.md) and the [security guide](docs/guides/security.md).

## Conformance

A blocking gate ([conformance guide](docs/guides/conformance.md)) runs the built package over corpora pinned by commit and SHA-256, levels L0 to L8:

- **x509-limbo** — all 30 361 unique x509-limbo certificates parse, or are refused only where every limbo case using them expects failure; 565 certificates refused, each held to a reviewed baseline. Every certificate re-encodes byte for byte, every parsed one agrees with OpenSSL on serial, validity, CA flag and fingerprint, and every limbo path-validation case is scored against the verdict the corpus expects.
- **RFC 5280, clause by clause** — the requirement sentences of §4.1 and §4.2 in the pinned RFC text, each held by a clause pkinative must diagnose or excluded with a written reason.
- **NIST PKITS** — the 405 certificates and 173 CRLs all parse; 195 of the 203 scored paths agree with NIST, and the 224 signed S/MIME messages are verified whole, each verdict equal to its signer's path. Every disagreement is a reviewed, written deviation.
- **Wycheproof** — all 1 530 Wycheproof ECDSA vectors on P-256, P-384 and P-521: every valid signature decodes, every encoding defect is refused.

What this is and is not evidence of, standard by standard, is the [standards self-assessment](docs/guides/standards.md).

## Known limitations

- **No external security audit** ([ADR 0010](docs/adr/0010-no-external-security-audit-at-1-0.md)). What stands in its place — the adversarial release audit, the conformance gate, 100 % coverage, the seeded adversarial suites — is listed in [SECURITY.md](SECURITY.md#in-place-of-an-external-audit).
- **Coverage-guided fuzzing has not run on GitHub yet.** The ClusterFuzzLite workflow is in place; its first run needs the published repository ([SECURITY.md](SECURITY.md#verification-of-the-parser)). The seeded adversarial suites run in every gate.
- **An `id-RSASSA-PSS` public key cannot be imported on Node.js 22**, so a certificate, list, response or message signed with one is reported `PKI_REASON_SIGNATURE_NOT_CHECKED` (`PKI_CRYPTO_KEY_UNSUPPORTED`): it fails closed, it is not verified. Keys of type `rsaEncryption` signing with RSASSA-PSS verify normally.
- **No PKCS#10 reader.** `createCertificationRequest` writes a certification request; nothing parses one.
- **Internationalized names are not converted**: a non-ASCII octet in an IA5String name is refused, not guessed, and IDNA is not applied.
- **X.520 attribute syntaxes are diagnosed, not enforced, when reading a name**: a `countryName` that is not a two-character PrintableString, or an `emailAddress` that is not an IA5String, is read with a diagnostic (refused under `strict: true`); a value past one of its other upper bounds is read as it is. TeletexString is read as Latin-1, with a diagnostic.
- **The Certificate Transparency SCT list** is kept in its TLS encoding, not decoded.
- **The SHA implementations** are synchronous TypeScript over public data; `computeFingerprintAsync` uses Web Crypto when the host has it.
- **Refusals by design** — PKCS#12 and PKCS#8 under PBES2 only, no DSA verification, no network fetching, no key generation or export, no PKCS#8 or PKCS#12 writer, no ETSI long-term (B-LTA) signature formats — are recorded decisions, listed below.

## What pkinative will NOT do

No runtime dependency. No TypeScript implementation of signing, key generation or modular arithmetic on secrets. No filesystem, network or process access inside the engine. No lenient decoder that silently accepts what the standard forbids. No PEM parsing inside the certificate parser. The larger refusals, and why each is a decision rather than a gap, are recorded as architecture decision records in [docs/adr/](docs/adr/README.md).

## Ecosystem

- [pdfnative](https://github.com/Nizoka/pdfnative) — the mother project; its PAdES and LTV signature stack is where pkinative comes from, and adopting pkinative there is pdfnative's own milestone.
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
