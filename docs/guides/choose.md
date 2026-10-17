# Choosing a library and a surface

> **Choose pkinative for strict, dependency-free PKI in any JavaScript runtime — certificates, paths and revocation, CMS and timestamps, PKCS#8 and PKCS#12 — with every refusal explained by a stable code. Choose another tool for what it will never do, listed below.**

## What pkinative does

- **Reads** DER (and BER on request), PEM and OIDs; every field and standard extension of an RFC 5280 certificate, with profile concerns as diagnostics; PKCS#10 certification requests, with the extensions they ask for; CRLs, OCSP responses, CMS SignedData, RFC 3161 timestamp tokens, PKCS#8 keys and PKCS#12 files under PBES2.
- **Builds** certificates, certification requests, OCSP requests, CMS SignedData attached or detached, and timestamp requests — signed through Web Crypto by a key you hold, or by an `ExternalSigner` for a key in an HSM or a remote service; RSA PKCS#1 v1.5 and PSS, ECDSA on P-256, P-384 and P-521, Ed25519, and Ed448 where the host has it.
- **Judges**: RFC 5280 §6 path building and validation with name constraints and the policy tree, revocation by CRL (delta lists and scoping included) or OCSP, RFC 6125 host names, extended key usage, CMS signatures and timestamps, and a certification request's proof of possession. The one-call reports — `verifyCertificateChain`, `verifySignedData`, `verifyTimeStampToken`, `verifyCertificationRequest`, `openPkcs12` — return every reason at once and never throw for a problem with the input.
- **Proves it**: scored against x509-limbo, NIST PKITS and its S/MIME messages, clause by clause against the pinned text of RFC 5280, and against OpenSSL and Windows in both directions — the [conformance guide](conformance.md) carries the current figures and every reviewed deviation.
- Runs one build on every runtime with Web Crypto, with zero runtime dependencies: tested in CI on Node.js 22 on Linux, Windows and macOS and on Node.js 24 on Linux, with a Deno, a Bun and a headless Chromium smoke test, and on Node.js 26 (Current) in an advisory run until its LTS date; other Web Crypto runtimes, such as Cloudflare Workers, are expected to work and are not tested in CI.

Verifying a signature is **not** validating a chain: `verifyCertificateSignature` says the issuer's key signed these bytes, and nothing about expiry, trust, revocation, or whether that issuer was entitled to sign. `verifyCertificateChain` is the call that answers those.

`docs/data/surfaces.json` lists each capability with the library exports, CLI commands and MCP tools that provide it and the version that brought it.

## What it does not do, by design

Each of these is a recorded decision, not a gap on a roadmap: the [decision records](../adr/README.md) say why, and what holds the line.

| You need | Why pkinative will not | Instead |
|---|---|---|
| A legacy PKCS#12 — RC2, 3DES, the RFC 7292 Appendix B MAC | Its KDF is iterated hashing with byte arithmetic over the password — secret-dependent cryptography in JavaScript ([ADR 0002](../adr/0002-pkcs12-pbes2-only.md)) | Convert it once: `openssl pkcs12 -in legacy.p12 -legacy -aes256 -out bundle.pem`, then `openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12` |
| To write a PKCS#8 or PKCS#12, or to generate or export a key | Web Crypto's `encrypt`, `wrapKey`, `generateKey` and `exportKey` are refused in every version ([ADR 0001](../adr/0001-no-secret-dependent-cryptography.md), [ADR 0003](../adr/0003-no-pkcs8-or-pkcs12-writer.md)) | Web Crypto or `node:crypto` in your own code, or OpenSSL |
| To verify DSA signatures | Web Crypto implements none of it, and pkinative implements no signature algorithm ([ADR 0004](../adr/0004-dsa-and-ed448-cms-signers-not-verified.md)) | `node:crypto` on Node.js |
| To fetch a CRL, an OCSP response, a missing intermediate or a timestamp | The engine does no I/O: a verifier that reached the network could be pointed at a host of an attacker's choosing ([ADR 0006](../adr/0006-no-network-io-in-the-engine.md)) | Fetch them yourself and pass the bytes |
| ETSI long-term signatures — archive timestamps, chained proof of existence | Out of scope through 1.0; `atTimeStamp` takes one level of evidence ([ADR 0009](../adr/0009-no-etsi-long-term-signature-formats.md)) | A PAdES or CAdES toolkit |
| Distinguished names matched by RFC 5280 §7.1 preparation when building chains | Names are compared by encoded bytes, as Go and webpki do; the miss is a refusal ([ADR 0005](../adr/0005-names-compared-by-encoded-bytes.md)) | Re-issue with consistent encodings |

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
- You ship to browsers or edge runtimes and count every dependency and every kilobyte: reading a certificate ships about 87 KB minified, describing a key file about 45 KB, and each subsystem's cost is a budget `npm run verify:bundle` checks.
- You build tools that must display every field of a certificate, including the ones other parsers skip.
- You drive a library from an AI agent and want machine-readable codes, diagnostics and an API manifest.
- You need a verdict you can act on: every refusal a reason code with its clause, several at once, and the one that would have been thrown kept in `errorCode`.

## Choosing your surface

pkinative reaches you three ways, and all three run the same engine: a verdict, a refusal code or an artefact does not depend on the surface that produced it. Pick the one that matches where your bytes live and who drives the call.

| Surface | For | Pick it when |
|---|---|---|
| **The library**, `npm install pkinative` | Applications and services on any runtime with Web Crypto — Node.js, Deno, Bun, browsers, edge workers | The bytes live in memory, you want the whole typed API, or the key sits in an HSM or a remote service behind an `ExternalSigner` — which only the library takes. You own the I/O: the engine reads no file and opens no socket |
| **[pkinative-cli](cli.md)**, the `pkinative` binary | Shell scripts, CI jobs, operators, and programs in any language that can run a process | Certificates, CRLs and signatures sit on disk or arrive through a pipe, and you want exit codes, `--dry-run` and one JSON envelope per run, offline. Node.js only; keys come from a PKCS#8 or PKCS#12 file, passwords never from argv |
| **[pkinative-mcp](mcp.md)**, the `pkinative-mcp` server | AI assistants and agents in any MCP client — Claude Desktop, Claude Code, Cursor, VS Code, the MCP Inspector, or any local client over stdio or loopback Streamable HTTP | A conversation needs PKI tools: 34 typed tools, seven prompts and sandboxed file resources, a negative verdict that is data rather than an error, and no key byte or network call, ever. Node.js 22.22.2, 24.14.1 or 25.8.2 and later (the engine's floor) |

The CLI and the MCP server are thin wrappers: neither adds a PKI decision of its own, both pin pkinative ^1.0.0, both carry the engine's `PKI_*` codes verbatim, and both reach every runtime export of pkinative 1.0.0. What they add is the boundary the engine deliberately lacks — files and exit codes for the CLI, a sandbox and an MCP protocol surface for the server — and the [errors guide](errors.md#where-the-codes-surface) shows how one failure looks on each.

Every capability `docs/data/surfaces.json` lists, by surface:

| Capability | Library | CLI | MCP |
|---|---|---|---|
| `errors` — typed errors with stable codes | `PkiError` and its subclasses | every command: `error.pkiCode` in the `--json` envelope; `explain` | every tool: `_meta.error.code`; `explain_code` |
| `limits` — named, CWE-tagged bounds | `DEFAULT_PKI_LIMITS`, the `limits` option | the 22 engine-limit `--max-*` flags (plus the CLI's `--max-content-size`); `limits` | the `limits` input of every engine tool, under the operator ceilings; `describe_engine` |
| `asn1-decode` | `decodeAsn1`, `decodeAsn1Sequence` | `asn1 decode` (`--sequence`) | `decode_asn1` (`sequence`) |
| `asn1-read` | `readInteger`, `readTime` and the other typed readers | `asn1 decode --path … --read …` | `decode_asn1` (`nodePath`, `read`) |
| `asn1-encode` | `encodeSequence`, `encodeAsn1Node` and the other encoders | `asn1 encode`; `asn1 decode --reencode` | `encode_asn1`; `decode_asn1` (`reencode`) |
| `oid` | `encodeOid`, `decodeOid`, `isValidOid`, `getOidName`, `OID_REGISTRY` | `oid name`, `encode`, `decode`, `validate`, `list` | `resolve_oid` |
| `pem` | `decodePem`, `encodePem` | `pem decode`, `pem encode` | `convert_pem` |
| `fingerprint` | `computeFingerprint`, `computeFingerprintAsync`, `formatFingerprint`, `computeKeyIdentifier`, `shake256` | `fingerprint` (`--key-id`, `--shake256`, `--webcrypto`) | `compute_fingerprint`; `inspect_certificate` (`fingerprints`) |
| `x509-parse` | `parseCertificate`, `getExtension`, `decodeExtensionValue`, `formatDistinguishedName` | `cert inspect`, `cert decode-extension` | `inspect_certificate`, `decode_extension` |
| `x509-verify` | `verifyCertificateSignature`, `verifySelfSignature`, `canVerify` | `cert verify-signature`; `doctor` | `inspect_certificate` (`issuer`, `checkSelfSignature`); `describe_engine` |
| `x509-create` | `createCertificate`, `createCertificationRequest`, the X.509 encoders, `canSign` | `cert create`, `csr create`, `cert encode`; `doctor` | `create_certificate`, `create_csr`, `encode_x509_structure`; `describe_engine` |
| `x509-csr` | `parseCertificationRequest`, `verifyCertificationRequest` | `csr inspect`, `csr verify` | `inspect_csr` |
| `x509-verify-chain` | `verifyCertificateChain` | `chain verify` | `verify_certificate_chain` |
| `x509-path` | `buildCertificatePath`, `validateCertificatePath` | `chain build`, `chain validate` | `build_certificate_path`, `validate_certificate_path` |
| `x509-server-name` | `checkServerName`, `matchDnsName` | `cert check-name`, `cert match-name`; `chain verify --host` | `check_certificate_name`; `verify_certificate_chain` (`serverName`) |
| `x509-purpose` | `checkExtendedKeyUsage`, `KEY_PURPOSES`, `ANY_EXTENDED_KEY_USAGE` | `cert check-purpose`; `--purpose` on `chain` and `cms verify` | `check_certificate_purpose`; `purposes` on `verify_certificate_chain`, `build_certificate_path` and `verify_cms` |
| `x509-crl` | `parseCertificateList`, `findRevocation`, `verifyCrlSignature`, `checkRevocation` | `crl inspect`, `find`, `verify-signature`, `check` | `inspect_crl` (`find`, `issuer`), `check_crl_revocation` |
| `x509-ocsp` | `createOcspRequest`, `encodeOcspCertId`, `parseOcspResponse`, `verifyOcspSignature`, `checkOcspStatus` | `ocsp request`, `cert-id`, `inspect`, `verify-signature`, `check` | `create_ocsp_request` (`certIdOnly`), `inspect_ocsp_response` (`responder`), `check_ocsp_status` |
| `cms-signed-data` | `createSignedData`, `parseSignedData`, `verifySignedData`, `verifySignerInfoSignature`, `addUnsignedAttribute` | `cms sign`, `verify`, `inspect`, `verify-signer`, `add-attribute` | `sign_cms`, `verify_cms`, `inspect_cms` (`signerCertificate`), `amend_cms` (`add-unsigned-attribute`) |
| `cms-timestamp` | `createTimeStampRequest`, `parseTimeStampResponse`, `parseTimeStampToken`, `parseTstInfo`, `verifyTimeStampToken`, `addTimeStampToken` | `tsp request`, `inspect`, `verify`; `cms add-timestamp` | `create_timestamp_request`, `inspect_timestamp`, `verify_timestamp`; `amend_cms` (`add-timestamp`) |
| `keys-pkcs8` | `parsePrivateKeyInfo`, `parseEncryptedPrivateKeyInfo`, `importPrivateKey`, `decryptPrivateKey`, `canDecrypt` | `key inspect`, `key check`; `--key` on the signing commands; `doctor` | `inspect_private_key` (`tryImport`); `signer.key` on the signing tools; `describe_engine` |
| `keys-pkcs12` | `parsePkcs12`, `verifyPkcs12Mac`, `openSafeContents`, `openPkcs12` | `p12 inspect`, `verify-mac`, `bags`, `open`; `--p12` on the signing commands | `inspect_pkcs12`, `open_pkcs12`; `signer.p12` on the signing tools |

The [CLI guide](cli.md) and the [MCP guide](mcp.md) document every command and tool; [CLI use cases](use-cases-cli.md) and [MCP use cases](use-cases-mcp.md) put them to work.
