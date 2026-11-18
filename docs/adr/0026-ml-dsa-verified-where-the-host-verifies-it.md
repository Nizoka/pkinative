---
status: accepted
date: 2026-11-17
since: 1.1.0
---

# ML-DSA signatures are verified where the host verifies ML-DSA; signing and private-key import wait, and SLH-DSA and ML-KEM keys are read only

## Context and Problem Statement

Until 1.1.0 the README listed "ML-DSA signatures are not verified, though ML-DSA keys are read" among the known limitations: `src/x509/x509-spki.ts` classified the three FIPS 204 keys (RFC 9881 §4), and `SIGNATURE_BY_OID` (`src/crypto/crypto-algorithms.ts`) held no ML-DSA entry, so a certificate signed with one was `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` on every host. That refusal rested on a fact that stopped being one: Web Crypto implementations now carry `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87` (Node.js 24.7 and later, per its documentation), while Node.js 22 — the runtime of `.nvmrc`, which the gate runs on — answers `NotSupportedError: Unrecognized algorithm name` to `importKey`. The hosts disagree, exactly as they do for Ed448 ([ADR 0022](0022-ed448-cms-signers-host-dependent.md)).

Three further questions come with the algorithm. RFC 9882 gives a CMS signer rules of its own for the `digestAlgorithm`. Signing, and the private key that signs, are a different promise from verifying. And RFC 9909 (SLH-DSA) and RFC 9935 (ML-KEM) define keys the OID registry already names and the parser kept as `kind: 'unknown'`.

## Decision Drivers

- AGENTS.md §Mission and constraints: no signature algorithm in TypeScript. Verification is one Web Crypto call through `src/crypto/webcrypto.ts`; `KEY_OPERATION_POLICY` is not touched.
- "Could not be checked" is never reported as "invalid" ([docs/guides/errors.md](../guides/errors.md)): a host without ML-DSA says nothing about an ML-DSA signature.
- One verdict per host for one algorithm, and one path for every host-dependent algorithm: ML-DSA must land where Ed448 lands, on the codes `PKI_CRYPTO_KEY_UNSUPPORTED` and `PKI_REASON_SIGNATURE_NOT_CHECKED` as they stand ([ADR 0012](0012-frozen-error-vocabulary.md)).
- No feature detection: `importKey` refusing the algorithm is the detection, as for Ed448. `SubtleCrypto.supports` does not exist on Node.js 22.
- Every structure a recipe or a test builds is parsed back and verified where the gate runs (`.github/instructions/pki-core.instructions.md`), and every signed sample is frozen byte for byte (`scripts/lib/samples.ts`, `scripts/data/output-bytes.json`).
- A widened union is semver-minor; anything else on an exported type is judged incompatible ([ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md), `scripts/lib/api-surface.ts`).

## Considered Options

1. Keep refusing ML-DSA signatures until every supported runtime implements them.
2. Verify ML-DSA signatures through the host, which decides per runtime; read the keys of the other two FIPS algorithms; leave signing for a later minor.
3. Option 2, plus ML-DSA signing (`SignatureAlgorithm`) and private-key import (`importPrivateKey`, `openPkcs12`) in the same release.
4. Implement ML-DSA verification in TypeScript, so the verdict is the same on every host.

## Decision Outcome

Chosen option: 2.

**Verification, for every signed structure.** `SIGNATURE_BY_OID` gains `id-ml-dsa-44`, `-65` and `-87` (2.16.840.1.101.3.4.3.17 to .19, RFC 9881 §2). `resolveAlgorithm` — which certificates, CRLs, OCSP responses and certification requests reach, and CMS signers and timestamp tokens through `resolveCmsAlgorithm` — returns `null` when the key is not of the very parameter set the signature names (a certificate signed "ML-DSA-65" under an ML-DSA-44 key is a decided mismatch, not a question for the host), refuses parameters with `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` (RFC 9881 §3 and RFC 9882 §3.3: "MUST be absent"; the host would ignore them), and otherwise hands the host `{ name: 'ML-DSA-65' }` for both `importKey` and `verify`. That is pure ML-DSA with the empty context string, the only mode RFC 9881 §3 and RFC 9882 §3.2 specify. The HashML-DSA identifiers (…3.32 to .34) stay out of the table: RFC 9881 §8.3 forbids them in PKIX, so they remain `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` by name.

**A host that cannot verify.** Nothing is probed. `importPublicKey` turns the host's refusal into `PKI_CRYPTO_KEY_UNSUPPORTED`, and the compositions report `PKI_REASON_SIGNATURE_NOT_CHECKED` carrying that code — the path an Ed448 signature takes on Bun and Chromium, byte for byte the same reason.

**CMS (RFC 9882 §3.3).** `_cmsAlgorithmProblem` judges an ML-DSA signer before the table, as it does Ed448. With signed attributes, the `digestAlgorithm` is held to the row of Table 1 for the signer's parameter set — ML-DSA-44: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256; ML-DSA-65: SHA-384, SHA-512, SHA3-384, SHA3-512, SHAKE256; ML-DSA-87: SHA-512, SHA3-512, SHAKE256 — with absent or NULL parameters, as every digest is read here. A digest outside the row is `PKI_REASON_CMS_ALGORITHM_MISMATCH`: the section lets a verifier reject a digest weaker than the parameter set, and the SHA-1 refusal of `verifySignerInfoSignature` keys on a hash the signature algorithm names, which ML-DSA does not, so without this rule a SHA-1 `messageDigest` would bind the content silently. A digest of the row that pkinative does not compute (the SHA-3 family and SHAKE128) is not a mismatch: the content cannot be tied to the signature, which is `PKI_REASON_SIGNATURE_NOT_CHECKED` with `PKI_CRYPTO_ALGORITHM_UNSUPPORTED`, as for any such digest. Without signed attributes the same section tells a verifier to ignore the field; `_cmsAlgorithmProblem` takes that fact as its third argument and `verifySignerInfoSignature` passes it.

**Signing and private-key import are not in 1.1.0.** Option 3 was rejected on four grounds, each of which a later record can lift. Node.js 22 cannot sign with ML-DSA, so "parse back and verify" cannot run where the gate runs. A host's ML-DSA `sign` is the hedged variant of FIPS 204 (fresh randomness in every signature), so no sample can be frozen byte for byte, which is why `scripts/lib/samples.ts` signs with EdDSA. RFC 9881 §6 gives a private key three encodings (seed, expanded, both), and the Node.js 24 line that `engines` admits changed which of them a PKCS#8 `importKey` takes, so one PKCS#8 would import on one supported release and be refused on the next. And `SignatureAlgorithm` is a union of inline object types, which the surface classifier may not accept as a widened union. A private key is therefore **classified and not imported**: `parsePrivateKeyInfo` reports `kind: 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87'`, and `importPrivateKey` refuses it with `PKI_CRYPTO_KEY_UNSUPPORTED`, as it did when the kind was `'unknown'`. To be revisited when `.nvmrc` moves to Node.js 24.

**SLH-DSA and ML-KEM keys are read, and nothing more.** `OCTET_KEYS` gains the twelve pure SLH-DSA parameter sets (…3.20 to .31, public keys of 32, 48 and 64 octets, RFC 9909 §5) and the three ML-KEM ones (2.16.840.1.101.3.4.4.1 to .3; 800, 1184 and 1568 octets, RFC 9935 §4), each with its parameters required absent. No SLH-DSA signature identifier enters `SIGNATURE_BY_OID` until a runtime the CI covers verifies one, and ML-KEM signs nothing.

**Key usage.** A certificate whose key is one of these and whose `keyUsage` contradicts the key's RFC raises the `warning` `PKI_DIAG_KEY_USAGE_KEY_ALGORITHM_MISMATCH`: a signature key (RFC 9881 §5, RFC 9909 §6) asserts at least one of `digitalSignature`, `nonRepudiation`, `keyCertSign` and `cRLSign` and none of `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `encipherOnly` and `decipherOnly`; an ML-KEM key (RFC 9935 §5) asserts `keyEncipherment` and nothing else. It is a sentence addressed to the issuing CA, so it is a diagnostic and not a refusal.

Option 4 was rejected for the reason [ADR 0001](0001-no-secret-dependent-cryptography.md) gives and ADR 0022 repeated for Ed448: a signature algorithm in `src/` is what the library exists not to contain, and it would make pkinative the one place where an algorithm verifies that the host refuses. Option 1 was rejected because the refusal rested on no host implementing the algorithm, and that no longer holds.

This record supersedes the ML-DSA sentence of the README's known limitations, as ADR 0022 did the Ed448 one.

### Consequences

- Good, because an ML-DSA certificate chain, CRL, OCSP response, certification request, CMS message and timestamp token verify on a host with ML-DSA, and are reported not checked — never invalid — on one without, with the reason and code an Ed448 signature yields there.
- Good, because one table entry per parameter set and one generic tail of `resolveAlgorithm` cover every structure: no line of `src/` exists only for hosts with ML-DSA, so coverage and mutation are complete on Node.js 22.
- Good, because an ML-DSA signature under a key of another parameter set is `false` before any host is asked, and an ML-DSA signer over a digest weaker than RFC 9882 allows is a named inconsistency.
- Bad, because the verdict depends on the runtime. On a host without ML-DSA the same input moved from `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` to `PKI_CRYPTO_KEY_UNSUPPORTED` (both under `PKI_REASON_SIGNATURE_NOT_CHECKED` in a report): a caller branching on the first code for ML-DSA must branch on the second.
- Bad, because a malformed SLH-DSA or ML-KEM key — a wrong length, parameters present — now throws `PKI_X509_SPKI_INVALID` where the certificate parsed with `kind: 'unknown'`.
- Bad, because the positive verdict is proved only where a CI leg runs a host with ML-DSA; the gate's own runtime exercises the refusal.
- Bad, because `_verifySigner` (`src/verify/verify-signer.ts`) asks `_cmsAlgorithmProblem` about the algorithm pair alone, so `verifySignedData` and `verifyTimeStampToken` hold an ML-DSA signer **without** signed attributes to Table 1 as well. It fails closed, and only for a signer that already broke the same section's MUST (SHA-512 there).
- Neutral, because the twelve HashSLH-DSA key identifiers of RFC 9909 §3 (…3.35 to .46) stay `kind: 'unknown'` with `PKI_DIAG_SPKI_ALGORITHM_UNRECOGNISED`; the OID registry does not name them either.
- Neutral, because `OctetPublicKeyInfo['kind']` and `PrivateKeyKind` widen; ADR 0018 already tells consumers to give a `switch` over an open union a `default`.

### Confirmation

- `tests/crypto/crypto-algorithms.test.ts`: the three identifiers resolve to their host names; every pair of signature and key of different parameter sets is `null`; parameters are refused; each row of RFC 9882 Table 1, SHA-1, and the signer without signed attributes.
- `tests/fixtures/ml-dsa/`: the three self-signed certificates of RFC 9881 Appendix C.3, and a root, a leaf, a certification request, a CRL, an OCSP response, two CMS messages (SHA-512 and SHAKE256) and a timestamp token made by OpenSSL 3.5, whose commands `tests/fixtures/PROVENANCE.md` records. `tests/verify/verify-ml-dsa.test.ts`, `tests/crypto/x509-verify.test.ts` and `tests/crypto/cms-verify.test.ts` assert `valid` under `it.runIf(the host imports an ML-DSA key)` and `PKI_REASON_SIGNATURE_NOT_CHECKED` with `PKI_CRYPTO_KEY_UNSUPPORTED` under the complementary condition, so the suite is correct on both kinds of host.
- The same suites run each structure against a host stubbed to refuse the key — Node.js 22, reproduced anywhere — and against one stubbed to accept it, which records the key, the signature and the covered bytes it is handed: everything around the signature is then proved on every host, and the three values are the ones an independent ML-DSA verifier takes.
- `.github/runtime-smoke/checks.mjs`: one ML-DSA certificate against the built package on every runtime of the smoke, expecting "verified, or not checked with `PKI_CRYPTO_KEY_UNSUPPORTED`" and naming which it got; no runtime's answer is hard-coded.
- `scripts/lib/interop.ts`: `openssl:cert-ml-dsa` and `openssl:cms-ml-dsa`, declared absent on an OpenSSL without ML-DSA.
- `tests/x509/x509-spki.test.ts`: every new identifier with its length, and each wrong length refused; `tests/x509/x509-certificate.test.ts`: the key-usage diagnostic per RFC sentence; `tests/keys/`: the classification, and the import still refused.
- `tests/tools/architecture.test.ts`: `KEY_OPERATION_POLICY` and the one door are unchanged.

## More Information

- FIPS 204 — ML-DSA; RFC 9881 §2 to §5 and §8.3 — identifiers, signatures, keys and key usage in PKIX, and why HashML-DSA is excluded; RFC 9882 §3 — ML-DSA in CMS.
- RFC 9909 §3, §5 and §6 — SLH-DSA identifiers, keys and key usage; RFC 9935 §3 to §5 — ML-KEM.
- [ADR 0001](0001-no-secret-dependent-cryptography.md) — why the signature is the host's.
- [ADR 0022](0022-ed448-cms-signers-host-dependent.md) — the precedent this record copies.
- [docs/guides/standards.md](../guides/standards.md) — the rows for these documents name the evidence.
