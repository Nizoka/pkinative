---
status: accepted
date: 2026-10-03
since: 1.0.0
---

# Ed448 CMS signers are verified where the host verifies Ed448: SHAKE256 is computed here, the signature is the host's; DSA stays refused

## Context and Problem Statement

[ADR 0004](0004-dsa-and-ed448-cms-signers-not-verified.md) refused an Ed448 CMS signer with `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` because RFC 8419 §3.1 makes its `digestAlgorithm` SHAKE256 with a 512-bit output (`id-shake256`, RFC 8419 §2.1), which Web Crypto does not compute, and pkinative did not either. The record itself said the gap was not one of principle: hashing public data in TypeScript is permitted by [ADR 0001](0001-no-secret-dependent-cryptography.md), and the FIPS 180-4 digests already live in `src/hash/`. What remained undecided was the other half of the question — the Ed448 signature itself is the host's to verify, and the hosts the build runs on disagree: Node.js implements Ed448 in Web Crypto, Bun and Chromium do not ([.github/runtime-smoke/checks.mjs](../../.github/runtime-smoke/checks.mjs)). An Ed448 *certificate* signature has always been verified under that same condition, and reported `PKI_REASON_SIGNATURE_NOT_CHECKED` where the host lacks the algorithm ([docs/data/reasons.json](../data/reasons.json)).

## Decision Drivers

- AGENTS.md §Mission and constraints: no signature algorithm in TypeScript; hashing covers public data. SHAKE256 over a message's content and signed attributes is hashing public data.
- "Could not be checked" is never reported as "invalid" ([docs/guides/errors.md](../guides/errors.md)): a host without Ed448 says nothing about an Ed448 signature.
- One verdict per host for one algorithm: an Ed448 CMS signer and an Ed448 certificate signature must land on the same code on the same host, or a reader of a report has two things to learn instead of one.
- The error and reason vocabularies are frozen ([ADR 0012](0012-frozen-error-vocabulary.md)); the change must reuse `PKI_CRYPTO_KEY_UNSUPPORTED` and `PKI_REASON_SIGNATURE_NOT_CHECKED` as they stand.
- The DSA decision of ADR 0004 rests on a different ground — Web Crypto implements no DSA at all, and the 0.5.0 release note is categorical — and is not reopened.

## Considered Options

1. Keep refusing Ed448 CMS signers everywhere, as ADR 0004 did, until every host the build runs on implements Ed448.
2. Compute SHAKE256 in TypeScript and verify an Ed448 CMS signer exactly as an Ed448 certificate signature is verified: through the host, which decides per runtime.
3. Compute SHAKE256 and implement Ed448 verification in TypeScript as well, so the verdict is the same on every host.

## Decision Outcome

Chosen option: 2. `src/hash/shake256.ts` implements Keccak-f[1600] over 32-bit lane halves and exposes `shake256(data, outputLength)`, the one extendable-output function pkinative computes; it hashes public data only, as ADR 0001 allows. `_cmsAlgorithmProblem` (`src/crypto/crypto-algorithms.ts`) holds an Ed448 signer to RFC 8419 §3.1 — the `digestAlgorithm` is `id-shake256` with absent or NULL parameters, and any other digest is `PKI_REASON_CMS_ALGORITHM_MISMATCH`, a verdict on the signer — and `resolveCmsAlgorithm` resolves the signer to the host's `Ed448`, as `resolveAlgorithm` always did for a certificate. `verifySignedData` computes the content digest with SHAKE256-512 for such a signer and compares it to `messageDigest` as for any other digest. The signature itself goes through `importPublicKey` and `verifySignature`: on a host without Ed448 the import is refused, which is `PKI_CRYPTO_KEY_UNSUPPORTED` from the primitive and `PKI_REASON_SIGNATURE_NOT_CHECKED` carrying that code in the report — the path an Ed448 certificate signature takes on that host, byte for byte the same reason.

Option 3 was rejected because Ed448 verification is elliptic-curve arithmetic, which ADR 0001 forbids in `src/` whatever the key's secrecy, and because it would make pkinative the one place where an algorithm verifies that the host refuses. Option 1 was rejected because the refusal rested on a digest nobody computed, and that reason no longer holds.

`createSignedData` signs with Ed448 under the same condition (amended 2026-10-03, the lot after this record): the builder computes the `messageDigest` with `shake256` and signs through the host's `Ed448`, and a host without it refuses with `PKI_CRYPTO_KEY_UNSUPPORTED` from `signData`, the path every signing key the host rejects takes; the ESSCertIDv2 of `signingCertificateV2` keeps its default SHA-256, which every verifier computes, since `id-shake256` is a CMS digest and not one a certificate hash is checked with. The DSA half of ADR 0004 is unchanged: DSA signatures, certificate or CMS, are not verified and never will be.

### Consequences

- Good, because an Ed448-signed CMS message verifies on Node.js, and is reported not checked — never invalid — on Bun and Chromium, with the same reason and code an Ed448 certificate yields there.
- Good, because an Ed448 signer whose `digestAlgorithm` is not `id-shake256` is now a decided inconsistency (`PKI_REASON_CMS_ALGORITHM_MISMATCH`) instead of an unsupported algorithm: RFC 8419 §3.1 is held, where before it was not read.
- Good, because `shake256` is a public export, so a caller verifying detached content can compute the `contentDigest` of an Ed448 signer as a tool would.
- Bad, because the verdict for an Ed448 CMS message depends on the runtime, as it does for an Ed448 certificate. The runtime smoke declares the expectation per host and fails when a host changes its answer.
- Bad, because `id-shake256-len` (NIST CSOR …4.2.18), whose INTEGER parameter chooses the output length, is not accepted as an Ed448 digest: RFC 8419 §2.1 names `id-shake256`, and a signer naming the other identifier is reported as an algorithm mismatch.
- Neutral, because about 4 KB of Keccak joins the hash layer; a bundle that verifies no CMS does not carry it (`sideEffects: false`, tree-shaking probed by `scripts/verify-bundle.ts`).

### Confirmation

- `tests/hash/shake256.test.ts`: FIPS 202 known answers (the empty message; NIST's 1600-bit example), every padding boundary and output length against `node:crypto` as an independent oracle.
- `tests/crypto/crypto-algorithms.test.ts`, `tests/crypto/cms-verify.test.ts` and `tests/verify/verify-signed-data.test.ts`: an Ed448 signer built in the test with the host's own key verifies on Node.js; with `importKey` stubbed to refuse Ed448 it is `PKI_REASON_SIGNATURE_NOT_CHECKED` with `PKI_CRYPTO_KEY_UNSUPPORTED`; over SHA-512 it is `PKI_REASON_CMS_ALGORITHM_MISMATCH`.
- `.github/runtime-smoke/checks.mjs`: one Ed448 CMS message with its expectation per runtime — verified on Node.js, not checked on Bun and Chromium — run against the built package in CI.
- `scripts/data/pkits-smime-score.json` still holds the three DSA-signed PKITS S/MIME messages as reviewed deviations; the L8 gate fails on a change.

## More Information

- RFC 8419 §2.1 and §3.1 — the Ed448 digest algorithm for CMS; FIPS 202 §6.2 — SHAKE256; RFC 8702 §3.1 — SHAKE identifiers in CMS.
- [ADR 0001](0001-no-secret-dependent-cryptography.md) — why the digest may be computed here and the signature may not.
- [ADR 0004](0004-dsa-and-ed448-cms-signers-not-verified.md) — the record this one supersedes for Ed448, and whose DSA decision it restates.
- [docs/guides/standards.md](../guides/standards.md) — the RFC 5652 row names the per-host verdict.
