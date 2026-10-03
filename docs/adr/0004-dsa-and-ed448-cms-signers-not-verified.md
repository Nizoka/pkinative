---
status: superseded by ADR 0022
date: 2026-09-29
since: 0.3.0
---

# DSA signatures and Ed448 CMS signers are not verified

## Context and Problem Statement

pkinative verifies signatures through Web Crypto and implements no signature algorithm of its own ([ADR 0001](0001-no-secret-dependent-cryptography.md)). The set it verifies is what Web Crypto offers: RSA PKCS#1 v1.5 and PSS, ECDSA on P-256/384/521, Ed25519 and Ed448 ([release-notes/v0.3.0.md](../../release-notes/v0.3.0.md)). Two signatures that appear in conformance corpora fall outside it:

- **DSA.** Web Crypto implements none of it. NIST PKITS has DSA certificates, and its S/MIME messages include three DSA signatures.
- **Ed448 as a CMS signer.** An Ed448 CMS signer digests the content with SHAKE256 (RFC 8419 §3.1), which neither Web Crypto nor pkinative computes. An Ed448 *certificate* signature is a different case and is verified wherever the runtime implements Ed448.

## Decision Drivers

- AGENTS.md §Mission and constraints: no signing algorithm in TypeScript — signing and verification are one call to Web Crypto with the caller's key.
- "Could not be checked" must never be reported as "invalid": a runtime that lacks an algorithm says nothing about whether a signature is good ([docs/guides/errors.md](../guides/errors.md)).
- Every disagreement with a corpus carries a written reason ([docs/guides/conformance.md](../guides/conformance.md)).

## Considered Options

1. Implement DSA verification, and SHAKE256, in TypeScript.
2. Verify what Web Crypto verifies; report the rest as not checked, with a distinct error or reason.

## Decision Outcome

Chosen option: 2. A certificate signature Web Crypto cannot express is `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` from the primitive, and `PKI_REASON_SIGNATURE_NOT_CHECKED` — never `PKI_REASON_SIGNATURE_INVALID` — in a report. An Ed448 CMS signer is refused with `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` naming SHAKE256 (`resolveCmsAlgorithm` in `src/crypto/crypto-algorithms.ts`).

The two halves carry different weight in the repository, and this record keeps them apart. For DSA the 0.5.0 release note is categorical: "DSA is not supported and never will be". For Ed448 CMS signers, the stated reason is that no one computes SHAKE256 here; hashing public data in TypeScript is permitted by ADR 0001, so the gap is not a matter of principle — it is closed for the 0.x line by the freeze, since 0.9 admits no new engine behaviour and 1.0 adds none over 0.9 ([ROADMAP.md](../../ROADMAP.md)).

### Consequences

- Good, because no signature algorithm exists in `src/`, and the verdict for an unsupported algorithm is honest: "ask elsewhere", not "bad".
- Good, because the corpora record every consequence: two of the nine NIST PKITS deviations are DSA (`ValidDSASignaturesTest4`, `ValidDSAParameterInheritanceTest5`), and three of the 224 PKITS S/MIME messages are not intact at the CMS layer because they are DSA-signed.
- Bad, because a DSA-signed chain or message cannot be validated by pkinative at all, and an Ed448-signed CMS message cannot either.
- Bad, because Ed448 certificate verification depends on the runtime: some implement it, some do not ([docs/data/reasons.json](../data/reasons.json)).

### Confirmation

- `scripts/data/pkits-score.json` and `scripts/data/pkits-smime-score.json` hold each DSA case as a reviewed deviation with its reason; the L7 and L8 gates fail on a new disagreement or an unexpected agreement.
- `docs/data/errors.json` (`PKI_CRYPTO_ALGORITHM_UNSUPPORTED`) and `docs/data/reasons.json` (`PKI_REASON_SIGNATURE_NOT_CHECKED`), each held to the code both ways by `error-parity` and `reason-parity`.

## More Information

- [release-notes/v0.5.0.md §Known limitations](../../release-notes/v0.5.0.md) — DSA.
- [release-notes/v0.7.0.md §Known limitations](../../release-notes/v0.7.0.md) — "DSA and Ed448 signers are not verified: Web Crypto implements neither DSA nor SHAKE256".
- The certificate-signature set took effect at 0.3.0; the Ed448 CMS refusal at 0.7.0, with the CMS layer.
- Superseded at 1.0.0 by [ADR 0022](0022-ed448-cms-signers-host-dependent.md) for its Ed448 half: SHAKE256 is computed in `src/hash/shake256.ts` under ADR 0001, and an Ed448 CMS signer is verified wherever the host verifies Ed448. The DSA half is unchanged, and ADR 0022 restates it.
