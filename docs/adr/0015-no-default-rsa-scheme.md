---
status: accepted
date: 2026-09-29
since: 1.0.0
---

# No default RSA scheme: openPkcs12 opens an RSA key only with the scheme the caller names

## Context and Problem Statement

`openPkcs12` unwraps each private key straight into a non-extractable `CryptoKey`, so Web Crypto must be told the key's algorithm before it decrypts it ([ADR 0001](0001-no-secret-dependent-cryptography.md), [src/verify/verify-pkcs12.ts](../../src/verify/verify-pkcs12.ts)). It takes that algorithm from the certificate sharing the key's `localKeyId`. For ECDSA and EdDSA the certificate is enough: the curve or the key type names what the key signs with, and an ECDSA key's hash is chosen again at every signature. An `rsaEncryption` certificate is not enough. It names an RSA key and says nothing of the scheme — RSASSA-PKCS1-v1_5 or RSASSA-PSS, RFC 8017 §8 — or of the hash, and a Web Crypto RSA key is bound to one scheme and one hash when it is imported.

From 0.8.0 to 0.9.0 `openPkcs12` filled the gap with a default, `{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }`, the scheme of nearly every RSA certificate in use. At 1.0.0 that default would become a promise for the whole major line. The question is whether pkinative should make that promise, or refuse to guess.

## Decision Drivers

- **A default is the one thing semver cannot take back within a major.** `api-surface-frozen` reduces a constant to its declared type: a changed default value is behaviour, not surface ([.github/instructions/api-design.instructions.md §Backward Compatibility](../../.github/instructions/api-design.instructions.md)). Once 1.0.0 opens an RSA key as PKCS#1 v1.5 with SHA-256 when asked nothing, changing that default is silently breaking, and removing it is semver-major. The reverse is not true: a 1.x minor may add a default where there was none, because every call that worked keeps working.
- **A wrong guess cannot be corrected by the caller.** The key is non-extractable, by design, so a caller holding a PSS key opened as PKCS#1 v1.5 cannot re-import it with the right scheme: they must open the file again.
- **The library's own primitive already refuses.** `importPrivateKey` throws `PKI_API_MISUSE` for an RSA key until the caller names its scheme ([docs/guides/use-cases.md §Private keys and PKCS#12](../guides/use-cases.md)). Two entry points to the same key should not answer the same question differently.
- **The platforms pkinative is built on are explicit.** Web Crypto's `importKey` and `unwrapKey` take the algorithm as a required argument, and pkinative's doctrine is to refuse ambiguity rather than resolve it silently (DER strict by default, `.github/instructions/security.instructions.md` "Refuse ambiguity").
- **Where the default points is moving.** PKCS#1 v1.5 is what certificates carry today; RSASSA-PSS is what newer profiles ask for. A default chosen in 2026 is the one most likely to be wrong by the end of a major line.
- **The report must still be useful.** `openPkcs12` never rejects for a problem with the file, and the certificates, CRLs and other keys of a file are worth reporting even when one key cannot be opened.

## Considered Options

1. Keep the default, `RSASSA-PKCS1-v1_5` with SHA-256, and freeze it at 1.0.0.
2. Make `rsaAlgorithm` a required option, for every file, RSA or not.
3. No default: an RSA key whose certificate is `rsaEncryption` is opened only with the scheme the caller names; without it the key stays shut, the report is `valid: false` with a new reason code naming the option, and everything else in the file is still reported.

## Decision Outcome

Chosen option: 3. It keeps both doors open — a later minor may introduce a default if the ecosystem settles on one, and nothing then breaks — where option 1 closes one for the whole of 1.x. Option 2 would make every caller of an ECDSA or EdDSA file name an RSA scheme that does not apply to them, and a required option cannot be relaxed back to optional without the same kind of review.

The reason is `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` (standard RFC 8017 §8). It is returned, not thrown, because the file is well formed: what is missing is a decision only the caller can make, and the report keeps the certificate, so the caller can see which key it is before choosing. `rsaAlgorithm` keeps its type and its validation: anything but `RSASSA-PKCS1-v1_5` or `RSA-PSS` over SHA-1, SHA-256, SHA-384 or SHA-512 is still `PKI_INVALID_OPTION` before the file is read.

This is a behaviour change and a new reason code in the rehearsal band, where both are otherwise refused. It is made here because it is the last moment it costs a minor; `npx tsx scripts/build-api-frozen.ts --rebaseline docs/adr/0015-no-default-rsa-scheme.md` moves the snapshot on this record, the second use of that mode after [ADR 0013](0013-renames-before-the-freeze.md).

### Consequences

- Good: 1.0.0 promises nothing about which RSA scheme a key is opened as, and a default can still be added in a minor.
- Good: `openPkcs12` and `importPrivateKey` agree; no RSA key anywhere in pkinative is bound to a scheme the caller did not name.
- Bad: the common case — an RSA `.p12` from OpenSSL or Windows — needs one more option than it did in 0.8 and 0.9. The reason's message and remedy name the exact option to pass, and the guide's example passes it.
- Bad: a caller who ignores `valid` and reads `keys[0].signingKey` finds `undefined` for an RSA file. That is the fail-closed outcome the report is designed around.
- Not changed: a certificate whose key is `id-RSASSA-PSS` is still reported `PKI_REASON_PKCS12_KEY_UNSUPPORTED`. Taking the scheme and hash from its parameters is a possible later addition, and it would be one.

### Confirmation

- `tests/verify/verify-pkcs12.test.ts`: an RSA file without `rsaAlgorithm` reports `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` alone, `valid: false`, the certificate reported and the key `undefined`; with PKCS#1 v1.5 or PSS named, the key opens and signs as its certificate.
- `docs/data/reasons.json` registers the code, and `reason-parity` holds it to the union in `src/types/pki-reasons.ts`.
- `docs/assets/api.frozen.json` lists the code among its reasons, and its `rebaselines` log names this record.
- The interoperability harness (`scripts/lib/interop-keys.ts`) opens every OpenSSL and Windows container with the scheme named, as a caller would.

## More Information

- RFC 8017 §8 — the two RSA signature schemes an `rsaEncryption` key may be used with.
- RFC 4055 §1.2 — `id-RSASSA-PSS` as a key identifier that does restrict the scheme.
- W3C Web Cryptography API — `importKey` and `unwrapKey` take the algorithm as a required argument.
