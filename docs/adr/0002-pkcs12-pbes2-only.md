---
status: accepted
date: 2026-09-29
since: 0.8.0
---

# PKCS#8 and PKCS#12 are opened under PBES2 only, and integrity fails closed

## Context and Problem Statement

0.8 opens the files private keys live in: PKCS#8, encrypted or not, and PKCS#12. RFC 7292's own schemes derive their key with the Appendix B KDF — iterated hashing with byte arithmetic over the password — and protect the content with 3DES, 40-bit RC2 or RC4; PBES1 adds DES, RC2 and MD2. Web Crypto offers none of that KDF. Worse for integrity: most PKCS#12 MACs are keyed with Appendix B too — even OpenSSL 3 files encrypted with AES and PBKDF2 — so a reader that implements no Appendix B cannot check them ([ROADMAP.md §0.8.x](../../ROADMAP.md)).

The interop run measured what real writers produce by default: OpenSSL `-export` keys its MAC with Appendix B, Windows exports 3DES, and .NET 9's AES export still uses the Appendix B MAC ([release-notes/v0.8.0.md](../../release-notes/v0.8.0.md)). The question is what to open, what to refuse, and what to report when integrity cannot be checked.

## Decision Drivers

- [ADR 0001](0001-no-secret-dependent-cryptography.md): the Appendix B KDF is secret-dependent code pkinative would have to write in TypeScript.
- An encrypted key's plaintext must never exist in JavaScript: every step has to be one Web Crypto call.
- A refusal must say what the file holds, before anyone types a password, and name a remedy that works.
- An unverified MAC must never read as a verified one: without a MAC, an unencrypted bag can be replaced by anyone who can write the file ([CHANGELOG.md, 0.8.0](../../CHANGELOG.md)).

## Considered Options

1. Implement Appendix B, RC2 and 3DES in TypeScript, as the files in the wild require.
2. Open PBES2 (PBKDF2 with HMAC-SHA-1/256/384/512, AES-CBC) only; describe and refuse every other scheme by name; verify only the RFC 9579 PBMAC1 MAC.
3. For integrity: report a MAC that cannot be checked as a warning and carry on, or fail closed unless the caller opts out.

## Decision Outcome

Chosen option: 2, with the fail-closed branch of 3. Option 1 is the secret-dependent cryptography this library exists without, so the refusal is a policy and not a gap. Every refused scheme is still recognised, so `parseEncryptedPrivateKeyInfo` and `parsePkcs12` say what protects a file, and opening one throws `PKI_KEY_ENCRYPTION_UNSUPPORTED` (a MAC that is not PBMAC1, `PKI_KEY_MAC_UNSUPPORTED`) with a conversion in the remedy, verified against OpenSSL 4.0.0:

```bash
openssl pkcs12 -in legacy.p12 -legacy -out bundle.pem
openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12
```

`openPkcs12` reports a MAC it cannot check as `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` and calls the container invalid unless the caller passes `allowUnverifiedIntegrity`. The password is UTF-8, as RFC 9579 and OpenSSL use it, or octets as given — not the BMPString of the refused KDF.

### Consequences

- Good, because no line of secret-dependent code exists: PBKDF2 and the PBMAC1 HMAC run in the host, and an encrypted key is unwrapped straight into a non-extractable `CryptoKey`.
- Good, because a tool can say what a file holds before asking for a password, and the remedy is a command that was run before it was written down.
- Good, because a file pkinative vouches for is one whose integrity it actually checked.
- Bad, because most PKCS#12 files in circulation cannot be integrity-checked here, and legacy ones cannot be opened at all: the caller converts them once.
- Bad, because a plain keyBag a writer nests inside an encrypted SafeContents is plaintext once opened; `openPkcs12` wipes those bytes after import, and that is a best effort, stated as one ([SECURITY.md](../../SECURITY.md)).

### Confirmation

- The `pkcs12-policy-parity` rule of `npm run verify:docs` holds the SECURITY.md table of opened and refused schemes to `HMAC_OIDS`, `AES_CBC_OIDS` and `REFUSED_PBE_SCHEMES` in `src/core/key-oids.ts`, both ways.
- `KEY_OPERATION_POLICY` refuses `deriveBits`, so the password can only become a non-extractable handle.
- `maxKdfIterations` bounds the iteration count a file declares before the host runs a single iteration.
- The interop read direction (`npm run interop`): OpenSSL 4.0.0, 45 checks over 13 key containers; Windows' .NET, 18 checks over 4 — every opened key signs data the foreign tool verifies, every refused one is refused by name ([docs/guides/conformance.md](../guides/conformance.md)).
- `tests/fuzzing/pkcs12.test.ts` refuses every truncation of its corpus files with a `PkiError`, and ends 10 000 seeded mutations of them in a PKCS#12 or a `PkiError`.

## More Information

- [SECURITY.md §Password-based encryption](../../SECURITY.md) — the table and the conversion.
- [ROADMAP.md §0.8.x](../../ROADMAP.md) — the decisions taken at the start of the band, each against a detail of the original plan that turned out wrong.
- [CHANGELOG.md, 0.2.0](../../CHANGELOG.md) — PKCS#12 reading first stated as PBES2 only, in the roadmap change of that release; it shipped at 0.8.0.
- `docs/data/errors.json` and `docs/data/reasons.json` — `PKI_KEY_ENCRYPTION_UNSUPPORTED`, `PKI_KEY_MAC_UNSUPPORTED`, `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED`, `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED`.
