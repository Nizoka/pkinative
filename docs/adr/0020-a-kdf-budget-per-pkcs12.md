---
status: accepted
date: 2026-10-01
since: 1.0.0
---

# One PKCS#12 costs a bounded number of PBKDF2 iterations in total: maxPkcs12KdfIterations joins the limits before the freeze

## Context and Problem Statement

A PKCS#12 declares its own key-derivation cost. Every PBES2 SafeContents, every shrouded key and an RFC 9579 PBMAC1 MAC carries a PBKDF2 iteration count, and the host runs that count inside Web Crypto, where no JavaScript bound can interrupt it ([ADR 0002](0002-pkcs12-pbes2-only.md)). Since 0.8.0 `maxKdfIterations` (10 000 000) has bounded each derivation before the host runs it ([src/keys/key-pbes2.ts](../../src/keys/key-pbes2.ts)).

The pre-publication audit of 1.0.0 found that nothing bounded the **number** of derivations. A file with no MAC and random ciphertext, built without knowing any password, made `openPkcs12` run one maximal derivation per `encryptedData` entry: 9.9 s for one entry, 34 s for three, and, extrapolated to the 4 096 entries `maxPkcs12Bags` admits, about eleven hours of PBKDF2 per call. That is the CVE-2022-36083 class — an attacker-chosen PBKDF2 count, CWE-400 at the GitHub CNA and CWE-834 at NVD — applied to the whole file rather than to one field. SECURITY.md said ten million iterations was "below a hang", which was true of one derivation only.

The fix needs a new member of `PkiLimits`. `docs/assets/api.frozen.json` already records the 1.0.0 surface as stable, and in the stable phase `api-surface-frozen` classifies a new required member of an interface that reaches a parameter as semver-major. The question is whether the bound can land before 1.0.0 is tagged, and under what name, since limit names are frozen at 1.0 ([ADR 0012](0012-frozen-error-vocabulary.md)).

## Decision Drivers

- **Every loop over input consults a named, CWE-tagged limit** (AGENTS.md). A loop over derivations that consults none breaks the doctrine, and the per-derivation limit alone cannot hold a total.
- **1.0.0 is prepared but not tagged, not published.** A change to the surface now costs a snapshot move, and after the tag it would cost either a major release or a limit that no caller's full `PkiLimits` literal expects.
- **The name is frozen forever.** It should say what it counts and over what, in the vocabulary the table already uses: `maxPkcs12Bags` is "the SafeBags read from one PKCS#12", so a PKCS#12-wide total belongs beside it.
- **Real files must keep opening.** OpenSSL 3 declares 2 048 iterations for each derivation by default (openssl-pkcs12(1)); Java's keytool declares 10 000 for the certificate encryption, the key encryption and the MAC (`keystore.pkcs12.*IterationCount` in `java.security`). GnuTLS's certtool wrote 600 000 in the files measured below. A file derives a few times.
- **The bound must hold where the file is not yet readable.** A shrouded key inside an encrypted SafeContents is only visible after that SafeContents is decrypted.

## Considered Options

1. Lower `maxKdfIterations` far enough that 4 096 derivations are bearable.
2. Stop deriving after the first decryption failure, since one password opens every entry.
3. A new limit, `maxPkcs12KdfIterations`, bounding the PBKDF2 iterations one PKCS#12 costs in total, checked before each derivation runs.

## Decision Outcome

Chosen option: 3, with a default of 10 000 000 — the per-derivation maximum. One untrusted file then costs at most what one maximal derivation already cost, about ten seconds of SHA-256, however it is built; the files real writers produce stay far below it: of 48 files written by OpenSSL, .NET, Java, GnuTLS and pyca/cryptography for the audit, the costliest — GnuTLS, 600 000 iterations for its encrypted SafeContents and 600 000 for its key — declares 1 200 000 in total.

Option 1 would refuse files a legitimate writer produces with a high count on one key, and would still leave 4 096 derivations. Option 2 is a heuristic, not a bound: a file whose first entry decrypts pays nothing less for the rest, and a report that stops at the first failure no longer says what else the file holds.

It is enforced at three places, so that each entry point bounds what it can see:

- `parsePkcs12` sums the counts it can see — the PBMAC1 MAC, every PBES2 SafeContents, every shrouded key in a plain SafeContents — and throws `PKI_LIMIT_EXCEEDED` before anything is derived. A scheme pkinative refuses, an RFC 7292 Appendix B MAC and public-key privacy mode cost nothing, because nothing derives them.
- `openSafeContents` refuses its own derivation past the budget before running it, and, once decrypted, the derivation together with the shrouded keys the plaintext reveals.
- `openPkcs12` charges every derivation it asks the host for, the keys inside encrypted SafeContents included, before each one runs. A charge that is refused leaves the total unchanged, since nothing ran; it is reported, as `maxKdfIterations` already was, as `PKI_REASON_INPUT_MALFORMED` carrying `PKI_LIMIT_EXCEEDED`.

The surface moves on this record: the 1.0.0 snapshot is restored to its rehearsal, moved with `npx tsx scripts/build-api-frozen.ts --rebaseline docs/adr/0020-a-kdf-budget-per-pkcs12.md`, and rebased again with `--major 1.0.0`, which is refused unless the rehearsal, rebaselined, still holds. This is the third use of the rebaseline mode, after [ADR 0013](0013-renames-before-the-freeze.md) and [ADR 0015](0015-no-default-rsa-scheme.md), and the last one: once 1.0.0 is tagged the mode no longer applies.

### Consequences

- Good: a PKCS#12 from an untrusted source costs a bounded amount of key derivation in every entry point, and SECURITY.md's "about ten seconds" is true of the file.
- Good: the name pairs with `maxPkcs12Bags` and says what it counts; a caller who opens a trusted keystore of many keys at high counts raises one limit.
- Bad: `PkiLimits` has one more required member, so a caller who writes a full `PkiLimits` literal must add it. Before the tag, that caller is hypothetical.
- Bad: a caller composing `parsePkcs12`, `openSafeContents` and `decryptPrivateKey` by hand is bounded per call, not across the calls it chooses to make; `openPkcs12` is the entry point that bounds the whole file.
- Not changed: `maxKdfIterations` still bounds each derivation, with the same default.

### Confirmation

- `tests/keys/key-pkcs12.test.ts` rebuilds the audit's file — three entries of ten million iterations, random ciphertext, no MAC — and `parsePkcs12` refuses it with `limit: 'maxPkcs12KdfIterations'` and `observed: 30000000`; the sum takes each of the MAC, the SafeContents and the keys, and refused schemes count nothing.
- `tests/verify/verify-pkcs12.test.ts`: `openPkcs12` reports the same file at once; a key revealed inside an encrypted SafeContents is refused past the budget, and a cheaper key after it still opens.
- `limits-parity` holds the limit to `src/core/pki-limits.ts`, `docs/data/limits.json` and SECURITY.md; `api-surface-frozen` holds `PkiLimits` to the snapshot, whose `rebaselines` log names this record.

## More Information

- CVE-2022-36083 (jose): an attacker-chosen PBES2 count; fixed by capping it with `maxPBES2Count`, default 10 000.
- RFC 8018 §5.2 — PBKDF2 and its iteration count.
- RFC 7292 §4 — the AuthenticatedSafe, whose every entry may be separately encrypted.
