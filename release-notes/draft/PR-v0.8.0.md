# release: v0.8.0 — private keys, and the vocabulary frozen

> **Branch:** `chore/release-v0.8.0` → `main`
> **Type:** Minor release (additive; the one-call reports tighten toward their documented contract, described below)
> **Milestone:** M5 — Keys, and the vocabulary frozen

## Summary

pkinative could sign with a key the caller had already imported; this release opens the files keys live in. PKCS#8, encrypted or not, and PKCS#12 are read under PBES2 only, by policy — RFC 7292's own schemes derive their key with Appendix B, iterated hashing with byte arithmetic over a password, which this library will not implement — and every encrypted key is unwrapped straight into a non-extractable `CryptoKey` without its plaintext existing in JavaScript. `readPkcs12` opens a whole `.p12` in one call and fails closed on integrity it cannot check. And the error-code vocabulary is frozen: 57 codes in `docs/data/errors.frozen.json`, held by a rule.

Zero runtime dependencies. No export removed or renamed. The seeded fuzzer that now drives every one-call report found a CRL escape and a misuse leak; the interop run against OpenSSL and Windows found a misreported legacy key. All three are fixed with locking tests.

Counts: **281** public exports (170 types, 111 values) · **57** error codes (frozen) · **39** diagnostic codes · **42** reason codes · **21** named limits · **58** verify-docs rules · **18** bundle probes · **3 231** tests · **100 %** statements, branches, functions and lines.

## Changes

### Engine surface

A new layer, `keys` (`types, core, asn1, crypto` — never `x509`), registered with its first file; `verify` gains `keys`.

- `src/crypto/webcrypto.ts` — `deriveKey`, `unwrapKey` and `decrypt` opened at the door in their own commit, each returning a handle or public bytes; `canDecrypt`, `derivePasswordKey`, `unwrapPrivateKey`, `importPkcs8Key`, `decryptContent`, `verifyMac`.
- `src/keys/key-pbes2.ts` — PBES2 read and bounded by `maxKdfIterations` before the host runs anything; every refused scheme described by name.
- `src/keys/key-pkcs8.ts`, `src/keys/key-import.ts` — `parsePrivateKeyInfo`, `parseEncryptedPrivateKeyInfo`, `importPrivateKey`, `decryptPrivateKey`.
- `src/keys/key-pkcs12.ts` — `parsePkcs12`, `verifyPkcs12Mac` (RFC 9579 PBMAC1), `openSafeContents`.
- `src/verify/verify-pkcs12.ts` — `readPkcs12`. `src/verify/verify-chain.ts` — argument guards shared by every report, a CRL entry reported rather than thrown, CRL reasons by the caller's index.
- `src/types/` — `PkiKeyError` and its four codes, `PKI_CRYPTO_DECRYPTION_FAILED`, `key-types.ts`, the `HostSubtle` probe type; six reasons, one diagnostic, two limits. `src/core/key-oids.ts`.

### Tooling (scripts/)

- `scripts/verify-docs/rules/` — `error-codes-frozen` and `pkcs12-policy-parity` (new); `error-parity` decides every throw site's code statically; `count-tokens` parses compound number words; `interop-matrix-declared` holds the key-container cases to the conformance guide.
- `scripts/build-errors-frozen.ts` — writes the snapshot, and refuses to once the version reaches `frozenAt`.
- `scripts/lib/interop-keys.ts`, `scripts/run-interop.ts` — the read direction for key containers, OpenSSL and Windows.
- `scripts/verify-bundle.ts` — three key probes; the package budget raised in the commit that measured it.

### CI and repository (.github/, root)

No workflow changed; `conformance.yml` already runs `npm run interop`, which now includes the key containers.

### Agent layer (.claude/, AGENTS.md, governance)

`AGENTS.md` records the `keys` layer and the six key operations of the door; `.github/instructions/security.instructions.md` and `api-design.instructions.md` state the door and the freeze; `.claude/rules/*.md` regenerated.

### Tests and conformance

3 231 tests across 87 files, 100 % on all four axes, the same three justified `v8 ignore` comments. New: `tests/keys/`, `tests/crypto/webcrypto-password.test.ts`, `tests/verify/verify-pkcs12.test.ts`, `tests/fuzzing/pkcs12.test.ts`, `tests/fuzzing/reports.test.ts`; two engine-independent writers, `tests/helpers/pkcs12-builder.ts` and the recipes' own. The interop matrix gained 63 read-direction checks.

### Documentation

`docs/guides/use-cases.md` "Private keys and PKCS#12"; `docs/guides/errors.md` the key codes, diagnostic and reasons; `docs/guides/conformance.md` the key-container interop table; SECURITY.md the password-based encryption table; two recipes, `recipes/private-key.ts` and `recipes/pkcs12.ts`.

## Independent audit

`/release-audit release-notes/v0.8.0.md v0.7.0` — **PENDING**

This PR is not ready to merge until the ledger is attached here with a fix commit for every confirmed blocker and major.

## Validation (what actually ran, on Windows 11 Pro 10.0.26200, Node 22.17.0)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 14 passed, 0 skipped in 1039.7 s` |
| `npm run test:coverage` | 3 231 tests across 87 files; statements 100 % (5 734/5 734), branches 100 % (4 227/4 227), functions 100 % (716/716), lines 100 % (4 976/4 976) |
| `npm run verify:bundle` | 18 probes, largest `{ * }` 259.6 KB against a 272 KB budget |
| `npx tsx scripts/verify-docs.ts` | 58 rules, 0 errors, 0 warnings |
| `npx tsx scripts/validate-certs.ts --require-all` | L5 19 clauses, 17 exercised · L6 9 156/9 208 (99.44 %) · L7 194/203 (95.57 %) · L8 221/224 intact, 204/204 equal to L7, 195/204 agree with NIST · Wycheproof 1 530 ECDSA vectors |
| `npm run interop` | OpenSSL 4.0.0: 11 checks agree, 45 read-direction checks over 13 key containers; Windows CryptoAPI: 6 checks agree, 18 over 4; windows-certutil, java-keytool and python-cryptography declared and not implemented |
| `npm run check:package` | attw + publint clean (inside the publish gate) |
| `npm run smoke:install` | ESM and CJS load from the packed tarball (inside the publish gate) |
| `npm pack --dry-run` | 12 files, 1.1 MB packed, 4.4 MB unpacked |
| `npm ls --omit=dev --all` | `pkinative@0.8.0` alone — zero runtime dependencies |

The publish gate ran on `5fb1316`, the commit before the bump; the bump changes versions and install URLs only.

## Backward compatibility

Every public export of v0.7.0 keeps its name and signature. Two changes tighten toward the documented contract, and are listed in the release note's Downstream integration notes: the one-call reports throw for misuse they used to turn into a reason, and three parsers throw `PKI_INVALID_INPUT` where a non-byte argument used to throw a `TypeError` or a length error. From this release the 57 error codes are frozen: removing or renaming one is a major version.

## Out of scope (tracked in ROADMAP.md)

- RFC 7292 Appendix B, RC2 and 3DES — refused in every version, by policy.
- Verifying a PKCS#12 MAC other than PBMAC1.
- `id-RSASSA-PSS` private keys, which no current runtime's Web Crypto imports.
- Writing PKCS#8 or PKCS#12.
- ClusterFuzzLite has still never executed.

## Human-in-the-loop — steps for the maintainer

0. **v0.5.0 and v0.7.0 first.** This branch stacks on the prepared, untagged 0.7.0 (itself on 0.5.0); their audits, merges and tags come before this one, and the audit above compares against `v0.7.0`.
1. Squash-merge to `main` with the title `release: v0.8.0 — private keys, and the vocabulary frozen`.
2. Wait for the seven required checks: `ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`.
3. Tag `v0.8.0` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `v0.8.0 — private keys, and the vocabulary frozen`, body = `release-notes/v0.8.0.md`).
   Below 1.0.0 expect `release-assets` green and `publish` red — the pre-1.0 refusal is deliberate and is the only proof the 1.0 guard still works.
5. **Announce the freeze** with the release: after this tag, renaming an error code is a major version. The bootstrap of `main` and the ruleset import (B0–B8) are still outstanding and are not part of this release.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — **PENDING, so this PR is not ready to merge.**
