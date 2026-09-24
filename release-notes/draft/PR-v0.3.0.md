# release: v0.3.0 — write certificates, check signatures, hold no key

> **Branch:** `chore/release-v0.3.0` → `main`
> **Type:** Minor release (additive, fully backward-compatible with v0.2.0 — no export removed or renamed, no parsing behaviour changed)
> **Milestone:** `M2-creation-through-webcrypto`, the 0.3.x band of ROADMAP.md, closed in full

## Summary

pkinative stops being a reading library. It verifies a certificate's signature against its issuer, and it builds and signs certificates and PKCS#10 requests from typed descriptions — both through Web Crypto and nothing else. The security position that makes this worth shipping is negative rather than positive: `generateKey` and `exportKey` remain refused inside `src/` in **every** version, so the key belongs to the caller, `subjectPublicKey` is a SubjectPublicKeyInfo in DER rather than a `CryptoKey`, and the claim is checkable by a test instead of stated in a README.

The layering claim is checked on the built artefact, not in review: neither `crypto` nor `build` imports `x509`, and `verify-bundle` measures 12.7 KB for the verifier and 17.2 KB for the whole builder, each with no parser, no ASN.1 decoder, no OID registry and no hashes retained.

165 public exports (70 runtime, 95 types; 127 before) · 47 error codes · 26 diagnostic codes · 11 named limits · 52 verify-docs rules · 8 bundle probes · 1 406 tests · 100.0 % statements, branches, functions and lines.

## Changes

### Engine surface

27 runtime exports and 11 types added; **nothing removed or renamed**, verified by diffing `docs/assets/api.json` against the v0.2.0 tree.

- `crypto` layer — `verifyCertificateSignature`, `verifySelfSignature`, `canVerify`, `canSign`, `PkiCryptoError` and its three codes. RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA on P-256/384/521, Ed25519 and Ed448.
- `build` layer — `createCertificate`, `createCertificationRequest`, `signatureAlgorithmDer`, and fifteen structural and extension-value encoders.
- `asn1` — `encodeExplicit`, `encodeImplicit`, `encodeEnumerated`, `encodeNamedBits`.

One behaviour change inside a new-in-this-release surface: a `serialNumber` given as content octets is now validated. An empty or non-minimal value throws `PKI_API_MISUSE` rather than producing a certificate pkinative's own decoder refuses with `PKI_ASN1_INTEGER_INVALID`. A negative serial is still written in that form — it exists to reproduce an existing serial byte for byte — and returns `PKI_DIAG_SERIAL_NOT_POSITIVE` on read.

### Tooling (scripts/)

- `KEY_OPERATION_POLICY` and `WEBCRYPTO_HOST_MODULES` replace the blanket eleven-operation ban, which refused the operations everywhere in `src/` including in a type declaration and so made 0.3 undeclarable. The policy is per **module**, not per layer.
- `LAYERS` gains `crypto` and `build`, each in the commit that introduced its first file.
- `verify-bundle` gains the builder probe; 8 probes total.
- `release-prepare.ts` scaffolds this file alongside the release note.

### CI and repository (.github/, root)

- `fuzz.yml` — ClusterFuzzLite, PR code-change mode and a weekly batch. Non-blocking **by construction**: the ruleset names the seven contexts that block a merge and this is not one of them.
- `.clusterfuzzlite/` — Dockerfile pinned by digest (resolved against gcr.io, not written from memory), `build.sh`, `project.yaml`. Jazzer.js is installed with `--no-save` inside the image and never enters `package.json`.
- Both shell tools are now guarded: `.claude/settings.json` wired the hook and the deny families to `Bash` alone, which on Windows is not a deny list.

### Agent layer (.claude/, AGENTS.md, governance)

- `.github/instructions/security.instructions.md` and `pki-core.instructions.md` rewritten for the two new layers; `.claude/rules/` regenerated from them. The previous text told an agent to deny that pkinative verifies signatures — the most expensive kind of stale instruction.
- `release-notes/PR_TEMPLATE.md` is the source of this file.

### Tests and conformance

- `tests/build/` (2 files), `tests/asn1/asn1-encode-tagging.test.ts`, `tests/fuzzing/targets.test.ts`, and the crypto suites. 1 406 tests, 100 % on all four axes with no per-path override.
- Every structure a test or a recipe builds is parsed back with `onDiagnostic` and **zero diagnostics** is the assertion.
- Six algorithms round-tripped through OpenSSL 3.5.5 by hand during development — each certificate and CSR read and verified by `openssl` before pkinative read it again. This is not automated yet; the interoperability matrix that automates it is the 0.4.0 band.

### Documentation

- `docs/guides/use-cases.md` grows a sixth job and loses the row that promised it.
- `recipes/create-certificate.ts` (new) and `recipes/asn1-primitives.ts` (extended) — 10 executable recipes, each asserted on every test run.
- SECURITY.md gains the key-operation table and the fuzzing section, the latter stating plainly that the container has never executed.

## Independent audit

`/release-audit release-notes/v0.3.0.md v0.2.0` — **PENDING**

Not run. This PR is not ready to merge until it is.

## Validation (what actually ran, on Windows 11 Pro 26200, Node 22)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 12 passed, 0 skipped in 344.3 s` |
| `npm run test:coverage` | 1 406 tests across 50 files; statements 100 %, branches 100 %, functions 100 %, lines 100 % |
| `npm run verify:bundle` | 8 probes within budget; largest is `{ * }` at 111.8 KB against 118 KB; the builder probe is 17.2 KB against 20 KB |
| `npx tsx scripts/verify-docs.ts` | `52 rule(s), 0 error(s), 0 warning(s)` |
| `npx tsx scripts/validate-certs.ts --require-all` | L0 9 793 cases / 30 361 certificates · L1 29 797 parsed, 564 refused, all in the baseline · L2 30 361 re-encoded byte for byte · L3 `node:crypto` (OpenSSL 3.0.16) 29 797/29 797 and OpenSSL 4.0.0 202/202 · L4 Microsoft CryptoAPI 202/202 on all five fields · Wycheproof 1 530 vectors · `PASSED: 0 failure(s), 0 skip(s)` |
| `npm run check:package` | attw + publint clean (gate step `check:package` PASS) |
| `npm run smoke:install` | ESM and CJS both load from the packed tarball (gate step PASS) |
| `npm pack --dry-run` | 12 files, 405.8 kB packed, 1.7 MB unpacked |
| `npm ls --omit=dev --all` | `pkinative@0.3.0` and `(empty)` — no runtime dependency |
| ClusterFuzzLite | **not run.** The container has never executed; this repository has no pushed history. `tests/fuzzing/targets.test.ts` proves the three targets load, survive a seeded corpus and rethrow a non-`PkiError`; the container wiring is unproven. |
| `npm run bench` | **not run.** No benchmark exists yet; `bench.yml` is the 0.4.0 band. |

## Backward compatibility

Every export present in v0.2.0 keeps its name, its signature and its behaviour. The additions are new modules reached through new names, and `parseCertificate`, `decodeAsn1`, `decodePem` and the readers are byte-for-byte unchanged in behaviour — the conformance corpus verdicts are identical to v0.2.0 (564 refusals, same baseline file, unmodified).

A consumer switching exhaustively on `PkiErrorCode` must handle three new values. They mean "could not check", never "the certificate is bad".

## Out of scope (tracked in ROADMAP.md)

- Path validation, CRL and OCSP — 0.5.0, and the `PkiReasonCode` vocabulary lands **first** in that band, before RFC 5280 §6, so verdict codes are never expressed as exception codes.
- The interoperability matrix and conformance level L5 (RFC 5280 §4 clause by clause) — 0.4.0. The write direction of the matrix was impossible before this release created anything.
- CMS and RFC 3161 — 0.7.0. PKCS#8 and PKCS#12 under PBES2 only — 0.8.0, where the error vocabulary freezes.

## Human-in-the-loop — steps for the maintainer

1. Squash-merge to `main` with the title `release: v0.3.0 — write certificates, check signatures, hold no key`.
2. Wait for the seven required checks: `ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`.
3. Tag `v0.3.0` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `v0.3.0 — write certificates, check signatures, hold no key`, body = `release-notes/v0.3.0.md`).
   Below 1.0.0 expect `release-assets` green and `publish` red — the pre-1.0 refusal is deliberate and is the only proof the 1.0 guard still works.
5. Version-specific: watch the **first** `fuzz.yml` run. Nothing in it has ever executed. If the image build fails, that is expected information and not a reason to hold the tag — the workflow blocks nothing. Remove the "has not yet executed" note from SECURITY.md once a run is green.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [ ] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — or the section says PENDING and this PR is not ready to merge.
