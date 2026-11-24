# release: v1.1.0 — post-quantum verification, attribute certificates, request readers

> **Branch:** `chore/release-v1.1.0` → `main`
> **Type:** Minor release (additive, fully backward-compatible with v1.0.0)
> **Milestone:** ROADMAP.md "1.1.x — next, additive by construction"

## Summary

The first minor of the 1.x line. Zero runtime dependencies, no breaking change: 29 exports added (300 → 329), none removed or re-typed; one error code added (`PKI_X509_ATTRIBUTE_MALFORMED`), 14 diagnostic codes, no named limit ([ADR 0027](../../docs/adr/0027-limit-names-are-closed-in-1-x.md)). The v1.0.0 test suite, as tagged, passes against these sources (`compat-previous`: 4374 tests, five tree tests excluded with a reason each, no behaviour exclusion).

Counts: 329 public exports · 58 error codes · 111 diagnostic codes · 22 named limits · 95 verify-docs rules · 18 bundle probes · 6815 tests · 100 % statements.

Closes #12, #13, #14, #15, #16, #17, #18. Carries the commits of #8, #9 and #19 (Dependabot), which close on merge.

## Changes

### Engine surface

- ML-DSA-44/65/87 signatures verified where the host's Web Crypto verifies them ([ADR 0026](../../docs/adr/0026-ml-dsa-verified-where-the-host-verifies-it.md)); SLH-DSA and ML-KEM public keys read as kinds of their own; ML-DSA private keys named, not imported.
- RFC 5755 attribute certificates: `parseAttributeCertificate`, `verifyAttributeCertificateSignature`, 27 types ([ADR 0028](../../docs/adr/0028-attribute-certificates-are-read-not-judged.md)) — read and signature-checked, not judged (no §5 validation).
- `parseTimeStampRequest`, `parseOcspRequest` (RFC 9654 nonce, 1 to 128 octets).
- `strict` on the verify and check inputs, `onDiagnostic` on `verifySignedData`; `openPkcs12` honours both (#18, [ADR 0025](../../docs/adr/0025-strict-in-the-verify-and-check-verbs.md)).
- `PKI_DIAG_SPKI_ALGORITHM_UNRECOGNISED` (#17), `PKI_DIAG_KEY_USAGE_KEY_ALGORITHM_MISMATCH`.
- An argument of the wrong type is a `PkiError` on every export: 37 of the 108 functions answered one with a `TypeError`, 20 more while writing the refusal's message for an object with no prototype, and others behind a valid first argument; none does now (`src/core/arguments.ts`, not exported; no error code added). An argument, its members and theirs are each refused where the function first reads them, so a call 1.0.0 already refused keeps its code.
- Everything a reader returns is frozen, the empty lists and the diagnostics included (46 paths in ten readers were not).
- `createTimeStampRequest` asks its hash table for own names only: `hashAlgorithm: '__proto__'` is `PKI_INVALID_OPTION`, as any unknown name.
- The decision-surface changes are listed in `release-notes/v1.1.0.md`, **Decision surface**.

### Tooling (scripts/)

- `scripts/satellite-sync.ts`, `scripts/lib/satellite-surface.ts` (`npm run satellites:sync`), rule `satellite-stamps`.
- `scripts/run-compat.ts` (`npm run compat:previous`), `tests/compat/allow-1.0.0.json`.
- `check-npm-drift` holds the GitHub release to its five files.
- `error-codes-frozen` reads the snapshot through its ratchet (`asOf`): the first error code a minor adds showed the rule could not accept it.
- One `escapeRegExp` for the verify-docs rules; six code-scanning findings fixed.
- Size budgets raised once, with measured figures and causes: the shipped files (`ecosystem.json → bundle`) and five tree-shaking probes (`scripts/verify-bundle.ts`); six more probes raised by 1 to 4 KB for the argument guards, each with its measure. No layer marker moved. **A reviewed decision: read both diffs.**

### CI and repository (.github/, root)

- Node.js 26 in the matrix and the ruleset; `node-current.yml` removed until a line is Current again.
- `reuse lint` in `workflow lint`; `compat-previous` job; advisory `mutation.yml`.
- `publish.yml`: a release without its files fails the run (#14); a step reads the five file names back and checks the tarball digest.
- Dependabot: majors of `@types/node` and `marked` ignored; vitest 4.1.12, vite 8.2.6, pyasn1 0.6.5.
- SECURITY.md: support period of the 1.x line (#16).

### Agent layer (.claude/, AGENTS.md, governance)

- The guard hook resolves from `$CLAUDE_PROJECT_DIR`, one `Bash|PowerShell` matcher (#13).
- Always-loaded instructions 12 680 → 11 147 bytes under a 12 KiB ceiling (#12).
- `/satellite-align` skill and `satellite-alignment.instructions.md`; [ADR 0024](../../docs/adr/0024-what-a-satellite-may-implement.md) (#15).

### Tests and conformance

- 6864 tests in 138 files; coverage 100 % on four axes. Mutation on the `src/` files touched: see **Validation**.
- Three suites hold the audit fixes for every export, present and future, each complete by construction: `tests/fuzzing/arguments.test.ts` (every function called with everything wrong at once), `tests/fuzzing/argument-members.test.ts` (a valid call of every function, wrong in one member at a time) and `tests/property/frozen-results.test.ts` (each `parse*`/`decode*` result frozen to its last nested list). The answer is a returned value or a `PkiError`, nothing else. The second also holds what the release audit added: every flag replaced by what only reads as a boolean, and every options argument by what is not an object, must be refused with `PKI_INVALID_OPTION`; it reads `docs/assets/api.json`, so a flag or an options parameter added later is held without being listed.
- Fuzz targets 8 → 11; recipes 22 → 25; a seventh requirement inventory (RFC 5755 §4: 69 sentences, 36 tests, 33 excluded).
- ML-DSA vectors generated by OpenSSL, with provenance; interoperability cases declared absent, not failed, where the tool lacks ML-DSA.

### Documentation

- `release-notes/v1.1.0.md`, CHANGELOG, ROADMAP (1.1.x closed, 1.2.x candidates), README, guides, registries, llms files, five ADRs (0024–0028).
- `package.json` and `CITATION.cff` name `hello@pkinative.dev`; `funding` lists GitHub Sponsors and plika.app; SUPPORT.md gains a Contact section; ROADMAP.md a Tooling section (`e271a65`).
- A twelfth guide, [Migrating from node-forge or pkijs](../../docs/guides/migrate.md): every third-party name read in the published package, the pkinative code executed by the tests (`30c1415`). The landing page's cards name ML-DSA and attribute certificates (`6dbbdee`); the README and every footer of the site link to GitHub Sponsors (`9dff620`).
- `package.json` keywords: cms, pkcs7, ocsp, crl, csr, pkcs10, pkcs8, pkcs12, rfc5652, rfc3161, timestamp, rfc6960, post-quantum, ml-dsa, fips204, attribute-certificate, rfc5755.

## Independent audit

`/release-audit release-notes/v1.1.0.md v1.0.0` ran on 2026-11-23 at `c5c965d` — two auditors, an autonomy pass, two verifiers. Verdict: **NO-GO**, 30 findings in the ledger (1 blocker, 7 majors, 21 minors, 1 note; 27 confirmed, 1 downgraded, 1 rejected, 3 duplicates). None was a wrong verdict of the engine. The blocker was three sentences calling `ci (26)` and `compat-previous` required checks while the live ruleset requires nothing (step 2 below): the text now says what the repository commits. The majors: a flag given as the text `'true'` left a check off without a word, and `cA: 'false'` encoded a CA — every flag is now a boolean or a refusal; an argument promise wider than the code, narrowed, with the nine refusals whose code changed listed; Downstream notes that did not name what stops compiling in the satellites (`PrivateKeyKind`, the typed code tables); and a missing issuer reported as a signature that was not checked — the codes are those of 1.0.0, which its suite asserts, so the message and the registries were corrected and the code change is in ROADMAP "At the next major". Fixed in `58c038a` and `cf21bb9`.

The fix was read by an independent reviewer given the ledger and the diff, not the conclusions: 28 of 30 closed, and seven minor points, all closed in `c97c124` — the main one being two codes for options that are not an object, now `PKI_INVALID_OPTION` on every function, the code the readers gave in 1.0.0. The sweep written to hold that found `readTime` documenting a parameter twice. **After the fix loop: GO**, no blocker and no major open; what remains is the maintainer's (step 2). The ledger and the verdict were written outside the repository — an agent may not write under `test-output/`, where the skill places them — and the commit messages of `cf21bb9` and `c97c124` carry what was fixed.

Before that run, one independent verifier agent had read the branch against the release criteria: 8 of 14 met, 6 partly, 8 defects. Fixed here: an empty GeneralNames accepted in an attribute certificate (`7a606fc`, with tests and 100 % mutation on both files) and six stale documentation points (`f6b3ac0`). Left to the maintainer: the live ruleset (step 2) and the alerts that stay open (step 7).

An external audit of the release candidate (2026-11-22) concluded "ready" with two minor findings; both were confirmed and both were wider than reported: a `TypeError` escaping on an argument of the wrong type (reported for two functions, fixed for the class), and an unfrozen empty `extensions` (reported for one reader; 46 paths in ten readers). Its third point — go-x509, python-cryptography and native ML-DSA not exercised locally — is a limit of the machine, covered by the CI matrix (see below).

The fix was then read twice by an independent verifier agent, given the criteria and not the conclusions. The first reading found nine families of defects in it (guards stricter than what 1.0.0 took, messages still written with `String(value)`, stale `@throws`); the second, seven more (guards placed before a refusal 1.0.0 made first, an unvalidated `staleTolerance`, gaps in the sweep). All were fixed except two, declined with their reason: freezing the `algorithm` of an imported key (1.0.0 hands back the caller's object, and its tests say so), and walking a hand-built OCSP response (outside the stated promise). The second sweep now starts from a valid call of each of the 108 functions — the lack of which is what both readings kept finding.

A last outside reading (2026-11-23) raised four points. One was settled already: the working tree is clean at the tip. Three were confirmed and done. The MCP explorer's page named `pkinative@1.0.0` while its loader ran 1.1.0: fixed, and `cdn-pin` now holds what the pages write, `release-prepare` moves it (`10356ac`). The landing page's cards did not name ML-DSA or attribute certificates: they do, worded as the release note words them, without the SLH-DSA and ML-KEM claim the reading suggested (`6dbbdee`). A migration guide from node-forge and pkijs was missing (`30c1415`); writing it showed `llms.txt` lacking the new guide with no rule to say so, and `llms-index-quality` now requires the entry point to link every guide.

## Validation (what actually ran, on Windows 11, Node 22)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | 17 passed, 0 skipped in 871 s, in one run on the tree of this commit less this file (2026-11-24, 04:47), on an idle machine. The run before it failed at `verify:bundle` alone: seven probes over their byte budget by 44 to 1 152 bytes, the weight of the flag and options guards; each budget is raised by 1 KB (2 KB for `verifyCertificateChain`) with its measurement in `scripts/verify-bundle.ts` |
| `npm run test:coverage` | 6864 tests, 17 skipped, 138 files; 100 % statements |
| `npm run verify:bundle` | 18 probes within budget; the whole entry point 353.2 KB against 355 KB |
| `npm run mutate -- --files <the 35 src files the audit fixes touched>` | 5185 mutants, 0 survived: 3693 killed, 9 timed out, 1391 refused by the compiler, 92 recorded equivalents. The whole run left three survivors and one recorded equivalent that a test now kills; `1262694` adds the three tests and removes the entry, and the three files ran again at 100 %. After the release audit, the 26 `src/` files its fixes touched: 3446 mutants, 0 survived — 2475 killed, 9 timed out, 908 refused by the compiler, 54 recorded equivalents. One run, on a loaded machine, counted two recorded equivalents of `src/asn1/asn1-encode.ts` as killed, with six timeouts where the unloaded run has four: message-only mutants, read as timeouts, entries kept |
| `npx tsx scripts/verify-docs.ts` | 95 rules, 0 errors, 0 warnings |
| `npx tsx scripts/validate-certs.ts --require-all` | pass (gate step `conformance`, 234 s) |
| `npm run compat:previous` | 4374 passed, 1 skipped, 89 files (2026-11-24, on the sources of this commit) |
| `npm run check:package` | pass |
| `npm run smoke:install` | pass |
| `npm pack --dry-run` | 12 files, 1.4 MB packed, 6.0 MB unpacked |
| `npm ls --omit=dev --all` | pkinative alone |

Not run here, and first exercised on the runner: the `ci (24)` and `ci (26)` legs (the only place a positive ML-DSA verdict runs — Node 22 has no ML-DSA), the `reuse lint` step, the `compat-previous` job, `mutation.yml`, and the release-file check of `publish.yml`.

**Known red:** `npm audit --audit-level=high` fails on `picomatch` ≤ 4.0.7 (GHSA-fc5q-39xc-vjpf), a development-only transitive dependency with no patched release. Decision taken: wait for upstream, no allow-list and no threshold change. `ci (22)` is red on that step until the fix ships.

## Backward compatibility

Every 1.0.0 export keeps its signature (`api.frozen.json` ratcheted, never rebased; 0 new refusals in `refusals.frozen.json`). What a caller can observe is listed in the release note's **Decision surface**: the `errorCode` of an ML-DSA signature on a host without it, a malformed SLH-DSA or ML-KEM key now refused, `openPkcs12` honouring `strict`, and one more `console.warn` line by default in two cases. The audit fixes add: a `PkiError` where a `TypeError` was thrown; an `at`, a tolerance, a purpose, a nonce or a list of the wrong type refused; an OCSP CertID digest refused before anything is hashed; a flag that is not a boolean, and options that are not an object (`null` among them), refused with `PKI_INVALID_OPTION`; and reader results frozen throughout.

## Out of scope (tracked in ROADMAP.md)

The SCT list reader (RFC 6962), CRL and OCSP-response writers, RFC 5755 §5 validation, ML-DSA signing and private-key import, SLH-DSA verification — ROADMAP.md "1.2.x — candidates".

## Human-in-the-loop — steps for the maintainer

1. Push `chore/release-v1.1.0`, open the pull request with this body, squash-merge with the title `release: v1.1.0 — post-quantum verification, attribute certificates, request readers`.
2. Rulesets: **the live `main` ruleset (24453575) targets no branch (`include: []`) and has no status-check rule — nothing is required today.** Import `.github/rulesets/main.json` and `tags.json` after the merge, once the workflows that report `ci (26)` and `compat-previous` are on `main` (earlier, the release pull request would block itself). Required checks then: `ci (22)`, `ci (24)`, `ci (26)`, `windows`, `macos`, `compat-previous`, `runtimes`, `workflow lint`, `conformance`, `conformance-windows`, `conformance-macos`, `dependency-review`.
3. `ci (22)` and `picomatch`: merge as an administrator, or wait for the patched release (see **Known red**).
4. Publish the GitHub Release `v1.1.0` (body = `release-notes/v1.1.0.md`). `publish.yml` passes its `guard` job, waits for the `npm-publish` reviewer, publishes and attests; then `npm view pkinative version` names 1.1.0 and `npm run check:npm-drift` is clean.
5. Release `v1.0.0` was published without its five files: attach them by hand, or the weekly drift check stays red on that release.
6. Close #3 (`@types/node` 26: the types follow the lowest supported line, 22) and #4 (`marked` 18: pinned on purpose, two tests and three rules depend on 12); both majors are now ignored in `dependabot.yml`.
7. Code scanning — dismiss as false positives, with these reasons:
   - file-system-race (×10), http-to-file-access: development scripts over repository paths; bytes are written after a SHA-256 check.
   - incomplete multi-character sanitization (×6), path-injection (×4), stored-xss: test and generator code over the repository's own files, no untrusted input.
   - weak-cryptographic-algorithm (SHA-1): the OCSP CertID hash RFC 6960 §4.1.1 defines, over public data.
   - Scorecard BranchProtection: a true finding until the rulesets are imported (step 2) — do not dismiss. PinnedDependencies (deliberate, `publish.yml` installs the pinned npm client), Maintained and CodeReview (repository age, single maintainer).
   - Scorecard SecurityPolicy (#5): SECURITY.md is present and names the private reporting channel; the finding's "no linked content" is not explained by the file. Re-read it after the next Scorecard run on `main`; dismiss only if it persists with the file unchanged.
   - Scorecard Vulnerabilities (#36): the vite, vitest and pyasn1 advisories are closed by this branch; it stays open on `picomatch` until upstream ships a fix (see **Known red**). Do not dismiss.
   - Scorecard CII-Best-Practices: register the project at bestpractices.dev and add the badge.
8. Satellites: file the drafts in `pkinative-cli/.github/drafts/`, `pkinative-mcp/.github/drafts/` and `pdfnative-cli/.github/drafts/`; after their next minors, `npm run satellites:sync` then `/satellite-align`.
9. Re-upload the social preview if the title changed.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [ ] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — or the section says PENDING and this PR is not ready to merge.
