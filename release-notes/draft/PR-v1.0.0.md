# release: v1.0.0 — the freeze, promised

> **Branch:** `chore/release-v1.0.0` → `main`, the first push of the repository (see the steps below: it is pushed, not squash-merged)
> **Type:** Major release, the first one. Against a 0.9.0 build of the tag — never published — it breaks in three places: `openPkcs12` has no default RSA scheme ([ADR 0015](../../docs/adr/0015-no-default-rsa-scheme.md)), name attributes are written in their RFC 5280 Appendix A string type, and `checkServerName`'s commonName fallback needs `path`.
> **Milestone:** ROADMAP.md §1.0.0 — M6: The freeze and the first publication

## Summary

This is pkinative's first release, on npm with provenance and on GitHub with attested assets. Versions 0.1 to 0.9 were milestones of the preparation, never tagged nor released. Before it, a multi-agent pre-publication audit — nine auditors over standards, consistency, foreign cross-validation in both directions, CVEs, documentation, irreversible decisions, CI and the site, each checked by an adversarial verifier — confirmed 98 findings; every one is fixed here or decided in an ADR. On 2026-10-03 every item the 1.1.x section of ROADMAP.md had deferred was pulled into 1.0.0 — a PKCS#10 reader and verdict, lazy signature verification in the chain search, the fourteen RFC 5652/3161/6960 sentences as thirteen diagnostics, id-RSASSA-PSS keys re-wrapped at the Web Crypto door, Ed448 CMS signers where the host has Ed448 (ADR 0022), an OCSP delegate judged at `producedAt`, the ENUMERATED and RELATIVE-OID readers, two X.520 diagnostics, and the tooling (surface classifier, `schemaVersion`, `check:guides`, the `a11y` job, the Node 26 advisory run, the 0.x tag script) — each under the publish gate, interop `--require-all`, 100 % mutation on the modules it touched and the `api.frozen.json` ratchet, so that it is promised at 1.0.0 and not a minor later.

- **The three-part compatibility promise** (export surface, error vocabulary, decision surface), each held by a snapshot and a rule, plus what ADR 0018 adds beyond the snapshots: option defaults, open unions, what is not promised.
- **Security fixes found before anyone could depend on the defect:** the PBKDF2 work of a whole PKCS#12 bounded (`maxPkcs12KdfIterations`, ADR 0020); `PKI_REASON_REVOKED` only from authenticated evidence; three name-constraint bypasses closed; id-RSASSA-PSS keys held to RFC 4055. A CVE-class corpus of 43 published vulnerabilities of comparable libraries.
- **A final review before publication (2026-10-02):** four adversarial reviewers and a verifier found 42 more — three bypasses (a trust anchor matched by its name alone; a CRL signer believed without validating under the anchors, which let a forged delta hide a revocation and a forged list satisfy `requireRevocation`), four majors (the user policy set intersected in the leaf's domain, RSA e = 1 verifying a signature made with no key, a SHA-1 timestamp imprint, a one-octet PBMAC1 key) and 22 minors — every one fixed with the test that reproduces it, and the corpora unchanged except where the fix made them agree.
- **Decisions 1.0 could not leave open:** one entry point (ADR 0016), the runtime and toolchain policy with a patched Node.js floor (ADR 0017), error identity across the ESM and CJS builds (ADR 0021).
- **Cross-validation made permanent:** eight foreign implementations and two linters read what pkinative writes, five of them also write what it reads, `--require-all`.
- **The release path** split so the job that builds cannot publish (ADR 0019), with CycloneDX, SPDX and toolchain SBOMs and the Sigstore bundle on a draft release.
- **Compatibility:** zero runtime dependencies; no error code added or changed.

Counts: 294 public exports · 57 error codes (frozen since 0.8.0) · 43 reason codes · 97 diagnostic codes · 22 named limits · 84 verify-docs rules · 61 L5 clauses · six RFC requirement inventories · 18 bundle probes · 5 216 tests · 100 % statements, branches, functions and lines · 22 decision records · 62 frozen samples · 79 mutation targets, 191 reviewed equivalents.

Conformance:

| Level | Result |
|---|---|
| L1 | 29 796 parsed, 565 refused — the 565 promised refusals held code for code |
| L2 | 30 361 re-encoded byte for byte |
| L3 | node:crypto 29 796/29 796; OpenSSL 4.0.0 202/202 sampled |
| L4 | CryptoAPI 202/202 on Windows; Python cryptography and Go `crypto/x509` on Linux (CI) |
| L5 | 61 clauses; RFC 5280: 182 sentences of §4.1–§4.2 (57 held by a clause, 125 excluded, 0 not diagnosed); RFC 5652 50 (44 tests, 6 excluded), 3161 38 (28, 10), 6960 23 (18, 5), 7292 9 (7, 2), 7468 12 (8, 4), every exclusion with its reason and none `not-diagnosed` |
| L6 | 9 158/9 208 (99.46 %) |
| L7 | 195/203 (96.06 %) |
| L8 | 221/224 intact, 196/204 agree with NIST |
| Interop | 9 tools agree on every artefact they read or write, on the Windows release machine; the Linux set (GnuTLS, gpgsm, Java keytool, Python cryptography, Go, zlint, pkilint) is required in the conformance workflow |

## Changes

### Engine surface

- New: the limit `maxPkcs12KdfIterations`; the exports `SubjectDirectoryAttributesExtension` and `DirectoryAttribute` (the extension kind `subjectDirectoryAttributes`); the option `CheckServerNameOptions.path`; five diagnostic codes; `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`.
- Fixed: REVOKED only from authenticated, applicable evidence; URI hosts by RFC 3986 and SmtpUTF8Mailbox under rfc822Name constraints; the commonName fallback under dNSName constraints; RFC 4055 for PSS keys; RSASSA-PSS AlgorithmIdentifiers with explicit NULL; name attributes in their Appendix A string types and bounds; X.690 §8.23 string violations diagnosed; `crls[n]` reason paths; whole-millisecond timestamp bounds; `KEY_USAGE_BITS` frozen; `instanceof` across builds; the path search indexes its signature verdicts once (a 65-certificate bag went from 18 minutes to 29 s).
- Fixed by the final review: a trust anchor is a name and a key; an off-path CRL issuer validates under the anchors with its own links; the policy set is intersected in the anchor's domain; RSA e < 3 or even refused; a SHA-1 timestamp imprint gated by `allowSha1`; PBMAC1 keys under 20 octets not verified; v1/v2 intermediates refused; an IP-literal `dns` reference read as an address; an unknown critical CRL entry extension makes the list unusable; an OCSP answer without `nextUpdate` stale, contradictory answers UNKNOWN, a delegated responder checked for revocation unless `id-pkix-ocsp-nocheck`; the reasons mask includes the distribution point's reasons; verdict reasons rooted at `crls[n]` / `ocspResponses[n]`; the implicit anchor counted against `maxChainLength`; the clock read once per call; the CRL/OCSP cursor as strict as the decoder; an indefinite child bounded by its parent; the RSASSA-PSS grammar enforced; `createCertificate` refusing a serial of 0 or over 20 octets.
- New since the review: 37 diagnostics — `PKI_DIAG_SPKI_RSA_EXPONENT_WEAK`, `PKI_DIAG_SPKI_EC_PARAMETERS_INVALID`, `PKI_DIAG_GENERAL_NAME_CONTROL_CHARACTER`, and 34 for the RFC 5280 §4.1–§4.2 sentences the inventory had recorded as not diagnosed (RFC 3986 and RFC 4516 grammar in `core/uri.ts`); `strict: true` refuses the first `warning` and reports every `info`.
- The former 1.1 list (2026-10-03): `parseCertificationRequest` and `verifyCertificationRequest` with `CertificationRequest`, `CsrAttribute`, `VerifyCertificationRequestOptions`, `VerifyCertificationRequestReport` (RFC 2986; no new error code); `shake256`; `readEnumerated`, `readRelativeOid`, `encodeRelativeOid`; 13 diagnostics for the RFC 5652/3161/6960 sentences once `not-diagnosed`, with `onDiagnostic` on `VerifyCertificateChainInput` and `VerifyTimeStampTokenInput` and `signer` + `onDiagnostic` on `CheckOcspStatusInput`; `PKI_DIAG_NAME_ATTRIBUTE_TOO_LONG` and `PKI_DIAG_NAME_COUNTRY_UNKNOWN` (`src/x509/iso3166.ts`); id-RSASSA-PSS public keys and unencrypted PKCS#8 re-wrapped under `rsaEncryption` at the door, a plain `keyBag` under a PSS certificate opened; Ed448 CMS signers verified where the host has Ed448 and written by `createSignedData` (ADR 0022); lazy signature verification in `verifyCertificateChain` (no verdict change); an OCSP delegate judged at `producedAt` (`PKI_REASON_REVOCATION_UNKNOWN` where it was accepted). The verdict changes are tabled in the release note under Conformance.
- `api.frozen.json` moved on ADR 0015 and ADR 0020 in the rehearsal, then rebased as `stable` at 1.0.0 and ratcheted after each lot (294 exports, 43 reason codes).

### Tooling (scripts/)

- `build-refusals-frozen.ts`; `check-ts-floor.ts` in the publish profile; the interop runner rebuilt over `scripts/lib/interop-*.ts` with ten tools, `REQUIRED_TOOLS` per platform and reviewed `TOOL_LIMITATIONS`; two new L4 validators.
- 84 rules, among them `option-defaults-parity`, `security-txt-parity`, `cve-class-parity`, `lint-waiver-reviewed`, `stale-milestone`, `standards-evidence`, `errors-guide-complete`, `code-token-registered`, `readme-surfaces`, `copilot-layer-parity`, `design-tokens-parity`, `a11y-structure`, `structured-data`, `architecture-diagram`, `comparison-current`, `refusal-baseline-frozen`, `contracts-shape`, `package-files-parity`, `reuse-shape`, `external-links`, `registry-schema-version` (every `docs/data/*.json` carries `schemaVersion: 1`); `skills-shape` now also fails on an undeclared skill.
- `scripts/lib/api-surface.ts` classifies a literal union widened inside an interface member as compatible (ADR 0018 updated); `scripts/check-guides.ts` compiles every ```ts fence of README and the guides under lib ES2020 + DOM (gate step `check:guides`, fast, CI and publish; one defect found, a guide variable named `document`); `scripts/a11y-check.ts` runs axe-core 4.13.0 over every page in both palettes.
- Bundle budgets raised with the measured cause of each (`scripts/verify-bundle.ts`): `*` 272.9 KB of 280 KB.
- Requirement inventories for RFC 5652, 3161, 6960, 7292 and 7468 (`scripts/data/rfc*-requirements.json`, `scripts/lib/rfc-requirements.ts` generalised, the L5 runner over all six); `scripts/mutate.ts` targets every executable module of `src/`; the `export-exercised`, `security-insights-parity` and extended `bench-parity` rules; the L4 validators' field masks pinned; gpgsm and keytool required on Linux, .NET's Unix gap declared.

### CI and repository (.github/, root)

- `publish.yml`: triggered by the `v*` tag; `guard` → `build` (no id-token) → `publish` (id-token only, uploads exactly the handed-on tarball) → `attest` (registry bytes, CycloneDX, SPDX and toolchain SBOMs, Sigstore bundle, attached to the draft release); `package-manager-cache: false` on every setup-node step — the audit's one blocker.
- `ci.yml`: no path filter on a required check; the `runtimes` job (Deno 2.9.7, Bun 1.4.2, headless Chromium, an Ed448 case per host); the `workflow lint` job (zizmor, actionlint). CodeQL over the workflows. harden-runner on every job, in block mode where the endpoints are known, and on macOS too.
- `node-current.yml`: Node.js 26 (Current) tested, advisory, promised by nothing until LTS on 2026-10-28 (`contracts.support.currentLines`, ADR 0017 amended). `docs.yml`: the `a11y` job, axe-core from jsDelivr by SRI, blocking.
- Rulesets: ten required checks (`ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`, `runtimes`, `workflow lint`, `dependency-review`) and a `code_scanning` rule (CodeQL, high or higher).
- Dependabot with a seven-day cooldown, the actions grouped, the ClusterFuzzLite image and the pinned fuzzing engine watched. brace-expansion lifted in the lockfile (three advisories published 2026-09-29, dev-only).
- ClusterFuzzLite over eight targets. A weekly OSV-Scanner job in `audit.yml`, installed at a fixed version through the Go checksum database.
- REUSE 3.3: `REUSE.toml` and `LICENSES/`; `reuse lint` reports 520/520 files compliant.
- `.github/SECURITY-INSIGHTS.yml` (OpenSSF Security Insights 2.0). ADR 0010 amended: no external audit is planned, and the offer to scope one on request is withdrawn. ADR 0016 amended: `index.d.ts` crossed its trigger on the diagnostics' vocabulary, decision unchanged.

### Agent layer (.claude/, AGENTS.md, governance)

- `.github/copilot-instructions.md` and the pki-core instructions describe 1.0; `copilot-layer-parity` holds the Copilot layer table to `LAYERS`.
- `AGENT_RULES.md` gains rule 7, byte-identity awareness (pdfnative's rule, adapted to `output-bytes.json` and L2).
- `ai-governance.json` declares the release-audit skill; its anti-goals are restated for 1.0. `guard.mjs` judges a list-form exemption on the leading segment.

### Tests and conformance

- `tests/security/cve-classes.test.ts` (43 classes), `tests/tools/dual-package.test.ts`, `tests/tools/exported-constants.test.ts`, `tests/tools/interop.test.ts`, `tests/conformance/guide-counts.test.ts`, `tests/tools/check-ts-floor.test.ts`; mutation testing back to 100 % on every module the fixes touched, `verify-chain.ts` (213 mutants) and `verify-timestamp.ts` (131) included — 22 reviewed equivalents in all, each with its argument in `scripts/data/mutation-equivalents.json`.
- `tests/performance/budgets.test.ts` (a time budget at every named limit), `tests/property/repeatability.test.ts` (two runs and two builds write the same bytes), `tests/x509/x509-profile.test.ts` (the 34 profile diagnostics, each with its twin and its strict verdict), `tests/core/uri.test.ts`; `openPkcs12` and `verifyCertificationRequest` under adversarial files (`tests/fuzzing/reports.test.ts`, `tests/fuzzing/csr.test.ts`); 62 frozen samples (`cert/v3-ed448-self-signed`, `cms/signed-data-ed448-shake256` and `asn1/relative-oid-8571-3-2` among them); 2 new benchmark files with the 1.0.0 section of `bench/RESULTS.md`; mutation at 100 % on every executable module of `src/` (79 files), 191 argued equivalents; the `openssl:csr` interop case; the pass found and fixed a realm-bound byte check in `addTimeStampToken`, an unchecked `extnValue` tag in the TSTInfo, CRL and OCSP extension readers, and a `TypeError` where `maxPolicyNodes` met a user policy set.

### Documentation

- README, guides, agent brief, llms.txt and the landing page describe 1.0 as it is, the former 1.1 list included (2026-10-03: the PKCS#10 reader, SHAKE256, the PSS and Ed448 verdicts, the lazy search, the two X.520 diagnostics, Node 26); the [standards guide](../../docs/guides/standards.md) is new, with an RFC 2986 row.
- SECURITY.md: the compatibility promise, supported runtimes and compilers (Node 26 advisory), two private reporting channels and the ISO/IEC 29147 and 30111 self-assessment clause by clause, release integrity, mutation testing over every executable module; `docs/.well-known/security.txt`.
- ADRs 0016–0022 (0022 supersedes the Ed448 half of 0004; 0017 and 0018 amended). The site at parity with pdfnative's design, with a WCAG 2.2 AA dark palette, underlined prose links, JSON-LD on every guide, the architecture drawn from `LAYERS`, and `docs/CNAME`.

## Independent audit

- **Pre-publication audit (agents, 2026-09-30):** 9 auditors and 9 adversarial verifiers; 98 findings CONFIRMED or DOWNGRADED — 1 blocker, 10 major, 48 minor, 39 note — all fixed or decided on this branch. The tools it used are recorded with their versions; the cross-validation it ran by hand is now the permanent interop matrix.
- **Final review (agents, 2026-10-02):** 4 reviewers (parsers; decision logic; crypto, encoders, CMS and keys; methodology, hardening and documentation) and 1 adversarial verifier replaying every finding; 42 findings, 0 rejected — 3 blocker, 4 major, 22 minor, 13 note — all fixed on this branch; the ledgers name the probe that reproduced each.
- `/release-audit release-notes/v1.0.0.md v0.9.0` — PENDING (the maintainer's GO/NO-GO).

## Validation (what actually ran, on Windows 11, Node v22.17.0)

The figures of 2026-10-02 (the final review) were superseded when the 1.1 list was pulled in on 2026-10-03 and re-run on the integrated branch (tip d2e2051) the same day; a row still marked `not run since 2026-10-02` names a check that was not repeated and the figure it gave then.

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | 16/16 passed in 584.0 s (2026-10-03, tip `d2e2051`): typecheck:all, lint, build, dist-check, bundle-check, test:coverage, check:package, verify:bundle, verify:samples, smoke:install, ts-floor, docs:playground-fresh, verify:docs, check:guides, conformance, interop |
| `npm run gate:fast` (typecheck:all, lint, test, check:guides, verify:samples, verify:docs) | 6/6 passed in 328.9 s (2026-10-03, 5 216 tests); every step re-run inside the publish gate above |
| `npm run test:coverage` | 5 216 tests; 100.0 % statements, and the 100 % threshold on all four axes held (publish gate, 2026-10-03) |
| `npx tsx scripts/mutate.ts` (every default target) | 79 modules; every module a lot touched was re-measured on the integrated branch on 2026-10-03 — verify-chain 283 mutants (192 killed, 17 equivalents), x509-certificate 298, asn1-encode 382, crypto-algorithms 263, cms-attributes 271, cms-signed-data 261, x509-csr 69, verify-csr 43, key-import 72, verify-signer 69, verify-pkcs12 97, shake256 156 (0 equivalents) — 100 % killed or argued on each; 191 reviewed equivalents in `scripts/data/mutation-equivalents.json`, 0 stale, 0 refuted; the untouched modules keep their 100 % of 2026-10-03 morning |
| `npm run verify:bundle` | 18 probes within budget (publish gate, 2026-10-03) after one reviewed raise of every budget with its measurement (`cab9a3b`); the whole library re-minifies to 314.6 KB, under the ~320 KB projection written for 1.0 |
| `npx tsx scripts/verify-docs.ts` | 84 rules, 0 errors, 0 warnings (2026-10-03, Lot C) |
| `npm run check:guides` | 27 TypeScript fences of README and the guides compiled against `src/index.ts` under lib ES2020 + DOM, 0 errors (publish gate, 2026-10-03) |
| `npx tsx scripts/validate-certs.ts --level 8 --require-all` | PASSED on 2026-10-03 on the integrated build: 0 failures, 0 skips, 2 not applicable on win32 (the Go and Python lineages); L1 565 promised refusals held code for code; L6 9 158/9 208 chains agree (99.46 %); L7 195/203 PKITS paths; L8 196/204 S/MIME verdicts, 221/224 messages intact; L5 six inventories, 0 todo — every figure unchanged from the final review: no corpus verdict moved |
| `npm run interop` (`PKINATIVE_INTEROP_REQUIRE_ALL=1`) | 9 tools agree on every artefact they read or write (2026-10-03, `--require-all`), `openssl:csr` included — the CSRs OpenSSL writes are parsed and verified by pkinative; pkilint cannot verify RSASSA-PSS signatures and windows-certutil prints a translated dump, both reviewed N/A |
| `npm run check:ts-floor` | PASS inside the publish gate (2026-10-03): TypeScript 5.0.4 under node16, bundler, node10 and nodom |
| `npm run check:package` | PASS inside the publish gate (2026-10-03) |
| `npm run smoke:install` | PASS inside the publish gate (2026-10-03) |
| `npm pack --dry-run` | 12 files, 1.3 MB packed, 5.4 MB unpacked (2026-10-03) |
| `npm audit` / `osv-scanner` (2.6.0) | `npm audit`: 0 vulnerabilities (2026-10-03); osv-scanner not re-run since 2026-10-02 (then no issues in 326 packages; the lockfile has not changed since) |
| zizmor 1.30.1 (offline) / actionlint 1.7.12 | not run since 2026-10-02 (then no findings / clean); `node-current.yml` and the `a11y` job are new |
| `reuse lint` (reuse 6.2.0) | not run since 2026-10-02 (then 520/520 files compliant with REUSE 3.3) |
| L4 Linux lineages, run locally under WSL Ubuntu on the release machine's validator input | not run since 2026-10-02 (then Go `crypto/x509` 202/202, Python cryptography 46.0.5 202/202, both canaries behaved) |
| Jazzer.js 4.0.0, 180 s per target over the eight ClusterFuzzLite targets | not run since 2026-10-02 (then 780 036 runs, 0 crashes, 0 artefacts) |
| axe-core 4.13.0 (WCAG 2.0/2.1/2.2 A and AA) over every page, light and dark | now the `a11y` job of `docs.yml` (`npm run check:a11y`); not run locally since 2026-10-02 (then 0 violations in 24 runs over 12 pages) |
| Lighthouse accessibility, the same 12 pages | not run since 2026-10-02 (then 100 on every page) |
| Horizontal overflow at 1280 and 375 px, light and dark | not run since 2026-10-02 (then 0 px on the home page and the guides) |

The local Node.js, 22.17.0, is below the floor this release declares (`^22.22.2`): it builds and tests, but the release gate that matters is the `build` job of `publish.yml`, which runs on the `.nvmrc` line's latest patch.

## Backward compatibility

Every export of 0.9.0 keeps its signature; twelve exports are added (294: two extension types, the PKCS#10 reader and verdict with their four types, `shake256`, the ENUMERATED and RELATIVE-OID readers and encoder), and four optional input members (`onDiagnostic` on the chain and timestamp inputs, `signer` and `onDiagnostic` on `CheckOcspStatusInput`). Against a 0.9.0 build:

- RSA containers in `openPkcs12` need `rsaAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }`, the former default.
- Drop `stringType: 'utf8'` on `countryName`, `serialNumber`, `dnQualifier`, `domainComponent` and `emailAddress`; pass DER to reproduce an existing name.
- Pass the validated `path` to `checkServerName` when `allowCommonNameFallback` is on.

From here, semver applies to all three parts of the promise and to what ADR 0018 adds.

## Out of scope (tracked in ROADMAP.md §1.1.x)

- `pkinative-cli` and `pkinative-mcp`, after 1.0.0.
- Nothing of the former 1.1 list is left but Node.js 26's LTS date (2026-10-28: `currentLines` → `nodeLines`, `ci.yml`, `engines`, the SECURITY.md table) and the attribute-certificate gap the standards guide records.

## Human-in-the-loop — steps for the maintainer

This is the first push to an empty repository, so the steps differ from the template. `main` must carry the whole linear history, not a squash, so that the audited history of the preparation (0.1 to 0.9, never tagged) stays readable.

0. Run `/release-audit release-notes/v1.0.0.md v0.9.0` and record GO/NO-GO above.
1. Create the mailbox security@pkinative.dev (SECURITY.md and `security.txt` name it), and the `npm-publish` environment: yourself as required reviewer, deployments limited to tags matching `v*`.
2. Push `main`:
   - `git remote add origin https://github.com/Nizoka/pkinative.git`
   - `git ls-remote --heads origin`: this must print nothing.
   - `git branch -f main chore/release-v1.0.0`, then push `main` to `origin` with upstream tracking.
   - Nothing protects `main` yet; that is by design.
3. The one-time settings of CONTRIBUTING §Branch protection: Dependency graph; private vulnerability reporting (check: `curl -s https://api.github.com/repos/Nizoka/pkinative/private-vulnerability-reporting` answers `{"enabled":true}`); Dependabot alerts and security updates; secret scanning with push protection; the CodeQL advanced set-up; Actions workflow permissions read-only; release immutability; Pages from `main` `/docs` with `pkinative.dev` and Enforce HTTPS.
4. Import the rulesets: `.github/rulesets/main.json`, then `.github/rulesets/tags.json` (Settings → Rules → Rulesets → Import).
5. Wait for CI, conformance (three platforms), runtimes, workflow lint, CodeQL and Scorecard to go green on `main`. (`dependency-review` reports on pull requests.)
6. No 0.x tag. Versions 0.1.0 to 0.9.0 were milestones of the preparation of 1.0.0: each has its CHANGELOG entry and its note under `release-notes/`, and none was tagged, released or published — the first tag of this repository is `v1.0.0`.

   **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
7. Configure Trusted Publishing on npmjs.com for `pkinative`, bound to `.github/workflows/publish.yml` and the `npm-publish` environment.
8. Draft the GitHub Release (title `v1.0.0 — the freeze, promised`, body = `release-notes/v1.0.0.md`, tag `v1.0.0` on the tip of `main`), **save it as a draft**, then create and push the tag `v1.0.0` — the push starts `publish.yml`.
9. What to expect: `guard` passes; `build` runs the publish gate and packs; approve `npm-publish` only once `build` is green; `publish` uploads the tarball with provenance; `attest` checks the registry's bytes and attaches the tarball, the SBOMs and the Sigstore bundle to the draft. **Then publish the draft.**
10. Check: `npm view pkinative version` shows `1.0.0`; `npm audit signatures`; `gh attestation verify pkinative-1.0.0.tgz --repo Nizoka/pkinative`; `npm run check:npm-drift`; `curl -sI https://pkinative.dev/llms.txt`.
11. CONTRIBUTING §Release step 11: require 2FA and disallow tokens on the package; deprecate the `0.0.1` reservation; upload `docs/assets/social-preview.png` (Settings → General → Social preview); fill the OpenSSF Best Practices questionnaire once the repository is public.
12. Optional: submit the nine issue drafts the audit wrote for pdfnative (`D:\Github\pdfnative\.github\drafts\`), each validated by pdfnative's `verify:issue`.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory; the rows marked `not run since 2026-10-02` name the checks not repeated after the 1.1 list landed and what they gave then.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files (plus the two re-rasterised images), nothing else; the audit fixes follow it as their own commits.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above — `/release-audit` PENDING: this PR is not ready to merge until it is.
