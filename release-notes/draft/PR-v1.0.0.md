# release: v1.0.0 — the freeze, promised

> **Branch:** `chore/release-v1.0.0` → `main`, the first push of the repository (see the steps below: it is pushed, not squash-merged)
> **Type:** Major release, the first one. Against a 0.9.0 build of the tag — never published — it breaks in three places: `openPkcs12` has no default RSA scheme ([ADR 0015](../../docs/adr/0015-no-default-rsa-scheme.md)), name attributes are written in their RFC 5280 Appendix A string type, and `checkServerName`'s commonName fallback needs `path`.
> **Milestone:** ROADMAP.md §1.0.0 — M6: The freeze and the first publication

## Summary

This is pkinative's first release, on npm with provenance and on GitHub with attested assets. Versions 0.1 to 0.9 are tagged but never released. Before it, a multi-agent pre-publication audit — nine auditors over standards, consistency, foreign cross-validation in both directions, CVEs, documentation, irreversible decisions, CI and the site, each checked by an adversarial verifier — confirmed 98 findings; every one is fixed here or decided in an ADR, and the 1.1.x section of ROADMAP.md lists what was deliberately deferred, all of it additive.

- **The three-part compatibility promise** (export surface, error vocabulary, decision surface), each held by a snapshot and a rule, plus what ADR 0018 adds beyond the snapshots: option defaults, open unions, what is not promised.
- **Security fixes found before anyone could depend on the defect:** the PBKDF2 work of a whole PKCS#12 bounded (`maxPkcs12KdfIterations`, ADR 0020); `PKI_REASON_REVOKED` only from authenticated evidence; three name-constraint bypasses closed; id-RSASSA-PSS keys held to RFC 4055. A CVE-class corpus of 43 published vulnerabilities of comparable libraries.
- **Decisions 1.0 could not leave open:** one entry point (ADR 0016), the runtime and toolchain policy with a patched Node.js floor (ADR 0017), error identity across the ESM and CJS builds (ADR 0021).
- **Cross-validation made permanent:** eight foreign implementations and two linters, both directions, `--require-all`.
- **The release path** split so the job that builds cannot publish (ADR 0019), with CycloneDX, SPDX and toolchain SBOMs and the Sigstore bundle on a draft release.
- **Compatibility:** zero runtime dependencies; no error code added or changed.

Counts: 284 public exports · 57 error codes (frozen since 0.8.0) · 43 reason codes · 45 diagnostic codes · 22 named limits · 82 verify-docs rules · 18 bundle probes · 3 875 tests · 100 % statements, branches, functions and lines · 21 decision records.

Conformance:

| Level | Result |
|---|---|
| L1 | 29 796 parsed, 565 refused — the 565 promised refusals held code for code |
| L2 | 30 361 re-encoded byte for byte |
| L3 | node:crypto 29 796/29 796; OpenSSL 4.0.0 202/202 sampled |
| L4 | CryptoAPI 202/202 on Windows; Python cryptography and Go `crypto/x509` on Linux (CI) |
| L5 | 25 clauses; 182 requirement sentences of §4.1–§4.2 accounted for (21 clauses, 161 excluded, 36 not yet diagnosed) |
| L6 | 9 156/9 208 (99.44 %) |
| L7 | 195/203 (96.06 %) |
| L8 | 221/224 intact, 196/204 agree with NIST |
| Interop | 9 tools agree on every artefact, both directions, on the Windows release machine; the Linux set (GnuTLS, Python cryptography, Go, zlint, pkilint) is required in the conformance workflow |

## Changes

### Engine surface

- New: the limit `maxPkcs12KdfIterations`; the exports `SubjectDirectoryAttributesExtension` and `DirectoryAttribute` (the extension kind `subjectDirectoryAttributes`); the option `CheckServerNameOptions.path`; five diagnostic codes; `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`.
- Fixed: REVOKED only from authenticated, applicable evidence; URI hosts by RFC 3986 and SmtpUTF8Mailbox under rfc822Name constraints; the commonName fallback under dNSName constraints; RFC 4055 for PSS keys; RSASSA-PSS AlgorithmIdentifiers with explicit NULL; name attributes in their Appendix A string types and bounds; X.690 §8.23 string violations diagnosed; `crls[n]` reason paths; whole-millisecond timestamp bounds; `KEY_USAGE_BITS` frozen; `instanceof` across builds; the path search indexes its signature verdicts once (a 65-certificate bag went from 18 minutes to 29 s).
- `api.frozen.json` moved on ADR 0015 and ADR 0020 in the rehearsal, then rebased as `stable` at 1.0.0 (284 exports, 43 reason codes).

### Tooling (scripts/)

- `build-refusals-frozen.ts`; `check-ts-floor.ts` in the publish profile; the interop runner rebuilt over `scripts/lib/interop-*.ts` with ten tools, `REQUIRED_TOOLS` per platform and reviewed `TOOL_LIMITATIONS`; two new L4 validators.
- 82 rules, among them `option-defaults-parity`, `security-txt-parity`, `cve-class-parity`, `lint-waiver-reviewed`, `stale-milestone`, `standards-evidence`, `errors-guide-complete`, `code-token-registered`, `readme-surfaces`, `copilot-layer-parity`, `design-tokens-parity`, `a11y-structure`, `structured-data`, `architecture-diagram`, `comparison-current`, `refusal-baseline-frozen`, `contracts-shape`, `package-files-parity`, `reuse-shape`, `external-links`; `skills-shape` now also fails on an undeclared skill.
- Bundle budgets raised with the measured cause of each (`scripts/verify-bundle.ts`): `*` 272.9 KB of 280 KB.

### CI and repository (.github/, root)

- `publish.yml`: triggered by the `v*` tag; `guard` → `build` (no id-token) → `publish` (id-token only, uploads exactly the handed-on tarball) → `attest` (registry bytes, CycloneDX, SPDX and toolchain SBOMs, Sigstore bundle, attached to the draft release); `package-manager-cache: false` on every setup-node step — the audit's one blocker.
- `ci.yml`: no path filter on a required check; the `runtimes` job (Deno 2.9.7, Bun 1.4.2, headless Chromium); the `workflow lint` job (zizmor, actionlint). CodeQL over the workflows. harden-runner on every job, in block mode where the endpoints are known, and on macOS too.
- Rulesets: ten required checks (`ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`, `runtimes`, `workflow lint`, `dependency-review`) and a `code_scanning` rule (CodeQL, high or higher).
- Dependabot with a seven-day cooldown, the actions grouped, the ClusterFuzzLite image and the pinned fuzzing engine watched. brace-expansion lifted in the lockfile (three advisories published 2026-09-29, dev-only).
- ClusterFuzzLite over eight targets. A weekly OSV-Scanner job in `audit.yml`, installed at a fixed version through the Go checksum database.
- REUSE 3.3: `REUSE.toml` and `LICENSES/`; `reuse lint` reports 520/520 files compliant.

### Agent layer (.claude/, AGENTS.md, governance)

- `.github/copilot-instructions.md` and the pki-core instructions describe 1.0; `copilot-layer-parity` holds the Copilot layer table to `LAYERS`.
- `AGENT_RULES.md` gains rule 7, byte-identity awareness (pdfnative's rule, adapted to `output-bytes.json` and L2).
- `ai-governance.json` declares the release-audit skill; its anti-goals are restated for 1.0. `guard.mjs` judges a list-form exemption on the leading segment.

### Tests and conformance

- `tests/security/cve-classes.test.ts` (43 classes), `tests/tools/dual-package.test.ts`, `tests/tools/exported-constants.test.ts`, `tests/tools/interop.test.ts`, `tests/conformance/guide-counts.test.ts`, `tests/tools/check-ts-floor.test.ts`; mutation testing back to 100 % on every module the fixes touched, `verify-chain.ts` (213 mutants) and `verify-timestamp.ts` (131) included — 22 reviewed equivalents in all, each with its argument in `scripts/data/mutation-equivalents.json`.

### Documentation

- README, guides, agent brief, llms.txt and the landing page describe 1.0 as it is; the [standards guide](../../docs/guides/standards.md) is new.
- SECURITY.md: the compatibility promise, supported runtimes and compilers, two private reporting channels mapped to ISO/IEC 29147 and 30111, release integrity; `docs/.well-known/security.txt`.
- ADRs 0016–0021. The site at parity with pdfnative's design, with a WCAG 2.2 AA dark palette, underlined prose links, JSON-LD on every guide, the architecture drawn from `LAYERS`, and `docs/CNAME`.

## Independent audit

- **Pre-publication audit (agents, 2026-09-30):** 9 auditors and 9 adversarial verifiers; 98 findings CONFIRMED or DOWNGRADED — 1 blocker, 10 major, 48 minor, 39 note — all fixed or decided on this branch. The tools it used are recorded with their versions; the cross-validation it ran by hand is now the permanent interop matrix.
- `/release-audit release-notes/v1.0.0.md v0.9.0` — PENDING (the maintainer's GO/NO-GO).

## Validation (what actually ran, on Windows 11, Node v22.17.0)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 15 passed, 0 skipped in 515.0 s` |
| `npm run test:coverage` | 3 875 tests; 100.0 % statements, and the 100 % threshold on all four axes held |
| `npm run verify:bundle` | 18 probes within budget; `*` 272.9 KB of 280 KB, `openPkcs12` 101.8 KB of 104 KB |
| `npx tsx scripts/verify-docs.ts` | 82 rules, 0 errors, 0 warnings |
| `npx tsx scripts/validate-certs.ts --level 8 --require-all` | PASSED: 0 failures, 0 skips, 2 not applicable (the Linux L4 validators on win32) |
| `npm run interop` (`PKINATIVE_INTEROP_REQUIRE_ALL=1`) | 9 tools agree on every artefact, in both directions |
| `npm run check:ts-floor` | TypeScript 5.0.4 compiles the declarations under node16, bundler, node10 and nodom |
| `npm run check:package` | PASS (attw, publint, the tarball file by file) |
| `npm run smoke:install` | PASS: ESM and CJS load from the packed tarball |
| `npm pack --dry-run` | 12 files, 1.2 MB packed, 4.7 MB unpacked |
| `npm audit` / `osv-scanner` (2.6.0) | 0 vulnerabilities / no issues in 326 packages |
| zizmor 1.30.1 (offline) / actionlint 1.7.12 | no findings / clean |
| `reuse lint` (reuse 6.2.0) | 520/520 files with copyright and licence information; compliant with REUSE 3.3 |
| L4 Linux lineages, run locally under WSL Ubuntu on the release machine's validator input | Go `crypto/x509` (go 1.27) 202/202 on all six fields, `tbsFp256` included; Python cryptography 46.0.5 202/202; both canaries behaved (1 positive accepted, 4/4 negative refused) — with CryptoAPI, three lineages agree |
| Jazzer.js 4.0.0, 180 s per target over the eight ClusterFuzzLite targets | 780 036 runs, 0 crashes, 0 artefacts |
| axe-core (WCAG 2.0/2.1/2.2 A and AA) over 12 pages, light and dark, Edge headless | 0 violations in 24 runs |
| Lighthouse accessibility, the same 12 pages | 100 on every page |
| Horizontal overflow at 1280 and 375 px, light and dark | 0 px on the home page and the guides |

The local Node.js, 22.17.0, is below the floor this release declares (`^22.22.2`): it builds and tests, but the release gate that matters is the `build` job of `publish.yml`, which runs on the `.nvmrc` line's latest patch.

## Backward compatibility

Every export of 0.9.0 keeps its signature; two types are added (284). Against a 0.9.0 build:

- RSA containers in `openPkcs12` need `rsaAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }`, the former default.
- Drop `stringType: 'utf8'` on `countryName`, `serialNumber`, `dnQualifier`, `domainComponent` and `emailAddress`; pass DER to reproduce an existing name.
- Pass the validated `path` to `checkServerName` when `allowCommonNameFallback` is on.

From here, semver applies to all three parts of the promise and to what ADR 0018 adds.

## Out of scope (tracked in ROADMAP.md §1.1.x)

- `pkinative-cli` and `pkinative-mcp`, after 1.0.0.
- The 36 RFC 5280 §4 requirements not yet diagnosed; id-RSASSA-PSS keys re-wrapped for Web Crypto; a PKCS#10 reader; lazy signature verification in the path search; Node.js 26 when it enters LTS.

## Human-in-the-loop — steps for the maintainer

This is the first push to an empty repository, so the steps differ from the template. `main` must carry the whole linear history, not a squash, so that each 0.x tag lands on an ancestor of `main`.

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
6. Tag the 0.x line: annotated tags, pushed, with **no GitHub Release**. Those commits carry the old `publish.yml`, triggered only by a published release, so the tags start nothing.

   | Tag | Commit |
   |---|---|
   | `v0.1.0` | `f271a88` |
   | `v0.2.0` | `adeb55f` |
   | `v0.3.0` | `de7a7c2` |
   | `v0.4.0` | `0c63bf5` |
   | `v0.5.0` | `87b9ff6` |
   | `v0.7.0` | `448713c` |
   | `v0.8.0` | `cd9e629` |
   | `v0.9.0` | `353f36e` |

   **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
7. Configure Trusted Publishing on npmjs.com for `pkinative`, bound to `.github/workflows/publish.yml` and the `npm-publish` environment.
8. Draft the GitHub Release (title `v1.0.0 — the freeze, promised`, body = `release-notes/v1.0.0.md`, tag `v1.0.0` on the tip of `main`), **save it as a draft**, then create and push the tag `v1.0.0` — the push starts `publish.yml`.
9. What to expect: `guard` passes; `build` runs the publish gate and packs; approve `npm-publish` only once `build` is green; `publish` uploads the tarball with provenance; `attest` checks the registry's bytes and attaches the tarball, the SBOMs and the Sigstore bundle to the draft. **Then publish the draft.**
10. Check: `npm view pkinative version` shows `1.0.0`; `npm audit signatures`; `gh attestation verify pkinative-1.0.0.tgz --repo Nizoka/pkinative`; `npm run check:npm-drift`; `curl -sI https://pkinative.dev/llms.txt`.
11. CONTRIBUTING §Release step 11: require 2FA and disallow tokens on the package; deprecate the `0.0.1` reservation; upload `docs/assets/social-preview.png` (Settings → General → Social preview); fill the OpenSSF Best Practices questionnaire once the repository is public.
12. Optional: submit the nine issue drafts the audit wrote for pdfnative (`D:\Github\pdfnative\.github\drafts\`), each validated by pdfnative's `verify:issue`.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [x] `git diff --stat` on the release commit reads as the bump and the regenerated files (plus the two re-rasterised images), nothing else; the audit fixes follow it as their own commits.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above — `/release-audit` PENDING: this PR is not ready to merge until it is.
