# Contributing to pkinative

Thank you for considering contributing to pkinative! This document explains how to get started.

## Development Setup

```bash
git clone https://github.com/Nizoka/pkinative.git
cd pkinative
npm ci
```

### Requirements

- Node.js 22 — the line in `.nvmrc` and `.node-version` (`nvm use` / `fnm use` / `volta` pick it up; CI also runs the suite on 24, on Windows and on macOS. `engines.node` is a patched floor per line, `^22.22.2 || ^24.14.1 || >=25.8.2`, which [ADR 0017](docs/adr/0017-runtime-and-toolchain-support.md) explains; a local 22.x below it builds and tests, but the release is gated on a patched one).
- npm — the version pinned by `packageManager` in `package.json` (Corepack honours it). The repository's `.npmrc` sets `ignore-scripts=true` (no dependency runs an install script here), `fund=false` and `audit-level=high`; `npm run <script>` still runs the script you name, but lifecycle hooks such as `prepublishOnly` do not fire, which is why the publish workflow builds explicitly before it packs.
- Dev dependencies use caret ranges on purpose: `package-lock.json` plus `npm ci` is what makes an install reproducible, not narrow ranges. Let npm manage the lockfile.

### First pull request in ten minutes

```bash
npm ci                     # reproducible install from the lockfile
npm run hooks:install      # optional: pre-commit lint + CRLF check, pre-push fast gate (core.hooksPath → .githooks)
npm run gate:fast          # typecheck, lint, tests, docs checks — the loop while you work
git switch -c fix/<what>   # feat/, fix/, docs/, chore/ (see Branch Strategy)
```

Edit, add a test beside the code you touched (`tests/` mirrors `src/`), run the fast gate, commit with a [Conventional Commits](#commit-messages) message, push your branch and open the pull request — its template is the [checklist below](#pull-request-checklist). `npm run gate` (the CI profile) before you ask for review; `npm run hooks:uninstall` removes the hooks.

Sign your commits if you can: with an SSH key already registered on GitHub, `git config gpg.format ssh`, `git config user.signingkey ~/.ssh/id_ed25519.pub`, `git config commit.gpgsign true` and `git config tag.gpgSign true` make every commit and tag verifiable.

Every file the project writes uses LF line endings (`.gitattributes` says `* text=auto eol=lf`); on Windows, Git converts on checkout and the pre-commit hook refuses a staged CRLF file.

## Build

```bash
npm run build          # tsup → dist/ (ESM + CJS + .d.ts)
npm run dev            # tsup --watch
npm run check:package  # build + @arethetypeswrong/cli + publint + the tarball file by file (docs/data/package-files.json)
```

### Preview the site

```bash
npm run docs:serve                              # http://localhost:5000
python -m http.server 5000 --directory docs/    # fallback, no npx
```

`serve` applies `cleanUrls`, as most static hosts do: it serves `/guides/quickstart.html` at
`/guides/quickstart` and `/guides/index.html` at `/guides`. `python -m http.server` does not.
That is why the guides index is linked as `guides/` everywhere — under `cleanUrls` the
`index.html` form loses a path segment and every relative stylesheet 404s. The `clean-url-safe`
rule of `npm run verify:docs` holds the site to it.

The Open Graph images are rasterised from their SVG sources; each SVG's header comment carries
the exact command, and `docs/assets/ecosystem.json` records the SHA-256 that proves the PNG is
not stale.

## Test

```bash
npm run test           # vitest run
npm run test:watch     # vitest (watch mode)
npm run test:coverage  # vitest with v8 coverage (CI enforces the thresholds below)
npm run verify:docs    # offline rules over docs, governance files, README and release notes
npm run gate           # Everything a pull request is held to, in one command
```

All new code must include tests. Coverage thresholds (vitest.config.ts): 100% of statements, branches, functions and lines, with no per-path override — a glob threshold replaces the global one, so an exception would only ever lower the bar. A branch no input can reach is removed by construction; where that is impossible it carries a `/* v8 ignore next -- why */` comment, counted by `declared.coverageIgnores` and checked by the `coverage-ignore-budget` rule of `npm run verify:docs`.

Coverage proves a line ran, not that a test would notice it being wrong. `npm run mutate` (`scripts/mutate.ts`, zero dependencies) applies one syntax-tree mutant at a time to a sandbox copy of the tree and runs the suites that import the file; it takes minutes per file, so it is not a gate step. Run it on the files you touched when you change a security decision — key decryption, the Web Crypto boundary, a path, revocation or CMS verdict, the decoder — with `npx tsx scripts/mutate.ts --files <file>` (`=N` samples a large file, `--seed` keeps the sample reproducible). Every survivor gets a test that kills it, or an entry in `scripts/data/mutation-equivalents.json` whose `reason` argues why no input can observe it; `tests/tools/mutation.test.ts` fails on an entry whose mutant no longer exists.

`npm run verify:docs` lists its rules with `npx tsx scripts/verify-docs.ts --list`. Each rule has a perturbation in `tests/docs/verify-docs.test.ts` that proves it fires; a new rule without one fails the suite.

## Lint & Type Check

```bash
npm run lint              # eslint src/
npm run typecheck         # tsc --noEmit (src/, strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes)
npm run typecheck:tests   # tsc --project tsconfig.test.json
npm run typecheck:scripts # tsc --project tsconfig.scripts.json
npm run typecheck:all     # all three above
```

All must pass before opening a PR.

## Code Style

- **English everywhere** — code, comments, messages, tests, recipes, docs and release notes. Another language appears only as demonstrated content (a certificate subject in an example), marked `demo-language: <tag> (reason)` on or above the line.
- **TypeScript strict mode** — plus `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride` in the library
- **No classes** — closure factories returning `readonly` interfaces; the `PkiError` family is the only exception
- **ESM-first** — all internal imports use the `.js` extension
- **`const` over `let`** — never use `var`
- **No `any`** — use `unknown` with type narrowing
- **Zero-copy** — `subarray`, never `slice`, in decoding paths

## Project Structure

```
src/
├── types/        # PkiError family and code unions, public types
├── core/         # named limits, diagnostics sink, byte / text / base64 helpers
├── hash/         # SHA-1/256/384/512 over public data, fingerprints
├── asn1/         # iterative X.690 decoder, value readers, time, OID codec, encoders
├── pem/          # RFC 7468 strict and lax PEM
├── oid/          # OID name registry
└── x509/         # RFC 5280 certificates, names, general names, SPKI, extensions
scripts/          # the gate, verify-docs, generators, the conformance runner
tests/            # unit, fuzzing, property, conformance, tools and docs suites, mirroring src/
docs/             # pkinative.dev sources
```

## Security

Every certificate and DER blob is attacker-controlled (`.github/instructions/security.instructions.md`):

- Every loop over input bytes consults a named limit from `src/core/pki-limits.ts`. A new loop means a new or cited limit, with its CWE, its default, a fuzzing test that trips it, and a SECURITY.md row — in the same pull request.
- Every thrown value is a `PkiError` subclass with a registered code; a `TypeError` escaping from malformed input is a bug.
- No secret-dependent cryptography, no `eval`, no dynamic `import()`, no I/O in the engine.
- Vulnerabilities are reported privately ([SECURITY.md](SECURITY.md)), never in an issue or a pull request.

## Conformance

pkinative is held to external corpora rather than to its own encoder ([conformance guide](docs/guides/conformance.md)):

- **x509-limbo** (C2SP, Apache-2.0) — every unique certificate parses, or is refused only where every limbo case using it expects failure, as the reviewed baseline `scripts/data/limbo-refusals.json` records.
- **Wycheproof** (C2SP, Apache-2.0) — the DER-encoded ECDSA signature vectors exercise the decoder's strictness.
- The corpora are pinned by commit and SHA-256 (`scripts/lib/corpora.ts`, `.github/checksums/`), downloaded into `test-output/corpora/` by `npm run conformance:fetch`, and never committed.
- The gate runs the built package, never `src/`, and an engine-independent DER walker (`scripts/lib/raw-der.ts`) cross-checks the boundaries; `node:crypto` and the openssl CLI are the differential oracles.

```bash
npm run build && npm run conformance:fetch && npx tsx scripts/validate-certs.ts --require-all
```

A change to decoding or parsing behaviour that moves a refusal regenerates the baseline in the same commit (`npx tsx scripts/validate-certs.ts --update-baseline`), and the commit message says why every changed entry was wrong before. Re-pinning a corpus updates `scripts/lib/corpora.ts`, the checksum file, `THIRD-PARTY-NOTICES.md` and the canaries of `docs/assets/ecosystem.json` together; the verify-docs rule `corpus-pin-parity` checks them.

## Branch Strategy

| Branch    | Purpose                                          |
| --------- | ------------------------------------------------ |
| `main`    | Stable branch; every tag is cut from it          |
| `feat/*`  | New features                                     |
| `fix/*`   | Bug fixes                                        |
| `docs/*`  | Documentation improvements                       |
| `chore/*` | Release tasks, metadata, governance, maintenance |

## Pull Request Checklist

- [ ] `npm run gate` passes — the CI profile in one command (`npm run gate:fast` for a quick loop while iterating)
- [ ] All tests pass (`npm run test`)
- [ ] Type check passes (`npm run typecheck:all`)
- [ ] Lint passes (`npm run lint`)
- [ ] New code has tests, and every new error code, diagnostic or limit is raised by at least one of them
- [ ] No `any` types introduced
- [ ] No new runtime dependencies added
- [ ] Every new loop over untrusted bytes consults a named limit, with its CWE, a fuzzing test and a SECURITY.md row (see [Security](#security))
- [ ] If decoding or parsing behaviour changed: the conformance gate passes and every expectation change is explained in the commit (see [Conformance](#conformance))
- [ ] If docs/, README or llms files changed: `npm run verify:docs` passes
- [ ] CHANGELOG.md updated if user-facing changes
- [ ] For releases: follow [Release](#release) — `release-notes/vX.Y.Z.md` written, and `npx tsx scripts/gate.ts --publish --require-all` passes locally

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(asn1): refuse non-minimal high tag numbers
fix(x509): skip issuerUniqueID before reading extensions
test(fuzzing): cover every truncation point of the fixtures
docs: document the BER option
```

## Release

The version bump is mechanical; the judgement goes into the release note.

1. Branch from `main`: `chore/release-vX.Y.Z`.
2. Bump `package.json` (and the lockfile with `npm install --package-lock-only`), `docs/assets/ecosystem.json` (`packages.pkinative.version`, `verifiedOn`) and `CITATION.cff` (`version`, `date-released`); `npm run verify:docs` names every file that still disagrees. `scripts/release-prepare.ts` also moves `docs/assets/api.frozen.json`, the only way it moves once released: a new major rebases it (`build-api-frozen.ts --major X.0.0` — at 1.0.0 it turns the 0.9 rehearsal into the stable promise, and refuses unless the rehearsal held), and a 1.x release ratchets it (`--ratchet`) so the surface it ships becomes part of the promise. At 1.0.0 it also swaps every sentence that says pkinative is not on npm for the stable-era text written, reviewed and held since 0.9 in `PRE_1_0_PROSE` (`scripts/verify-docs/rules/freeze.ts`): one `edit … 1.0 prose — …` line per row, and the bump is refused, with nothing written, if any phrase or span is not found exactly once — below 1.0.0 `release-era-prose` checks that on every commit, so it does not first surface on the release commit. In its diff, review that each swapped paragraph still reads in its surroundings, that `npm install pkinative` is now the install in README.md, the quick start, the agent brief and both halves of the landing page's install command, and that the README and the quick start keep the attested tarball at the new version as the alternative. Its two `todo` lines are the one step no text edit can do: re-rasterise `docs/assets/og-image.png` and `docs/assets/social-preview.png` with the command in each SVG's header comment and record their `svgSha256` in `docs/assets/ecosystem.json`, or `social-images` fails the gate.
3. `git diff --stat` — the diff must read as the bump and nothing else.
4. Write `release-notes/vX.Y.Z.md` from [release-notes/TEMPLATE.md](release-notes/TEMPLATE.md) and the matching `CHANGELOG.md` entry (`## [X.Y.Z] – YYYY-MM-DD`).
5. Run the pre-release audit (two independent auditors, an adversarial verifier, a docs-autonomy pass, a GO/NO-GO ledger under `test-output/.audit/`). Fix what survives, in batches by owner.
6. `npx tsx scripts/gate.ts --publish --require-all`: the full gate, conformance included.
7. Fill `release-notes/draft/PR-vX.Y.Z.md`, which step 2 scaffolded from [release-notes/PR_TEMPLATE.md](release-notes/PR_TEMPLATE.md). **These bodies are committed.** They are the auditable record of what each release claimed and what was actually run — the one place a reader can check, a year later, whether a figure came from a command or from somebody's memory. Paste the numbers the gate printed into the Verification table, and mark anything not run as `not run`, never as a guess.
8. Squash-merge with the title `release: vX.Y.Z — <headline>`, where the headline is the release note's GitHub Release title.
9. The maintainer drafts the GitHub Release first (title `vX.Y.Z — <headline>`, body = the release note, tag `vX.Y.Z` on the merge commit, **saved as a draft**), then tags `vX.Y.Z` on the merge commit and pushes the tag — the push is what starts `publish.yml` ([ADR 0019](docs/adr/0019-release-integrity-slsa-build-l2.md)). `guard` checks the tag against `package.json` and refuses a version below 1.0.0 before any approval is asked (the 0.x line is tagged, never released); `build`, which can never publish, runs the publish gate (the tarball checked file by file against `docs/data/package-files.json` included) and packs the tarball once; `publish` waits for the `npm-publish` environment's reviewer — approve it only once `build` is green — checks the tarball against the build job's digests and uploads it with provenance; `attest` checks what the registry serves against the same digests and the registry signatures, attests the tarball and the SBOMs and attaches them, with the Sigstore bundle, to the draft. **Then** the maintainer publishes the draft: with release immutability on, a published release accepts no new asset, so the files must be on the draft before it is published.
10. After a 1.x publication: `npm run check:npm-drift` — the registry's `latest` against the manifest (below 1.0.0 it expects the `0.0.1` name reservation and nothing else; the Docs workflow runs it weekly).
11. Once, after the first green `publish` run (1.0.0): in the npm package settings, set *Publishing access* to require two-factor authentication **and disallow tokens**, so Trusted Publishing from `publish.yml` is the only way a version reaches the registry; then deprecate the `0.0.1` name reservation (`npm deprecate pkinative@0.0.1 "name reservation; install 1.0.0 or later"`). If the upload in the `publish` job fails with `ENEEDAUTH` or a 404 on `PUT`, npm refused the OIDC token: the Trusted Publishing entry does not name exactly this repository, `publish.yml` and the `npm-publish` environment — fix the entry on npmjs.com and re-run the failed jobs; never add an `NPM_TOKEN` secret.

### Branch protection

The rules for `main` are versioned in [.github/rulesets/main.json](.github/rulesets/main.json), GitHub's ruleset format: no deletion, no force-push, pull request required (squash merges only, every review thread resolved, stale reviews dismissed on push), CodeQL results required — a pull request with a CodeQL security alert of high severity or above, or an error-level alert, cannot merge — and ten status checks required and up to date with `main`: `ci (22)`, `ci (24)`, `windows`, `macos`, `runtimes` and `workflow lint` from `ci.yml`, `conformance`, `conformance-windows` and `conformance-macos` from `conformance.yml`, and `dependency-review`. None of these workflows is path-filtered, because GitHub leaves the checks of a filtered-out workflow pending forever and the pull request blocked; `tests/tools/workflows.test.ts` holds the list to the jobs both ways. The tag rules ([.github/rulesets/tags.json](.github/rulesets/tags.json)) forbid deleting, moving or updating a `v*` tag, with an empty `bypass_actors` — **a pushed tag is permanent for everyone, the repository owner included.** Import a file after editing it: Settings → Rules → Rulesets → Import a ruleset.

What the ruleset deliberately does not do, on a single-maintainer project:

- **Zero required approvals.** One person cannot approve their own pull request, so requiring one would make every merge an admin bypass — the opposite of a control. OpenSSF Scorecard caps *Branch-Protection* and *Code-Review* for it; the score is accepted, the pretence is not. The number goes to 1 the day a second maintainer exists.
- **No code-owner review and no last-push approval**, for the same reason.
- **An admin bypass in `pull_request` mode only.** It lets the admin merge a pull request whose checks are red; it never allows a direct push to `main`. With no path filter left, a red check is a real failure, so a bypass is an event worth a sentence in the pull request, not a routine.
- **Signed commits are not required.** `main` only receives squash merges, which GitHub signs itself — but GitHub checks every commit of the head branch before it allows the squash, so one unsigned commit blocks the merge, and a first-time contributor would meet the rule as a wall. Signing is asked for instead ([First pull request in ten minutes](#first-pull-request-in-ten-minutes)); the rule goes on once every regular contributor signs.
- **No OpenSSF Best Practices badge yet** (Scorecard *CII-Best-Practices*): it is a questionnaire to fill once the repository is public, not a setting.

Settings that live outside the rulesets, to set once when the repository is created (Settings → Code security, Settings → General):

- **Dependency graph: on.** `dependency-review.yml` needs it, and `dependency-review` is a required check — without the graph every pull request fails it.
- **Private vulnerability reporting: on**, with Dependabot alerts, Dependabot security updates, and secret scanning with push protection. SECURITY.md names private vulnerability reporting as the first channel; check it before the first tag with `curl -s https://api.github.com/repos/Nizoka/pkinative/private-vulnerability-reporting`, which must answer `{"enabled":true}`. The second channel, security@pkinative.dev, is a mailbox the maintainer keeps.
- **Pages: from `main`, folder `/docs`, custom domain `pkinative.dev`, Enforce HTTPS.** `docs/CNAME` carries the domain; the DNS record already proves ownership. Check with `curl -sI https://pkinative.dev/llms.txt` once the first build has run.
- **Discussions: off**, until there is a reason to open them; SUPPORT.md sends questions to issues meanwhile, and says so.
- **Code scanning: the CodeQL *advanced* set-up** (`codeql.yml`), not the default set-up, which would analyse a second time with other settings.
- **Release immutability: on** (Settings → General → Releases). A published release then accepts no new or changed asset, which is why `publish.yml` attaches its files to the draft and the maintainer publishes it afterwards.
- **Environments → `npm-publish`: the maintainer as required reviewer, and deployments limited to tags matching `v*`**, so no branch run can reach the job that holds the npm token, whatever the guard says.
- **Actions → General: workflow permissions read-only**, and "Allow GitHub Actions to create and approve pull requests" off; every workflow grants its own writes per job.

Two consequences worth stating once. The ruleset requires a pull request, and `bypass_mode: "pull_request"` lets an admin merge one whose checks are red — it does not let anyone push directly to `main`. So on a repository whose `main` does not exist yet, **the rulesets are imported after the first push**, never before: there is no legal path to seed the branch otherwise. And the `v0.1.0`–`v0.9.0` tags are pushed as tags only, with no GitHub Release: the commits they name carry a `publish.yml` that only a published Release starts, so pushing them starts no workflow — and should one ever reach a commit with today's `publish.yml`, it ends red in the `guard` job on *"Refuse a pre-1.0 publication"*, before the `npm-publish` environment is reached, so no approval is ever requested for a run designed to fail. An approval prompt for a 0.x version is itself a defect: it means the guard no longer runs first.

No workflow of this repository has run yet: at the time of writing the GitHub repository has no pushed history. The first push to `main` is the first run of CI, conformance, CodeQL and Scorecard, and the first release tag the first run of `publish.yml`; until then every statement above is what the files say and what the local tests, zizmor and actionlint check.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
