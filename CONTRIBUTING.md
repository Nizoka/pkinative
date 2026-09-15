# Contributing to pkinative

Thank you for considering contributing to pkinative! This document explains how to get started.

## Development Setup

```bash
git clone https://github.com/Nizoka/pkinative.git
cd pkinative
npm ci
```

### Requirements

- Node.js 22 — the line in `.nvmrc` and `.node-version` (`nvm use` / `fnm use` / `volta` pick it up; CI also runs the suite on 24 and on Windows, and `engines.node` allows `>=22`).
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
npm run check:package  # build + @arethetypeswrong/cli + publint
```

## Test

```bash
npm run test           # vitest run
npm run test:watch     # vitest (watch mode)
npm run test:coverage  # vitest with v8 coverage (CI enforces the thresholds below)
npm run verify:docs    # offline rules over docs, governance files, README and release notes
npm run gate           # Everything a pull request is held to, in one command
```

All new code must include tests. Coverage thresholds (vitest.config.ts): statements 95%, branches 90%, functions 95%, lines 95% globally, and 98 / 95 / 98 / 98 on the ASN.1 and PEM parsers.

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

pkinative is held to external corpora rather than to its own encoder:

- **x509-limbo** (C2SP, Apache-2.0) — every certificate of every testcase is parsed, or refused with the code the expectation map names.
- **Wycheproof** (C2SP, Apache-2.0) — the DER-encoded ECDSA signature vectors exercise the decoder's strictness.
- The corpora are pinned by commit and SHA-256 in `.github/checksums/`, downloaded into `test-output/corpora/`, and never committed.
- The runner never imports `src/`'s decoder to judge the decoder: an engine-independent DER walker cross-checks the boundaries.

A change to decoding or parsing behaviour updates the expectation maps in the same commit, and the commit message says why the previous expectation was wrong.

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
2. Bump `package.json` (and the lockfile with `npm install --package-lock-only`), `docs/assets/ecosystem.json` (`packages.pkinative.version`, `verifiedOn`) and `CITATION.cff` (`version`, `date-released`); `npm run verify:docs` names every file that still disagrees.
3. `git diff --stat` — the diff must read as the bump and nothing else.
4. Write `release-notes/vX.Y.Z.md` from [release-notes/TEMPLATE.md](release-notes/TEMPLATE.md) and the matching `CHANGELOG.md` entry (`## [X.Y.Z] – YYYY-MM-DD`).
5. Run the pre-release audit (two independent auditors, an adversarial verifier, a docs-autonomy pass, a GO/NO-GO ledger under `test-output/.audit/`). Fix what survives, in batches by owner.
6. `npx tsx scripts/gate.ts --publish --require-all`: the full gate, conformance included.
7. Draft the pull-request body from [release-notes/PR_TEMPLATE.md](release-notes/PR_TEMPLATE.md) into `RELEASE_PR_vX.Y.Z.md` at the repository root (git-ignored); paste the numbers the gate printed into its Verification section.
8. Squash-merge with the title `release: vX.Y.Z — <headline>`, where the headline is the release note's GitHub Release title.
9. The maintainer tags `vX.Y.Z` on the merge commit and publishes the GitHub Release (title `vX.Y.Z — <headline>`, body = the release note). Below 1.0.0, `publish.yml` refuses to publish to npm by design; from 1.0.0 it waits for the `npm-publish` environment's reviewer, runs the publish gate, publishes with provenance and attests the tarball and SBOM.
10. After a 1.x publication: `npm view pkinative version`.

### Branch protection

The rules for `main` are versioned in [.github/rulesets/main.json](.github/rulesets/main.json), GitHub's ruleset format: no deletion, no force-push, pull request required (single maintainer, so zero approvals — but every review thread resolved, stale reviews dismissed on push, squash merges only), and the status checks `ci (22)`, `ci (24)` and `windows` required and up to date with `main`. The tag rules ([.github/rulesets/tags.json](.github/rulesets/tags.json)) forbid deleting or moving a `v*` tag. Import a file after editing it: Settings → Rules → Rulesets → Import a ruleset.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
