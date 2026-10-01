# scripts/

Every tool the repository runs on itself. Nothing here ships in the package.

**One convention governs the whole directory: exit 2 is always usage or
infrastructure, never a content failure.** That is what lets the gate tell
"the tool is missing" apart from "the check failed", and it is why a missing
veraPDF-style dependency is a `SKIP` with a reason rather than a red build —
until `--require-all` turns every skip into a failure, which is what a release
runner uses.

## The gate

`npx tsx scripts/gate.ts` is the one definition of green. It runs a declared
table of steps, one line of output each, with the full output of every step in
`test-output/.gate/<id>.log`; on the first failure it prints the last twelve
lines of that log and stops.

| Profile | Command | Steps |
|---|---|---|
| Fast — before every commit | `npm run gate:fast` | 5: typecheck:all, lint, test, verify:samples, verify:docs |
| CI — the default | `npm run gate` | 12: typecheck:all, lint, then build, dist-check, bundle-check, test:coverage (in place of test), check:package (attw, publint, the tarball file by file), verify:bundle, verify:samples, smoke:install, docs:playground-fresh, verify:docs |
| Publish — release branches | `npx tsx scripts/gate.ts --publish --require-all` | 15: adds conformance, interop and ts-floor |

Flags: `--only <id>` runs one step; `--from <id>` runs the profile from that
step's position in the full table; `--json` emits `{ ok, profile, steps }`.
Exit `0` every selected step passed or legitimately skipped, `1` a step failed
or would have skipped under `--require-all`, `2` bad usage.

On PowerShell call `npx tsx scripts/gate.ts --flag` directly: a bare `--`
is swallowed before `npm run gate` sees it.

## The scripts

| Script | npm alias | Gate step | What it does | Exit |
|---|---|---|---|---|
| `gate.ts` | `gate`, `gate:fast` | — | The step table and the three profiles | 0/1/2 |
| `verify-docs.ts` | `verify:docs` | yes | 79 named rules over the docs, the registries, the manifest, the published file list and the agent layer. Never writes. `--strict`, `--json` | 0/1/2 |
| `verify-bundle.ts` | `verify:bundle` | yes | Re-minifies one export at a time with esbuild and asserts a byte budget and the absence of markers proving unrelated code was retained | 0/1/2 |
| `smoke-install.ts` | `smoke:install` | yes | Packs the tarball, installs it into an empty project, loads it as ESM and as CJS | 0/1/2 |
| `package-files.ts` | inside `check:package` | yes | The tarball, file by file: `npm pack --dry-run --json` against `docs/data/package-files.json` — a file added, removed or made executable, or a changed LICENSE or THIRD-PARTY-NOTICES.md, fails; nothing under `src/`/`tests/`, no dotfile, no key or certificate, every `dist/` file budgeted, whatever the manifest says. `--update` regenerates it (and refuses a forbidden file) | 0/1/2 |
| `run-interop.ts` | `interop` | publish only | The write and read directions against foreign implementations: ten tools and two linters (zlint, pkilint) over everything the API writes, and their artefacts read back by pkinative. `--require-all` (or `PKINATIVE_INTEROP_REQUIRE_ALL=1`, set by the gate) fails on a missing tool `REQUIRED_TOOLS` names for the platform | 0/1/2 |
| `check-ts-floor.ts` | `check:ts-floor` | publish only | ADR 0017's TypeScript floor: packs the build and compiles a consumer of every export under that compiler release, four resolutions (`node16`, `bundler`, `node10`, `nodom`) | 0/1/2 |
| `validate-certs.ts` | `conformance` | publish only | Conformance levels L0–L8 over the pinned corpora. `--level N`, `--require-all`, `--update-baseline` | 0/1/2 |
| `fetch-corpora.ts` | `conformance:fetch` | — | Downloads x509-limbo and Wycheproof at their pinned commits, refusing any file whose SHA-256 differs | 0/1/2 |
| `release-prepare.ts` | — | — | The mechanical half of a version bump: every row of its `EDITS` table, at 1.0.0 every stable-era swap of `PRE_1_0_PROSE`, plus the release-note and pull-request-body scaffolds; a pure `planRelease` a test runs on the in-memory tree. Never commits, tags, pushes or publishes. `--version`, `--date`, `--dry-run` | 0/1/2 |
| `build-api-json.ts` | `docs:api` | — | The public export surface, from the TSDoc of every export of `src/index.ts` | 0/1 |
| `build-guides.ts` | `docs:guides` | — | `docs/guides/*.md` → static pages with their JSON-LD (TechArticle, BreadcrumbList, WebPage), plus the nav and footer every hand-written page pastes, and `docs/assets/architecture.svg` drawn from `LAYERS` | 0/1 |
| `build-sitemap.ts` | `docs:sitemap` | — | `docs/sitemap.xml`, from the canonical URL each page declares, every `<lastmod>` stamped with `verifiedOn` | 0/1 |
| `build-playground.ts` | `docs:playground`, `docs:playground-fresh` | yes (`--check`) | Copies `dist/index.js` into the playground byte for byte and records its hashes in the manifest; `--check` re-derives and compares | 0/1/2 |
| `build-llms-full.ts` | `docs:llms` | — | `llms.txt`, `llms-full.txt`, `llms-recipes.txt`, `llms-index.json` | 0/1 |
| `build-claude-rules.ts` | `agents:rules` | — | `.github/instructions/*.instructions.md` → `.claude/rules/*.md`, each scoped by `paths:`. `--check` exits 1 on drift | 0/1 |
| `build-errors-frozen.ts` | — | — | `docs/data/errors.frozen.json`, the error-code snapshot `error-codes-frozen` holds the registry to; refuses to change it once `frozenAt` is released | 0/1/2 |
| `build-api-frozen.ts` | — | — | `docs/assets/api.frozen.json`, the public-surface snapshot `api-surface-frozen` holds the sources to. Refuses to change it once `asOf` is released, except `--rebaseline docs/adr/NNNN-slug.md` (the rehearsal only, on an accepted ADR, logged in the snapshot), `--major X.0.0` (a new major's release commit; at 1.0.0 only if the rehearsal held) and `--ratchet` (a 1.x release's compatible additions) — both run by `release-prepare.ts` | 0/1/2 |
| `check-npm-drift.ts` | `check:npm-drift` | — | Online, so never a gate step: the registry's `latest` for `pkinative` against the manifest — below 1.0.0 the `0.0.1` name reservation and no other version at all, from 1.0.0 the manifest's version. Run weekly by the `npm-drift` job of `docs.yml`. `--json` | 0/1/2 |
| `mutate.ts` | `mutate` | — | Deterministic mutation testing: mutants enumerated on the syntax tree, type-checked, applied one at a time to a sandbox copy under `test-output/mutation/` and run against the suites that import the file; survivors re-run against every reaching suite. Reviewed equivalents in `data/mutation-equivalents.json`. `--files a,b=N`, `--sample N`, `--seed S`, `--concurrency K`, `--list` | 0/1/2 |
| `verify-issue.mjs` | `verify:issue` | — | The policy check on an agent's issue draft: refuses a proposed runtime dependency or a missing reproduction block | 0/1/2 |
| `install-git-hooks.mjs` | `hooks:install`, `hooks:uninstall` | — | Opt-in `core.hooksPath`; refuses to overwrite an existing value | 0/1 |

**Order matters in `docs:all`**: `docs:sitemap` reads the canonicals of the
generated pages, and `docs:llms` measures the size of everything else.
Inverted, `llms-index-sync` and `sitemap-parity` contend for the same commit.

## `lib/` — the shared, pure modules

| Module | Used by |
|---|---|
| `architecture.ts` | `LAYERS`, `KEY_OPERATION_POLICY`, `WEBCRYPTO_HOST_MODULES` and the checks over `src/` — one definition, two consumers (`tests/tools/architecture.test.ts` and the `layer-parity` rule) |
| `agent-config.ts` | `.claude/settings.json` parity, `GUARDED_SHELL_TOOLS`, the generated-rule banner, the line-ending check, the pull-request-template parity |
| `bundle-probe.ts` | What `dist/` must and must not contain, decided on the artefact |
| `corpora.ts` | The corpus pins, their checksum paths and their local directories |
| `raw-der.ts` | An engine-independent DER walker: the conformance gate's second opinion, which never imports `src/` |
| `mutation.ts` | `mutate.ts` and `tests/tools/mutation.test.ts`: the mutation operators, the seeded sampler, the import graph that selects suites, the equivalents table and the score |
| `validators.ts` | The cross-implementation confrontation of level L4 — CryptoAPI, Python cryptography and Go `crypto/x509` — its blob format and its canaries |
| `interop.ts` | The interoperability registries: `IMPLEMENTED_TOOLS`, `REQUIRED_TOOLS`, `TOOL_PLATFORMS`, `TOOL_LIMITATIONS`, `READ_CASES` |
| `interop-keys.ts`, `interop-reads.ts` | The read direction: key containers and CMS, timestamps, OCSP and CRLs written by foreign tools, with the verdict each must get |
| `interop-artefacts.ts`, `interop-tools.ts`, `interop-judge.ts`, `interop-host.ts` | The write direction: what the API writes, how each tool is driven (directly or through WSL), how its answer is judged, and how a tool is found by running it |
| `pkits.ts`, `pkits-smime.ts` | NIST PKITS read and scored: the paths of level L7, and the signed messages of level L8 — split, linked to their signer's test and held to its path verdict |
| `prose-language.ts` | The English-only prose detector |
| `api-surface.ts` | The public surface fingerprinted from the syntax tree, and the semver classification of a change — `build-api-frozen.ts` and the `api-surface-frozen` rule |

## Conventions

- **Pure functions over file contents where possible.** A rule that takes
  `path → text` can be perturbation-tested in memory, which is what
  `tests/docs/verify-docs.test.ts` does for every one of them: every rule must
  fail on one deliberate edit, or it is a rule that matches nothing.
- **Never reserialise JSON, YAML or XML.** `release-prepare.ts` rewrites one
  targeted regex per field, so formatting and key order survive a bump.
- **Generated files are generated.** `.claude/rules/`, `docs/assets/api.json`,
  the guides, the sitemap, the llms files and the playground bundle are all
  regenerated, never hand-edited; a `verify:docs` rule fails on drift for each.
- **A script never pushes, tags, opens a pull request or publishes.** Those
  are the maintainer's (`.github/AGENT_RULES.md` §5), and
  `.claude/hooks/guard.mjs` refuses them at the tool boundary for Bash and
  PowerShell alike.
