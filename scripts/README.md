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
| Fast — before every commit | `npm run gate:fast` | typecheck:all, lint, test, verify:docs |
| CI — the default | `npm run gate` | 11: adds build, dist-check, bundle-check, test:coverage, check:package, verify:bundle, smoke:install, docs:playground-fresh |
| Publish — release branches | `npx tsx scripts/gate.ts --publish --require-all` | 12: adds conformance |

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
| `verify-docs.ts` | `verify:docs` | yes | 52 named rules over the docs, the registries, the manifest and the agent layer. Never writes. `--strict`, `--json` | 0/1/2 |
| `verify-bundle.ts` | `verify:bundle` | yes | Re-minifies one export at a time with esbuild and asserts a byte budget and the absence of markers proving unrelated code was retained | 0/1/2 |
| `smoke-install.ts` | `smoke:install` | yes | Packs the tarball, installs it into an empty project, loads it as ESM and as CJS | 0/1/2 |
| `validate-certs.ts` | `conformance` | publish only | Conformance levels L0–L8 over the pinned corpora. `--level N`, `--require-all`, `--update-baseline` | 0/1/2 |
| `fetch-corpora.ts` | `conformance:fetch` | — | Downloads x509-limbo and Wycheproof at their pinned commits, refusing any file whose SHA-256 differs | 0/1/2 |
| `release-prepare.ts` | — | — | The mechanical half of a version bump: 18 fields across 9 files, plus the release-note and pull-request-body scaffolds. Never commits, tags, pushes or publishes. `--version`, `--date`, `--dry-run` | 0/1/2 |
| `build-api-json.ts` | `docs:api` | — | The public export surface, from the TSDoc of every export of `src/index.ts` | 0/1 |
| `build-guides.ts` | `docs:guides` | — | `docs/guides/*.md` → static pages, plus the nav and footer every hand-written page pastes | 0/1 |
| `build-sitemap.ts` | `docs:sitemap` | — | `docs/sitemap.xml`, from the canonical URL each page declares | 0/1 |
| `build-playground.ts` | `docs:playground`, `docs:playground-fresh` | yes (`--check`) | Copies `dist/index.js` into the playground byte for byte and records its hashes in the manifest; `--check` re-derives and compares | 0/1/2 |
| `build-llms-full.ts` | `docs:llms` | — | `llms.txt`, `llms-full.txt`, `llms-recipes.txt`, `llms-index.json` | 0/1 |
| `build-claude-rules.ts` | `agents:rules` | — | `.github/instructions/*.instructions.md` → `.claude/rules/*.md`, each scoped by `paths:`. `--check` exits 1 on drift | 0/1 |
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
| `validators.ts` | The cross-implementation confrontation of level L4, its blob format and its canaries |
| `pkits.ts`, `pkits-smime.ts` | NIST PKITS read and scored: the paths of level L7, and the signed messages of level L8 — split, linked to their signer's test and held to its path verdict |
| `prose-language.ts` | The English-only prose detector |

## Conventions

- **Pure functions over file contents where possible.** A rule that takes
  `path → text` can be perturbation-tested in memory, which is what
  `tests/docs/verify-docs.test.ts` does for all 52 of them: every rule must
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
