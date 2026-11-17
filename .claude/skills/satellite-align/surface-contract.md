# Satellite surface contract — `docs/assets/surface.json`

What pkinative-cli and pkinative-mcp emit at `release:prepare` so that `npm run satellites:sync` reads their release as a file (contract mode) instead of deriving it from what they happen to commit (degraded mode). Until a package ships it, the script runs in degraded mode and names under "Unverified" what it could not derive. The issue drafts that ask each satellite for it are `.github/drafts/satellite-surface-contract.md` in each satellite repository (git-ignored, local).

The reader is `normaliseSurface` in `scripts/lib/satellite-surface.ts`; `tests/tools/satellite-surface.test.ts` holds the shape.

## Envelope — one file per package

```json
{
  "$schema": "https://pkinative.dev/schema/surface/1.json",
  "kind": "satellite-surface",
  "package": "pkinative-cli",
  "version": "1.1.0",
  "previous": "1.0.0",
  "releasedOn": "2026-11-28",
  "engine": { "pin": "^1.1.0", "pinField": "dependencies", "minimum": "1.1.0" },
  "runtime": { "node": "^22.22.2 || ^24.14.1 || >=25.8.2" },
  "lists": { "commands": ["pem", "oid"], "invocations": ["pem decode", "pem encode"], "errorClasses": ["E_USAGE"] },
  "structured": { "commands": [{ "name": "pem", "group": "Encodings", "summary": "…", "subcommands": [{ "name": "decode", "summary": "…", "flags": [{ "name": "input", "alias": "i", "value": "file" }] }] }] },
  "counts": { "commands": 18, "invocations": 53, "commandsWithoutSubcommands": 6 },
  "delta": { "commands": { "added": [], "removed": [] }, "flags:cert inspect": { "added": ["fields"], "removed": [] } },
  "constraints": ["--at and --now are never both given (E_USAGE)"],
  "engineCoverage": { "exports": 294, "capability": 117, "typeOnly": 177 },
  "ledger": [{ "id": "C1", "summary": "cert inspect takes --fields" }],
  "docs": { "guide": "https://pkinative.dev/guides/cli.html", "llms": "https://raw.githubusercontent.com/Nizoka/pkinative-cli/main/llms.txt", "agentContract": "docs/AGENT_CONTRACT.md" }
}
```

Rules of the envelope:

- **Lists, not counts.** Every count is the length of a list of the same name; `counts` adds only the derived splits named below. A reader that finds `counts.commands` different from `lists.commands.length` takes the list and reports the disagreement.
- `releasedOn` is the day the tag was made, not the day the release was prepared.
- `delta` is computed against the previous release's `surface.json` (`git show v<previous>:docs/assets/surface.json`): per list, the items added and removed; plus the pseudo-lists `flags:<invocation>` and `inputs:<tool>`. A first release has `"previous": null` and an empty delta.
- `ledger` is the release note's `## Downstream integration notes`, one entry per bullet.
- `unverified` (optional) names what the satellite itself could not establish, as `<key>: <why>`.

## pkinative-cli

Verified against the v1.0.0 checkout: 18 commands, 53 invocations, 13 error classes, five exit codes, 12 schema subjects, 57 `PKI_*` codes mapped, 39 global flags, 96 distinct invocation flags.

`lists`:

| List | Source in the CLI | At 1.0.0 |
|---|---|---|
| `commands` | `commandNames()` (`src/commands/registry.ts`) | 18 |
| `invocations` | every `command subcommand`, or `command` when it takes none ("cert inspect") | 53 |
| `globalFlags` | `GLOBAL_FLAGS` names | 39 |
| `flags` | the distinct flag names of every invocation | 96 |
| `errorClasses` | `ERROR_CODES` | 13 |
| `exitCodes` | the keys of the manifest's `exitCodes` | 0, 1, 2, 130, 143 |
| `schemaSubjects` | `SUBJECTS` names (`src/commands/schema.ts`) | 12 |
| `pkiCodes` | the keys of `PKI_TO_CLI` | 57 |
| `limitFlags` | `LIMIT_FLAG_NAMES` (`src/utils/limits.ts`) | 22 |
| `configKeys` | the keys the `config` schema admits | — |
| `envVars` | the variables the CLI reads | 4 |
| `completionShells` | the shells `completion` writes | 4 |

`structured` is exactly what `renderCliSurface` (`scripts/build-cli-surface.ts`) projects from `pkinative schema manifest`, so `docs/data/cli-surface.json` is rendered from it without a capture: `commands[{ name, group, summary, flags | subcommands[{ name, summary, flags, operands }], operands }]`, `globalFlags`, `errorClasses[{ code, meaning }]`, `exitCodes`, `wire`, the scalars `pkinative` (the engine version resolved) and `offline`; plus `flagDefaults: { "<invocation>.<flag>": "<default>" }`, empty until `FlagSpec` carries a default.

`counts`: the list lengths, plus `commandsWithoutSubcommands`. `engineCoverage`: the `counts` of `surfaceDocument()` (`scripts/lib/surface.ts` — the engine-export reach matrix, which is not the command surface and keeps its name).

Degraded mode today: one capture of `pkinative schema manifest` gives `commands`, `invocations`, `globalFlags`, `flags`, `errorClasses`, `exitCodes` and the whole of `structured`; `docs/data/errors.json` gives `pkiCodes`; `docs/data/core-exports.json` gives `engineCoverage`. Unverified: `schemaSubjects` (the manifest names its 9 JSON Schema subjects, not the 3 documents), `limitFlags`, `configKeys`, `envVars`, `completionShells`, `flagDefaults`.

## pkinative-mcp

Verified against the v1.0.0 checkout: 34 tools (23 read-only, 6 writing, 5 producing), seven prompts, one resource template, nine environment variables, 26 error codes of which 21 are wrapper codes, 89 examples.

`lists`:

| List | Source in the server | At 1.0.0 |
|---|---|---|
| `tools` | `listToolsPayload()` (`src/server.ts`), in `tools/list` order | 34 |
| `prompts` | `promptNames()` (`scripts/lib/mcp-surface.ts`) | 7 |
| `resourceTemplates` | `listResourceTemplates()` | 1 |
| `envVars` | `serverJsonEnvVars()` | 9 |
| `errorCodes` | `errorCodes()` — every `ToolError` code under `src/` (`derived.errorCodes`) | 26 |
| `wrapperCodes` | `WRAPPER_CODE_NAMES` (`src/wrapper-codes.ts`) — the codes that are the server's own | 21 |
| `transports` | stdio, streamable-http | 2 |
| `legacyRevisions` | the protocol revisions answered besides `mcpRevision` | 5 |
| `examples` | the `examples/*.json` file names | 89 |

`errorCodes` and `wrapperCodes` are two lists, named apart: pkinative.dev quotes the 21.

`structured`: `tools[{ name, group, annotation, inputs[] }]` (`annotation` is `readOnly`, `writes` or `produces`; `inputs` the top-level properties of the input schema), `envVars[{ name, default, isSecret }]`, and the scalars `mcpRevision`, `registryName`, `toolApiVersion`, `toolsListBytes`, `instructionsBytes`.

`counts`: the list lengths, plus `readOnlyTools`, `writingTools`, `producingTools`.

Degraded mode today needs no capture and no install: `tests/_fixtures/tool-shape.json` (tools, annotations, inputs; `tool-shape.v<previous>.json` is the previous release), `server.json` (variables, registry name), `docs/assets/ecosystem.json` (`derived.toolGroups`; `declared` for the revisions, the tool API version and the two byte sizes), `src/server.ts` (prompts), `src/wrapper-codes.ts`, `src/resources.ts`, `examples/`. Unverified: `transports`.

## Per-repository checklist

One pull request per satellite:

1. `computeSurface(root): SatelliteSurface` with a unit test over inline fixtures, the counts derived from the lists — pkinative-cli: a new `scripts/lib/cli-surface.ts` importing `manifest()` (`scripts/lib/surface.ts` keeps its name); pkinative-mcp: beside `computeDerived` in `scripts/lib/mcp-surface.ts`.
2. `release:prepare` writes `docs/assets/surface.json`, its `delta` against `git show v<previous>:docs/assets/surface.json` — the first pkinative-mcp delta from `tests/_fixtures/tool-shape.v1.0.0.json`, the first pkinative-cli delta empty with `"previous": null`.
3. A `surface-sync` rule in `verify:docs` (the committed file equals a fresh `computeSurface`), with its perturbation test.
4. `release:prepare` refreshes the sibling `packages.*` rows from the neighbouring checkouts, or warns naming the row (pkinative-mcp records those rows; pkinative-cli only emits).
5. Package-specific — pkinative-cli: `FlagSpec.default` feeding `flagDefaults`, and a `## Downstream integration notes` section in its release-note template; pkinative-mcp: the CHANGELOG heading in the en-dash form `## [X.Y.Z] – YYYY-MM-DD`, and `envVars` as objects.
