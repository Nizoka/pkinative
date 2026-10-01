---
paths:
  - "src/index.ts"
  - "src/types/**"
---
<!-- GENERATED from .github/instructions/api-design.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# API Design Standards

## Public API Rules
- All public symbols exported from `src/index.ts` — the single entry point; there are no subpath exports (a subpath is a contract only a major release may remove)
- Every exported function has a TSDoc comment with a summary sentence, `@param` for each parameter, `@returns`, and `@throws` naming the error classes and codes it can raise
- Type exports use `export type { ... }` — zero runtime cost
- Never export internal helpers — if it's not in `src/index.ts`, it's private
- **Every option object type a public option refers to is exported** — check `docs/assets/api.json` (`npm run docs:api`) lists the type before the feature is called done
- **Every new error code** goes in the code union of its class (`src/types/pki-errors.ts`) AND in `docs/data/errors.json` with `since`, `raisedWhen`, `remedy`, `standard` and `cwe` — the `error-parity` rule of `verify:docs` fails on either side missing, and on a throw site whose code is not a literal of its class's union (or a parameter typed with that union, whose every caller passes one)
- **Every new diagnostic code** goes in the `PkiDiagnosticCode` union AND in `docs/data/diagnostics.json` — the union is additions-only by contract

## Backward Compatibility
- Pre-1.0: a minor release may change the API, and the release note says how under Downstream integration notes
- From 0.8.0 the error-code vocabulary is frozen: removing or renaming a code, or moving it to another class, is semver-major; adding one is semver-minor. `docs/data/errors.frozen.json` is the snapshot (`scripts/build-errors-frozen.ts` writes it, and refuses to once 0.8.0 is released); the `error-codes-frozen` rule of `verify:docs` fails on a frozen code that leaves the registry or its union, and on an addition whose `since` is not newer than `frozenAt`. Diagnostic codes are additions-only: a code is never renamed or removed, while its severity and wording may change in a minor
- **The public surface is frozen by phase.** `docs/assets/api.frozen.json` (written by `scripts/build-api-frozen.ts`) holds every export's name, kind and canonical signature, and every reason code; the `api-surface-frozen` rule of `verify:docs` holds the sources to it:
  - `phase: "rehearsal"` (0.8.x–0.9.x): **any** addition, removal or signature change fails, and so does any error code outside `errors.frozen.json` or reason code outside the snapshot, whatever its `since` — ROADMAP 0.9's "zero new exports, zero new codes", made executable
  - `phase: "stable"` (from 1.0.0): a removal, a kind change or an incompatible signature change is semver-major and fails; a new export, a new optional trailing parameter, a new optional member, a new required member on a type no exported function takes, and a widened union are semver-minor and pass. Anything else — a widened parameter type included — is treated as incompatible, because proving it compatible takes a type checker
  - The signature is what semver promises for a TypeScript export: read from the syntax tree of the declaring module (not from `api.json`, whose member types are first-line-only), with **comments, parameter names and default values removed** (a call is positional), union and member order ignored, inherited members merged, a constant reduced to its declared type (a changed default value is behaviour, not surface) and a class to its non-private members. The code unions are delegated: error codes to `errors.frozen.json`, reason codes to the snapshot's `reasons`, diagnostic codes to nothing — the snapshot does not hold them, because their contract is **additions-only** (`diagnostics-parity`), with severity and wording free to change, in either phase
  - The snapshot moves in `scripts/release-prepare.ts`: `--major X.0.0` rebases it at a new major (at 1.0.0 it becomes `stable`, and is refused unless the rehearsal held), `--ratchet` records a 1.x release's compatible additions so they are promised too. Between releases it moves only by `--rebaseline docs/adr/NNNN-slug.md`, in the rehearsal phase, on an accepted ADR that records a rename set; the move is logged in the snapshot's `rebaselines` (first use: ADR 0013 at 0.9.0). Error codes never move this way
- **Option defaults are part of the promise** ([ADR 0018](../../docs/adr/0018-what-the-1-x-promise-covers-beyond-its-snapshots.md)): every default of an exported `*Options`/`*Input`/`*Description` type has a row in `docs/data/defaults.json` saying in which direction a minor may move it, and `option-defaults-parity` holds each row to the line of `src/` that applies it — a new optional member with a default adds its row in the same commit
- Adding new optional parameters: always at the end, with sensible defaults
- New features: new functions > new parameters on existing functions
- Deprecation: mark with `@deprecated` TSDoc, keep for at least one minor version

## Function Signature Conventions
- Options object pattern for functions with >3 parameters
- Required params first, optional config object last: `fn(data, options?)`
- Return types: always explicit, never inferred for public API
- Outputs declare every key (`readonly x: T | undefined`); inputs accept `?: T | undefined`, so consumers compile with or without `exactOptionalPropertyTypes`
- Decoded structures are immutable (`readonly` everywhere) and expose zero-copy `Uint8Array` views of the input; document that the caller must not mutate the input
- Times are `epochMilliseconds` numbers, never `Date` (mutable, and a lossy representation of year 0000–9999 text)

## Naming Conventions
- Functions: `verbNoun` — `decodeAsn1`, `parseCertificate`, `computeFingerprint`
- Types: `PascalCase` — `Asn1Node`, `Certificate`, `GeneralName`
- Constants: `UPPER_SNAKE` — `DEFAULT_PKI_LIMITS`, `OID_REGISTRY`
- Error codes: `PKI_<SUBJECT>_<CONDITION>`; diagnostic codes: `PKI_DIAG_<SUBJECT>_<CONDITION>`
- Internal helpers: `_prefixed` or unexported

## Export Categories (maintain grouping in index.ts)
1. Errors, limits and diagnostics (`PkiError` family, `DEFAULT_PKI_LIMITS`, their types)
2. ASN.1 — decoding, value readers, encoders
3. OID — codec and registry
4. PEM — decode and encode
5. Fingerprints
6. X.509 — certificate parsing, extensions, names

## Documentation Requirements
- README Quick Start must work as-is (copy-paste ready), and is executed by the recipes suite
- Changelog entry for every user-visible change
- Every public option documented in a guide under `docs/guides/`
