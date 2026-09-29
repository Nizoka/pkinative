---
description: "Use when designing public API, adding exports, modifying function signatures, updating src/index.ts or src/types/, or planning breaking changes. Covers API stability, backward compatibility, error codes and documentation standards."
applyTo: "src/index.ts,src/types/**"
---
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
- From 0.8.0 the error-code vocabulary is frozen: removing or renaming a code, or moving it to another class, is semver-major; adding one is semver-minor. `docs/data/errors.frozen.json` is the snapshot (`scripts/build-errors-frozen.ts` writes it, and refuses to once 0.8.0 is released); the `error-codes-frozen` rule of `verify:docs` fails on a frozen code that leaves the registry or its union, and on an addition whose `since` is not newer than `frozenAt`. Diagnostic codes are not frozen
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
