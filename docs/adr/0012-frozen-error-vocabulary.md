---
status: accepted
date: 2026-09-29
since: 0.8.0
---

# The error vocabulary is frozen at 0.8.0; diagnostics are not frozen; limit names freeze at 1.0

## Context and Problem Statement

Callers branch on `PkiError.code`, and two satellites — `pkinative-cli` and `pkinative-mcp` — will consume the registries as machine contracts after 1.0 ([ROADMAP.md §1.0.0](../../ROADMAP.md)). A code that is renamed breaks every caller silently. The question is when each of the four vocabularies a caller can depend on — error codes, diagnostic codes, reason codes, limit names — stops being free to change, and what "frozen" means for each.

## Decision Drivers

- Freeze only once the vocabulary is complete: PKCS#12 is the last subsystem that introduces error codes ([docs/data/errors.json](../data/errors.json)).
- Prove the freeze holds before promising it forever: zipnative's precedent is to spend a whole band proving it rather than freezing and releasing in the same breath ([CHANGELOG.md, 0.2.0](../../CHANGELOG.md)).
- A diagnostic is advice, not a contract a caller's control flow should rest on.
- The set of reasons a chain can be rejected for grows with the standards.

## Considered Options

1. Freeze the error codes at 0.9, and release 1.0 on top.
2. Freeze the error codes at 0.8.0, when the vocabulary is complete, and spend 0.9 proving no rename is needed.
3. Freeze all four vocabularies at once.

## Decision Outcome

Chosen option: 2, decided in the 0.2.0 roadmap change and taken at 0.8.0.

| Vocabulary | Status |
|---|---|
| `PkiErrorCode` | **Frozen at 0.8.0.** `docs/data/errors.frozen.json` holds the 57 codes. Removing or renaming one, or moving it to another class, is semver-major; adding one is semver-minor and must carry a `since` newer than `frozenAt`. |
| `PkiDiagnosticCode` | **Not frozen**: a diagnostic is advice, and its severity may change in a minor ([release-notes/v0.8.0.md](../../release-notes/v0.8.0.md)). The union is additions-only by contract — a code is never renamed or removed ([docs/data/diagnostics.json](../data/diagnostics.json)). |
| `PkiReasonCode` | **Not frozen at 0.8**: the set grows with the standards; adding a reason is semver-minor, removing or renaming one is semver-major ([docs/data/reasons.json](../data/reasons.json)). |
| `PkiLimits` names | **Freeze at 1.0.** |

### Consequences

- Good, because from 0.8.0 a caller can branch on an error code without fearing a minor release, and a whole band exists to find any rename before the promise becomes permanent.
- Good, because diagnostics stay free to become more or less severe as profiles evolve, without a major version.
- Bad, because a code named badly at 0.8.0 is now named badly until 2.0 — which is why ROADMAP.md §0.9.x asks for every wanted rename to be proposed in that band.
- Bad, because "not frozen" does not mean "free" for diagnostics or reasons: removals and renames are still ruled out or semver-major, and a reader has to learn four different contracts.

### Confirmation

- The `error-codes-frozen` rule of `npm run verify:docs` fails when a frozen code leaves the registry or its union or changes class, and when an addition's `since` is not newer than `frozenAt`; `scripts/build-errors-frozen.ts` refuses to rewrite the snapshot once 0.8.0 is released.
- `error-parity` decides every throw site's code from the syntax tree, following a code passed through a typed helper to every caller.
- `diagnostics-parity` and `reason-parity` hold the other two registries to their unions both ways; `limits-parity` holds the limit names across their four copies.
- `docs/assets/ecosystem.json` → `contracts.error_codes_frozen_since`: "0.8.0".

## More Information

- [docs/data/errors.frozen.json](../data/errors.frozen.json) — the snapshot and its `$comment`.
- [release-notes/v0.8.0.md §Downstream integration notes](../../release-notes/v0.8.0.md).
- [.github/instructions/api-design.instructions.md](../../.github/instructions/api-design.instructions.md) — the contributor-side statement of the same rules.
