---
status: accepted
date: 2026-11-17
since: 1.1.0
---

# Limit names are closed in 1.x: a new loop over input cites an existing limit, and a new name waits for a major

## Context and Problem Statement

Every loop over untrusted input consults a named bound of `PkiLimits` ([src/core/pki-limits.ts](../../src/core/pki-limits.ts), [.github/instructions/security.instructions.md](../../.github/instructions/security.instructions.md)): "adding a loop means adding or citing a limit". Until 1.0.0 the usual answer was to add one — `maxPkcs12KdfIterations` joined the table days before the freeze for exactly that reason ([ADR 0020](0020-a-kdf-budget-per-pkcs12.md)).

1.1.0 adds two readers, each with loops of its own: `parseTimeStampRequest` (the extensions of a request) and `parseOcspRequest` (the `requestList`, two kinds of extensions, the certificates of a signed request). The question is whether a minor may give them names of their own — `maxOcspRequests`, say — or must bound them with names that already exist.

`PkiLimits` is an interface every member of which is required, and it is the type of the exported constant `DEFAULT_PKI_LIMITS` and, through `Partial<PkiLimits>`, of the `limits` option of every reader. A consumer may hold a complete one: a satellite that validates operator ceilings key by key, a wrapper that builds its own defaults as `const limits: PkiLimits = { … }`. A new required member stops that object literal compiling. The stable phase of the surface freeze says the same mechanically: `classify` ([scripts/lib/api-surface.ts](../../scripts/lib/api-surface.ts)) reports a new required member on a type that reaches a parameter of an exported function as incompatible, and `api-surface-frozen` fails on it ([.github/instructions/api-design.instructions.md](../../.github/instructions/api-design.instructions.md)).

## Decision Drivers

- The 1.x promise ([ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md)): a minor adds, it does not stop a caller's code compiling.
- The security rule is "adding or citing": a loop without a bound is the defect, not a loop without a name of its own.
- The limits are vendored. pkinative-cli maps each limit to a `--max-*` flag and pkinative-mcp to an operator ceiling ([ADR 0024](0024-what-a-satellite-may-implement.md)); a name they do not know is a bound an operator cannot set until each satellite releases.
- A bound must mean one thing to the caller who sets it. Reusing a name for a quantity of another nature makes `limits: { maxX: n }` say something its author did not mean.

## Considered Options

1. Add a name per new loop, as optional members of `PkiLimits`.
2. Add a name per new loop, as required members, and call the release a major.
3. Bound every new loop with an existing limit whose meaning already covers a quantity of the same nature, and record the mapping.

## Decision Outcome

Chosen option: 3. For the whole of 1.x the set of limit names is closed. A new loop over input cites the existing limit that bounds a quantity of the same nature, the limit's `guards` text in [docs/data/limits.json](../data/limits.json) and its row in [SECURITY.md](../../SECURITY.md#resource-limits) gain the new quantity in the same change, and a test trips the limit through the new reader and asserts `PKI_LIMIT_EXCEEDED` with that name. `src/x509/x509-csr.ts` had already done this at 1.0.0, bounding the attributes of a certification request and their values with `maxExtensions`.

The two readers of 1.1.0, loop by loop:

| Reader | Loop | Limit | Why this one |
|---|---|---|---|
| `parseTimeStampRequest` | the `Extension` values of `extensions [0]` | `maxExtensions` | The same structure, read by the same function as the extensions of a `TSTInfo` (`_readImplicitExtensions`), which the limit already bounds. |
| `parseOcspRequest` | the `Request` entries of `requestList` | `maxOcspSingleResponses` | A response answers a request entry for entry, so the two lists have one length; a caller who caps what a responder may send has capped what a client may ask. |
| `parseOcspRequest` | `requestExtensions` and each `singleRequestExtensions` | `maxExtensions` | The `Extensions` type of RFC 5280, read by the function that reads the extensions of a response (`_readExtensions`). |
| `parseOcspRequest` | the certificates of `Signature.certs` | `maxChainLength` | What the limit already bounds for the `certs` of a `BasicOCSPResponse`: certificates attached to help build one path. |
| `parseOcspRequest` | the octets of the input | `maxInputBytes` | Checked before a byte is read, as every reader that walks its input with the cursor does; `parseTimeStampRequest` goes through the decoder, which checks it itself. |

Option 1 was rejected because an optional member of `PkiLimits` is not a limit: `DEFAULT_PKI_LIMITS` would have to carry it while its declared type did not require it, `resolveLimits` returns a complete table by construction, and `limits-parity` holds the interface, the defaults, the registry and SECURITY.md to one list of required names. Making that list two lists to save a name would cost the invariant the four copies exist for. Option 2 was rejected because none of these loops needs a bound of its own value: each sits beside a loop of the same nature that an existing default already bounds sensibly, and a major release for a name is the cost of a break paid for a preference.

### Consequences

- Good, because a 1.0.0 consumer holding a complete `PkiLimits`, and both satellites with their vendored limit tables, compile and run against 1.1.0 unchanged: no flag, ceiling or schema lags the engine.
- Good, because a caller who has already tightened `maxExtensions` or `maxOcspSingleResponses` for untrusted input has tightened the new readers too, without knowing they exist.
- Bad, because one name now bounds quantities a caller cannot set apart: an OCSP request list and an OCSP response list share `maxOcspSingleResponses`, a name that says only half of it. The `guards` text is where that is said.
- Bad, because a loop whose honest bound differs by orders of magnitude from every existing default has nowhere to go in 1.x. Neither reader is in that case; the next one that is waits for 2.0, or ships with a fixed, documented constant that is not a `PkiLimits` member.
- Neutral, because the next major may split the shared names; a split is a removal of meaning from the old name and belongs there.

### Confirmation

- `api-surface-frozen` (`npm run verify:docs`) fails on a required member added to `PkiLimits`, and `limits-parity` on an interface, a default, a registry row and a SECURITY.md row that disagree: a name cannot be added by accident, nor documented without being enforced.
- `tests/cms/tsp-request.test.ts` ("should stop at maxExtensions…") and `tests/revocation/ocsp-request.test.ts` (the `the limits` group: `maxInputBytes`, `maxOcspSingleResponses`, `maxExtensions` for both extension fields, `maxChainLength`) each trip the limit through the new reader, at the bound and one past it, and assert `PKI_LIMIT_EXCEEDED` with the limit's name.
- The two fuzz targets (`fuzz/tsp-request.js`, `fuzz/ocsp-request.js`) run under the default limits; `tests/fuzzing/targets.test.ts` executes them on every gate run.
- `docs/data/limits.json` and the Resource Limits table of SECURITY.md name the new quantities under each limit reused; `limits-parity` holds the two tables to the same names, defaults and CWE.

## More Information

- [ADR 0020](0020-a-kdf-budget-per-pkcs12.md) — the last limit added, before the freeze, and why it could not wait.
- [ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md) — what a minor may move.
- [ADR 0024](0024-what-a-satellite-may-implement.md) — the satellites vendor the registries; a limit name is a downstream change.
- [docs/guides/security.md](../guides/security.md) — the limits as a caller sets them.
