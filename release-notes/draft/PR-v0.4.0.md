# release: v0.4.0 — prove what it writes, not only what it reads

> **Branch:** `chore/release-v0.4.0` → `main`
> **Type:** Minor release (additive, fully backward-compatible with v0.3.0 — one type added, one input widened, nothing removed or renamed)
> **Milestone:** `M2b-interop-clauses-and-trend`, the 0.4.x band of ROADMAP.md

## Summary

This release adds almost no library. It adds the machinery that decides whether the library is right, and whether it is right *for the reasons it claims*.

The conformance gate could say a certificate changed behaviour. It could not say which sentence of RFC 5280 a certificate violates, nor whether pkinative noticed. L5 does: 19 clauses, each quoting its normative sentence, each decided from raw bytes by a reader that never imports `src/`, each tied to the diagnostic that must report it. And every level before it pointed one way — bytes someone else wrote, read by pkinative. 0.3 opened the other direction and gave it no oracle, because nobody publishes a corpus of certificates a library is supposed to have written. The tools are the oracle, and they now run on three platforms, blocking.

166 public exports (70 runtime, 96 types; 165 before) · 47 error codes · 26 diagnostic codes · 19 RFC 5280 clauses · 11 named limits · 55 verify-docs rules · 8 bundle probes · 24 byte-baselined artefacts · 1 459 tests · 100.0 % statements, branches, functions and lines.

## Changes

### Engine surface

One type added, one input widened, nothing removed.

- `GeneralNameDescription` is exported, and `encodeSubjectAltName` accepts `iPAddress` (bytes, 4 or 16 octets) and `registeredID`. The parser has modelled `iPAddress` since 0.1; the encoder could not write one, and that asymmetry was the defect.

Everything else is unchanged. The conformance verdicts are identical to v0.3.0 — same 564 refusals, same baseline file, unmodified.

### Tooling (scripts/)

- `lib/clauses.ts` + `validators/rfc5280-clauses.ts` — conformance level L5.
- `lib/samples.ts` — the artefact catalogue, built once and used twice: hashed by `verify-samples.ts`, handed to foreign tools by `run-interop.ts`. One catalogue, because a baseline blessed over one set and a matrix run over another would each be green about something the other never saw.
- `run-interop.ts` + `lib/interop.ts` — the write direction and its declared-but-pending tools.
- `verify-samples.ts` + `data/output-bytes.json` — the output-byte baseline.
- Three new gate steps: `verify:samples` (fast/ci/publish), `interop` (publish).

### CI and repository (.github/, root)

- `bench.yml` — a weekly trend, never a threshold, with the run context in the artefact.
- `conformance.yml` runs `npm run interop`. Its three contexts are already required, so the write direction is blocking on Linux, Windows and macOS without the ruleset changing.
- `ISSUE_TEMPLATE/interop_report.md`.

### Agent layer (.claude/, AGENTS.md, governance)

No change. The instruction files were rewritten in 0.3.0 for the two new layers.

### Tests and conformance

- `tests/conformance/clauses.test.ts` — a violating and a conforming certificate for **every** clause. The corpus run says how often a clause fires; only this can catch an evaluator that always answers "pass".
- The string-confusion fuzzing suite no longer calls `expect` 45 000 times inside its loop. Same search budget, same seed; the `test` step went from 100 s to 31 s.

### Documentation

- `docs/guides/conformance.md` gains L5 and the write direction.
- `bench/RESULTS.md` gains a dated 0.3.0 section, with an explicit note that its parsing rows are not comparable with the 2026-09-19 section because that one ran under load.

## Independent audit

`/release-audit release-notes/v0.4.0.md v0.3.0` — **PENDING**

Not run. This PR is not ready to merge until it is.

## Validation (what actually ran, on Windows 11 Pro 26200, Node 22)

| Command | Result |
|---|---|
| `npx tsx scripts/gate.ts --publish --require-all` | `gate: 14 passed, 0 skipped in 156.6 s` |
| `npm run test:coverage` | 1 459 tests; statements 100 %, branches 100 %, functions 100 %, lines 100 % |
| `npm run verify:bundle` | 8 probes within budget; largest `{ * }` at 112.2 KB against 118 KB |
| `npm run verify:samples` | 24 sample(s) byte for byte against the baseline |
| `npm run interop` | `openssl` (OpenSSL 4.0.0) 11 checks agree; `windows-cryptoapi` (PowerShell 5.1.26100.9444) 6 checks agree; 3 tools skipped as declared-and-pending |
| `npx tsx scripts/verify-docs.ts` | `55 rule(s), 0 error(s), 0 warning(s)` |
| `npx tsx scripts/validate-certs.ts --require-all` | L0–L5 and Wycheproof green. L5: 19 clauses, 17 exercised by the corpus (2 waived), 8 violated by 15 readings, every violation attributed to its diagnostic. `PASSED: 0 failure(s), 0 skip(s)` |
| `npm run check:package` | attw + publint clean (gate step PASS) |
| `npm run smoke:install` | ESM and CJS load from the packed tarball (gate step PASS) |
| `npm pack --dry-run` | 12 files, 410.5 kB packed |
| `npm ls --omit=dev --all` | `pkinative@0.4.0` and `(empty)` — no runtime dependency |
| `npm run bench` | ran; the numbers are in `bench/RESULTS.md` under 2026-09-25, with the machine and the command. No threshold is enforced and none is claimed. |
| ClusterFuzzLite | **not run.** The container has never executed; this repository has no pushed history. |
| `certtool`, `keytool`, `security`, `python-cryptography` | **not run.** Declared and not implemented; each carries its reason in `scripts/lib/interop.ts`. |

## Backward compatibility

Every export present in v0.3.0 keeps its name, signature and behaviour. `encodeSubjectAltName` accepts two additional `kind` values and produces identical bytes for every call that compiled before.

Downstream forks that run the gate get three more steps. `interop` shells out to installed tools and is publish-only for that reason; a contributor laptop without OpenSSL must not go red for not having it.

## Out of scope (tracked in ROADMAP.md)

- Five of seven interop tools. Declared, each with its reason; `--require-all` goes on with the last one.
- L5 over RFC 5280 §6 — arrives with path validation in 0.5, roughly doubling the clause table. The completeness assertion becomes blocking at 0.9.
- `PkiReasonCode`, path validation, CRL and OCSP — 0.5.0, and the reason vocabulary lands **first** in that band, before §6, so verdict codes are never expressed as exception codes.

## Human-in-the-loop — steps for the maintainer

1. Squash-merge to `main` with the title `release: v0.4.0 — prove what it writes, not only what it reads`.
2. Wait for the seven required checks: `ci (22)`, `ci (24)`, `windows`, `macos`, `conformance`, `conformance-windows`, `conformance-macos`.
3. Tag `v0.4.0` on the merge commit and push it. **`tags.json` has an empty `bypass_actors`: a pushed tag can never be moved or deleted, by anyone.**
4. Publish the GitHub Release (title `v0.4.0 — prove what it writes, not only what it reads`, body = `release-notes/v0.4.0.md`).
   Below 1.0.0 expect `release-assets` green and `publish` red — the pre-1.0 refusal is deliberate and is the only proof the 1.0 guard still works.
5. Version-specific: the `conformance` job now runs `npm run interop` on all three platforms for the first time. On Linux and macOS only `openssl` will be found, and the matrix will pass with skips — that is expected. A **failure** there is the interesting case: it means a foreign tool on a platform this machine is not, refuses bytes pkinative wrote.

## Self-review checklist

- [x] Every count above was produced by a command on this branch, not typed from memory.
- [ ] `git diff --stat` on the release commit reads as the bump and the regenerated files, nothing else.
- [x] The release note carries all six mandatory sections and the CHANGELOG entry mirrors it.
- [x] No `Co-Authored-By` trailer and no "generated with" footer anywhere on the branch.
- [ ] The independent audit ledger is attached above, with a fix commit for every confirmed blocker and major — or the section says PENDING and this PR is not ready to merge.
