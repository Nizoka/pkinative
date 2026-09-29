---
status: accepted
date: 2026-09-29
since: 0.5.0
---

# A third vocabulary of reasons, returned and never thrown, and one layer that converts

## Context and Problem Statement

Until 0.5, pkinative had two vocabularies: `PkiErrorCode`, **thrown** when the input is not the structure it claims to be or the API is misused, and `PkiDiagnosticCode`, **emitted** when a structure deviates from a profile. Path validation, revocation and name matching add a third kind of answer: the input is well formed, and the judgement asked for is *no*. A verification produces several such answers at once, and an exception carries one ([release-notes/v0.5.0.md](../../release-notes/v0.5.0.md)).

## Decision Drivers

- A report must be able to say everything that is wrong with a chain, not the first thing.
- A log reader must tell an exception from a verdict at a glance.
- A report that promises never to throw for bad input must still say what was wrong with it, without copying the encoding codes into a second vocabulary that would then have to be frozen too.
- Nothing should be built on `try/catch` and migrated later: the vocabulary has to land before the code that needs it.

## Considered Options

1. Throw on a failed judgement, as on a malformed input.
2. Reuse `PkiErrorCode` for verdicts, returned instead of thrown.
3. A third, disjoint vocabulary, `PkiReasonCode`, returned in reports — with one rule for who throws and who reports.

## Decision Outcome

Chosen option: 3. **Primitives return and throw; compositions report; exactly one layer converts** ([docs/guides/errors.md §Three vocabularies](../guides/errors.md)). `PkiReasonCode` landed as the first item of the 0.5 band, before any code that needed it ([ROADMAP.md §0.5.x](../../ROADMAP.md)).

- A reason message never starts with `pkinative: `, the prefix that marks what is thrown.
- `PKI_REASON_INPUT_MALFORMED` carries, in `errorCode`, the `PkiErrorCode` that would have been thrown: the reason registry wraps the error registry instead of mirroring it.
- `verify/` is the converting layer: the one-call reports (`verifyCertificateChain`, `verifySignedData`, `verifyTimeStampToken`, `openPkcs12`) catch what the primitives throw and turn it into reasons, and since 0.8.0 each decides misuse **before** its first catch, so a bad argument still throws its documented code.

The rule as it was first written in AGENTS.md and the errors guide — `verify/` is "the only place in `src/` that catches a `PkiError`" — was stronger than the code, and was corrected in 0.9.0. Other layers do catch, in two narrow forms: to re-throw a lower layer's error as their own class (`src/x509/x509-spki.ts`, `src/x509/x509-extensions.ts`, `src/cms/cms-attributes.ts`), or to drop a malformed optional value (the `cRLNumber`, reason code and `invalidityDate` readers of `src/revocation/crl-parse.ts`, which since 0.9.0 diagnose it with `PKI_DIAG_CRL_EXTENSION_MALFORMED` rather than dropping it silently, and pass what they catch through the core guard `_pkiError`; the argument probes of `src/build/build-signed-data.ts`, the RSASSA-PSS parameter check of `src/crypto/crypto-algorithms.ts`). What holds without exception is narrower: only `verify/` converts a `PkiError` into a `PkiReason`.

### Consequences

- Good, because a report lists every reason, each tied to a path in the input, and nothing in a report's contract is an exception.
- Good, because the reason registry did not need its own copy of the encoding failures.
- Bad, because a `try/catch` around a one-call report catches only misuse — callers used to exceptions must read the report.
- Bad, because the boundary is subtle enough to leak both ways: at 0.8.0 a seeded fuzzer found a CRL entry that escaped as a throw from three reports, and misuse swallowed into a reason ([CHANGELOG.md, 0.8.0](../../CHANGELOG.md)).
- Bad, because the placement of `catch` clauses is held by review; no rule decides it.

### Confirmation

- The `reason-parity` rule of `npm run verify:docs` keeps `docs/data/reasons.json` in sync with the `PkiReasonCode` union both ways, refuses a `PKI_REASON_*` literal inside a throw and a reason message with the `pkinative: ` prefix, and requires the three registries to be disjoint.
- `LAYERS` in [`scripts/lib/architecture.ts`](../../scripts/lib/architecture.ts) makes `verify` the only layer that reaches both a key and a verdict, enforced by `tests/tools/architecture.test.ts`.
- `tests/fuzzing/reports.test.ts` drives `verifyCertificateChain`, `verifySignedData` and `verifyTimeStampToken` with structural mutations and tiny limits, and asserts that each always resolves with a registered report; `tests/verify/verify-chain.test.ts` and `tests/verify/verify-pkcs12.test.ts`, among others, assert that misuse still throws.

## More Information

- [docs/data/reasons.json](../data/reasons.json) — the registry; the reason vocabulary does not freeze with the error codes ([ADR 0012](0012-frozen-error-vocabulary.md)).
- [CHANGELOG.md, 0.5.0](../../CHANGELOG.md) — the rule was written in 0.5's first commit with nothing yet obeying its last clause.
