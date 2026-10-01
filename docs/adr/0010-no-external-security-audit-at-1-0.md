---
status: accepted
date: 2026-09-29
since: 0.2.0
---

# No external security audit at 1.0

## Context and Problem Statement

pkinative parses attacker-controlled input and decides whether to believe certificates, messages and key files. An external security audit is the usual evidence for such a library, and the first roadmap promised one at 1.0. The question is whether 1.0 waits for it, and if not, what stands in its place.

## Decision Drivers

- A promise that is going to be broken should be removed, not left to be broken ([CHANGELOG.md, 0.2.0](../../CHANGELOG.md)).
- Precedent: neither pdfnative nor zipnative shipped 1.0 with an external audit ([ROADMAP.md §1.0.0](../../ROADMAP.md)).
- Whatever replaces the audit must be named, repeatable, and run on every release rather than once.

## Considered Options

1. Keep the promise and hold 1.0 until an external audit has been commissioned and completed.
2. Remove the promise, name what stands in its place, and scope an audit on request.

## Decision Outcome

Chosen option: 2, decided in the 0.2.0 roadmap change. What stands in place, as ROADMAP.md §1.0.0 lists it, and where each is held:

| In place of an audit | Where it lives |
|---|---|
| The adversarial release review — two independent auditors, an adversarial verifier, a docs-autonomy pass, a GO/NO-GO ledger | [CONTRIBUTING.md §Release](../../CONTRIBUTING.md), step 5 |
| The conformance gate over third-party corpora | [docs/guides/conformance.md](../guides/conformance.md) — L0 to L8 today |
| 100 % coverage on all four axes, every unproven branch a counted decision | `vitest.config.ts`, the `coverage-ignore-budget` rule |
| Seeded adversarial suites | `tests/fuzzing/`, [SECURITY.md §Verification of the Parser](../../SECURITY.md) |
| CodeQL, OpenSSF Scorecard and Dependency Review on every change | [SECURITY.md §Code Safety](../../SECURITY.md) |

A user who needs an audit for procurement opens an issue; it will be scoped, and ROADMAP.md will say when it happens.

### Consequences

- Good, because 1.0 is not gated on an engagement the project does not control, and the roadmap carries no promise it knows it will break.
- Good, because every item in its place runs on every release, where an audit is a snapshot of one.
- Bad, because none of it is independent of the project in the way an external audit is: the release review is run by agents under the maintainer's direction, and the corpora judge conformance, not the absence of vulnerabilities.
- Bad, because a procurement process that requires an audit report cannot be satisfied from the repository alone.

### Confirmation

- ROADMAP.md §1.0.0 states the absence and the list; the `release-pr-drafts` rule of `npm run verify:docs` requires every release's committed pull-request body to carry its **Independent audit** section.
- `coverage-ignore-budget` holds the four coverage thresholds at 100 and the ignore count to `declared.coverageIgnores`.

## More Information

- [CHANGELOG.md, 0.2.0](../../CHANGELOG.md) and [release-notes/v0.2.0.md](../../release-notes/v0.2.0.md) — "1.0 no longer promises an external audit or the satellites".
- When this record was written, ROADMAP.md §1.0.0 said what stands in the audit's place "is named in SECURITY.md", and SECURITY.md named the corpora, the seeded suites, CodeQL, Scorecard and Dependency Review but not the release review or the coverage bar, which live in CONTRIBUTING.md and `vitest.config.ts`. The table above cites each where it actually is.
- When this record was written, ROADMAP.md §1.0.0 still described the gate as "L0–L5", although the gate had run L6 since 0.5.0 and L8 since 0.7.0.
- Amended at 1.0.0 (the decision is unchanged): both gaps above are closed. SECURITY.md §In place of an external audit now names the adversarial release audit and 100 % coverage on all four axes, and ROADMAP.md §1.0.0 describes the L0–L8 conformance gate.
