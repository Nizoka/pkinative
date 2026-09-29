---
status: accepted
date: 2026-09-29
since: 0.5.0
---

# RFC 5280 §6 is judged by scored corpora, not by a second clause table

## Context and Problem Statement

Conformance level L5 (0.4.0) checks RFC 5280 clause by clause: `scripts/lib/clauses.ts` holds 19 clauses — seventeen sentences of RFC 5280 §4.1 and §4.2 and two X.690 DER rules the profile inherits — each quoting its normative sentence and naming the diagnostic that must report it, and `scripts/validators/rfc5280-clauses.ts` decides each from the raw bytes without importing `src/`.

The 0.4.0 release note promised more: "L5 covers RFC 5280 §4 only. §6 roughly doubles the table and arrives with path validation in 0.5" ([release-notes/v0.4.0.md](../../release-notes/v0.4.0.md)). ROADMAP.md §0.4.x says the same. That did not happen: 0.5.0 shipped path validation with two scored corpora instead, and the table still holds the same 19 clauses at 0.8.0 ([release-notes/draft/PR-v0.8.0.md](../../release-notes/draft/PR-v0.8.0.md)). This record states that the plan was superseded, and why.

## Decision Drivers

- A clause table decides **one certificate from its own bytes**. Its own header says what that excludes: "Everything requiring an issuer, a trust anchor or a clock — key usage consistency across a chain, name constraints, policy trees — is §6" (`scripts/lib/clauses.ts`).
- §6 is a property of a **chain and a trust store**: a validity instant, a path, the policy tree across it, name constraints intersected down it. A sentence of §6 has no verdict on a certificate taken alone.
- What a validator of §6 must be held to is its verdict on whole cases, against expectations someone else wrote down — and, because a validator that rejects everything scores well on a mostly-failure corpus, on the reason for each rejection.

## Considered Options

1. Double the clause table with §6 sentences, as the 0.4.0 release note promised.
2. Judge §6 end to end with corpora that carry expected verdicts: every case built, name-matched and revocation-checked the way a caller would, every disagreement carrying a written reason.

## Decision Outcome

Chosen option: 2, in three levels:

- **L6 — x509-limbo, scored.** 9 156 of 9 208 chains agree (99.44 %); 52 reviewed deviations, each with a reason; 30 cases pinned on their `PkiReasonCode`; two canaries against a scorer that stopped deciding anything.
- **L7 — NIST PKITS.** A second corpus written independently, around the US Federal PKI: 195 of 203 paths agree (96.06 %), eight deviations, the 20 §4.8 policy tests skipped because the archive states no `user-initial-policy-set`.
- **L8 — the 224 PKITS S/MIME messages**, each verified whole: 221 intact at the CMS layer, and 204 of 204 scored verdicts equal to the L7 verdict on the signer's own path.

L5 keeps what a clause table does well: attributing a violation of §4 to its sentence and proving that pkinative's diagnostic fires for it, with every clause exercised by a corpus certificate or waived to `tests/conformance/clauses.test.ts` with a written reason.

### Consequences

- Good, because the corpora found what reading the code had not: ten ways a name escaped its constraint (CVE-2025-61727 among them), a trust anchor that was never judged and SHA-1 signatures treated as evidence at L6; the whole of CRL scoping and a revoked CRL signer at L7 ([release-notes/v0.5.0.md](../../release-notes/v0.5.0.md), [ROADMAP.md §0.5.x](../../ROADMAP.md)).
- Good, because two corpora from different authors catch a misreading one of them shares with pkinative.
- Bad, because a corpus score is a measurement, not a promise: it moves when a corpus is re-pinned, which is why the 1.0 freeze names the decision surface instead ([docs/guides/conformance.md](../guides/conformance.md)).
- Bad, because a §6 sentence no corpus case exercises is not attributed anywhere, as a §4 clause would be.
- Bad, because the promise of 0.4.0 still stands as written in the 0.4.0 release note, which is frozen history, and in the parenthesis of ROADMAP.md §0.4.x; this record is where it is withdrawn.

### Confirmation

- `scripts/validate-certs.ts` runs L5 to L8 from `dist/`; `scripts/data/limbo-score.json`, `scripts/data/pkits-score.json` and `scripts/data/pkits-smime-score.json` hold every deviation with a reason, and an empty reason fails the gate — `--update-baseline` records the id and never fills the reason in.
- The `clause-table-complete` rule of `npm run verify:docs` keeps every L5 clause citing a real diagnostic or a written waiver.
- The ROADMAP.md §0.9.x item promoting clause completeness to blocking is unaffected by this record and remains open there.

## More Information

- [docs/guides/conformance.md §The levels](../guides/conformance.md#the-levels) — L5 to L8 in full.
- [release-notes/v0.5.0.md §Conformance](../../release-notes/v0.5.0.md) and [release-notes/v0.7.0.md §Conformance](../../release-notes/v0.7.0.md).
