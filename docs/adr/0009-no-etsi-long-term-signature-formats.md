---
status: accepted
date: 2026-09-29
since: 0.7.0
---

# No ETSI long-term signature formats; `atTimeStamp` takes one level of evidence

## Context and Problem Statement

0.7.0 verifies CMS SignedData and RFC 3161 timestamps. With `atTimeStamp`, `verifySignedData` judges each signer's chain at the earliest instant a verified timestamp proves, while the timestamp authority's own chain is judged at `at` — never at the `genTime` it wrote itself ([docs/guides/use-cases.md §Prove when it was signed](../guides/use-cases.md)).

That makes one timestamp worth exactly as long as its TSA's certificate. Carrying proof of existence beyond it takes the ETSI long-term formats: archive timestamps (PAdES and CAdES B-LTA), each covering the signature, its validation material and the timestamps before it. The question is whether pkinative implements them.

## Decision Drivers

- A TSA judged at a time its own token claims could be made to backdate tokens after a key compromise, so each level of evidence has to be judged at a time the verifier chose.
- The consumer that needs long-term validation is pdfnative's PAdES and LTV stack, and adopting pkinative there is pdfnative's milestone, not this one — "a cross-repository commitment must never gate a release here" ([ROADMAP.md §0.7.x](../../ROADMAP.md)).
- The 0.x line closes with no new engine behaviour: 0.9 admits none, and 1.0 adds none over 0.9 ([ROADMAP.md](../../ROADMAP.md)).

## Considered Options

1. Implement the ETSI long-term formats: archive timestamps and proof of existence chained over several timestamps.
2. Verify one level of evidence — a signature and the timestamps on its signer — and state the limit.

## Decision Outcome

Chosen option: 2. `atTimeStamp` takes one level of evidence; B-LTA archive timestamps and chained proof of existence are not implemented. What a caller can build from the parts is available — `verifyTimeStampToken` judges a token against the data or the imprint at any `at` the caller chooses — but the composition of several levels is not pkinative's.

### Consequences

- Good, because the TSA rule stays simple and safe: every token's authority is judged at `at`.
- Good, because the release line is not gated on another repository's milestone.
- Bad, because once the TSA's certificate has expired, the stamped signature is `PKI_REASON_EXPIRED` too: the only proof of time no longer counts, and TSA certificates are long-lived for exactly this reason.
- Bad, because archival validation over decades is outside what pkinative decides in one call.

### Confirmation

- Stated as a known limitation in [ROADMAP.md §0.7.x](../../ROADMAP.md) and [release-notes/v0.7.0.md](../../release-notes/v0.7.0.md).
- The 0.9 band's "zero new engine behaviour" and 1.0's "adds no engine behaviour over 0.9" hold the scope through the freeze.
- `recipes/timestamp.ts` runs the whole one-level loop — a replayed answer, the signer judged at the proved time, the TSA judged after its own expiry — as executable documentation.

## More Information

- [docs/guides/use-cases.md](../guides/use-cases.md) says B-LTA is not implemented "yet"; this record covers the 0.x line and 1.0, and says nothing about after.
