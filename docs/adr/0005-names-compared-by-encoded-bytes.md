---
status: accepted
date: 2026-09-29
since: 0.5.0
---

# Distinguished names are compared by encoded bytes, not by RFC 5280 §7.1 string preparation

## Context and Problem Statement

Path validation (0.5) compares names everywhere: a subject with the next issuer when chaining, a CRL issuer with a certificate's, a subject with a `directoryName` constraint. RFC 5280 §7.1 says two distinguished names match when they compare equal after LDAP string preparation — case folded, whitespace collapsed, and across `PrintableString` and `UTF8String` alike. The question is which comparison pkinative runs.

## Decision Drivers

- A cross-signed pair must be decidable: two CAs that print the same name and encode it differently are two CAs, and a validator that merged them would choose a chain by accident ([`scripts/data/pkits-score.json`](../../scripts/data/pkits-score.json)).
- Agreement with the modern implementations: Go's `crypto/x509` compares `RawIssuer` and `RawSubject` with `bytes.Equal`, and webpki does the same.
- The cost of the deviation must be measured, and its direction known.

## Considered Options

1. RFC 5280 §7.1 LDAP string preparation.
2. Byte equality of the DER encoding, everywhere.

## Decision Outcome

Chosen option: 2, everywhere and deliberately; every module that touches a name says so.

The measured cost is six of the nine NIST PKITS deviations ([docs/guides/conformance.md](../guides/conformance.md)), and the direction of the miss is **not uniform**, which this record states because shipped documents do not:

- **Five are chaining tests** — `ValidNameChainingCapitalizationTest5`, `ValidNameChainingWhitespaceTest3`, `ValidNameChainingWhitespaceTest4`, `ValidRolloverfromPrintableStringtoUTF8StringTest10`, `ValidUTF8StringCaseInsensitiveMatchTest11`. The miss is a **refusal**: pkinative rejects a path a §7.1 validator accepts. That costs availability, not security.
- **One is a name constraint** — `InvalidDNandRFC822nameConstraintsTest29`. For a constraint the direction inverts: a name that does not match is a name not excluded, so this one is an **acceptance** of a path NIST expects to fail. The reviewed reason in `pkits-score.json` says so in as many words.

### Consequences

- Good, because chain selection is deterministic under cross-signing, and x509-limbo, written for the Web PKI, scores 99.44 % on the same code.
- Good, because the comparison is the one Go and webpki make, so a certificate that works with them works here.
- Bad, because a hierarchy that re-encodes a name — a case change, extra whitespace, a rollover from `PrintableString` to `UTF8String` — does not chain here.
- Bad, because an excluded `directoryName` subtree that differs from the subject only by §7.1 preparation does not exclude it. The 0.5.0 release note ("the direction of the miss is refusal, never acceptance"), and the claim of the 0.5.0 and 0.7.0 release notes and of CHANGELOG.md 0.5.0 that none of the nine deviations accepts anything a standards body rejects, do not hold for `InvalidDNandRFC822nameConstraintsTest29`. Those are shipped history and stay as written; the conformance guide, which is live, now states both directions.

### Confirmation

- `scripts/data/pkits-score.json` records each of the six with the reviewed reason, and L7 fails on a new disagreement, an unexpected agreement or an empty reason.
- `scripts/data/pkits-smime-score.json` carries the same six at L8, message for message.

## More Information

- [release-notes/v0.5.0.md §Known limitations](../../release-notes/v0.5.0.md).
- [docs/guides/conformance.md §The levels](../guides/conformance.md#the-levels) — L7 and L8, and the nine deviations.
- Internationalized names are not converted either: a non-ASCII octet in an IA5String name is refused, not guessed ([README.md §Known limitations](../../README.md)).
