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
- A deviation may cost availability; it may never let through a name a CA excluded.

## Considered Options

1. RFC 5280 §7.1 LDAP string preparation.
2. Byte equality of the DER encoding, everywhere.
3. Byte equality everywhere, except that an **excluded** `directoryName` subtree also matches after §7.1 preparation.

## Decision Outcome

Chosen option: 3, since 0.9.0 (2026-09-29). From 0.5.0 to 0.8.0 it was option 2, everywhere; every module that touches a name says which comparison it runs.

The direction of a missed match is **not uniform**, and that is what decided the exception:

- **Chaining, CRL issuers and permitted subtrees** — a miss is a **refusal**: pkinative rejects a path a §7.1 validator accepts. That costs availability, not security, and byte equality stays. Five NIST PKITS deviations measure it: `ValidNameChainingCapitalizationTest5`, `ValidNameChainingWhitespaceTest3`, `ValidNameChainingWhitespaceTest4`, `ValidRolloverfromPrintableStringtoUTF8StringTest10`, `ValidUTF8StringCaseInsensitiveMatchTest11`.
- **Excluded subtrees** — a miss is an **acceptance**: a name that does not match an exclusion is a name not excluded. Under option 2 a CA could escape its issuer's excluded `directoryName` subtree by re-spelling the name in another case, another string type or with other spaces, where RFC 5280 §6.1.3 (b) and §4.2.1.10 require a refusal. That is a security defect, not a conformance deviation.

No corpus measures the second case. The 0.5.0 record counted `InvalidDNandRFC822nameConstraintsTest29` as its instance, and that attribution was wrong: re-scored after this change, Test29 was still accepted, because its end entity has no `subjectAltName` and a subject `emailAddress` outside its issuer's permitted `rfc822Name` subtree, which §4.2.1.10 says the constraint MUST reach. That is a different defect — no name comparison is involved — and 0.9.0 fixes it separately in `src/path/path-validate.ts`.

So `src/path/path-name-constraints.ts` tests an excluded `directoryName` subtree twice: by bytes, and after preparation — the same number of RDNs in the prefix, each RDN the same set of attribute types, and each value equal after NFKC, a case fold and RFC 4518 §2.6.1 insignificant-space handling. A value that is not a DirectoryString or IA5String is compared by its encoding only. The prepared test can only **add** an exclusion, so any imprecision in the preparation errs toward refusal. Nothing else moved: chain building, issuer matching, CRL scoping and permitted subtrees still compare bytes.

### Consequences

- Good, because chain selection is deterministic under cross-signing, and x509-limbo, written for the Web PKI, scores 99.44 % on the same code.
- Good, because the comparison is the one Go and webpki make for chaining, so a certificate that works with them works here.
- Good, because every remaining name-comparison deviation is a refusal: none of the five accepts a path a standards body rejects.
- Bad, because a hierarchy that re-encodes a name — a case change, extra whitespace, a rollover from `PrintableString` to `UTF8String` — does not chain here.
- Bad, because a permitted `directoryName` subtree that differs from the subject only by §7.1 preparation does not permit it: the subject is refused as not permitted.
- Bad, because until 0.9.0 an excluded `directoryName` subtree that differed from the subject only by §7.1 preparation did not exclude it. The 0.5.0 release note ("the direction of the miss is refusal, never acceptance"), and the claim of the 0.5.0 and 0.7.0 release notes and of CHANGELOG.md 0.5.0 that none of the nine deviations accepts anything a standards body rejects, did not hold — neither for that case nor for `InvalidDNandRFC822nameConstraintsTest29`. Those are shipped history and stay as written.

### Confirmation

- `scripts/data/pkits-score.json` records each of the five name deviations with the reviewed reason, and L7 fails on a new disagreement, an unexpected agreement or an empty reason.
- `scripts/data/pkits-smime-score.json` carries the same five at L8, message for message.
- `tests/path/path-name-constraints.test.ts` excludes a subject differing from an excluded subtree by case, spaces, string type or an NFKC-equivalent character, and keeps a permitted subtree byte-exact.

## More Information

- [release-notes/v0.5.0.md §Known limitations](../../release-notes/v0.5.0.md).
- [docs/guides/conformance.md §The levels](../guides/conformance.md#the-levels) — L7 and L8, and the deviations.
- Internationalized names are not converted either: a non-ASCII octet in an IA5String name is refused, not guessed ([README.md §Known limitations](../../README.md)).
