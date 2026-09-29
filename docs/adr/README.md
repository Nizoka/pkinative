# Architecture decision records

Each record below explains one decision that shapes what pkinative is — most of them something it will **not** do, and why that is a decision rather than a gap. They exist because a refusal stated only as a known limitation reads like a backlog item; a record states the problem, the options weighed, the consequences accepted on both sides, and what holds the decision in the repository.

The format is [MADR 4](https://adr.github.io/madr/): YAML front matter with the `status`, the `date` the record was written and the version `since` which the decision has been in effect, then the sections *Context and Problem Statement*, *Decision Drivers*, *Considered Options*, *Decision Outcome* (with *Consequences* and *Confirmation*) and *More Information*. Every fact is taken from the repository and cites its source. A record is never edited to change its decision: a new record supersedes it, and the old one's status says so.

| Record | Decision | Status | Since |
|---|---|---|---|
| [0001](0001-no-secret-dependent-cryptography.md) | No secret-dependent cryptography in TypeScript; Web Crypto is the one door | accepted | 0.1.0 |
| [0002](0002-pkcs12-pbes2-only.md) | PKCS#8 and PKCS#12 are opened under PBES2 only, and integrity fails closed | accepted | 0.8.0 |
| [0003](0003-no-pkcs8-or-pkcs12-writer.md) | No PKCS#8 or PKCS#12 writer | accepted | 0.8.0 |
| [0004](0004-dsa-and-ed448-cms-signers-not-verified.md) | DSA signatures and Ed448 CMS signers are not verified | accepted | 0.3.0 |
| [0005](0005-names-compared-by-encoded-bytes.md) | Distinguished names are compared by encoded bytes, not by RFC 5280 §7.1 string preparation | accepted | 0.5.0 |
| [0006](0006-no-network-io-in-the-engine.md) | No network I/O in the engine | accepted | 0.1.0 |
| [0007](0007-no-subpath-exports-before-1-0.md) | One entry point until 1.0; subpath exports are decided at 1.0, for the whole partition at once | accepted | 0.3.0 |
| [0008](0008-section-6-judged-by-scored-corpora.md) | RFC 5280 §6 is judged by scored corpora, not by a second clause table | accepted | 0.5.0 |
| [0009](0009-no-etsi-long-term-signature-formats.md) | No ETSI long-term signature formats; `atTimeStamp` takes one level of evidence | accepted | 0.7.0 |
| [0010](0010-no-external-security-audit-at-1-0.md) | No external security audit at 1.0 | accepted | 0.2.0 |
| [0011](0011-reasons-returned-and-one-converting-layer.md) | A third vocabulary of reasons, returned and never thrown, and one layer that converts | accepted | 0.5.0 |
| [0012](0012-frozen-error-vocabulary.md) | The error vocabulary is frozen at 0.8.0; diagnostics are not frozen; limit names freeze at 1.0 | accepted | 0.8.0 |

## Adding a record

Copy the shape of an existing record, take the next number, and add its row here in the same commit. The `adr-index` rule of `npm run verify:docs` holds this table to the files both ways: every `NNNN-slug.md` in this directory has exactly one row, every row names a file that exists, numbers run from 0001 without gaps, the decision and status of a row equal the record's title and front matter, and every record carries a status, a date, a version and the MADR sections above.
