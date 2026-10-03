---
status: accepted
date: 2026-10-01
since: 1.0.0
---

# What the 1.x promise covers beyond its three snapshots: option defaults, verdicts, open unions, report fields and the wire form

## Context and Problem Statement

[SECURITY.md §Compatibility promise](../../SECURITY.md#compatibility-promise) promises three things for 1.x, each held by a snapshot and a rule: the export surface ([ADR 0013](0013-renames-before-the-freeze.md)), the error vocabulary ([ADR 0012](0012-frozen-error-vocabulary.md)) and the decision surface ([ADR 0014](0014-the-decision-surface-contract.md)). The pre-publication audit of 1.0.0 found what those three leave unsaid, each a question a caller or a satellite (`pkinative-cli`, `pkinative-mcp`) will ask the day they depend on `^1.0.0`:

- **Option defaults.** [ADR 0015](0015-no-default-rsa-scheme.md) says "a default is the one thing semver cannot take back within a major". SECURITY.md lets a path, revocation or CMS verdict change in a minor, and flipping `requireRevocation`, `allowWildcards` or `restrictIssuers` changes exactly such verdicts. `api-surface-frozen` strips default values by design ([.github/instructions/api-design.instructions.md](../../.github/instructions/api-design.instructions.md)), so no rule held them: the snapshot even records `encodeBitString(bytes, unusedBits = 0)` as `(_: Uint8Array, _?) => Uint8Array`.
- **Verdicts outside path, revocation and CMS.** `openPkcs12`, `verifyTimeStampToken`, the signature checks and the key imports return or throw verdicts that no row covered. ADR 0015 and the 1.0.0 release note call a later default RSA scheme, or `id-RSASSA-PSS` keys opened from their parameters, compatible additions; both turn a returned refusal into an acceptance, the direction ADR 0014 calls major for parse refusals.
- **Returned unions.** A function returning a wider type is breaking under the [semver-ts specification](https://www.semver-ts.org/formal-spec/2-breaking-changes.html) ("returns a less specific ('wider') type"). pkinative returns many discriminated unions (`Extension`, `SubjectPublicKeyInfo`, `GeneralName`, `PrivateKeyKind`, `SafeBagKind`, the reason codes) and decodes some inputs as `kind: 'unknown'`: SLH-DSA and ML-KEM keys today. The `classify` function of `scripts/lib/api-surface.ts` calls a widened alias union compatible and a widened inline member union incompatible.
- **Report fields.** A `PkiReason` carries `code`, `message`, `standard` and `path`; a `PkiError` carries `offset` and sometimes `path`; reports carry counts. Only error message wording was disclaimed, and ADR 0013 treated a renamed reason path as caller-visible.
- **The wire form.** `JSON.stringify(parseCertificate(der))` throws on the `bigint` serial number. The registries (`docs/data/errors.json`, `reasons.json`, `diagnostics.json`, `limits.json`, `docs/assets/api.json`), which the 1.0.0 release note calls the machine contracts for the satellites, carry no schema version and are not in the npm tarball.
- **Non-default options.** The promise is made "for the default options". Nothing said what holds under `encodingRules: 'ber'`, `strict: true`, raised limits or the other flags.
- **A re-pinned corpus.** ADR 0014 lets a certificate the new corpus brings, and pkinative refuses, join the snapshot without a `since`. It did not say what happens when conformance L1 calls such a refusal wrong.
- **The reason vocabulary** was called "not frozen" in `docs/guides/errors.md` and `docs/data/reasons.json`, and "frozen" in the release note, for the same grow-only policy.

## Decision Drivers

- Every rule must be one a caller can act on: what to pin, what to branch on, what to read in a release note.
- Security fixes must stay possible in a minor ([ADR 0014](0014-the-decision-surface-contract.md)).
- A promise is held by a rule wherever a rule can see it; where none can, the record says who checks.
- The records already accepted stand: ADR 0014 for refusals and verdicts, ADR 0015 for adding a default where there was none.
- What is not promised is said as plainly as what is.

## Considered Options

1. **Freeze everything**: every default, every verdict, closed unions, every field's text, a JSON form fixed at 1.0.
2. **State each, with its direction**: defaults frozen with two named exceptions; verdicts corrected in a minor, never silently, and capabilities added in a minor; returned unions open; codes and path grammar promised, prose not; the wire form deferred, with its convention reserved.
3. **Leave it to the release notes**, case by case.

## Decision Outcome

Chosen option: 2. Option 1 makes every security fix to a verdict, and every new algorithm, a major release. Option 3 is what the audit found.

### Option defaults

**The default value of every option is part of the 1.x promise. Changing one is semver-major, in either direction**, including where the verdict the option drives may otherwise change in a minor. The verdict rule below covers the engine's reading of a standard under fixed options; a default is the caller's input, chosen by the library on their behalf, and moving it changes what an unchanged call means.

`docs/data/defaults.json` lists every default with the source line that implements it, and its `semver` for 1.x:

| `semver` | Meaning | Options |
|---|---|---|
| `frozen` | Changing it is major. | Every default not listed below. |
| `lowerable` | A default may be lowered in a minor, as a recorded new refusal ([ADR 0014](0014-the-decision-surface-contract.md)); never raised by the library. | `limits` (`DEFAULT_PKI_LIMITS`) |
| `addable` | There is no default; a minor may add one, because every call that worked keeps working ([ADR 0015](0015-no-default-rsa-scheme.md)). Once added, it is `frozen`. | `openPkcs12` `rsaAlgorithm`; `importPrivateKey` `algorithm` for an RSA key |
| `not-promised` | The behaviour is a diagnostic, which is not promised. | `onDiagnostic` (the once-per-code `console.warn` sink) |

### Returned verdicts

A verdict is what an operation answers about well-formed input: a report's `valid`, its reasons, a `boolean` from a signature check, or a refusal thrown because pkinative cannot act on an input it parsed.

| Change in a 1.x release | Semver | Held by |
|---|---|---|
| A verdict of `validateCertificatePath`, `buildCertificatePath`, `verifyCertificateChain`, `checkRevocation`, `checkOcspStatus`, `checkExtendedKeyUsage`, `checkServerName`, `verifySignedData`, `verifyTimeStampToken`, `openPkcs12`, `verifyPkcs12Mac` or a signature check, corrected toward what the standard requires — in either direction | minor, never silent: the release note lists it, and where L6, L7 or L8 hold the case, the reviewed baseline moves in the same diff | conformance L6–L8; the release audit for the rest |
| A capability added: an outcome that meant "pkinative cannot decide this" becomes a decision — a `PKI_REASON_SIGNATURE_NOT_CHECKED`, `PKI_REASON_PKCS12_KEY_UNSUPPORTED`, `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` or `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED` no longer returned, a `'not-checked'` signature now checked, a `PkiKeyError` or `PKI_API_MISUSE` for an unsupported or ambiguous key no longer thrown | minor, listed under Downstream integration notes | the release audit |
| A refusal the doctrine makes permanent lifted: the RFC 7292 Appendix B MAC and Appendix C ciphers, PBES1 ([ADR 0002](0002-pkcs12-pbes2-only.md)), a key operation `KEY_OPERATION_POLICY` refuses ([ADR 0001](0001-no-secret-dependent-cryptography.md)) | never, in any version | `pkcs12-policy-parity`, `key-operation-parity`, the architecture test |
| A parse refusal of a corpus certificate lifted or recoded | major ([ADR 0014](0014-the-decision-surface-contract.md)) | `refusal-baseline-frozen`, L1 |

The asymmetry with ADR 0014 is deliberate. A parse refusal is filed by code, and the corpus holds every one; a verdict is a judgement against a standard that a scored corpus, not a snapshot, measures ([ADR 0008](0008-section-6-judged-by-scored-corpora.md)), and both fixes of 0.9.0 were verdicts. A lifted "cannot decide" outcome is a new capability: a caller who relied on it relied on pkinative not knowing how, not on the input being wrong — which is why ADR 0015 could leave a default RSA scheme to a minor.

### Returned unions are open

**Every union pkinative returns may gain members in a minor**: a new `kind` of extension, key, name, bag or policy qualifier; a new variant of a result; a new reason or diagnostic code. **An input reported as `'unknown'`, or as the generic variant of a union, may be reported as a known kind in a minor** — for instance an SLH-DSA or ML-KEM public key, an extension pkinative learns to decode. A caller keeps a default branch, and branches on the positive member: `valid === true`, `status === 'valid'`, never "not a known failure".

Two consequences are recorded rather than avoided. Decoding a kind that was `'unknown'` can refuse a malformed value of it that used to pass undecoded: that is a new refusal, under ADR 0014's rule for new refusals. And a critical extension pkinative learns to process stops producing `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION`: that is a verdict correction, under the table above. A union that only reaches parameters may widen in a minor (it accepts more); narrowing any union is major.

The classifier of `api-surface-frozen` proves the alias case today: a new variant added to `SubjectPublicKeyInfo` or `Extension` is compatible. A literal union widened inline in an interface member (`OctetPublicKeyInfo['kind']`, for instance) was classified incompatible until 1.0.0, which was conservative and wrong under this policy; since 2026-10-03 `classify` treats a member whose flat union of literals or identifiers only gained members as compatible (`literalUnionWidened` in `scripts/lib/api-surface.ts`, held by `tests/tools/api-frozen.test.ts`), whether the type reaches a parameter or a result — a reader's `switch` must already carry a default for an open union. Anything but a flat union stays incompatible: proving more takes a type checker.

### Report and error fields

| Field | 1.x |
|---|---|
| `PkiReason.code`, `PkiError.code`, the error class, `PkiReason.errorCode`, `PkiReason.limit`, `PkiLimitError.limit` | Promised: codes and limit names are frozen vocabularies. |
| `PkiReason.path`, `PkiError.path` | The grammar is promised: a path starts at a member of the input the operation took, or at `path` for the certification path a report describes, and descends with `.member` and `[index]` steps. The steps may be refined in a minor (a path may point deeper); a path naming a member the input does not have is a defect, fixed in a patch ([ADR 0013](0013-renames-before-the-freeze.md)). |
| `PkiError.offset` | A byte offset into the input, for a human or a tool to look at; its exact value may change in a minor, when a check moves. |
| `PkiReason.message`, `PkiReason.standard`, the message of a `PkiError` | Not promised: for a human. A cited clause may become more precise. |
| The order of `reasons` | Not promised: treat them as a set. |
| Counts in a report (`explored`, `signatureVerifications`, …) | Not promised: they measure the work done. |
| The order of properties in a returned object | Not promised. |

### The wire form

- **Results are JavaScript values, not JSON.** They hold `bigint` and `Uint8Array`, and `JSON.stringify` refuses a `bigint`. 1.x does not promise a JSON form; a serialiser, if one is added, is a new export in a minor.
- **The convention is reserved now**, so that the satellites and any later serialiser agree: a `bigint` becomes its decimal string, a `Uint8Array` its lowercase hexadecimal string, `epochMilliseconds` stays a number, an absent optional member is omitted, and member names are unchanged.
- **The registries are machine contracts, additions-only.** Their codes follow the promise of their vocabulary. Their schema grows only: in 1.x an entry or a field may be added, and no field is removed, renamed or given another meaning; the parity rules (`error-parity`, `reason-parity`, `diagnostics-parity`, `limits-parity`, `api-json-sync`) require the fields that exist. Every registry under `docs/data/` carries `schemaVersion`, an integer that is `1` throughout 1.x and moves only with a change of meaning — which 1.x never makes — so a consumer can refuse a shape it does not know before reading it (the `registry-schema-version` rule holds the field on every file). They are not in the npm tarball: the copy that describes version X.Y.Z is the one at the git tag `vX.Y.Z`, which the tag ruleset forbids moving. A `schemaVersion` field, or shipping them in the package, is additive and needs no major.

### Non-default options

The three snapshots are taken, and the gate runs, under the default options. Under the others:

| Option | What 1.x keeps | What a minor may change, never silently |
|---|---|---|
| Any option | Its name, its type and its meaning — the check it switches on or off — and its default (above) | — |
| `encodingRules: 'ber'` | The error codes; the export surface | Which BER constructs are accepted: more, as a capability; fewer, as a security fix |
| `strict: true` | `PKI_STRICT_DIAGNOSTIC` as the code | Which inputs are refused, because diagnostics may change in a minor |
| `limits` raised | The codes and the limit names | What parses beyond the default limits |
| `mode: 'lax'` (`decodePem`) | The code of every refusal | Which deviations are tolerated |
| A relaxing flag (`allowSha1`, `allowTrailingData`, `allowUnverifiedIntegrity`, `allowCommonNameFallback`, `allowNonCriticalTimeStampingEku`, `allowWildcards`) or a tightening one (`requireRevocation`, `requireOcspNonce`, `requireExplicitPurpose`, `requireSigningCertificate`, `requireAlgorithmProtection`, the policy inputs) | What the flag switches | The verdicts reached under it, by the verdict table above |

### A re-pinned corpus

A certificate that a re-pinned corpus brings and pkinative refuses joins the refusal snapshot at the re-pin, without a `since`, and is promised from then ([ADR 0014](0014-the-decision-surface-contract.md)); the release note that ships the re-pin gives their number under `### Decision surface`. If L1 calls such a refusal wrong — a case of the new corpus expects the certificate to be accepted — the engine is fixed first, in its own commit tested against the candidate pin, and the re-pin follows with no engine change. The certificate was never promised, so accepting it lifts nothing.

### The reason vocabulary

`PkiReasonCode` is **grow-only**: every name is frozen with the export surface (`api-surface-frozen` holds them in `docs/assets/api.frozen.json`), and a new code is a minor. "Not frozen", used for it before 1.0, meant only that it may grow; the guide and the registry now say grow-only.

### Consequences

- Good, because a caller knows, for every default, every verdict, every union and every field, what a minor release may do to them.
- Good, because a security fix and a new algorithm both stay minor releases, and neither can arrive unannounced.
- Good, because ADR 0015's sentence on defaults and SECURITY.md's verdict row no longer contradict each other: the first governs the default, the second the reading of the standard.
- Good, because the satellites have a wire convention and a way to fetch the registries at the installed version before they write any code.
- Bad, because a caller with an exhaustive `switch` over a returned union gets a compile error, not a runtime error, when the union grows in a minor; that is the price of open unions, stated here.
- Bad, because the verdicts outside L6–L8 (time-stamps, PKCS#12, key imports, purpose and server-name checks) are held by tests and the release audit, not by a scored corpus.
- Bad, because `docs/data/defaults.json` is held to the source lines it cites, not to history: a change to a default and to its row in the same diff passes the rule, and the review is what calls it major.

### Confirmation

- `option-defaults-parity` (`npm run verify:docs`) holds `docs/data/defaults.json` to the source: every row's evidence is found in the file it cites, every type or function it names is exported with that option, and every optional `boolean` member of an exported `…Options`, `…Input` or `…Description` type has a row.
- `contracts-shape` holds `docs/assets/ecosystem.json` → `contracts.compatibility.policies` to this record, to ADR 0016 and 0017, to the registry and to SECURITY.md §Compatibility promise, both ways, and `notPromised` to SECURITY.md §What is not promised, entry for entry.
- `refusal-baseline-frozen` and conformance L1 hold the re-pin rule's half that a rule can see; L6–L8 hold the verdicts they score.
- `reason-parity` and `api-surface-frozen` hold the reason vocabulary.

## More Information

- [SECURITY.md §Compatibility promise](../../SECURITY.md#compatibility-promise) — the promise as a user reads it.
- [`docs/data/defaults.json`](../data/defaults.json) — every option default and its `semver`.
- [ADR 0014](0014-the-decision-surface-contract.md), [ADR 0015](0015-no-default-rsa-scheme.md), [ADR 0016](0016-one-entry-point-for-1-x.md), [ADR 0017](0017-runtime-and-toolchain-support.md).
- The Rust reference's [`non_exhaustive`](https://doc.rust-lang.org/reference/attributes/type_system.html) attribute — "a type or variant may have more fields or variants added in the future" — is the same open-union policy, stated in a type system that can enforce it.
