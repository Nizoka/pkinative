---
status: accepted
date: 2026-09-29
since: 0.9.0
---

# The rename set before the freeze, landed once in the band that exists for it

## Context and Problem Statement

From 1.0.0 every export's name, kind and signature is a semver promise ([docs/assets/api.frozen.json](../assets/api.frozen.json), rule `api-surface-frozen`), and so is every `PkiLimits` key ([ADR 0012](0012-frozen-error-vocabulary.md)). ROADMAP §0.9.x asks for "every rename you will ever want" to be proposed in this band, because after it a rename is semver-major. A naming audit of the 0.8.0 surface found names that break the library's own conventions — a type named after a concept when every other is named after its function, a limit named after one of the three structures it bounds, a British spelling beside the standards' American one, a reason code that disagrees with the diagnostic reporting the same condition, a boolean parameter where every other function takes an options object — and a few that invite a wrong reading. The question is which of them to change, and how to change a snapshot that the rehearsal otherwise refuses to move.

## Decision Drivers

- A name wrong at 1.0 stays wrong until 2.0: the cost of a rename is lowest now, before any caller depends on it under semver ([ROADMAP.md §0.9.x](../../ROADMAP.md)).
- One rule a reader can apply without a table: a function's input, options and report types are its PascalCase name plus `Input`, `Options` or `Report` ([.github/instructions/api-design.instructions.md §Naming Conventions](../../.github/instructions/api-design.instructions.md)).
- Error codes are frozen at 0.8.0 and diagnostic codes are additions-only: neither may be renamed, so a rename elsewhere must align to them, never the reverse ([docs/data/errors.frozen.json](../data/errors.frozen.json), [docs/data/diagnostics.json](../data/diagnostics.json)).
- No behaviour change: every rename is a spelling, and the gate, the corpora and coverage must say the same after it as before.
- The move must leave a trace a rule can check, not a hand edit of the snapshot ([scripts/build-api-frozen.ts](../../scripts/build-api-frozen.ts) `--rebaseline`).

## Considered Options

1. Rename nothing, and carry the inconsistencies into 1.0.
2. Rename now with deprecated aliases kept until 1.0.
3. Rename now, once, without aliases, and move the rehearsal snapshot with `--rebaseline` on this record.

## Decision Outcome

Chosen option: 3. Pre-1.0 versions are git tags, never npm releases, so there is no installed base an alias would protect, and an alias frozen at 1.0 would be a second name promised forever. The whole set lands in one commit, and `npx tsx scripts/build-api-frozen.ts --rebaseline docs/adr/0013-renames-before-the-freeze.md` moves the snapshot and appends this record to its `rebaselines` log — the first use of that mode.

### The set

The file counts are the tracked, hand-written files whose text changed for that row (generated pages, the playground bundle and `api.json` excluded).

| Old | New | Reason | Files |
|---|---|---|---|
| `PkiLimits.maxCmsAttributes` | `maxAttributes` | Consistency: since 0.8 it bounds a PKCS#8 key's and a PKCS#12 bag's attribute set too, not only a CMS signer's | 17 |
| `PkiLimits.maxCmsBagEntries` | `maxCmsCertificatesAndCrls` | A trap: "bag" is PKCS#12's word, and this limit bounds the `certificates` and `crls` fields of a SignedData, which `maxPkcs12Bags` does not | 13 |
| `PkiLimits.maxOcspResponses` | `maxOcspSingleResponses` | The standard's spelling: it counts the `SingleResponse` entries of one response (RFC 6960 §4.2.1), not responses | 9 |
| `verified: number` on `VerifyCertificateChainReport`, `VerifySignedDataReport`, `VerifyTimeStampTokenReport` and the internal signer outcome | `signatureVerifications` | A trap: beside `valid: boolean`, a field named `verified` reads as a verdict; it is a count of Web Crypto calls | 14 |
| `ocsp` on `VerifyCertificateChainInput`, `VerifySignedDataInput`, `VerifyTimeStampTokenInput` | `ocspResponses` | Consistency: `SignedData.ocspResponses` already names the same DER list; the reason path of a malformed one follows (`ocspResponses[0]`) | 10 |
| `CheckOcspStatusInput.responderAuthorised` | `responderAuthorized` | The standard's spelling: RFC 6960 §4.2.2.2 "Authorized Responders", and the code's other names are American | 5 |
| `BuildCertificatePathInput.requiredPurposes` | `purposes` | Consistency: `VerifyCertificateChainInput.purposes` is the same list, and the composition had to translate one into the other | 4 |
| `ValidateCertificatePathInput.certificates` | `path` | Consistency: the reasons already point into it as `path[n]`, and `certificates` elsewhere names an unordered bag | 6 |
| `CheckExtendedKeyUsageOptions.requireExplicit` | `requireExplicitPurpose` | A trap: `requireExplicitPolicy` sits beside it on every chain input and means something else entirely | 5 |
| `allowNonCriticalTimestampingEku` | `allowNonCriticalTimeStampingEku` | Consistency: every other name spells it `TimeStamp` (`parseTimeStampToken`, `verifyTimeStampToken`) | 3 |
| `CheckRevocationInput.options?: PkiParseOptions` | `limits?` and `onDiagnostic?` at the top level | Consistency: every other input takes its limits at the top level; see the decision on `onDiagnostic` below | 5 |
| `PrivateKeyInfo.namedCurve: 'P-256' \| 'P-384' \| 'P-521' \| undefined`, `PrivateKeyInfo.keyType` | `curve: EcCurve \| undefined`, `kind` | Consistency: `EcPublicKeyInfo` says `curve` for the name (its `namedCurve` is the OID) and every discriminant in the library is `kind` | 7 |
| type `PrivateKeyType` | `PrivateKeyKind` | Follows `kind` | 3 |
| `PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION`, factory `unrecognisedCriticalExtensionReason` | `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION`, `unknownCriticalExtensionReason` | Aligns with `PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION`, which reports the same condition and can never be renamed; `since` stays 0.5.0 | 14 |
| `signatureAlgorithmDer`, taking a `Signer` | `encodeSignatureAlgorithm(signer)` | Consistency: every function returning DER is `encode…`, and a noun is not a verb | 8 |
| `dnsMatches`, whose third parameter was `wildcards = true` | `matchDnsName(presented, reference, options?: MatchDnsNameOptions)` | A verb, and an options object last like every other function: a bare `false` third argument says nothing at the call site. `MatchDnsNameOptions.allowWildcards` defaults to `true`, as `CheckServerNameOptions.allowWildcards` does. The internal §4.2.1.10 twin in `path-name-constraints.ts` became `dnsConstraintCovers`, a distinct name for a different rule | 9 |
| `encodeCertId` | `encodeOcspCertId` | A trap: "CertId" alone reads as any certificate identifier, and CRMF (RFC 4211) and ESS (RFC 5035) each define their own; this one is RFC 6960's `CertID` | 8 |
| `readPkcs12`, `ReadPkcs12Options`, `ReadPkcs12Report` | `openPkcs12`, `OpenPkcs12Options`, `OpenPkcs12Report` | Consistency: `read…` is the ASN.1 value-reader family (`readInteger`, `readTime`); this decrypts and judges, and pairs with `openSafeContents`. Behaviour, including the `rsaAlgorithm` default, unchanged | 19 / 6 / 6 |
| `VerifyChainInput`, `VerifyChainReport` | `VerifyCertificateChainInput`, `VerifyCertificateChainReport` | The rule: function name plus suffix | 4 / 7 |
| `VerifyTimeStampInput`, `VerifyTimeStampReport` | `VerifyTimeStampTokenInput`, `VerifyTimeStampTokenReport` | The rule | 6 / 6 |
| `PathBuildInput`, `PathBuildReport` | `BuildCertificatePathInput`, `BuildCertificatePathReport` | The rule | 3 / 6 |
| `PathValidationInput`, `PathValidationReport` | `ValidateCertificatePathInput`, `ValidateCertificatePathReport` | The rule | 6 / 7 |
| `OcspCheckInput`, `RevocationCheckInput` | `CheckOcspStatusInput`, `CheckRevocationInput` | The rule | 5 / 6 |
| `CheckPurposeOptions`, `VerifySignerInfoOptions` | `CheckExtendedKeyUsageOptions`, `VerifySignerInfoSignatureOptions` | The rule | 4 / 3 |
| `SignerVerification` | `SignerReport` | Consistency: the per-signer part of `VerifySignedDataReport`, and every result object is a `…Report` | 3 |
| `CmsAttribute` | `Attribute` | Consistency: X.501's `Attribute`, shared by CMS, PKCS#8 and PKCS#12 — the same widening as `maxAttributes` | 8 |
| `CreateOptions` | `PkiBuildOptions` | Consistency with `PkiParseOptions`; it now lives in `src/types/build-types.ts`, and `encodeDistinguishedName` and `encodeExtensions`, which typed the same `{ limits }` inline, take it | 7 |

**One export added.** `MatchDnsNameOptions` is new, because the rule that every option object type a public option refers to is exported applies to it. The surface grows by that one type.

**`CheckRevocationInput`: `onDiagnostic` kept beside `limits`.** The brief was `limits?`, and `encodingRules?` only if something passes it today. Nothing passes `encodingRules` or `strict`, so both went. `onDiagnostic` is passed today — by `verifyCertificateChain`, which keeps a CRL entry's dropped extension out of the console because its report is the answer, by the `check-revocation` recipe, and by the tests — and the walk does emit diagnostics (`findRevocation` diagnoses a malformed `reasonCode` or `invalidityDate` and drops it). Dropping it would have sent those to `console.warn` for every caller that silences them now, which is a behaviour change; flattening it keeps the behaviour.

### Checked against the rule and deliberately left

| Name | Why it stays |
|---|---|
| `DeltaCrlInput` | Not a function's input: it is a member type of `CheckRevocationInput.delta`, named for what it describes. |
| `VerifyCertificateSignatureOptions` | Shared by `verifyCertificateSignature`, `verifyCrlSignature` and `verifySelfSignature`; it is named for the first, and three names for one type would be worse. |
| `PkiParseOptions` | Shared by fifteen readers and parsers; the `Pki` prefix is what says so. `PkiBuildOptions` now mirrors it. |
| `DecodeAsn1Options` | Shared by `decodeAsn1` and `decodeAsn1Sequence`, and already named for the first. |
| `SignatureResult` | Not an input, options or report type: a caller-computed verdict fed into `signatures`. |
| `CreateSignedDataInput`, `VerifySignedDataInput`, `VerifySignedDataReport`, `CheckServerNameOptions`, `CreateOcspRequestOptions`, `CreateTimeStampRequestOptions`, `DecodePemOptions`, `DecryptPrivateKeyOptions`, `ImportPrivateKeyOptions`, `FindRevocationOptions`, `FormatFingerprintOptions`, `ParseCertificateOptions`, `ParseSignedDataOptions`, `ReadStringOptions`, `ReadTimeOptions`, `DecodeExtensionValueOptions` | Already follow the rule. |
| Every error code | Frozen at 0.8.0 ([ADR 0012](0012-frozen-error-vocabulary.md)); `error-codes-frozen` passes unchanged. |
| Every diagnostic code | Additions-only: a diagnostic code is never renamed or removed, while its severity and wording may change in a minor. Where a reason and a diagnostic disagreed, the reason moved. |
| `at` | Short, universal across every input, and unambiguous where it appears. |
| The other `allow*` / `require*` names | Their polarity is the contract (`allow*` relaxes, `require*` tightens); only the two that collided or misspelled were touched. |
| `canVerify`, `canSign`, `canDecrypt` | Capability probes, read as questions; a `verbNoun` form would say less. |
| The `parse*` family, `openSafeContents` | Already consistent: `parse` decodes without secrets, `open` decrypts. |
| `Pkcs12Key.signingKey`, `atTimeStamp`, `PkiTime.type`, `Asn1String.raw` | Each names exactly what it holds: `signingKey` the handle a caller signs with, `atTimeStamp` the option that moves `at` to a verified timestamp, `type` which of the two ASN.1 time types was read, `raw` the octets before the charset decided `value`. |

### Consequences

- Good, because a caller can derive a type's name from its function's, and every result object is a `…Report`.
- Good, because the three traps — `verified` read as a verdict, `requireExplicit` confused with `requireExplicitPolicy`, `maxCmsBagEntries` confused with PKCS#12 bags — are gone before they are promised.
- Good, because the snapshot's `rebaselines` log names this record, so the move is visible to `api-surface-frozen` and to anyone reading the snapshot.
- Bad, because every 0.8 caller has to rename, with no alias to lean on. The 0.9.0 release note carries the table under Downstream integration notes.
- Bad, because the reason path of a malformed stapled OCSP response changes from `ocsp[n]` to `ocspResponses[n]`: a path names the input field it points into, and a path naming a field that no longer exists would be a bug.

### Confirmation

- `api-surface-frozen` holds the sources to the moved snapshot, and the snapshot's `rebaselines` holds `{ "adr": "docs/adr/0013-renames-before-the-freeze.md", "asOf": "0.8.0" }` — the version `package.json` was at when the move was made, before the 0.9.0 bump.
- `error-codes-frozen` passes with `docs/data/errors.frozen.json` untouched; `diagnostics-parity` passes with no diagnostic code changed.
- `limits-parity` holds the three new limit names across `PkiLimits`, `DEFAULT_PKI_LIMITS`, `docs/data/limits.json` and SECURITY.md; `reason-parity` holds `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION` to its union.
- `api-exists` holds every guide, the README, llms.txt, the agent brief and every recipe to `docs/assets/api.json`, so an old name left in prose fails.
- The test suite and the conformance corpora answer as before, with coverage at 100 %.

## More Information

- [ADR 0012](0012-frozen-error-vocabulary.md) — the four vocabularies and when each stops being free; its wording on diagnostic codes ("not frozen") was corrected with this record to "additions-only", which is what its table already said.
- [scripts/build-api-frozen.ts](../../scripts/build-api-frozen.ts) — `--rebaseline`, and why a hand edit of the snapshot is not an option.
- [ROADMAP.md §0.9.x](../../ROADMAP.md) — the band's "propose here every rename you will ever want".

## Amendments

- **2026-10-04, before the first publication.** "Pre-1.0 versions are git tags" described the intention when this record was written; in the end no 0.x tag was created at all (zipnative's model — the 0.x versions exist only as commits in the history, and 1.0.0 is the first tag and the first npm release). The argument stands a fortiori: there is no installed base an alias would protect.
