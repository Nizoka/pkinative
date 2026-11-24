---
status: accepted
date: 2026-11-18
since: 1.1.0
---

# Attribute certificates are read and signature-checked, not judged: RFC 5755 §5 validation waits for a corpus

## Context and Problem Statement

Until 1.1.0 the README listed attribute certificates (RFC 5755) among the known limitations: no reader, so an `AttributeCertificate` was `PKI_X509_STRUCTURE_INVALID` under `parseCertificate` and opaque everywhere else. An attribute certificate (AC) binds attributes — a role, a group, a clearance, an access identity — to a holder named by reference to a public-key certificate (PKC), and is signed by an AC issuer that RFC 5755 §4.5 forbids to be a CA. Its envelope is the envelope of a certificate (`acinfo`, `signatureAlgorithm`, `signatureValue`), its `acinfo` is not.

Two things can be shipped: a reader, which decides structure, and a verdict, which decides whether a relying party may act on the AC. RFC 5755 §5 makes the verdict a composition of five checks — the AC signature, the issuer's PKC path to a trust anchor, the holder binding (which, for `objectDigestInfo`, means recomputing a digest of the holder's key or certificate, §7.3), the targeting check against the verifier's own identity (§4.3.2), and AC revocation (§6) — plus the rule that the AC issuer's PKC is not a CA certificate. The question is how much of that 1.1.0 ships.

## Decision Drivers

- [ADR 0008](0008-section-6-judged-by-scored-corpora.md): a verdict surface is judged by a scored corpus. x509-limbo, PKITS and Wycheproof score paths, CRLs and signatures; none scores an attribute certificate, and no public AC corpus exists to pin.
- The 1.x promise ([ADR 0018](0018-what-the-1-x-promise-covers-beyond-its-snapshots.md)): an Input and a Report shape enter `docs/assets/api.frozen.json` at the release and cannot shrink afterwards. A shape guessed without a corpus is a shape frozen without evidence.
- `checkRevocation` takes a `Certificate`, and an AC is not one: AC revocation would need a second entry point or a widened parameter, each a promise of its own.
- `x509/` parses and nothing more (`.github/instructions/pki-core.instructions.md`); verification lives in `crypto/`, and `crypto/` never imports `x509/`.
- Limit names are closed in 1.x ([ADR 0027](0027-limit-names-are-closed-in-1-x.md)).
- Throw or diagnose, never both: the ASN.1 module of RFC 5755 admits much that its profile forbids (an empty attribute list, the `v1Form` issuer, a non-critical `targetInformation`).

## Considered Options

1. Ship nothing in 1.1.0; keep attribute certificates a known limitation.
2. Ship a reader (`parseAttributeCertificate`) and a boolean signature check (`verifyAttributeCertificateSignature`); document the §5 composition as a recipe; leave the verdict verb to a later minor.
3. Option 2 plus a `verifyAttributeCertificate` verb, taking an Input and resolving to a Report, implementing RFC 5755 §5.

## Decision Outcome

Chosen option: 2.

**The reader.** `parseAttributeCertificate(der, options?)` lives in `x509/`, beside `parseCertificate`, and takes the same `ParseCertificateOptions`. A structural violation of the RFC 5755 ASN.1 module throws `PkiCertificateError`; a profile violation the module admits is a diagnostic. It reuses the certificate's codes — `PKI_X509_STRUCTURE_INVALID`; `PKI_X509_VERSION_INVALID` for a version other than v2, a v1 AC of X.509 (1997) included (RFC 5755 §4.2.1); `PKI_X509_VALIDITY_INVALID` for a UTCTime in `attrCertValidityPeriod`, which the module types GeneralizedTime; the `PKI_X509_EXTENSION_*` and `PKI_X509_GENERAL_NAME_INVALID` codes — and adds one, `PKI_X509_ATTRIBUTE_MALFORMED`, for an attribute of §4.4 whose value does not match its syntax (CWE-1286). The six attributes of §4.4 are decoded (`authenticationInfo`, `accessIdentity`, `chargingIdentity`, `group`, `role`, `clearance` under `2.5.4.55`); any other is kept with its values' DER as `kind: 'unknown'`. The RFC 3281 clearance syntax and OID (`2.5.1.5.55`), which §4.4.6 asks a reader to decode (SHOULD), is kept as `unknown`: no issuer outputs it any more, and §4.4.6 forbids outputting it.

**AC-only extensions are scoped to the AC.** `targetInformation` (2.5.29.55), `auditIdentity` (1.3.6.1.5.5.7.1.4) and `noRevAvail` (2.5.29.56) are decoded by a map that only `parseAttributeCertificate` hands to the shared extension reader. Adding them to the global map would make `parseCertificate` decode them in public-key certificates, where a malformed one would become a new refusal against the L1 baseline, and `decodeExtensionValue` would grow kinds the satellites document as a closed list of 19. `authorityKeyIdentifier`, `authorityInfoAccess` and `crlDistributionPoints` reuse their certificate decoders and diagnostics.

**Diagnostics, all since 1.1.0.** `PKI_DIAG_AC_HOLDER_EMPTY`, `PKI_DIAG_AC_HOLDER_MULTIPLE` (an `info`: §4.2.2 RECOMMENDS one option), `PKI_DIAG_AC_ISSUER_V1_FORM` (read, diagnosed, never refused), `PKI_DIAG_AC_ISSUER_NOT_PROFILED`, `PKI_DIAG_AC_ATTRIBUTES_EMPTY`, `PKI_DIAG_AC_ATTRIBUTE_DUPLICATE`, `PKI_DIAG_AC_ATTRIBUTE_PROFILE`, `PKI_DIAG_AC_EXTENSION_CRITICALITY` and `PKI_DIAG_AC_EXTENSION_PROFILE`; the serial, validity, GeneralizedTime-fraction, unique-identifier, algorithm-mismatch and named-bit diagnostics of certificates are reused with the AC's paths.

**Limits, per ADR 0027.** No new name. The octets of the input: `maxInputBytes`, in the decoder. The attributes of `acinfo` and the values of each, the values of an `IetfAttrSyntax` and the security categories of a clearance: `maxAttributes`, the bound `subjectDirectoryAttributes` already puts on the same `Attribute` structure. Every `GeneralNames` and the targets of `targetInformation` (each a `GeneralName`): `maxGeneralNames`. The extensions: `maxExtensions`, through the reader certificates use.

**The signature check.** `verifyAttributeCertificateSignature(ac, issuer, options?)` in `crypto/` hands the AC to the `verifySignedStructure` certificates and CRLs go through — the same algorithm-match rule, SHA-1 refusal and fail-closed answers — taking the AC by its structural type, so `crypto/` still imports nothing from `x509/`. No new Web Crypto operation: `KEY_OPERATION_POLICY` is unchanged.

**No verdict verb in 1.1.0.** Option 3 was rejected because every driver above weighs against freezing it now: no corpus scores it, its revocation step has no entry point that takes an AC, and holder binding by `objectDigestInfo` hashes a public key or certificate in a form §7.3 defines and no test vector exists for. The recipe `recipes/attribute-certificate.ts` shows the composition a caller writes today: the signature against the issuer's PKC, `verifyCertificateChain` on that PKC, the AC's validity at the caller's instant, and the holder's `baseCertificateID` against the holder's PKC. When a verb comes, its reasons will need names; this record reserves `PKI_REASON_AC_HOLDER_MISMATCH` and `PKI_REASON_AC_TARGET_MISMATCH` for it, and adds neither to `docs/data/reasons.json` now. Option 1 was rejected because a reader and a signature check need no verdict to be useful — an authorisation server that already knows its AC issuers needs exactly them.

### Consequences

- Good, because an RFC 5755 AC can be read, its profile concerns reported, and its signature checked with the machinery certificates use, without a new limit name, a new Web Crypto operation or a new layer edge.
- Good, because `parseCertificate`, `decodeExtensionValue` and the `Extension` union behave exactly as in 1.0: the three AC-only extension kinds exist only on `AttributeCertificate.extensions`.
- Bad, because a caller must compose RFC 5755 §5 by hand — and holder binding, targeting and AC revocation are theirs to get right. The recipe and the guides say so; nothing in the library can say "this AC is valid".
- Bad, because the reader's positive cases are generated by a test builder and not by a second implementation: OpenSSL 4.0, installed where the lot was written, has no attribute-certificate command, so no foreign AC is cross-checked.
- Neutral, because the reserved reason names cost nothing until a verb uses them, and a later minor may add the verb without changing the reader.

### Confirmation

- `tests/x509/x509-attribute-certificate.test.ts` and `tests/x509/x509-ac-attributes.test.ts`: every field of the envelope, the holder, the issuer forms, every attribute of §4.4 and every AC-only extension, each refusal by code and class, each diagnostic through `onDiagnostic` and, for a `warning`, under `strict: true`; one test per loop trips its limit and asserts `PKI_LIMIT_EXCEEDED` with the limit's name.
- `tests/x509/x509-certificate.test.ts` keeps holding `parseCertificate` to the 19 extension kinds: an AC-only extension in a certificate is `kind: 'unknown'`.
- `tests/crypto/x509-verify.test.ts`: an AC signed by a generated key verifies, a flipped octet and a rewritten outer algorithm do not, SHA-1 is refused.
- `fuzz/attribute-certificate.js`, executed by `tests/fuzzing/targets.test.ts`: every input ends in a value or a `PkiError`.
- `scripts/data/rfc5755-requirements.json` accounts for every requirement sentence of RFC 5755 §4; §5 is outside its scope by this record.
- `tests/tools/architecture.test.ts`: `x509/` imports neither `crypto/` nor `oid/`, and the Web Crypto door is unchanged.

## More Information

- RFC 5755 §4 (the profile), §5 (validation), §7.3 (`objectDigestInfo`); RFC 3281, which it obsoletes.
- [ADR 0008](0008-section-6-judged-by-scored-corpora.md) — why a verdict waits for a corpus.
- [ADR 0027](0027-limit-names-are-closed-in-1-x.md) — the limits the reader cites.
- [docs/guides/standards.md](../guides/standards.md) — the RFC 5755 row.
