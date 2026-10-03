# Errors, diagnostics and reasons

> **Every failure has a stable code, and every code has a cause and a remedy.** Branch on the code; the message is for people. The machine-readable registries are `docs/data/errors.json`, `docs/data/diagnostics.json` and `docs/data/reasons.json`.

## Three vocabularies, three questions

They are separate because they answer different questions, and one registry answering two of them is one registry answering neither well.

| Vocabulary | The question | About | How it travels |
|---|---|---|---|
| `PkiErrorCode` | "Is this the structure it claims to be, and is the API being used correctly?" — **no** | the input, or the call | **thrown** |
| `PkiDiagnosticCode` | "It is that structure, but it deviates from a profile." | **one object** | **emitted** (`onDiagnostic`, `strict`, `console.warn`) |
| `PkiReasonCode` | "The input is well formed, and the **judgement** you asked for is *no* — here is why." | a **relation** | **returned**, in a report |

The rule this establishes, and that every composed operation follows:

> **Primitives return and throw. Compositions report.** Exactly one layer converts, and it is the only place in `src/` that turns a `PkiError` into a reason. Anywhere else a `PkiError` is caught, it is to throw it again under a more precise class, or to diagnose and drop a value no verdict depends on — and every such catch passes what it caught through one guard that throws anything that is not a `PkiError` on, as the bug it is.

Two consequences worth knowing before you write a `catch`:

- **A reason message never starts with `pkinative: `.** That prefix marks what is thrown, and keeping it exclusive is what lets you tell an exception from a verdict in a log. `reason-parity` refuses it.
- **A reason never duplicates an error code.** `PKI_REASON_INPUT_MALFORMED` carries in its `errorCode` field the `PkiErrorCode` that *would* have been thrown, so a report can promise never to throw for a malformed input without copying 47 encoding codes into a second vocabulary — which would then have to be frozen too. The reason registry **wraps** the error registry; it never mirrors it.

Unlike `PkiErrorCode`, frozen whole since 0.8, the reason vocabulary is **grow-only**: every name is frozen with the export surface, and the set of ways a chain can be rejected grows with the standards. Adding a reason is semver-minor; removing or renaming one is major ([ADR 0018](../adr/0018-what-the-1-x-promise-covers-beyond-its-snapshots.md)).

## The error classes

| Class | Raised for | Extra fields |
|---|---|---|
| `PkiError` | Usage faults: a wrong argument, an invalid option, `strict: true` escalating a diagnostic | `code` |
| `PkiEncodingError` | X.690, OBJECT IDENTIFIER and RFC 7468 syntax | `code`, `offset` |
| `PkiCertificateError` | The RFC 5280 certificate structure | `code`, `path`, `offset` |
| `PkiLimitError` | A configured limit exceeded, or an invalid limits override | `code`, `limit`, `configured`, `observed` |
| `PkiCryptoError` | A verification **could not be performed** — never one that failed | `code`, `algorithm` |
| `PkiCmsError` | Well-formed DER that is not the RFC 5652 CMS or RFC 3161 timestamp structure it was read as | `code`, `path`, `offset` |
| `PkiKeyError` | A PKCS#8 or PKCS#12 structure pkinative cannot read, or a password scheme or MAC it refuses by policy — **never** a wrong password | `code`, `path`, `offset` |

Every subclass extends `PkiError`, so `error instanceof PkiError` catches them all — also for an error thrown by the other build (the CommonJS copy beside the ES module one) or by another realm, through a brand every copy shares ([ADR 0021](../adr/0021-error-identity-across-builds.md)) — and every message starts with `pkinative: `. The error vocabulary is frozen under semantic versioning: within the 1.x line no code is renamed, removed or moved to another class, and a new code is semver-minor (`docs/data/errors.frozen.json` is the snapshot, [ADR 0012](../adr/0012-frozen-error-vocabulary.md) the decision). Diagnostic codes are additions-only: none is ever renamed or removed, while a diagnostic's severity and wording may change in a minor release.

Each class types its own `code`, so narrowing the error narrows the codes: `PkiBaseErrorCode` on `PkiError`, and `PkiEncodingErrorCode`, `PkiCertificateErrorCode`, `PkiLimitErrorCode`, `PkiCryptoErrorCode`, `PkiCmsErrorCode` and `PkiKeyErrorCode` on the six subclasses. `PkiErrorCode` is the union of all seven — the type to write when you store or pass a code without caring which class raised it.

### The line `PkiCryptoError` draws

`verifyCertificateSignature` returns a boolean, and **throws only when the question could not be put**. A signature that does not check out is `false`. So is one whose bytes are malformed, one whose issuer key is of the wrong family entirely, and one whose two `signatureAlgorithm` fields disagree — every case where the answer is knowably "no". Failing closed is deliberate: a caller who forgets a `catch` gets "not verified", which is the safe reading, instead of an exception some layer above may swallow into a success path.

A `PkiCryptoError` means something else, and it is worth reacting to differently: pkinative did not decide. Retrying elsewhere may give a different answer, and treating it as a rejection would blame a certificate for the runtime's limits.

One code of that class is the exception, and it is on the decrypting side, where there is no boolean to return: `PKI_CRYPTO_DECRYPTION_FAILED` says the host tried to decrypt a key or a SafeContents and could not. It stays a `PkiCryptoError` rather than a `PkiKeyError` because only the host can find it out: the file was readable, and AES-CBC, which carries no authentication tag, cannot say whether the password was wrong, the bytes altered, or the key not of the algorithm it was unwrapped as.

## Error codes

### Usage

- `PKI_INVALID_INPUT` — the input has the wrong type: not a `Uint8Array`, not a string, not a parsed certificate.
- `PKI_INVALID_OPTION` — an option fails validation, e.g. `encodingRules: 'cer'`.
- `PKI_API_MISUSE` — a caller contract is violated, e.g. DER-encoding an indefinite-length node, or reading an implicitly tagged value without saying its type.
- `PKI_STRICT_DIAGNOSTIC` — `strict: true` refused an input because of its first diagnostic; the message carries that diagnostic's code.
- `PKI_INTERNAL` — an internal invariant broke: a pkinative bug, please report it.

### ASN.1 and OIDs

- `PKI_ASN1_TRUNCATED` — a header or value runs past the end of the input (CWE-125).
- `PKI_ASN1_LENGTH_OVERFLOW` — a declared length overruns its enclosing value (CWE-130).
- `PKI_ASN1_TAG_INVALID`, `PKI_ASN1_LENGTH_INVALID` — a malformed tag or length octet.
- `PKI_ASN1_LENGTH_NON_MINIMAL`, `PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN`, `PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN` — a BER-only construct under DER (CWE-436); decode with `encodingRules: 'ber'` if the input is BER.
- `PKI_ASN1_CONSTRUCTED_FORM_INVALID`, `PKI_ASN1_EOC_UNEXPECTED`, `PKI_ASN1_UNEXPECTED_TAG` — the wrong form or type where the structure requires another.
- `PKI_ASN1_TRAILING_DATA` — bytes after the outermost value.
- `PKI_ASN1_BOOLEAN_INVALID`, `PKI_ASN1_INTEGER_INVALID`, `PKI_ASN1_INTEGER_UNREPRESENTABLE`, `PKI_ASN1_BIT_STRING_INVALID`, `PKI_ASN1_NULL_INVALID`, `PKI_ASN1_STRING_INVALID`, `PKI_ASN1_TIME_INVALID` — a value that does not match its type.
- `PKI_ASN1_VALUE_OUT_OF_RANGE` — an encoder argument the type cannot represent.
- `PKI_OID_INVALID` — an OBJECT IDENTIFIER that is empty, non-minimal or malformed.

### PEM

- `PKI_PEM_NO_BLOCK`, `PKI_PEM_UNTERMINATED` — no block, or a BEGIN line without its END.
- `PKI_PEM_LABEL_INVALID`, `PKI_PEM_LABEL_MISMATCH` — a label outside the RFC 7468 grammar, or an END label that differs.
- `PKI_PEM_UNEXPECTED_LABEL` — a block whose label is not the one requested with `label`, such as a private key in a certificate bundle.
- `PKI_PEM_BASE64_INVALID`, `PKI_PEM_HEADERS_FORBIDDEN` — the body is not canonical base64, or strict mode met RFC 1421 headers.

### Certificates

- `PKI_X509_STRUCTURE_INVALID` — the DER is not the structure the reader expects: a Certificate for `parseCertificate`, a CertificationRequest for `parseCertificationRequest`. Check that the input is not the other one, a CRL or a key; each has its own reader.
- `PKI_X509_VERSION_INVALID`, `PKI_X509_NAME_INVALID`, `PKI_X509_VALIDITY_INVALID`, `PKI_X509_SPKI_INVALID`, `PKI_X509_UNIQUE_ID_INVALID` — a malformed field.
- `PKI_X509_EXTENSIONS_EMPTY`, `PKI_X509_EXTENSION_DUPLICATE` — an empty extensions field, or one extension twice (CWE-694).
- `PKI_X509_EXTENSION_MALFORMED` — a recognised extension whose value does not match its definition; parse with `decodeExtensions: false` to keep every extension raw.
- `PKI_X509_GENERAL_NAME_INVALID` — a malformed GeneralName: an unknown tag, a bad iPAddress length, a non-ASCII IA5String name.

### Limits

- `PKI_LIMIT_EXCEEDED` — a bound of `PkiLimits` was exceeded; raise it only for trusted input (CWE-400).
- `PKI_LIMIT_INVALID` — `options.limits` itself is invalid.

### Verification that could not run

- `PKI_CRYPTO_UNAVAILABLE` — this runtime exposes no `crypto.subtle` with `importKey` and `verify`, or, to open a password-protected key, with `deriveKey`, `unwrapKey` and `decrypt` too. Call `canVerify()`, `canSign()` or `canDecrypt()` first; a page on plain HTTP has none (CWE-693).
- `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` — the signature algorithm is outside the set pkinative verifies, or its RSASSA-PSS parameters name something Web Crypto cannot express. MD2 and MD5 are here on purpose: Web Crypto implements neither, so the honest answer names the algorithm instead of a verification that did not happen (CWE-757).
- `PKI_CRYPTO_KEY_UNSUPPORTED` — the issuer's key is of the right family but on a curve Web Crypto does not verify, or the host refused to import it. Web Crypto does ECDSA only on P-256, P-384 and P-521; Ed448 and, on several runtimes still, Ed25519 are absent — for a certificate signature as for a CMS signer, which since 1.0.0 is verified wherever the host has Ed448 ([ADR 0022](../adr/0022-ed448-cms-signers-host-dependent.md)). An `id-RSASSA-PSS` public key is no longer this error: it is handed to the host under `rsaEncryption` once the signature has been held to the key's parameters (RFC 4055), so what it signed verifies on every runtime; only an `id-RSASSA-PSS` private key under PBES2 still depends on the host, since a shrouded key is unwrapped there and never re-wrapped here (CWE-757).
- `PKI_CRYPTO_ALGORITHM_REFUSED` — the signature is over SHA-1. Web Crypto would compute it, and pkinative refuses to treat it as evidence: SHA-1 collisions have been practical since 2017, so a SHA-1 signature does not bind the bytes it covers, and `true` would be a false assurance (RFC 9155 §3). Get the certificate reissued under SHA-256 or better. To examine a historical artefact rather than rely on it, pass `{ allowSha1: true }` and treat the answer as an archival fact, not an authentication decision. A certificate's own SHA-1 fingerprint is unaffected: that is public data, not a signature (CWE-327).

### CMS and timestamps

- `PKI_CMS_STRUCTURE_INVALID` — the value does not match the RFC 5652 or RFC 3161 module; `path` names the field. The usual cause is a `SignedData` passed without its `ContentInfo` wrapper, or a PDF `/Contents` passed with its zero padding and without `allowTrailingData` (CWE-1286).
- `PKI_CMS_CONTENT_TYPE_UNEXPECTED` — the wrong kind of CMS content: enveloped or encrypted data handed to `parseSignedData`, which pkinative never decrypts, or a `SignedData` over anything but a `TSTInfo` handed to `parseTimeStampToken` (CWE-843).
- `PKI_CMS_VERSION_UNSUPPORTED` — a `SignedData`, `TSTInfo` or `TimeStampReq` version the syntax does not define. A defined version that disagrees with the content is only `PKI_DIAG_CMS_VERSION_MISMATCH` (CWE-1286).
- `PKI_CMS_CONTENT_NOT_OCTET_STRING` — PKCS #7 content that is not an OCTET STRING, such as Authenticode, whose digest rule differs from RFC 5652's (CWE-843).

`verifySignedData` and `verifyTimeStampToken` throw none of these for the message or token they judge: there, they are `PKI_REASON_INPUT_MALFORMED` with the code in `errorCode`. The one exception is `verifyTimeStampToken`'s `request`, which is your own bytes, so a malformed one is thrown.

### Private keys and PKCS#12

- `PKI_KEY_STRUCTURE_INVALID` — well-formed DER that does not match the RFC 5958 PKCS#8 or RFC 7292 PKCS#12 module: a field missing or out of order, PBES2 parameters that contradict each other, an initialisation vector that is not 16 octets. The usual cause is a PEM block decoded from the wrong label — `PRIVATE KEY` for PKCS#8, `ENCRYPTED PRIVATE KEY` for its encrypted form — or a `.p12` read as text (CWE-1286).
- `PKI_KEY_VERSION_UNSUPPORTED` — a `PrivateKeyInfo` version other than 0 or 1, or a PFX version other than 3; re-export the file from the tool that owns the key (CWE-1286).
- `PKI_KEY_ENCRYPTION_UNSUPPORTED` — a key or a SafeContents protected by anything but PBES2 with PBKDF2 and AES-CBC: an RFC 7292 Appendix C scheme such as `pbeWithSHAAnd3-KeyTripleDES-CBC`, PBES1, PBES2 with another cipher, or public-key privacy mode. **A policy, not a gap**, and the message names the scheme and the conversion: `openssl pkcs12 -in legacy.p12 -legacy -out bundle.pem`, then `openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12` (OpenSSL 3.4 or later), or `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256` for a key alone (CWE-327).
- `PKI_KEY_MAC_UNSUPPORTED` — `verifyPkcs12Mac` asked to check a MAC keyed with the RFC 7292 Appendix B KDF, which is every MAC OpenSSL wrote before 3.4, or `parsePkcs12` given public-key integrity mode. Re-export with `openssl pkcs12 -export -pbmac1_pbkdf2`; `openPkcs12` reports such a file as `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` and takes `allowUnverifiedIntegrity` for the decision (CWE-327).
- `PKI_CRYPTO_DECRYPTION_FAILED` — a `PkiCryptoError`: Web Crypto could not decrypt a PBES2 payload or unwrap a key with the key derived from the password. Check the password first — a string is encoded as UTF-8; pass the exact octets as a `Uint8Array` for a file written with another encoding — then that the algorithm named fits the key. A file that fails with both right has been altered (CWE-354).

`openPkcs12` throws none of these for the file it opens: they are its `PKI_REASON_PKCS12_*` reasons, or `PKI_REASON_INPUT_MALFORMED` for a file it cannot read at all.

## Diagnostics

A diagnostic is a non-fatal conformance concern: `{ code, severity, message, standard, path, offset }`. Receive them with `onDiagnostic`, read them on `certificate.diagnostics`, or refuse them all with `strict: true`.

- **Serial number and algorithms** — `PKI_DIAG_SERIAL_TOO_LONG`, `PKI_DIAG_SERIAL_NOT_POSITIVE`, `PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH`, `PKI_DIAG_RSA_PARAMETERS_NOT_NULL`.
- **Version and encoding** — `PKI_DIAG_EXTENSIONS_REQUIRE_V3`, `PKI_DIAG_UNIQUE_ID_REQUIRES_V2`, `PKI_DIAG_DEFAULT_ENCODED`, `PKI_DIAG_STRING_SIGNATURE` (a BMPString or UniversalString starting with the U+FEFF signature X.690 §8.23 forbids), `PKI_DIAG_STRING_ESCAPE_SEQUENCE` (an ISO/IEC 2022 escape or shift control inside an ISO/IEC 10646 string type).
- **Time** — `PKI_DIAG_GENERALIZED_TIME_BEFORE_2050`, `PKI_DIAG_GENERALIZED_TIME_FRACTION`, `PKI_DIAG_VALIDITY_INVERTED`.
- **Names** — `PKI_DIAG_EMPTY_ISSUER`, `PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL`, `PKI_DIAG_SAN_EMPTY`, `PKI_DIAG_RDN_SET_NOT_SORTED`, `PKI_DIAG_PRINTABLE_STRING_CHARSET`, `PKI_DIAG_TELETEX_AS_LATIN1`, `PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX`, `PKI_DIAG_GENERAL_NAME_CONTROL_CHARACTER` (a NUL, another C0 control or DEL in a dNSName, rfc822Name or URI: kept and compared literally, but a consumer that stops at NUL reads another name — the CVE-2009-2408 class), `PKI_DIAG_COMMON_NAME_NOT_IN_SAN`, `PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE` (an attribute encoded outside the syntax RFC 5280 Appendix A.1 gives it, such as a UTF8String countryName), `PKI_DIAG_COUNTRY_NAME_SIZE` (a countryName that is not two characters), `PKI_DIAG_NAME_ATTRIBUTE_TOO_LONG` (a value past the RFC 5280 Appendix A.1 upper bound of its attribute — 64 characters for a commonName, 255 for an emailAddress — read as it is; informational), `PKI_DIAG_NAME_COUNTRY_UNKNOWN` (a two-letter countryName that is neither an assigned ISO 3166-1 alpha-2 code nor a user-assigned one; informational).
- **Extensions** — `PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION`, `PKI_DIAG_PATHLEN_WITHOUT_CA`, `PKI_DIAG_KEY_USAGE_EMPTY`, `PKI_DIAG_NAMED_BITS_TRAILING_ZERO`, `PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL`, `PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY`, `PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL`, `PKI_DIAG_POLICY_CONSTRAINTS_NOT_CRITICAL`, `PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA`, `PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED`, `PKI_DIAG_POLICY_DUPLICATE`, `PKI_DIAG_POLICY_CONSTRAINTS_EMPTY`, `PKI_DIAG_SUBJECT_DIRECTORY_ATTRIBUTES_CRITICAL` (RFC 5280 §4.2.1.8 says non-critical).

  The six added in 0.5.0 share one shape: each is a sentence RFC 5280 or the CA/Browser Forum addresses to the **issuing CA**, and none of them refuses a chain. pkinative reads and enforces the extension whatever the profile says about its criticality, so refusing would make it stricter than the standards ask of a verifier while accepting exactly the same set of chains; `strict: true` is where that choice belongs. Each answers a case of the x509-limbo corpus that expects a refusal, and the reason it stays a diagnostic is written beside that case in `scripts/data/limbo-score.json`. `PKI_DIAG_COMMON_NAME_NOT_IN_SAN` is the first to cite CA/Browser Forum Baseline Requirements rather than an RFC, because no RFC says it — and it fires only for a `commonName` that could be matched **as a host**, since reporting `CN=Example Issuing CA` would be reporting the ordinary shape of every organisational subject.
- **Key identifiers** — `PKI_DIAG_AKI_MISSING` (a v3 certificate naming another subject as its issuer without an `authorityKeyIdentifier`: path building falls back to names, which costs exploration, not correctness) and `PKI_DIAG_SKI_MISSING` (a CA certificate without a `subjectKeyIdentifier`, so the certificates it issues cannot name its key). `computeKeyIdentifier` with `encodeAuthorityKeyIdentifier` and `encodeSubjectKeyIdentifier` writes both.
- **The rest of the RFC 5280 §4.1–§4.2 profile** — one code per requirement sentence a single certificate can be checked against, each held to an independent reading by its L5 clause; a MUST is a `warning`, a SHOULD an `info`, and none changes what is decoded or refuses a chain.
  - Criticality: `PKI_DIAG_AKI_CRITICAL`, `PKI_DIAG_SKI_CRITICAL`, `PKI_DIAG_INHIBIT_ANY_POLICY_NOT_CRITICAL`, `PKI_DIAG_FRESHEST_CRL_CRITICAL`, `PKI_DIAG_AIA_CRITICAL`, `PKI_DIAG_SIA_CRITICAL` (MUST); `PKI_DIAG_KEY_USAGE_NOT_CRITICAL`, `PKI_DIAG_POLICY_MAPPINGS_NOT_CRITICAL`, `PKI_DIAG_SAN_CRITICAL` (critical beside a non-empty subject), `PKI_DIAG_ISSUER_ALT_NAME_CRITICAL`, `PKI_DIAG_EKU_ANY_CRITICAL` (critical while listing anyExtendedKeyUsage), `PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL` (SHOULD).
  - Presence: `PKI_DIAG_UNIQUE_ID_PRESENT` (a unique identifier at any version, beside `PKI_DIAG_UNIQUE_ID_REQUIRES_V2` for the v1 case), `PKI_DIAG_SKI_MISSING_END_ENTITY` (an end-entity certificate without a `subjectKeyIdentifier`: RFC 5280 recommends one, the CA/Browser Forum now advises against it in subscriber certificates, so it is an `info` to weigh against the profile you issue under).
  - Policies: `PKI_DIAG_ANY_POLICY_QUALIFIER`, `PKI_DIAG_NOTICE_REF_USED`, `PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE` (a VisibleString or BMPString explicitText — the one fact two sentences of §4.2.1.4 state, so one code), `PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER`, `PKI_DIAG_EXPLICIT_TEXT_NOT_NFC`, `PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED` (an issuerDomainPolicy the certificate's own certificatePolicies does not list).
  - Alternative names, in `subjectAltName` and `issuerAltName` (§4.2.1.7 encodes the latter as §4.2.1.6 does): `PKI_DIAG_ALT_NAME_URI_INVALID` (not an RFC 3986 URI, a relative reference included), `PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING`, `PKI_DIAG_ALT_NAME_URI_HOST_INVALID` (an authority whose host is neither a fully qualified domain name nor an IP address), `PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY`. The URI is still kept and compared literally; the grammar is the one `src/core/uri.ts` gives name constraints too.
  - Name constraints: `PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX` (a non-zero minimum or any maximum, which path validation never lets cover a name), `PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN`.
  - Where to fetch: `PKI_DIAG_DISTRIBUTION_POINT_WITHOUT_NAME`, `PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE` (no `<dn>` or not one `<attrdesc>`, RFC 4516 §2), `PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI`, `PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME`, `PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME_AMBIGUOUS`, for `cRLDistributionPoints` and `freshestCRL` alike; `PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE` (an `id-ad-caIssuers` or `id-ad-caRepository` LDAP URI without `<dn>` or `<attributes>`: one sentence in §4.2.2.1 and §4.2.2.2, one code, the path names the extension), `PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI`, `PKI_DIAG_CA_REPOSITORY_NO_HTTP_OR_LDAP_URI`.

  `strict: true` refuses the first `warning` — a MUST the input broke — and still reports every `info`: a SHOULD the input did not follow, such as the subjectKeyIdentifier nine thousand x509-limbo end-entity certificates omit, is advice to the issuer, not a reason to refuse the certificate.
- **CMS** — `PKI_DIAG_CMS_VERSION_MISMATCH`, `PKI_DIAG_CMS_SET_NOT_SORTED`, `PKI_DIAG_CMS_SIGNED_ATTRIBUTES_NOT_DER`, `PKI_DIAG_CMS_DIGEST_ALGORITHM_NOT_LISTED`, on `SignedData.diagnostics`. None of them touches a signed octet — the signed attributes are verified over the bytes as they were signed, never over a re-sorted set — so none changes a verdict; they tell you which other verifiers may refuse the message. The same holds for what the message says against RFC 5652 §5.2, §11.3 and §11.4: `PKI_DIAG_CMS_CERTS_ONLY_CONTENT` (a signer-less SignedData whose eContentType is not id-data, or which carries an eContent), `PKI_DIAG_CMS_SIGNING_TIME_NOT_UTC` and `PKI_DIAG_CMS_SIGNING_TIME_FRACTION` (a signingTime in GeneralizedTime for 1950–2049, or with fractional seconds — the instant is read as written), `PKI_DIAG_CMS_COUNTERSIGNATURE_CONTENT_TYPE`, `PKI_DIAG_CMS_COUNTERSIGNATURE_NO_MESSAGE_DIGEST` and `PKI_DIAG_CMS_COUNTERSIGNATURE_EMPTY` (a countersignature's own signed attributes, looked into as far as their types; the countersignature stays carried, not verified).
- **Timestamps** — `PKI_DIAG_TSP_CERTREQ_UNMET`, `PKI_DIAG_TSP_CERTS_UNREQUESTED`: the token's certificates field against the request's `certReq` (RFC 3161 §2.4.1), decided only where `verifyTimeStampToken` holds both, and reported through its `onDiagnostic`. The verdict is the same either way: the TSA is found among the token's certificates and the ones you pass.
- **OCSP** — `PKI_DIAG_OCSP_CERTS_EMPTY` (a certs field present and empty) and `PKI_DIAG_OCSP_VERSION_NOT_V1` (an explicit ResponseData version that is not the INTEGER 0; a v1 written out is `PKI_DIAG_DEFAULT_ENCODED`), on `OcspResponse.diagnostics`; `PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH` and `PKI_DIAG_OCSP_NOCHECK_CRITICAL`, when `checkOcspStatus` is given the certificate that signed (its `signer`) and the responderID names neither its subject nor its key hash, or its `id-pkix-ocsp-nocheck` is critical; `PKI_DIAG_OCSP_SINGLE_RESPONSE_UNREQUESTED`, the answers about certificates nobody asked about beside the one that was. `verifyCertificateChain` passes the signer it established and forwards every one of them, with what the lists and responses say about themselves, to its own `onDiagnostic` — and says nothing without one.
- **Revocation lists** — `PKI_DIAG_CRL_EXTENSION_MALFORMED`: a `cRLNumber` or `deltaCRLIndicator` that is not a DER INTEGER, an entry `reasonCode` RFC 5280 does not assign, or an `invalidityDate` that is not a GeneralizedTime. The value is ignored, because none of them decides whether a serial is revoked: a revocation with an unreadable reason is still a revocation, and a delta whose base number cannot be read is never paired with a base.
- **Keys** — `PKI_DIAG_KEY_KDF_ITERATIONS_LOW`: a PBKDF2 iteration count, for a key, a SafeContents or a PBMAC1 MAC, below the 1 000 RFC 8018 recommends. The file still opens; the count is what a stolen copy costs to brute-force. A count above `maxKdfIterations` is not a diagnostic but `PKI_LIMIT_EXCEEDED`, because the host would run it where nothing can interrupt it.
- **Public keys** — `PKI_DIAG_SPKI_RSA_EXPONENT_WEAK`: an RSA public exponent below 3 or even, outside RFC 8017 §3.1. The certificate still parses; no signature under that key is ever checked, since under e = 1 a message is its own signature (`PKI_REASON_SIGNATURE_NOT_CHECKED` with `PKI_CRYPTO_KEY_UNSUPPORTED` at verification). `PKI_DIAG_SPKI_EC_PARAMETERS_INVALID`: an EC key whose parameters are NULL (implicitCurve) or explicit (specifiedCurve), which RFC 5480 §2.1.1 forbids, or a namedCurve other than P-256, P-384 and P-521. The key decodes with `curve` undefined; no signature under it is checked, for the same reason code.
- **Accepted tolerances** — `PKI_DIAG_BER_CONSTRUCT_ACCEPTED`, `PKI_DIAG_PEM_LAX_ACCEPTED`: the input used a construct you allowed with `encodingRules: 'ber'` or `mode: 'lax'`.

`docs/data/diagnostics.json` gives each one's cause, remedy and the clause it cites.

## Reasons

A reason is why a **judgement** came out negative: `{ code, message, standard, path }`, plus `errorCode` or `limit` where they apply. It is returned inside a report, never thrown and never printed — and several are returned together whenever several apply, because a certificate can be expired *and* outside a name constraint, and a report that stopped at the first would hide the work still to do.

- **The input, wrapped** — `PKI_REASON_INPUT_MALFORMED`, carrying in `errorCode` the `PkiErrorCode` that would have been thrown.
- **The certificate alone** — `PKI_REASON_NOT_YET_VALID`, `PKI_REASON_EXPIRED`, `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION`.
- **The link to the issuer** — `PKI_REASON_ISSUER_NOT_FOUND`, `PKI_REASON_SIGNATURE_INVALID`, `PKI_REASON_SIGNATURE_NOT_CHECKED`.
- **The chain** — `PKI_REASON_NO_TRUST_ANCHOR`, `PKI_REASON_NOT_A_CA`, `PKI_REASON_PATH_TOO_LONG`, `PKI_REASON_PATH_LOOPS`.
- **What a CA above it forbade** — `PKI_REASON_NAME_NOT_PERMITTED`, `PKI_REASON_NAME_EXCLUDED`, `PKI_REASON_NO_VALID_POLICY`, `PKI_REASON_POLICY_MAPPING_INVALID`.
- **Revocation** — `PKI_REASON_REVOKED` (carrying the date, because a signature made before it may still be good), `PKI_REASON_REVOCATION_STALE`, `PKI_REASON_REVOCATION_WRONG_ISSUER`, `PKI_REASON_REVOCATION_UNKNOWN`, `PKI_REASON_REVOCATION_MISMATCH`, `PKI_REASON_REVOCATION_OUT_OF_SCOPE` (the right CA, but a list whose `issuingDistributionPoint` excludes this certificate — its silence is not evidence) and `PKI_REASON_REVOCATION_PARTIAL` (a list with `onlySomeReasons`, which rules out those reasons and no others; `verifyCertificateChain` adds up the lists you supply and drops it once the union is complete).
- **The questions §6 does not ask** — `PKI_REASON_NAME_MISMATCH` (from `checkServerName`: the chain is sound and the certificate is for somebody else) and `PKI_REASON_PURPOSE_NOT_PERMITTED` (from `checkExtendedKeyUsage`: the chain is sound and the certificate is for something else).
- **A signed message** (from `verifySignedData`) — `PKI_REASON_CMS_NO_SIGNERS` (a certificate bundle is not a signature), `PKI_REASON_CMS_SIGNER_NOT_FOUND`, `PKI_REASON_CMS_CONTENT_MISSING` (absent content is never empty content), `PKI_REASON_CMS_DIGEST_MISMATCH`, `PKI_REASON_CMS_ATTRIBUTE_INVALID`, `PKI_REASON_CMS_ALGORITHM_MISMATCH` (the shape of an algorithm substitution), `PKI_REASON_CMS_SIGNING_CERTIFICATE_MISMATCH` (the signature presented under another certificate for the same key).
- **A timestamp** (from `verifyTimeStampToken`, and under `unsignedAttrs.timeStampToken[i]` from `verifySignedData`) — `PKI_REASON_TSP_IMPRINT_MISMATCH` (the token stamps something else), `PKI_REASON_TSP_REQUEST_MISMATCH` (a nonce or policy the request did not ask for — what a replay looks like; send a new request rather than retrying), `PKI_REASON_TSP_TOKEN_INVALID`, and `PKI_REASON_TSP_NOT_GRANTED` (a response whose status is neither granted nor grantedWithMods, so it carries no token; the message carries the status, the TSA's text and its failure codes).
- **A PKCS#12** (from `openPkcs12`) — `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED` (the MAC cannot be checked here, or there is none: the contents are reported and `valid` is false unless you pass `allowUnverifiedIntegrity`), `PKI_REASON_PKCS12_MAC_MISMATCH` (a PBMAC1 that does not match — most likely the password — after which nothing is decrypted), `PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED` (a scheme pkinative refuses, or one this runtime's Web Crypto lacks, such as AES-192 in several browsers), `PKI_REASON_PKCS12_DECRYPTION_FAILED`, `PKI_REASON_PKCS12_KEY_UNMATCHED` (no certificate shares the key's `localKeyId`, so its algorithm is unknown — `decryptPrivateKey` with a named algorithm opens it), `PKI_REASON_PKCS12_KEY_UNSUPPORTED` (a key Web Crypto does not sign with, such as DSA or X25519) and `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED` (an RSA key whose scheme you did not name in `rsaAlgorithm`: pkinative does not guess one, so the key stays shut until you do).
- **Your own limits** — `PKI_REASON_LIMIT_EXCEEDED`, with `limit` naming the bound that stopped the search.

**`PKI_REASON_SIGNATURE_NOT_CHECKED` is not a rejection.** A runtime with no Web Crypto, or one that refuses Ed448 — Bun and Chromium today, for a certificate signature as for a CMS signer — says nothing about whether a signature is good. Treating it as `PKI_REASON_SIGNATURE_INVALID` turns "ask me elsewhere" into "this certificate is bad", which is the most expensive confusion available in this vocabulary — the same distinction `PkiCryptoError` draws on the throwing side.

**`PKI_REASON_REVOCATION_UNKNOWN` is not "not revoked" either**, for the same reason: a missing or unsigned list is an absence of evidence, and reporting it as a clean answer would make the soft-fail decision on your behalf, invisibly.

`docs/data/reasons.json` gives each one's cause, remedy and the clause it cites. Which of them a real chain actually earns is measured rather than asserted: every case of the x509-limbo corpus is scored on each release, and a reviewed subset is pinned on its reason code rather than on the pass/fail boolean — because *rejected for the wrong reason* is a defect no count can see.
