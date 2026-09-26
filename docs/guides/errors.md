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

> **Primitives return and throw. Compositions report.** Exactly one layer converts, and it is the only place in `src/` that catches a `PkiError`.

Two consequences worth knowing before you write a `catch`:

- **A reason message never starts with `pkinative: `.** That prefix marks what is thrown, and keeping it exclusive is what lets you tell an exception from a verdict in a log. `reason-parity` refuses it.
- **A reason never duplicates an error code.** `PKI_REASON_INPUT_MALFORMED` carries in its `errorCode` field the `PkiErrorCode` that *would* have been thrown, so a report can promise never to throw for a malformed input without copying 47 encoding codes into a second vocabulary — which would then have to be frozen too. The reason registry **wraps** the error registry; it never mirrors it.

Unlike `PkiErrorCode`, which freezes at 0.8, the reason vocabulary is **not frozen**: the set of ways a chain can be rejected grows with the standards. Adding a reason is semver-minor; removing or renaming one is major.

## The error classes

| Class | Raised for | Extra fields |
|---|---|---|
| `PkiError` | Usage faults: a wrong argument, an invalid option, `strict: true` escalating a diagnostic | `code` |
| `PkiEncodingError` | X.690, OBJECT IDENTIFIER and RFC 7468 syntax | `code`, `offset` |
| `PkiCertificateError` | The RFC 5280 certificate structure | `code`, `path`, `offset` |
| `PkiLimitError` | A configured limit exceeded, or an invalid limits override | `code`, `limit`, `configured`, `observed` |
| `PkiCryptoError` | A verification **could not be performed** — never one that failed | `code`, `algorithm` |

Every subclass extends `PkiError`, so `error instanceof PkiError` catches them all, and every message starts with `pkinative: `. Before 0.8 an error code may still be renamed or removed in a minor release, and the release note lists every such change under Downstream integration notes; from 0.8 the vocabulary is frozen under semantic versioning. PKCS#12 is the last subsystem that introduces codes, so 0.8 is the first version at which the vocabulary is complete — and 0.9 exists to prove that nothing needed renaming after all. Diagnostic codes are additions-only already: none is ever renamed or removed.

Each class types its own `code`, so narrowing the error narrows the codes: `PkiBaseErrorCode` on `PkiError`, and `PkiEncodingErrorCode`, `PkiCertificateErrorCode`, `PkiLimitErrorCode` and `PkiCryptoErrorCode` on the four subclasses. `PkiErrorCode` is the union of all five — the type to write when you store or pass a code without caring which class raised it.

### The line `PkiCryptoError` draws

`verifyCertificateSignature` returns a boolean, and **throws only when the question could not be put**. A signature that does not check out is `false`. So is one whose bytes are malformed, one whose issuer key is of the wrong family entirely, and one whose two `signatureAlgorithm` fields disagree — every case where the answer is knowably "no". Failing closed is deliberate: a caller who forgets a `catch` gets "not verified", which is the safe reading, instead of an exception some layer above may swallow into a success path.

A `PkiCryptoError` means something else, and it is worth reacting to differently: pkinative did not decide. Retrying elsewhere may give a different answer, and treating it as a rejection would blame a certificate for the runtime's limits.

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

- `PKI_X509_STRUCTURE_INVALID` — the DER is not a Certificate: check that the input is not a CSR, a CRL or a key.
- `PKI_X509_VERSION_INVALID`, `PKI_X509_NAME_INVALID`, `PKI_X509_VALIDITY_INVALID`, `PKI_X509_SPKI_INVALID`, `PKI_X509_UNIQUE_ID_INVALID` — a malformed field.
- `PKI_X509_EXTENSIONS_EMPTY`, `PKI_X509_EXTENSION_DUPLICATE` — an empty extensions field, or one extension twice (CWE-694).
- `PKI_X509_EXTENSION_MALFORMED` — a recognised extension whose value does not match its definition; parse with `decodeExtensions: false` to keep every extension raw.
- `PKI_X509_GENERAL_NAME_INVALID` — a malformed GeneralName: an unknown tag, a bad iPAddress length, a non-ASCII IA5String name.

### Limits

- `PKI_LIMIT_EXCEEDED` — a bound of `PkiLimits` was exceeded; raise it only for trusted input (CWE-400).
- `PKI_LIMIT_INVALID` — `options.limits` itself is invalid.

### Verification that could not run

- `PKI_CRYPTO_UNAVAILABLE` — this runtime exposes no `crypto.subtle` with `importKey` and `verify`. Call `canVerify()` first; a page on plain HTTP has none (CWE-693).
- `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` — the signature algorithm is outside the set pkinative verifies, or its RSASSA-PSS parameters name something Web Crypto cannot express. MD2 and MD5 are here on purpose: Web Crypto implements neither, so the honest answer names the algorithm instead of a verification that did not happen (CWE-757).
- `PKI_CRYPTO_KEY_UNSUPPORTED` — the issuer's key is of the right family but on a curve Web Crypto does not verify, or the host refused to import it. Web Crypto does ECDSA only on P-256, P-384 and P-521; Ed448 and, on several runtimes still, Ed25519 are absent (CWE-757).

## Diagnostics

A diagnostic is a non-fatal conformance concern: `{ code, severity, message, standard, path, offset }`. Receive them with `onDiagnostic`, read them on `certificate.diagnostics`, or refuse them all with `strict: true`.

- **Serial number and algorithms** — `PKI_DIAG_SERIAL_TOO_LONG`, `PKI_DIAG_SERIAL_NOT_POSITIVE`, `PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH`, `PKI_DIAG_RSA_PARAMETERS_NOT_NULL`.
- **Version and encoding** — `PKI_DIAG_EXTENSIONS_REQUIRE_V3`, `PKI_DIAG_UNIQUE_ID_REQUIRES_V2`, `PKI_DIAG_DEFAULT_ENCODED`.
- **Time** — `PKI_DIAG_GENERALIZED_TIME_BEFORE_2050`, `PKI_DIAG_GENERALIZED_TIME_FRACTION`, `PKI_DIAG_VALIDITY_INVERTED`.
- **Names** — `PKI_DIAG_EMPTY_ISSUER`, `PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL`, `PKI_DIAG_SAN_EMPTY`, `PKI_DIAG_RDN_SET_NOT_SORTED`, `PKI_DIAG_PRINTABLE_STRING_CHARSET`, `PKI_DIAG_TELETEX_AS_LATIN1`.
- **Extensions** — `PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION`, `PKI_DIAG_PATHLEN_WITHOUT_CA`, `PKI_DIAG_KEY_USAGE_EMPTY`, `PKI_DIAG_NAMED_BITS_TRAILING_ZERO`, `PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL`, `PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED`, `PKI_DIAG_POLICY_DUPLICATE`, `PKI_DIAG_POLICY_CONSTRAINTS_EMPTY`.
- **Accepted tolerances** — `PKI_DIAG_BER_CONSTRUCT_ACCEPTED`, `PKI_DIAG_PEM_LAX_ACCEPTED`: the input used a construct you allowed with `encodingRules: 'ber'` or `mode: 'lax'`.

`docs/data/diagnostics.json` gives each one's cause, remedy and the clause it cites.

## Reasons

A reason is why a **judgement** came out negative: `{ code, message, standard, path }`, plus `errorCode` or `limit` where they apply. It is returned inside a report, never thrown and never printed — and several are returned together whenever several apply, because a certificate can be expired *and* outside a name constraint, and a report that stopped at the first would hide the work still to do.

- **The input, wrapped** — `PKI_REASON_INPUT_MALFORMED`, carrying in `errorCode` the `PkiErrorCode` that would have been thrown.
- **The certificate alone** — `PKI_REASON_NOT_YET_VALID`, `PKI_REASON_EXPIRED`, `PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION`.
- **The link to the issuer** — `PKI_REASON_ISSUER_NOT_FOUND`, `PKI_REASON_SIGNATURE_INVALID`, `PKI_REASON_SIGNATURE_NOT_CHECKED`.
- **The chain** — `PKI_REASON_NO_TRUST_ANCHOR`, `PKI_REASON_NOT_A_CA`, `PKI_REASON_PATH_TOO_LONG`, `PKI_REASON_PATH_LOOPS`.
- **Your own limits** — `PKI_REASON_LIMIT_EXCEEDED`, with `limit` naming the bound that stopped the search.

**`PKI_REASON_SIGNATURE_NOT_CHECKED` is not a rejection.** A runtime with no Web Crypto, or one that refuses Ed448, says nothing about whether a signature is good. Treating it as `PKI_REASON_SIGNATURE_INVALID` turns "ask me elsewhere" into "this certificate is bad", which is the most expensive confusion available in this vocabulary — the same distinction `PkiCryptoError` draws on the throwing side.

`docs/data/reasons.json` gives each one's cause, remedy and the clause it cites. The reports that return them arrive with path validation in 0.5; the vocabulary lands first, deliberately, so that no verdict is ever expressed as an exception code and then has to be migrated.
