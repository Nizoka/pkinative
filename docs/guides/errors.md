# Errors and diagnostics

> **Every failure has a stable code, and every code has a cause and a remedy.** Branch on `error.code`; the message is for people. The machine-readable registries are `docs/data/errors.json` and `docs/data/diagnostics.json`.

## The error classes

| Class | Raised for | Extra fields |
|---|---|---|
| `PkiError` | Usage faults: a wrong argument, an invalid option, `strict: true` escalating a diagnostic | `code` |
| `PkiEncodingError` | X.690, OBJECT IDENTIFIER and RFC 7468 syntax | `code`, `offset` |
| `PkiCertificateError` | The RFC 5280 certificate structure | `code`, `path`, `offset` |
| `PkiLimitError` | A configured limit exceeded, or an invalid limits override | `code`, `limit`, `configured`, `observed` |

Every subclass extends `PkiError`, so `error instanceof PkiError` catches them all, and every message starts with `pkinative: `. Before 0.9 an error code may still be renamed or removed in a minor release, and the release note lists every such change under Downstream integration notes; from 0.9 the vocabulary is frozen under semantic versioning. Diagnostic codes are additions-only already: none is ever renamed or removed.

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

## Diagnostics

A diagnostic is a non-fatal conformance concern: `{ code, severity, message, standard, path, offset }`. Receive them with `onDiagnostic`, read them on `certificate.diagnostics`, or refuse them all with `strict: true`.

- **Serial number and algorithms** — `PKI_DIAG_SERIAL_TOO_LONG`, `PKI_DIAG_SERIAL_NOT_POSITIVE`, `PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH`, `PKI_DIAG_RSA_PARAMETERS_NOT_NULL`.
- **Version and encoding** — `PKI_DIAG_EXTENSIONS_REQUIRE_V3`, `PKI_DIAG_UNIQUE_ID_REQUIRES_V2`, `PKI_DIAG_DEFAULT_ENCODED`.
- **Time** — `PKI_DIAG_GENERALIZED_TIME_BEFORE_2050`, `PKI_DIAG_GENERALIZED_TIME_FRACTION`, `PKI_DIAG_VALIDITY_INVERTED`.
- **Names** — `PKI_DIAG_EMPTY_ISSUER`, `PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL`, `PKI_DIAG_SAN_EMPTY`, `PKI_DIAG_RDN_SET_NOT_SORTED`, `PKI_DIAG_PRINTABLE_STRING_CHARSET`, `PKI_DIAG_TELETEX_AS_LATIN1`.
- **Extensions** — `PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION`, `PKI_DIAG_PATHLEN_WITHOUT_CA`, `PKI_DIAG_KEY_USAGE_EMPTY`, `PKI_DIAG_NAMED_BITS_TRAILING_ZERO`, `PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL`, `PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED`, `PKI_DIAG_POLICY_DUPLICATE`, `PKI_DIAG_POLICY_CONSTRAINTS_EMPTY`.
- **Accepted tolerances** — `PKI_DIAG_BER_CONSTRUCT_ACCEPTED`, `PKI_DIAG_PEM_LAX_ACCEPTED`: the input used a construct you allowed with `encodingRules: 'ber'` or `mode: 'lax'`.

`docs/data/diagnostics.json` gives each one's cause, remedy and the clause it cites.
