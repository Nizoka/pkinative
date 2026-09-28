/**
 * pkinative — Error hierarchy
 * ===========================
 * The only classes in the package (AGENTS.md §Mission and constraints). Every
 * message starts with `pkinative: ` and names the remedy. Subclasses exist
 * only where callers must branch with `instanceof`.
 *
 * Every error carries a stable, machine-readable {@link PkiErrorCode} — the
 * contract agents and wrappers branch on without parsing messages. The
 * vocabulary is frozen from 0.8.0: removing or renaming a code is then
 * semver-major, adding one semver-minor; until then every code records the
 * version that introduced it. The registry is `docs/data/errors.json`; the
 * `error-parity` rule of `scripts/verify-docs.ts` keeps the two in
 * bidirectional sync and checks the message prefix of every throw site.
 *
 * @module types/pki-errors
 */

// ── Code vocabularies ────────────────────────────────────────────────

/** Codes carried by the base {@link PkiError} (usage and invariant faults). */
export type PkiBaseErrorCode =
    | 'PKI_INVALID_INPUT'       // the input has the wrong type (not a Uint8Array, not a string)
    | 'PKI_INVALID_OPTION'      // an option value fails validation
    | 'PKI_API_MISUSE'          // a caller contract violation (e.g. DER-encoding an indefinite-length node)
    | 'PKI_STRICT_DIAGNOSTIC'   // strict: true escalated a diagnostic
    | 'PKI_INTERNAL';           // an internal invariant broke — a pkinative bug, report it

/** Codes carried by {@link PkiEncodingError}: X.690, OID and RFC 7468 syntax. */
export type PkiEncodingErrorCode =
    | 'PKI_ASN1_TRUNCATED'                    // a header or content runs past the end of the input (CWE-125)
    | 'PKI_ASN1_TAG_INVALID'                  // a high-tag-number form is non-minimal or overflows (CWE-1286)
    | 'PKI_ASN1_LENGTH_INVALID'               // the reserved length octet 0xFF (CWE-1286)
    | 'PKI_ASN1_LENGTH_NON_MINIMAL'           // DER: a length not in its shortest form (CWE-436)
    | 'PKI_ASN1_LENGTH_OVERFLOW'              // a declared length exceeds its enclosing value (CWE-130)
    | 'PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN'  // DER: the indefinite length form (CWE-436)
    | 'PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN' // DER: a string type in constructed form (CWE-436)
    | 'PKI_ASN1_CONSTRUCTED_FORM_INVALID'     // a universal type in the wrong form (CWE-1286)
    | 'PKI_ASN1_EOC_UNEXPECTED'               // an end-of-contents marker where none may appear (CWE-1286)
    | 'PKI_ASN1_TRAILING_DATA'                // bytes after the outermost value (CWE-436)
    | 'PKI_ASN1_UNEXPECTED_TAG'               // a value of another type where one type is required (CWE-1286)
    | 'PKI_ASN1_BOOLEAN_INVALID'              // a BOOLEAN that is not one octet, or not 0x00/0xFF under DER (CWE-436)
    | 'PKI_ASN1_INTEGER_INVALID'              // an empty or non-minimal INTEGER (CWE-436)
    | 'PKI_ASN1_INTEGER_UNREPRESENTABLE'      // an INTEGER outside the range a reader returns (CWE-190)
    | 'PKI_ASN1_BIT_STRING_INVALID'           // a BIT STRING with a bad unused-bits count or padding (CWE-1286)
    | 'PKI_ASN1_NULL_INVALID'                 // a NULL with content (CWE-1286)
    | 'PKI_ASN1_STRING_INVALID'               // string bytes outside the character set of their type (CWE-176)
    | 'PKI_ASN1_TIME_INVALID'                 // a UTCTime or GeneralizedTime that is malformed or out of range (CWE-1284)
    | 'PKI_ASN1_VALUE_OUT_OF_RANGE'           // an encoder argument outside what the type can represent (CWE-1284)
    | 'PKI_OID_INVALID'                       // an OBJECT IDENTIFIER that is empty, non-minimal or malformed (CWE-1286)
    | 'PKI_PEM_NO_BLOCK'                      // no PEM block in the text (CWE-1286)
    | 'PKI_PEM_LABEL_INVALID'                 // a label outside the RFC 7468 grammar (CWE-1286)
    | 'PKI_PEM_LABEL_MISMATCH'                // the END label differs from the BEGIN label (CWE-436)
    | 'PKI_PEM_UNEXPECTED_LABEL'              // a block whose label is not the one requested (CWE-1286)
    | 'PKI_PEM_UNTERMINATED'                  // a BEGIN line without its END line (CWE-1286)
    | 'PKI_PEM_BASE64_INVALID'                // the block body is not canonical base64 (CWE-1286)
    | 'PKI_PEM_HEADERS_FORBIDDEN';            // RFC 1421 headers inside a strict RFC 7468 block (CWE-1286)

/** Codes carried by {@link PkiCertificateError}: the RFC 5280 certificate structure. */
export type PkiCertificateErrorCode =
    | 'PKI_X509_STRUCTURE_INVALID'     // the certificate does not match the RFC 5280 ASN.1 module (CWE-1286)
    | 'PKI_X509_VERSION_INVALID'       // a version other than v1, v2 or v3 (CWE-1286)
    | 'PKI_X509_NAME_INVALID'          // a malformed distinguished name (CWE-1286)
    | 'PKI_X509_VALIDITY_INVALID'      // a malformed validity period (CWE-1286)
    | 'PKI_X509_SPKI_INVALID'          // a malformed subject public key info (CWE-1286)
    | 'PKI_X509_UNIQUE_ID_INVALID'     // a malformed or misplaced unique identifier (CWE-1286)
    | 'PKI_X509_EXTENSIONS_EMPTY'      // an extensions field with no extension (CWE-1286)
    | 'PKI_X509_EXTENSION_DUPLICATE'   // the same extension OID twice (CWE-694)
    | 'PKI_X509_EXTENSION_MALFORMED'   // a recognised extension whose value does not match its definition (CWE-1286)
    | 'PKI_X509_GENERAL_NAME_INVALID'; // a malformed GeneralName (CWE-1286)

/** Codes carried by {@link PkiLimitError}. */
export type PkiLimitErrorCode =
    | 'PKI_LIMIT_EXCEEDED'   // a configured PkiLimits bound was exceeded (CWE-400)
    | 'PKI_LIMIT_INVALID';   // the limits override itself is invalid (configured/observed are NaN)

/**
 * Codes carried by {@link PkiCryptoError}: pkinative could not **decide**.
 *
 * Every one of these means the verification did not happen, never that it
 * failed — a signature that does not check out is `false`, and so is one
 * whose bytes are malformed. See the class for why.
 */
export type PkiCryptoErrorCode =
    | 'PKI_CRYPTO_UNAVAILABLE'              // the host exposes no crypto.subtle to verify with (CWE-693)
    | 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED'    // pkinative maps no Web Crypto algorithm to this signature OID (CWE-757)
    | 'PKI_CRYPTO_KEY_UNSUPPORTED'          // the host refused to import the public key, or its kind has no Web Crypto form (CWE-757)
    | 'PKI_CRYPTO_ALGORITHM_REFUSED';       // pkinative can compute this signature but will not treat it as evidence (CWE-327)

/**
 * Codes carried by {@link PkiCmsError}: the DER is well formed but is not the
 * RFC 5652 or RFC 3161 structure it was read as.
 *
 * Four, and each is a different remedy. Every way a value can fail to match
 * the ASN.1 module is one code, as it is for certificates; the other three
 * are the cases a caller acts on differently — the wrong kind of CMS content,
 * a syntax version from the future, and PKCS #7 content that is not octets.
 */
export type PkiCmsErrorCode =
    | 'PKI_CMS_STRUCTURE_INVALID'           // the value does not match the RFC 5652 or RFC 3161 ASN.1 module (CWE-1286)
    | 'PKI_CMS_CONTENT_TYPE_UNEXPECTED'     // a ContentInfo of another type than the one asked for, e.g. enveloped-data (CWE-843)
    | 'PKI_CMS_VERSION_UNSUPPORTED'         // a SignedData or TSTInfo version the syntax does not define (CWE-1286)
    | 'PKI_CMS_CONTENT_NOT_OCTET_STRING';   // PKCS #7 content that is not an OCTET STRING, e.g. Authenticode (CWE-843)

/**
 * Every stable error code pkinative can throw. Frozen from 0.8.0:
 * removal or renaming is semver-major; additions are semver-minor.
 */
export type PkiErrorCode =
    | PkiBaseErrorCode
    | PkiEncodingErrorCode
    | PkiCertificateErrorCode
    | PkiLimitErrorCode
    | PkiCryptoErrorCode
    | PkiCmsErrorCode;

// ── Classes ──────────────────────────────────────────────────────────

/**
 * Base class for every error thrown by pkinative. The type parameter narrows
 * `code` in subclasses, so `err instanceof PkiEncodingError` also narrows
 * `err.code` to {@link PkiEncodingErrorCode}.
 */
export class PkiError<Code extends PkiErrorCode = PkiErrorCode> extends Error {
    /** Stable machine-readable code — see the module header for the stability promise. */
    readonly code: Code;

    constructor(code: Code, message: string) {
        super(message);
        this.name = 'PkiError';
        this.code = code;
    }
}

/** The input violates the syntax of X.690, of an OBJECT IDENTIFIER or of RFC 7468. */
export class PkiEncodingError extends PkiError<PkiEncodingErrorCode> {
    /** Absolute byte offset (character offset for PEM) where decoding failed, when known. */
    readonly offset: number | undefined;

    constructor(code: PkiEncodingErrorCode, message: string, offset?: number) {
        super(code, message);
        this.name = 'PkiEncodingError';
        this.offset = offset;
    }
}

/** The DER is well formed but does not match the RFC 5280 certificate structure. */
export class PkiCertificateError extends PkiError<PkiCertificateErrorCode> {
    /** Where in the certificate, e.g. `tbsCertificate.extensions[3]`, when known. */
    readonly path: string | undefined;
    /** Absolute byte offset of the offending value, when known. */
    readonly offset: number | undefined;

    constructor(code: PkiCertificateErrorCode, message: string, path?: string, offset?: number) {
        super(code, message);
        this.name = 'PkiCertificateError';
        this.path = path;
        this.offset = offset;
    }
}

/** A configured security bound from {@link PkiLimits} was exceeded, or the override is invalid. */
export class PkiLimitError extends PkiError<PkiLimitErrorCode> {
    /** The `PkiLimits` key involved (e.g. `'maxDepth'`), or `'limits'` for a malformed override object. */
    readonly limit: string;
    /** The configured bound (`NaN` under `PKI_LIMIT_INVALID`). */
    readonly configured: number;
    /** The observed value that exceeded it (`NaN` under `PKI_LIMIT_INVALID`). */
    readonly observed: number;

    constructor(code: PkiLimitErrorCode, message: string, limit: string, configured: number, observed: number) {
        super(code, message);
        this.name = 'PkiLimitError';
        this.limit = limit;
        this.configured = configured;
        this.observed = observed;
    }
}

/**
 * pkinative could not decide whether a signature is valid.
 *
 * This class draws the line the rest of the library is built around, so it
 * is worth stating plainly: **a verification that runs returns a boolean. It
 * throws only when it could not run.** No Web Crypto on the host, an
 * algorithm pkinative does not map, a key the host will not import — those
 * are the three, and they are all "ask me again elsewhere", never "this
 * certificate is bad".
 *
 * A signature whose bytes are malformed is **`false`**, not an exception.
 * That is deliberate and it fails closed: a caller who forgets a `catch`
 * gets "not verified", which is the safe answer, instead of an exception
 * that some layer above may swallow into a success path. It also matches
 * what every other verification API does with garbage.
 *
 * From 0.5 this class is what the one-call report layer catches and
 * converts into a reason code; it is the only `PkiError` subclass that
 * carries a cause from the host.
 */
export class PkiCryptoError extends PkiError<PkiCryptoErrorCode> {
    /** The algorithm OID involved, in dotted notation, when one is known. */
    readonly algorithm: string | undefined;

    constructor(code: PkiCryptoErrorCode, message: string, algorithm?: string) {
        super(code, message);
        this.name = 'PkiCryptoError';
        this.algorithm = algorithm;
    }
}

/**
 * The DER is well formed but does not match the RFC 5652 CMS or RFC 3161
 * timestamp structure it was read as.
 *
 * Its own class rather than a {@link PkiCertificateError}, which revocation
 * lists and OCSP responses share with certificates: those three are RFC 5280
 * and RFC 6960 structures read with the certificate readers, and a caller
 * catching certificate errors expects to be told about one of them. A signed
 * message is a different object, and `instanceof` should say so.
 *
 * It says nothing about whether any signature is good. A SignedData whose
 * signature does not verify parses without complaint; that verdict belongs to
 * `verifySignedData`, which reports it rather than throwing.
 */
export class PkiCmsError extends PkiError<PkiCmsErrorCode> {
    /** Where in the structure, e.g. `signerInfos[0].signedAttrs`, when known. */
    readonly path: string | undefined;
    /** Absolute byte offset of the offending value, when known. */
    readonly offset: number | undefined;

    constructor(code: PkiCmsErrorCode, message: string, path?: string, offset?: number) {
        super(code, message);
        this.name = 'PkiCmsError';
        this.path = path;
        this.offset = offset;
    }
}
