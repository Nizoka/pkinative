/**
 * pkinative — Shared types
 * ========================
 * The option, limit and diagnostic types every layer references. They live
 * in `types/` so lower layers can name them without importing the modules
 * that implement them: the diagnostics emitter and the resolved limits are
 * handed down by parameter, never imported sideways.
 *
 * @module types/pki-types
 */

// ── Limits ───────────────────────────────────────────────────────────

/**
 * The named security bounds every loop over untrusted input consults.
 * Defaults are `DEFAULT_PKI_LIMITS`; override any subset with
 * `options.limits`. Each bound is a positive integer or `Infinity`.
 */
export interface PkiLimits {
    /** Maximum size of one input, in bytes for DER or characters for PEM. CWE-400. */
    readonly maxInputBytes: number;
    /** Maximum nesting depth of constructed ASN.1 values. CWE-674. */
    readonly maxDepth: number;
    /** Maximum number of ASN.1 values decoded from one input. CWE-770. */
    readonly maxNodes: number;
    /** Maximum content length of one INTEGER, in bytes. CWE-407. */
    readonly maxIntegerBytes: number;
    /** Maximum content length of one OBJECT IDENTIFIER, in bytes. CWE-400. */
    readonly maxOidBytes: number;
    /** Maximum number of segments joined from one BER constructed string. CWE-400. */
    readonly maxBerSegments: number;
    /** Maximum number of PEM blocks read from one text. CWE-400. */
    readonly maxPemBlocks: number;
    /** Maximum number of extensions in one certificate. CWE-400. */
    readonly maxExtensions: number;
    /** Maximum number of GeneralName entries in one field. CWE-400. */
    readonly maxGeneralNames: number;
    /** Maximum number of attributes in one distinguished name. CWE-400. */
    readonly maxNameAttributes: number;
    /** Maximum number of policies or policy mappings in one extension. CWE-400. */
    readonly maxPolicies: number;
    /** Maximum number of certificates a certification path may hold. CWE-400. */
    readonly maxChainLength: number;
    /** Maximum number of live nodes in the RFC 5280 valid_policy_tree. CWE-770. */
    readonly maxPolicyNodes: number;
    /** Maximum number of entries walked in one CRL revokedCertificates list. CWE-400. */
    readonly maxRevokedCertificates: number;
    /** Maximum number of SingleResponse entries in one OCSP response. CWE-400. */
    readonly maxOcspSingleResponses: number;
    /** Maximum number of candidate paths explored while building one. CWE-400. */
    readonly maxPathsExplored: number;
    /** Maximum number of SignerInfo entries in one SignedData — each costs a signature verification. CWE-400. */
    readonly maxSignerInfos: number;
    /** Maximum number of attributes in one attribute set — a CMS signer's signed or unsigned set, a PKCS#8 key's, a PKCS#12 bag's. CWE-400. */
    readonly maxAttributes: number;
    /** Maximum number of certificates plus revocation entries a SignedData carries — the signer search walks them. CWE-400. */
    readonly maxCmsCertificatesAndCrls: number;
    /** Maximum PBKDF2 iteration count honoured in one derivation — a count the file declares, and the host then runs. CWE-400. */
    readonly maxKdfIterations: number;
    /** Maximum number of SafeBags read from one PKCS#12, across every SafeContents. CWE-400. */
    readonly maxPkcs12Bags: number;
    /** Maximum PBKDF2 iterations one PKCS#12 costs in total — its PBMAC1 MAC, every encrypted SafeContents and every shrouded key together. CWE-400. */
    readonly maxPkcs12KdfIterations: number;
}

// ── Diagnostics ──────────────────────────────────────────────────────

/**
 * Every diagnostic code. The union is additions-only by contract: a code is
 * never renamed or removed. Registry: `docs/data/diagnostics.json`.
 */
export type PkiDiagnosticCode =
    | 'PKI_DIAG_SERIAL_TOO_LONG'
    | 'PKI_DIAG_SERIAL_NOT_POSITIVE'
    | 'PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH'
    | 'PKI_DIAG_RSA_PARAMETERS_NOT_NULL'
    | 'PKI_DIAG_EXTENSIONS_REQUIRE_V3'
    | 'PKI_DIAG_UNIQUE_ID_REQUIRES_V2'
    | 'PKI_DIAG_GENERALIZED_TIME_BEFORE_2050'
    | 'PKI_DIAG_GENERALIZED_TIME_FRACTION'
    | 'PKI_DIAG_VALIDITY_INVERTED'
    | 'PKI_DIAG_EMPTY_ISSUER'
    | 'PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL'
    | 'PKI_DIAG_SAN_EMPTY'
    | 'PKI_DIAG_RDN_SET_NOT_SORTED'
    | 'PKI_DIAG_PRINTABLE_STRING_CHARSET'
    | 'PKI_DIAG_TELETEX_AS_LATIN1'
    | 'PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION'
    | 'PKI_DIAG_PATHLEN_WITHOUT_CA'
    | 'PKI_DIAG_KEY_USAGE_EMPTY'
    | 'PKI_DIAG_NAMED_BITS_TRAILING_ZERO'
    | 'PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL'
    | 'PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY'
    | 'PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL'
    | 'PKI_DIAG_POLICY_CONSTRAINTS_NOT_CRITICAL'
    | 'PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA'
    | 'PKI_DIAG_AKI_MISSING'
    | 'PKI_DIAG_SKI_MISSING'
    | 'PKI_DIAG_COMMON_NAME_NOT_IN_SAN'
    | 'PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX'
    | 'PKI_DIAG_GENERAL_NAME_CONTROL_CHARACTER'
    | 'PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED'
    | 'PKI_DIAG_POLICY_DUPLICATE'
    | 'PKI_DIAG_POLICY_CONSTRAINTS_EMPTY'
    | 'PKI_DIAG_DEFAULT_ENCODED'
    | 'PKI_DIAG_BER_CONSTRUCT_ACCEPTED'
    | 'PKI_DIAG_PEM_LAX_ACCEPTED'
    | 'PKI_DIAG_CMS_VERSION_MISMATCH'
    | 'PKI_DIAG_CMS_SET_NOT_SORTED'
    | 'PKI_DIAG_CMS_SIGNED_ATTRIBUTES_NOT_DER'
    | 'PKI_DIAG_CMS_DIGEST_ALGORITHM_NOT_LISTED'
    | 'PKI_DIAG_KEY_KDF_ITERATIONS_LOW'
    | 'PKI_DIAG_SPKI_RSA_EXPONENT_WEAK'
    | 'PKI_DIAG_SPKI_EC_PARAMETERS_INVALID'
    | 'PKI_DIAG_CRL_EXTENSION_MALFORMED'
    | 'PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE'
    | 'PKI_DIAG_COUNTRY_NAME_SIZE'
    | 'PKI_DIAG_STRING_SIGNATURE'
    | 'PKI_DIAG_STRING_ESCAPE_SEQUENCE'
    | 'PKI_DIAG_SUBJECT_DIRECTORY_ATTRIBUTES_CRITICAL'
    | 'PKI_DIAG_UNIQUE_ID_PRESENT'
    | 'PKI_DIAG_AKI_CRITICAL'
    | 'PKI_DIAG_SKI_CRITICAL'
    | 'PKI_DIAG_SKI_MISSING_END_ENTITY'
    | 'PKI_DIAG_KEY_USAGE_NOT_CRITICAL'
    | 'PKI_DIAG_ANY_POLICY_QUALIFIER'
    | 'PKI_DIAG_NOTICE_REF_USED'
    | 'PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE'
    | 'PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER'
    | 'PKI_DIAG_EXPLICIT_TEXT_NOT_NFC'
    | 'PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED'
    | 'PKI_DIAG_POLICY_MAPPINGS_NOT_CRITICAL'
    | 'PKI_DIAG_SAN_CRITICAL'
    | 'PKI_DIAG_ALT_NAME_URI_INVALID'
    | 'PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING'
    | 'PKI_DIAG_ALT_NAME_URI_HOST_INVALID'
    | 'PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY'
    | 'PKI_DIAG_ISSUER_ALT_NAME_CRITICAL'
    | 'PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX'
    | 'PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN'
    | 'PKI_DIAG_EKU_ANY_CRITICAL'
    | 'PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL'
    | 'PKI_DIAG_DISTRIBUTION_POINT_WITHOUT_NAME'
    | 'PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE'
    | 'PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI'
    | 'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME'
    | 'PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME_AMBIGUOUS'
    | 'PKI_DIAG_INHIBIT_ANY_POLICY_NOT_CRITICAL'
    | 'PKI_DIAG_FRESHEST_CRL_CRITICAL'
    | 'PKI_DIAG_AIA_CRITICAL'
    | 'PKI_DIAG_SIA_CRITICAL'
    | 'PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE'
    | 'PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI'
    | 'PKI_DIAG_CA_REPOSITORY_NO_HTTP_OR_LDAP_URI'
    | 'PKI_DIAG_CMS_CERTS_ONLY_CONTENT'
    | 'PKI_DIAG_CMS_COUNTERSIGNATURE_CONTENT_TYPE'
    | 'PKI_DIAG_CMS_COUNTERSIGNATURE_NO_MESSAGE_DIGEST'
    | 'PKI_DIAG_CMS_COUNTERSIGNATURE_EMPTY'
    | 'PKI_DIAG_CMS_SIGNING_TIME_NOT_UTC'
    | 'PKI_DIAG_CMS_SIGNING_TIME_FRACTION'
    | 'PKI_DIAG_TSP_CERTREQ_UNMET'
    | 'PKI_DIAG_TSP_CERTS_UNREQUESTED'
    | 'PKI_DIAG_OCSP_CERTS_EMPTY'
    | 'PKI_DIAG_OCSP_VERSION_NOT_V1'
    | 'PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH'
    | 'PKI_DIAG_OCSP_SINGLE_RESPONSE_UNREQUESTED'
    | 'PKI_DIAG_OCSP_NOCHECK_CRITICAL';

/** `warning`: a profile violation a verifier may refuse. `info`: an accepted, documented tolerance. */
export type PkiDiagnosticSeverity = 'warning' | 'info';

/** One non-fatal conformance concern. Structural failures throw instead. */
export interface PkiDiagnostic {
    /** The stable identifier. Branch on it, never on `message`; every code is registered in docs/data/diagnostics.json. */
    readonly code: PkiDiagnosticCode;
    /** How much it matters: `'warning'` for something a strict reader would refuse, `'info'` for something merely worth knowing. */
    readonly severity: PkiDiagnosticSeverity;
    /** What was found and what it means, without the `pkinative: ` prefix. */
    readonly message: string;
    /** The clause the concern cites, e.g. `RFC 5280 §4.1.2.2`. */
    readonly standard: string;
    /** Where in the structure, e.g. `tbsCertificate.serialNumber`; empty for the whole input. */
    readonly path: string;
    /** Absolute byte offset of the value concerned, when known. */
    readonly offset: number | undefined;
}

/** Receives every diagnostic of an operation; replaces the default `console.warn` sink. */
export type PkiDiagnosticHandler = (diagnostic: PkiDiagnostic) => void;

/** The per-operation diagnostics channel handed down to every layer. */
export interface PkiDiagnosticEmitter {
    /** Report a diagnostic: throws under `strict`, otherwise records and delivers it. */
    emit(diagnostic: PkiDiagnostic): void;
    /** Every diagnostic recorded so far, in emission order. */
    readonly diagnostics: readonly PkiDiagnostic[];
}

// ── Options ──────────────────────────────────────────────────────────

/** `der` (default) refuses every BER-only construct; `ber` accepts them with a diagnostic. */
export type EncodingRules = 'der' | 'ber';

/** Options shared by every parsing function. */
export interface PkiParseOptions {
    /** `'der'` (default) or `'ber'`. */
    readonly encodingRules?: EncodingRules | undefined;
    /** Overrides for any subset of `DEFAULT_PKI_LIMITS`. */
    readonly limits?: Partial<PkiLimits> | undefined;
    /** Escalate every diagnostic to a thrown `PkiError` with code `PKI_STRICT_DIAGNOSTIC`. */
    readonly strict?: boolean | undefined;
    /** Receive every diagnostic instead of the default once-per-code `console.warn`. */
    readonly onDiagnostic?: PkiDiagnosticHandler | undefined;
}
