/**
 * pkinative — Conformance diagnostics
 * ===================================
 * The single channel for non-fatal conformance concerns: profile violations
 * real issuers commit, and tolerances the caller asked for. Structural
 * failures THROW; conformance concerns DIAGNOSE; the two never mix.
 *
 * Every diagnostic of an operation is recorded (parse results expose them),
 * and delivered to exactly one place:
 *   - `strict: true` → the first diagnostic throws a `PkiError` with code
 *     `PKI_STRICT_DIAGNOSTIC`, before any result is returned;
 *   - `onDiagnostic` → the handler receives every diagnostic;
 *   - default → `console.warn`, once per code per operation.
 *
 * This is the ONLY module allowed to reach `console` (AGENTS.md; enforced by
 * tests/tools/architecture.test.ts). Diagnostic TYPES live in
 * `types/pki-types.ts`; every code has one payload factory below, whose
 * message states the situation and what the caller can do about it.
 *
 * @module core/pki-diagnostics
 */

import { PkiError } from '../types/pki-errors.js';
import type {
    PkiDiagnostic,
    PkiDiagnosticCode,
    PkiDiagnosticEmitter,
    PkiDiagnosticHandler,
    PkiDiagnosticSeverity,
} from '../types/pki-types.js';

interface WarnSink {
    readonly warn?: (message: string) => void;
}

/** Deliver to the host console when it has one (every runtime pkinative supports does). */
function _warn(message: string): void {
    const sink = (globalThis as { readonly console?: WarnSink }).console;
    if (sink !== undefined && typeof sink.warn === 'function') sink.warn(message);
}

/**
 * Create the per-operation diagnostics channel.
 *
 * @param strict  Escalate the first diagnostic to a thrown error.
 * @param handler Receive every diagnostic instead of the console.
 * @returns The emitter to hand down to every layer of the operation.
 */
export function createDiagnosticEmitter(strict: boolean | undefined, handler: PkiDiagnosticHandler | undefined): PkiDiagnosticEmitter {
    const recorded: PkiDiagnostic[] = [];
    const warned = new Set<PkiDiagnosticCode>();
    return {
        diagnostics: recorded,
        emit(diagnostic: PkiDiagnostic): void {
            if (strict === true) {
                throw new PkiError('PKI_STRICT_DIAGNOSTIC',
                    `pkinative: [${diagnostic.code}] ${diagnostic.message} — refused because strict: true; omit it to accept the input with this diagnostic`);
            }
            recorded.push(diagnostic);
            if (handler !== undefined) {
                handler(diagnostic);
                return;
            }
            if (!warned.has(diagnostic.code)) {
                warned.add(diagnostic.code);
                _warn(`pkinative: [${diagnostic.code}] ${diagnostic.message}`);
            }
        },
    };
}

function _diagnostic(
    code: PkiDiagnosticCode,
    severity: PkiDiagnosticSeverity,
    standard: string,
    message: string,
    path: string,
    offset: number | undefined,
): PkiDiagnostic {
    return Object.freeze({ code, severity, message, standard, path, offset });
}

// ── Payload factories — serial, algorithms, version ──────────────────

export function serialTooLongDiagnostic(octets: number, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SERIAL_TOO_LONG', 'warning', 'RFC 5280 §4.1.2.2',
        `the serial number is ${octets} octets long; RFC 5280 allows at most 20, and some verifiers refuse longer serials`,
        'tbsCertificate.serialNumber', offset);
}

export function serialNotPositiveDiagnostic(offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SERIAL_NOT_POSITIVE', 'warning', 'RFC 5280 §4.1.2.2',
        'the serial number is zero or negative; RFC 5280 requires a positive integer (the value is still returned as decoded)',
        'tbsCertificate.serialNumber', offset);
}

export function signatureAlgorithmMismatchDiagnostic(outer: string, inner: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SIGNATURE_ALGORITHM_MISMATCH', 'warning', 'RFC 5280 §4.1.1.2',
        `signatureAlgorithm (${outer}) differs from tbsCertificate.signature (${inner}); a verifier must refuse this certificate`,
        'signatureAlgorithm', undefined);
}

export function rsaParametersNotNullDiagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_RSA_PARAMETERS_NOT_NULL', 'warning', 'RFC 3279 §2.2.1',
        'an RSA PKCS#1 v1.5 algorithm identifier has absent or non-NULL parameters; RFC 3279 requires NULL',
        path, offset);
}

export function extensionsRequireV3Diagnostic(version: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_EXTENSIONS_REQUIRE_V3', 'warning', 'RFC 5280 §4.1.2.1',
        `the certificate carries extensions but declares version ${version}; extensions require version 3`,
        'tbsCertificate.version', undefined);
}

export function uniqueIdRequiresV2Diagnostic(version: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_UNIQUE_ID_REQUIRES_V2', 'warning', 'RFC 5280 §4.1.2.8',
        `the certificate carries a unique identifier but declares version ${version}; unique identifiers require version 2 or 3`,
        'tbsCertificate.version', undefined);
}

// ── Payload factories — time ─────────────────────────────────────────

export function generalizedTimeBefore2050Diagnostic(path: string, text: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_GENERALIZED_TIME_BEFORE_2050', 'warning', 'RFC 5280 §4.1.2.5',
        `"${text}" is a GeneralizedTime before 2050; RFC 5280 requires UTCTime for dates through 2049`,
        path, offset);
}

export function generalizedTimeFractionDiagnostic(path: string, text: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_GENERALIZED_TIME_FRACTION', 'warning', 'RFC 5280 §4.1.2.5.2',
        `"${text}" carries fractional seconds, which RFC 5280 forbids in certificates`,
        path, offset);
}

export function validityInvertedDiagnostic(notBefore: string, notAfter: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_VALIDITY_INVERTED', 'warning', 'RFC 5280 §4.1.2.5',
        `notBefore (${notBefore}) is later than notAfter (${notAfter}); the certificate is valid at no instant`,
        'tbsCertificate.validity', undefined);
}

// ── Payload factories — names ────────────────────────────────────────

export function emptyIssuerDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_EMPTY_ISSUER', 'warning', 'RFC 5280 §4.1.2.4',
        'the issuer name is empty; RFC 5280 requires a non-empty issuer distinguished name',
        'tbsCertificate.issuer', undefined);
}

export function emptySubjectSanNotCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_EMPTY_SUBJECT_SAN_NOT_CRITICAL', 'warning', 'RFC 5280 §4.2.1.6',
        'the subject is empty but the subjectAltName extension is absent or not critical; the identity lives only in an extension a verifier may ignore',
        'tbsCertificate.subject', undefined);
}

export function sanEmptyDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SAN_EMPTY', 'warning', 'RFC 5280 §4.2.1.6',
        'an alternative-name extension contains no name; RFC 5280 requires at least one GeneralName',
        path, undefined);
}

export function rdnSetNotSortedDiagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_RDN_SET_NOT_SORTED', 'warning', 'ITU-T X.690 §11.6',
        'a multi-valued relative distinguished name is not in DER SET OF order; name comparison by bytes will differ from other implementations',
        path, offset);
}

/**
 * A SignedData or SignerInfo declares a version RFC 5652 knows, but not the
 * one §5.1 or §5.3 derives from what the structure carries.
 *
 * A diagnostic, not a refusal: RFC 5652 §1.3 asks readers to be forgiving of
 * a wrong version, and the version is not covered by any signature — so it
 * decides nothing. The tag of `sid`, not the version, says which alternative
 * a signer uses.
 */
export function cmsVersionMismatchDiagnostic(path: string, declared: number, derived: number, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_VERSION_MISMATCH', 'warning', 'RFC 5652 §5.1',
        `declares version ${String(declared)} where the structure it carries calls for version ${String(derived)}; the version is not signed and decides nothing here, but a strict reader may refuse it`,
        path, offset);
}

/**
 * A SET OF outside every signature is not in DER order.
 *
 * `digestAlgorithms`, `certificates`, `crls` and `signerInfos` are all SET OF
 * and none is signed, so the order changes nothing a verifier decides. It is
 * still a DER violation, and the one real signers commit most: 91 of the 224
 * signed messages NIST ships with PKITS carry an unsorted certificate set.
 */
export function cmsSetNotSortedDiagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_SET_NOT_SORTED', 'warning', 'ITU-T X.690 §11.6',
        'this SET OF is not in DER order; nothing signed depends on it, but a strict DER reader will refuse the message',
        path, offset);
}

/**
 * The signed attributes are not in DER SET OF order.
 *
 * RFC 5652 §5.3 requires DER, and many signers do not sort. The signature is
 * over the bytes **as they were signed**, so pkinative verifies those bytes
 * and says so here. The concern is interoperability: a verifier that
 * re-encodes the set before checking the signature will reject this message.
 */
export function cmsSignedAttributesNotDerDiagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_SIGNED_ATTRIBUTES_NOT_DER', 'warning', 'RFC 5652 §5.3',
        'the signed attributes are not in DER SET OF order; the signature is checked over the bytes as signed, but a verifier that re-encodes them before checking will reject it',
        path, offset);
}

/** A signer's digest algorithm is missing from `SignedData.digestAlgorithms`. */
export function cmsDigestAlgorithmNotListedDiagnostic(path: string, oid: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_DIGEST_ALGORITHM_NOT_LISTED', 'warning', 'RFC 5652 §5.1',
        `the signer's digest algorithm ${oid} is not listed in digestAlgorithms, which exists so that a one-pass verifier can start hashing before it reaches the signers; RFC 5652 lets such a verifier fail`,
        path, offset);
}

/**
 * A PBKDF2 iteration count below the 1 000 RFC 8018 recommends.
 *
 * Not refused: the file opens, and the count protects the password rather than
 * the reader. A diagnostic because it is the one number in the file that says
 * how cheaply a stolen copy can be brute-forced.
 */
export function keyKdfIterationsLowDiagnostic(path: string, iterations: number, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_KEY_KDF_ITERATIONS_LOW', 'warning', 'RFC 8018 §4.2',
        `PBKDF2 runs ${String(iterations)} iterations, below the minimum of 1 000 RFC 8018 recommends; a stolen copy of this file is cheap to brute-force`,
        path, offset);
}

/**
 * A CRL extension whose value pkinative drops rather than reads.
 *
 * `cRLNumber`, `deltaCRLIndicator`, and an entry's `reasonCode` and
 * `invalidityDate`: none decides whether a serial is revoked, so a malformed
 * one does not refuse the list — but it is never dropped silently. A delta whose
 * base number is unreadable is simply never paired.
 */
export function crlExtensionMalformedDiagnostic(path: string, name: string, detail: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CRL_EXTENSION_MALFORMED', 'warning', 'RFC 5280 §5.2',
        `the ${name} extension is ${detail}, so its value is ignored; the revocation answer does not depend on it, but a strict validator may refuse the list`,
        path, offset);
}

/**
 * A naming attribute whose value is not of the syntax RFC 5280 Appendix A.1
 * gives it: a `countryName`, `serialNumber` or `dnQualifier` that is not a
 * PrintableString, a `domainComponent` or `emailAddress` that is not an
 * IA5String, or a DirectoryString attribute written as none of the five
 * DirectoryString types. The value is still decoded and compared by its
 * bytes; the concern is a strict reader, which refuses the name (pkilint:
 * a fatal ASN.1 decoding failure).
 */
export function nameAttributeStringTypeDiagnostic(path: string, attribute: string, found: string, expected: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE', 'warning', 'RFC 5280 Appendix A.1',
        `the ${attribute} attribute is encoded as ${found}, where RFC 5280 Appendix A.1 defines it as ${expected}; the value is still read, but a strict reader refuses the name`,
        path, offset);
}

/** A `countryName` that is not two characters — X520countryName is PrintableString (SIZE (2)). */
export function countryNameSizeDiagnostic(path: string, characters: number, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_COUNTRY_NAME_SIZE', 'warning', 'RFC 5280 Appendix A.1',
        `the countryName is ${String(characters)} characters long; RFC 5280 Appendix A.1 defines it as exactly two, an ISO 3166 alpha-2 code`,
        path, offset);
}

export function printableStringCharsetDiagnostic(path: string, character: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_PRINTABLE_STRING_CHARSET', 'warning', 'ITU-T X.680 §41.4',
        `a PrintableString contains "${character}", which is outside the PrintableString alphabet; the value was decoded as ASCII`,
        path, offset);
}

/** A BMPString or UniversalString that starts with the byte-order signature U+FEFF, which X.690 forbids. */
export function stringSignatureDiagnostic(path: string, type: 'BMPString' | 'UniversalString', offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_STRING_SIGNATURE', 'warning', 'ITU-T X.690 §8.23.7, §8.23.8',
        `a ${type} starts with the byte-order signature U+FEFF, which X.690 forbids ("Signatures shall not be used"); the value was decoded with the U+FEFF kept, so it compares unequal to the same text without it`,
        path, offset);
}

/** A UTF8String, BMPString or UniversalString that carries an ISO/IEC 2022 code-extension control. */
export function stringEscapeSequenceDiagnostic(path: string, type: 'UTF8String' | 'BMPString' | 'UniversalString', control: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_STRING_ESCAPE_SEQUENCE', 'warning', 'ITU-T X.690 §8.23.9, §8.23.10',
        `a ${type} contains the ISO/IEC 2022 control ${control}, which X.690 forbids in the ISO/IEC 10646 string types; the value was decoded as ISO/IEC 10646 regardless, but a reader that honours the escape shows other characters`,
        path, offset);
}

export function teletexAsLatin1Diagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_TELETEX_AS_LATIN1', 'info', 'RFC 5280 §4.1.2.4',
        'a TeletexString was decoded as ISO 8859-1, the interpretation of real-world issuers; the original bytes are in the raw field',
        path, offset);
}

// ── Payload factories — extensions ───────────────────────────────────

export function unknownCriticalExtensionDiagnostic(oid: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_UNKNOWN_CRITICAL_EXTENSION', 'warning', 'RFC 5280 §4.2',
        `the critical extension ${oid} is not recognised; a verifier must refuse a certificate with an unrecognised critical extension`,
        path, undefined);
}

export function pathLenWithoutCaDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_PATHLEN_WITHOUT_CA', 'warning', 'RFC 5280 §4.2.1.9',
        'basicConstraints sets pathLenConstraint while cA is false; the constraint is meaningless and RFC 5280 forbids it',
        'tbsCertificate.extensions.basicConstraints', undefined);
}

export function keyUsageEmptyDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_KEY_USAGE_EMPTY', 'warning', 'RFC 5280 §4.2.1.3',
        'keyUsage asserts no usage bit; RFC 5280 requires at least one bit set',
        'tbsCertificate.extensions.keyUsage', undefined);
}

export function namedBitsTrailingZeroDiagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_NAMED_BITS_TRAILING_ZERO', 'warning', 'ITU-T X.690 §11.2.2',
        'a named bit list keeps trailing zero bits that DER requires to be removed',
        path, offset);
}

export function nameConstraintsNotCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_NAME_CONSTRAINTS_NOT_CRITICAL', 'warning', 'RFC 5280 §4.2.1.10',
        'nameConstraints is not marked critical; RFC 5280 requires conforming CAs to mark it critical',
        'tbsCertificate.extensions.nameConstraints', undefined);
}

export function nameConstraintsInEndEntityDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_NAME_CONSTRAINTS_IN_END_ENTITY', 'warning', 'RFC 5280 §4.2.1.10',
        'nameConstraints appears in a certificate that is not a CA; the extension "MUST be used only in a CA certificate", and an end-entity certificate issues nothing for it to constrain',
        'tbsCertificate.extensions.nameConstraints', undefined);
}

export function basicConstraintsNotCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_BASIC_CONSTRAINTS_NOT_CRITICAL', 'warning', 'RFC 5280 §4.2.1.9',
        'basicConstraints asserts cA without being marked critical; RFC 5280 requires conforming CAs to mark it critical, so a verifier that skipped non-critical extensions would not see that this is a CA',
        'tbsCertificate.extensions.basicConstraints', undefined);
}

export function policyConstraintsNotCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_POLICY_CONSTRAINTS_NOT_CRITICAL', 'warning', 'RFC 5280 §4.2.1.11',
        'policyConstraints is not marked critical; RFC 5280 requires conforming CAs to mark it critical, and a verifier that ignored it would grant a path the policy the CA withheld',
        'tbsCertificate.extensions.policyConstraints', undefined);
}

export function keyCertSignWithoutCaDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_KEY_CERT_SIGN_WITHOUT_CA', 'warning', 'RFC 5280 §4.2.1.3',
        'keyUsage asserts keyCertSign while basicConstraints does not assert cA; that bit "is for use in CA certificates only", and §6.1.4 (k) refuses to let this key issue anything regardless',
        'tbsCertificate.extensions.keyUsage', undefined);
}

export function commonNameNotInSanDiagnostic(commonName: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_COMMON_NAME_NOT_IN_SAN', 'warning', 'CA/Browser Forum BR 7.1.4.3',
        `the commonName ${JSON.stringify(commonName)} is not one of the subjectAltName entries; CA/Browser Forum BR 7.1.4.3 requires it to repeat a SAN value, and a name that appears only in the commonName is one no modern relying party will match`,
        'tbsCertificate.subject', undefined);
}

export function dnsNameNotPreferredSyntaxDiagnostic(name: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_DNS_NAME_NOT_PREFERRED_SYNTAX', 'warning', 'RFC 5280 §4.2.1.6',
        `the dNSName ${JSON.stringify(name)} is outside RFC 1034's preferred name syntax; it is compared literally, so it can only ever match a host asked for with the same spelling`,
        path, undefined);
}

export function akiMissingDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_AKI_MISSING', 'warning', 'RFC 5280 §4.2.1.1',
        'authorityKeyIdentifier is absent from a certificate that names another subject as its issuer; RFC 5280 requires conforming CAs to include it, and without it a path builder must try every candidate issuer by name',
        'tbsCertificate.extensions', undefined);
}

export function skiMissingDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SKI_MISSING', 'warning', 'RFC 5280 §4.2.1.2',
        'subjectKeyIdentifier is absent from a CA certificate; RFC 5280 requires conforming CAs to include it so that the certificates they issue can name their key',
        'tbsCertificate.extensions', undefined);
}

export function akiIssuerSerialUnpairedDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_AKI_ISSUER_SERIAL_UNPAIRED', 'warning', 'RFC 5280 §4.2.1.1',
        'authorityKeyIdentifier carries only one of authorityCertIssuer and authorityCertSerialNumber; they must appear together',
        'tbsCertificate.extensions.authorityKeyIdentifier', undefined);
}

export function policyDuplicateDiagnostic(oid: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_POLICY_DUPLICATE', 'warning', 'RFC 5280 §4.2.1.4',
        `certificatePolicies lists the policy ${oid} more than once; a policy OID must not appear twice`,
        'tbsCertificate.extensions.certificatePolicies', undefined);
}

export function policyConstraintsEmptyDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_POLICY_CONSTRAINTS_EMPTY', 'warning', 'RFC 5280 §4.2.1.11',
        'policyConstraints sets neither requireExplicitPolicy nor inhibitPolicyMapping; RFC 5280 forbids an empty sequence',
        'tbsCertificate.extensions.policyConstraints', undefined);
}

export function defaultEncodedDiagnostic(path: string, value: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_DEFAULT_ENCODED', 'warning', 'ITU-T X.690 §11.5',
        `the field encodes its DEFAULT value ${value}, which DER omits; the value reads the same either way, but a strict DER verifier may refuse the certificate`,
        path, offset);
}

// ── Payload factories — accepted tolerances ──────────────────────────

export function berConstructAcceptedDiagnostic(construct: string, offset: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_BER_CONSTRUCT_ACCEPTED', 'info', 'ITU-T X.690 §10',
        `accepted a BER-only construct (${construct}) because encodingRules is 'ber'; a DER decoder refuses this input`,
        '', offset);
}

export function pemLaxAcceptedDiagnostic(deviation: string, offset: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_PEM_LAX_ACCEPTED', 'info', 'RFC 7468 §3',
        `accepted a lax PEM deviation (${deviation}) because mode is 'lax'; strict parsing refuses this text`,
        '', offset);
}
