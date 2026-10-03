/**
 * pkinative — Conformance diagnostics
 * ===================================
 * The single channel for non-fatal conformance concerns: profile violations
 * real issuers commit, and tolerances the caller asked for. Structural
 * failures THROW; conformance concerns DIAGNOSE; the two never mix.
 *
 * Every diagnostic of an operation is recorded (parse results expose them),
 * and delivered to exactly one place:
 *   - `strict: true` → the first `warning` diagnostic throws a `PkiError` with
 *     code `PKI_STRICT_DIAGNOSTIC`, before any result is returned; an `info`
 *     diagnostic — a SHOULD the input did not follow — is reported, never thrown;
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
            // A warning is a MUST the input broke; an info is a SHOULD it did
            // not follow. `strict` refuses the first and reports the second:
            // nine thousand end-entity certificates of x509-limbo omit the
            // subjectKeyIdentifier RFC 5280 only recommends, and a strict
            // reader that refused every one of them would be a reader nobody
            // could leave on.
            if (strict === true && diagnostic.severity === 'warning') {
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

// ── Payload factories — RFC 5652 §5.2, §11.3 and §11.4 ───────────────
//
// Each is one requirement sentence of scripts/data/rfc5652-requirements.json
// that the parser can decide from the message alone. None changes what is
// decoded and none touches a verdict: the certificates-only case has no
// signer to judge, a countersignature is carried and never verified, and a
// signing time is read to the millisecond whatever its form.

/**
 * A SignedData with no signer whose `eContentType` is not id-data, or which
 * still carries `eContent`. RFC 5652 §5.2 reserves the signer-less form for
 * the certificates-only message, and says what its content must look like.
 */
export function cmsCertsOnlyContentDiagnostic(path: string, found: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_CERTS_ONLY_CONTENT', 'warning', 'RFC 5652 §5.2',
        `this SignedData has no signer and ${found}; RFC 5652 §5.2 requires a signer-less message to carry id-data and no eContent, and a strict reader may refuse it`,
        path, offset);
}

/** A countersignature whose own signed attributes carry a content-type attribute, which §11.4 forbids: there is no content type for a countersignature. */
export function cmsCountersignatureContentTypeDiagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_COUNTERSIGNATURE_CONTENT_TYPE', 'warning', 'RFC 5652 §11.4',
        'this countersignature carries a content-type attribute among its signed attributes; RFC 5652 §11.4 forbids one there, since a countersignature has no content type — the countersignature is carried, not verified',
        path, offset);
}

/** A countersignature whose signed attributes lack a message-digest attribute while holding others. */
export function cmsCountersignatureNoMessageDigestDiagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_COUNTERSIGNATURE_NO_MESSAGE_DIGEST', 'warning', 'RFC 5652 §11.4',
        'this countersignature has signed attributes and none of them is a message-digest attribute, which RFC 5652 §11.4 requires whenever any other attribute is signed; a verifier of the countersignature has nothing to bind it to',
        path, offset);
}

/** A countersignature attribute whose SET OF values is empty. */
export function cmsCountersignatureEmptyDiagnostic(path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_COUNTERSIGNATURE_EMPTY', 'warning', 'RFC 5652 §11.4',
        'this countersignature attribute holds no value; RFC 5652 §11.4 requires one or more SignerInfo values, so the attribute countersigns nothing',
        path, offset);
}

/** A signing time in GeneralizedTime for a date 1950–2049, which §11.3 requires as UTCTime. */
export function cmsSigningTimeNotUtcDiagnostic(path: string, text: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_SIGNING_TIME_NOT_UTC', 'warning', 'RFC 5652 §11.3',
        `"${text}" is a GeneralizedTime for a date between 1950 and 2049; RFC 5652 §11.3 requires UTCTime for those years — the instant is read as written, and a strict reader may refuse the attribute`,
        path, offset);
}

/** A GeneralizedTime signing time with fractional seconds, which §11.3 forbids. */
export function cmsSigningTimeFractionDiagnostic(path: string, text: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CMS_SIGNING_TIME_FRACTION', 'warning', 'RFC 5652 §11.3',
        `"${text}" carries fractional seconds, which RFC 5652 §11.3 forbids in a signing time; the instant is read to the millisecond`,
        path, offset);
}

// ── Payload factories — RFC 3161 §2.4.1: certReq against the token ───
//
// Decided only where the request and the token are both in hand — the
// verifier — because neither side alone says what the other asked for.

/** `certReq` was TRUE and the token does not carry the TSA's certificate. */
export function tspCertReqUnmetDiagnostic(path: string, found: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_TSP_CERTREQ_UNMET', 'warning', 'RFC 3161 §2.4.1',
        `the request set certReq and ${found}; RFC 3161 §2.4.1 requires the TSA to include the certificate its SigningCertificate attribute names — the token verifies against the certificates you pass, but a reader without them cannot`,
        path, undefined);
}

/** `certReq` was FALSE or absent and the token carries certificates anyway. */
export function tspCertsUnrequestedDiagnostic(path: string, count: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_TSP_CERTS_UNREQUESTED', 'warning', 'RFC 3161 §2.4.1',
        `the request did not set certReq and the token carries ${String(count)} certificate(s); RFC 3161 §2.4.1 then forbids the certificates field — they are read as the TSA's hint, and the token is no less valid for it`,
        path, undefined);
}

// ── Payload factories — RFC 6960 §4.2: what a response says about itself ──

/** The `certs` field is present and holds no certificate; §4.2.1 says it should then be absent. */
export function ocspCertsEmptyDiagnostic(offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_OCSP_CERTS_EMPTY', 'info', 'RFC 6960 §4.2.1',
        'the certs field is present and empty; RFC 6960 §4.2.1 says it should be absent when no certificate is included — nothing is lost, the responder is found as if the field were absent',
        'BasicOCSPResponse.certs', offset);
}

/** `ResponseData.version` is present and is not the one-octet INTEGER 0 of v1. */
export function ocspVersionNotV1Diagnostic(found: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_OCSP_VERSION_NOT_V1', 'warning', 'RFC 6960 §4.2.2.3',
        `ResponseData.version ${found}; RFC 6960 §4.2.2.3 defines v1 (0) only, so the response is read with the v1 syntax — a strict reader may refuse it`,
        'ResponseData.version', offset);
}

/** The `responderID` names neither the subject nor the key of the certificate that signed the response. */
export function ocspResponderIdMismatchDiagnostic(path: string, kind: 'byName' | 'byKey'): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH', 'warning', 'RFC 6960 §4.2.2.3',
        kind === 'byName'
            ? 'responderID names a subject that is not the subject of the certificate whose key verified the signature; RFC 6960 §4.2.2.3 requires it to correspond — the signature decides who answered, the name here is what the responder claims'
            : 'responderID carries a key hash that is not the SHA-1 of the public key that verified the signature; RFC 6960 §4.2.2.3 requires it to correspond — the signature decides who answered, the hash here is what the responder claims',
        `${path}.responderID`, undefined);
}

/** The response answers about certificates nobody asked about, beside the one that was. */
export function ocspSingleResponseUnrequestedDiagnostic(path: string, extra: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_OCSP_SINGLE_RESPONSE_UNREQUESTED', 'info', 'RFC 6960 §4.2.2.3',
        `the response carries ${String(extra)} SingleResponse element(s) about certificates that were not asked about; RFC 6960 §4.2.2.3 says a responder should not add them, and allows pre-generated responses to — the answer about the certificate asked about is the one judged`,
        `${path}.responses`, undefined);
}

/** The responder's certificate marks `id-pkix-ocsp-nocheck` critical; §4.2.2.2.1 says it should not be. */
export function ocspNoCheckCriticalDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_OCSP_NOCHECK_CRITICAL', 'info', 'RFC 6960 §4.2.2.2.1',
        'the certificate that signed the response marks id-pkix-ocsp-nocheck critical; RFC 6960 §4.2.2.2.1 says the extension should be non-critical — it is honoured either way, and a reader that does not know it must refuse the certificate',
        `${path}.signer.ocspNoCheck`, undefined);
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
 * An RSA public exponent outside what RFC 8017 §3.1 defines — below 3, or
 * even. The key still decodes; no signature under it is ever checked
 * (`PKI_CRYPTO_KEY_UNSUPPORTED` at verification), because under e = 1 a
 * message is its own signature.
 */
export function spkiRsaExponentWeakDiagnostic(path: string, exponent: bigint, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SPKI_RSA_EXPONENT_WEAK', 'warning', 'RFC 8017 §3.1',
        `the RSA public exponent is ${exponent.toString()}; RFC 8017 defines RSA for an odd exponent of at least 3, and no signature under this key will be checked`,
        path, offset);
}

/**
 * An EC key whose parameters do not name a curve pkinative knows: NULL
 * (implicitCurve) or explicit parameters (specifiedCurve), which RFC 5480
 * §2.1.1 forbids, or a namedCurve OID outside P-256, P-384 and P-521. The key
 * still decodes, with `curve` undefined; no signature under it is checked
 * (`PKI_CRYPTO_KEY_UNSUPPORTED` at verification).
 *
 * @param namedCurve The curve OID when the parameters are one, else undefined.
 */
export function spkiEcParametersInvalidDiagnostic(path: string, namedCurve: string | undefined, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SPKI_EC_PARAMETERS_INVALID', 'warning', 'RFC 5480 §2.1.1',
        namedCurve === undefined
            ? 'the EC key parameters are not a namedCurve OBJECT IDENTIFIER; RFC 5480 forbids implicitCurve (NULL) and specifiedCurve, and no signature under this key will be checked'
            : `the EC key names the curve ${namedCurve}, which pkinative does not know; no signature under this key will be checked`,
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

export function subjectDirectoryAttributesCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SUBJECT_DIRECTORY_ATTRIBUTES_CRITICAL', 'warning', 'RFC 5280 §4.2.1.8',
        'subjectDirectoryAttributes is marked critical; RFC 5280 requires conforming CAs to mark it non-critical, and a relying party that does not process it must then refuse the certificate',
        'tbsCertificate.extensions.subjectDirectoryAttributes', undefined);
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

/**
 * A NUL, another C0 control or DEL inside a dNSName, an rfc822Name or a
 * uniformResourceIdentifier. None of their syntaxes admits one; a display or
 * log consumer that stops at NUL reads a different name than the one matched
 * (the CVE-2009-2408 class). The name is kept and compared literally.
 */
export function generalNameControlCharacterDiagnostic(kind: string, name: string, path: string, offset?: number): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_GENERAL_NAME_CONTROL_CHARACTER', 'warning', 'RFC 5280 §4.2.1.6',
        `the ${kind} ${JSON.stringify(name)} contains a control character; no name syntax admits one, and a consumer that stops at NUL reads a different name than the one compared`,
        path, offset);
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

// ── Payload factories — the rest of the RFC 5280 §4.1–§4.2 profile ───
//
// Each is one requirement sentence of scripts/data/rfc5280-requirements.json,
// held to an independent reading by its L5 clause in scripts/lib/clauses.ts.
// A MUST is a `warning`, a SHOULD an `info`; none of them changes what is
// decoded, and none refuses a chain.

export function uniqueIdPresentDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_UNIQUE_ID_PRESENT', 'warning', 'RFC 5280 §4.1.2.8',
        'the certificate carries a unique identifier; RFC 5280 forbids conforming CAs to generate one, and no relying party gives it a meaning',
        path, undefined);
}

export function akiCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_AKI_CRITICAL', 'warning', 'RFC 5280 §4.2.1.1',
        'authorityKeyIdentifier is marked critical; RFC 5280 requires conforming CAs to mark it non-critical',
        'tbsCertificate.extensions.authorityKeyIdentifier', undefined);
}

export function skiCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SKI_CRITICAL', 'warning', 'RFC 5280 §4.2.1.2',
        'subjectKeyIdentifier is marked critical; RFC 5280 requires conforming CAs to mark it non-critical',
        'tbsCertificate.extensions.subjectKeyIdentifier', undefined);
}

export function skiMissingEndEntityDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SKI_MISSING_END_ENTITY', 'info', 'RFC 5280 §4.2.1.2',
        'subjectKeyIdentifier is absent from an end-entity certificate; RFC 5280 says it should be included, though the CA/Browser Forum now advises against it in subscriber certificates',
        'tbsCertificate.extensions', undefined);
}

export function keyUsageNotCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_KEY_USAGE_NOT_CRITICAL', 'info', 'RFC 5280 §4.2.1.3',
        'keyUsage is not marked critical; RFC 5280 says conforming CAs should mark it critical, so that a verifier which does not process it refuses the certificate rather than ignore the restriction',
        'tbsCertificate.extensions.keyUsage', undefined);
}

export function anyPolicyQualifierDiagnostic(oid: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_ANY_POLICY_QUALIFIER', 'warning', 'RFC 5280 §4.2.1.4',
        `anyPolicy carries the qualifier ${oid}; with anyPolicy, RFC 5280 limits qualifiers to the CPS pointer and the user notice`,
        path, undefined);
}

export function noticeRefUsedDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_NOTICE_REF_USED', 'info', 'RFC 5280 §4.2.1.4',
        'a user notice uses noticeRef; RFC 5280 says conforming CAs should not, since a relying party can rarely resolve it to text',
        path, undefined);
}

export function explicitTextStringTypeDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_EXPLICIT_TEXT_STRING_TYPE', 'warning', 'RFC 5280 §4.2.1.4',
        'a user notice\'s explicitText is a VisibleString or a BMPString, which RFC 5280 forbids there; it asks for UTF8String (or IA5String)',
        path, undefined);
}

export function explicitTextControlCharacterDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_EXPLICIT_TEXT_CONTROL_CHARACTER', 'info', 'RFC 5280 §4.2.1.4',
        'a user notice\'s explicitText contains a control character (U+0000 to U+001F or U+007F to U+009F), which RFC 5280 says it should not; the text is kept as decoded',
        path, undefined);
}

export function explicitTextNotNfcDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_EXPLICIT_TEXT_NOT_NFC', 'info', 'RFC 5280 §4.2.1.4',
        'a UTF8String explicitText is not in Unicode normalization form C, which RFC 5280 says it should be; the text is kept as decoded, so two spellings of it compare unequal',
        path, undefined);
}

export function policyMappingNotAssertedDiagnostic(oid: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_POLICY_MAPPING_NOT_ASSERTED', 'info', 'RFC 5280 §4.2.1.5',
        `policyMappings maps the issuerDomainPolicy ${oid}, which the certificate's certificatePolicies does not assert; RFC 5280 says it should`,
        'tbsCertificate.extensions.policyMappings', undefined);
}

export function policyMappingsNotCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_POLICY_MAPPINGS_NOT_CRITICAL', 'info', 'RFC 5280 §4.2.1.5',
        'policyMappings is not marked critical; RFC 5280 says conforming CAs should mark it critical',
        'tbsCertificate.extensions.policyMappings', undefined);
}

export function sanCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SAN_CRITICAL', 'info', 'RFC 5280 §4.2.1.6',
        'subjectAltName is marked critical while the subject is not empty; RFC 5280 says conforming CAs should then mark it non-critical',
        'tbsCertificate.extensions.subjectAltName', undefined);
}

export function altNameUriInvalidDiagnostic(uri: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_ALT_NAME_URI_INVALID', 'warning', 'RFC 5280 §4.2.1.6',
        `the uniformResourceIdentifier ${JSON.stringify(uri)} is not an absolute URI by the RFC 3986 grammar; RFC 5280 forbids a relative or ill-formed one, and two URI parsers may read it two ways`,
        path, undefined);
}

export function altNameUriSchemeMissingDiagnostic(uri: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_ALT_NAME_URI_SCHEME_MISSING', 'warning', 'RFC 5280 §4.2.1.6',
        `the uniformResourceIdentifier ${JSON.stringify(uri)} lacks a scheme or a scheme-specific part; RFC 5280 requires both`,
        path, undefined);
}

export function altNameUriHostInvalidDiagnostic(uri: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_ALT_NAME_URI_HOST_INVALID', 'warning', 'RFC 5280 §4.2.1.6',
        `the uniformResourceIdentifier ${JSON.stringify(uri)} has an authority whose host is neither a fully qualified domain name nor an IP address, which RFC 5280 requires`,
        path, undefined);
}

export function altNameGeneralNameEmptyDiagnostic(kind: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_ALT_NAME_GENERAL_NAME_EMPTY', 'warning', 'RFC 5280 §4.2.1.6',
        `an alternative name holds an empty ${kind}; RFC 5280 forbids empty GeneralName fields, and an empty name identifies nothing`,
        path, undefined);
}

export function issuerAltNameCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_ISSUER_ALT_NAME_CRITICAL', 'info', 'RFC 5280 §4.2.1.7',
        'issuerAltName is marked critical; RFC 5280 says conforming CAs should mark it non-critical',
        'tbsCertificate.extensions.issuerAltName', undefined);
}

export function nameConstraintsMinMaxDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_NAME_CONSTRAINTS_MIN_MAX', 'warning', 'RFC 5280 §4.2.1.10',
        'a GeneralSubtree sets a non-zero minimum or a maximum; RFC 5280 requires minimum 0 and no maximum, and path validation never treats such a subtree as covering a name',
        path, undefined);
}

export function nameConstraintsUriNotFqdnDiagnostic(constraint: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_NAME_CONSTRAINTS_URI_NOT_FQDN', 'warning', 'RFC 5280 §4.2.1.10',
        `the uniformResourceIdentifier constraint ${JSON.stringify(constraint)} is not a fully qualified domain name (with a leading period for a domain), which RFC 5280 requires; it is still matched against the host of each URI`,
        path, undefined);
}

export function ekuAnyCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_EKU_ANY_CRITICAL', 'info', 'RFC 5280 §4.2.1.12',
        'extKeyUsage is marked critical and contains anyExtendedKeyUsage; RFC 5280 says conforming CAs should not mark it critical then',
        'tbsCertificate.extensions.extKeyUsage', undefined);
}

export function crlDistributionPointsCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CRL_DISTRIBUTION_POINTS_CRITICAL', 'info', 'RFC 5280 §4.2.1.13',
        'cRLDistributionPoints is marked critical; RFC 5280 says the extension should be non-critical',
        'tbsCertificate.extensions.cRLDistributionPoints', undefined);
}

export function distributionPointWithoutNameDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_DISTRIBUTION_POINT_WITHOUT_NAME', 'warning', 'RFC 5280 §4.2.1.13',
        'a DistributionPoint has neither distributionPoint nor cRLIssuer; RFC 5280 requires one of them, and without either it locates no CRL',
        path, undefined);
}

export function distributionPointLdapUriIncompleteDiagnostic(uri: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_DISTRIBUTION_POINT_LDAP_URI_INCOMPLETE', 'warning', 'RFC 5280 §4.2.1.13',
        `the LDAP URI ${JSON.stringify(uri)} lacks a <dn> or a single <attrdesc>; RFC 5280 requires both, to name the entry and the attribute that hold the CRL`,
        path, undefined);
}

export function distributionPointNoHttpOrLdapUriDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_DISTRIBUTION_POINT_NO_HTTP_OR_LDAP_URI', 'info', 'RFC 5280 §4.2.1.13',
        'a DistributionPointName includes no HTTP or LDAP URI; RFC 5280 says it should include at least one, the two schemes a relying party is expected to fetch',
        path, undefined);
}

export function distributionPointRelativeNameDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME', 'info', 'RFC 5280 §4.2.1.13',
        'a distribution point is named by nameRelativeToCRLIssuer; RFC 5280 says conforming CAs should not use it',
        path, undefined);
}

export function distributionPointRelativeNameAmbiguousDiagnostic(path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_DISTRIBUTION_POINT_RELATIVE_NAME_AMBIGUOUS', 'warning', 'RFC 5280 §4.2.1.13',
        'a distribution point uses nameRelativeToCRLIssuer while cRLIssuer holds more than one distinguished name; RFC 5280 forbids it, since the name is relative to none of them in particular',
        path, undefined);
}

export function inhibitAnyPolicyNotCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_INHIBIT_ANY_POLICY_NOT_CRITICAL', 'warning', 'RFC 5280 §4.2.1.14',
        'inhibitAnyPolicy is not marked critical; RFC 5280 requires conforming CAs to mark it critical (pkinative enforces it either way)',
        'tbsCertificate.extensions.inhibitAnyPolicy', undefined);
}

export function freshestCrlCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_FRESHEST_CRL_CRITICAL', 'warning', 'RFC 5280 §4.2.1.15',
        'freshestCRL is marked critical; RFC 5280 requires conforming CAs to mark it non-critical',
        'tbsCertificate.extensions.freshestCRL', undefined);
}

export function aiaCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_AIA_CRITICAL', 'warning', 'RFC 5280 §4.2.2.1',
        'authorityInfoAccess is marked critical; RFC 5280 requires conforming CAs to mark it non-critical',
        'tbsCertificate.extensions.authorityInfoAccess', undefined);
}

export function siaCriticalDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_SIA_CRITICAL', 'warning', 'RFC 5280 §4.2.2.2',
        'subjectInfoAccess is marked critical; RFC 5280 requires conforming CAs to mark it non-critical',
        'tbsCertificate.extensions.subjectInfoAccess', undefined);
}

/**
 * An LDAP URI of an `id-ad-caIssuers` (authorityInfoAccess) or
 * `id-ad-caRepository` (subjectInfoAccess) location without its `<dn>` or its
 * `<attributes>`. One code for both: the two sections state the requirement
 * in the same sentence, and the path names the extension.
 */
export function infoAccessLdapUriIncompleteDiagnostic(uri: string, path: string): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_INFO_ACCESS_LDAP_URI_INCOMPLETE', 'warning', 'RFC 5280 §4.2.2.1, §4.2.2.2',
        `the LDAP URI ${JSON.stringify(uri)} lacks a <dn> or an <attributes> field; RFC 5280 requires both, to name the entry and the attributes that hold the certificates`,
        path, undefined);
}

export function caIssuersNoHttpOrLdapUriDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CA_ISSUERS_NO_HTTP_OR_LDAP_URI', 'info', 'RFC 5280 §4.2.2.1',
        'no id-ad-caIssuers access location is an HTTP or LDAP URI; RFC 5280 says at least one should be',
        'tbsCertificate.extensions.authorityInfoAccess', undefined);
}

export function caRepositoryNoHttpOrLdapUriDiagnostic(): PkiDiagnostic {
    return _diagnostic('PKI_DIAG_CA_REPOSITORY_NO_HTTP_OR_LDAP_URI', 'info', 'RFC 5280 §4.2.2.2',
        'no id-ad-caRepository access location is an HTTP or LDAP URI; RFC 5280 says at least one should be',
        'tbsCertificate.extensions.subjectInfoAccess', undefined);
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
