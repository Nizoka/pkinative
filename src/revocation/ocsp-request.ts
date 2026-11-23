/**
 * pkinative — RFC 6960 OCSP requests
 * ==================================
 * Build the bytes you POST to a responder — and read such a request back.
 *
 * The part worth reading is what a `CertID` identifies the issuer **by**: not
 * its name, but hashes of its encoded name and of its public key bits. That
 * is RFC 6960 §4.1.1's own choice, and it has two consequences this module has
 * to get exactly right or the responder answers about a different certificate.
 *
 * `issuerNameHash` is over the **encoded `Name`**, tag and length included —
 * `issuer.subject.der`, never a rendering and never the content octets alone.
 * `issuerKeyHash` is over the `subjectPublicKey` BIT STRING's **content
 * without its unused-bits octet**, not over the whole SubjectPublicKeyInfo.
 * Hashing the SPKI instead is the single most common OCSP client bug, and it
 * produces a request a responder answers `unknown` to — which a careless
 * client then reports as "not revoked".
 *
 * SHA-1 is the default because RFC 6960 §4.3 makes it mandatory for
 * responders and nothing else is universally supported. It is **not** used as
 * a security primitive here: these hashes are identifiers over public data,
 * and a collision buys an attacker the right to ask a question about a
 * certificate they could have named directly.
 *
 * `parseOcspRequest` is the other direction, for whoever inspects a request
 * before it leaves or after it was logged. It reads; it does not answer, and
 * it does not verify a signed request — pkinative is not a responder.
 *
 * @module revocation/ocsp-request
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { readTlvHeader, walkChildren, type TlvHeader } from '../asn1/asn1-cursor.js';
import { encodeOctetString, encodeSequence, encodeTlv } from '../asn1/asn1-encode.js';
import { _readBitString } from '../asn1/asn1-read.js';
import { encodeAlgorithmIdentifier } from '../build/build-structures.js';
import { A_CERTIFICATE, assertOptions, assertParsed, describeValue } from '../core/arguments.js';
import { assertBytes, isBytes } from '../core/bytes.js';
import { ocspNonceLengthDiagnostic, ocspRequestExtensionCriticalDiagnostic, ocspRequestSignedUnnamedDiagnostic } from '../core/pki-diagnostics.js';
import { _pkiError } from '../core/pki-error-guard.js';
import { enforceLimit } from '../core/pki-limits.js';
import { computeKeyIdentifier } from '../hash/key-identifier.js';
import { sha1 } from '../hash/sha1.js';
import { sha256 } from '../hash/sha256.js';
import type { OcspRequest, OcspRequestEntry, OcspRequestSignature } from '../types/ocsp-types.js';
import { PkiCertificateError, PkiEncodingError, PkiError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { Certificate, Extension, GeneralName } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from '../x509/x509-algorithm.js';
import { _readGeneralName } from '../x509/x509-general-name.js';
import { _OCSP_STRUCTURE, _decodeAt, _fieldsOf, _ocspError, _readCertId, _readExtensions, _readOcspVersion } from './ocsp-shared.js';

/** The digests RFC 6960 §4.3 lets a `CertID` use. */
export type OcspHashAlgorithm = 'SHA-1' | 'SHA-256';

const HASH_OID: Readonly<Record<OcspHashAlgorithm, string>> = Object.freeze({
    'SHA-1': '1.3.14.3.2.26',
    'SHA-256': '2.16.840.1.101.3.4.2.1',
});

/** Options of {@link createOcspRequest}. */
export interface CreateOcspRequestOptions {
    /**
     * The digest for the two issuer hashes. SHA-1 by default, because RFC 6960
     * §4.3 makes it mandatory for responders and a SHA-256 `CertID` is
     * answered `unknown` by many of them — which a client must not read as
     * "not revoked".
     */
    readonly hashAlgorithm?: OcspHashAlgorithm | undefined;
    /**
     * A nonce (RFC 6960 §4.4.1), which binds the response to this request.
     * Without one a responder may serve a cached answer, and an attacker who
     * can replay it can serve a stale "good" indefinitely. Supply your own
     * random bytes; pkinative generates none.
     */
    readonly nonce?: Uint8Array | undefined;
}

/**
 * Build a `CertID` for one certificate under one issuer.
 *
 * Exposed because a caller matching a response back to a question needs the
 * same three values, and recomputing them by hand is where the two hashes get
 * taken over the wrong bytes.
 *
 * @param certificate The certificate being asked about.
 * @param issuer      The certificate that issued it.
 * @param algorithm   The digest; SHA-1 by default.
 * @returns The encoded `CertID`.
 * @throws {PkiError} `PKI_INVALID_INPUT` when either argument is not parsed; `PKI_INVALID_OPTION` for a digest other than SHA-1 or SHA-256.
 */
export function encodeOcspCertId(certificate: Certificate, issuer: Certificate, algorithm: OcspHashAlgorithm = 'SHA-1'): Uint8Array {
    assertParsed(certificate, 'certificate', A_CERTIFICATE, ['der', 'serialNumber.bytes']);
    assertParsed(issuer, 'issuer', A_CERTIFICATE, ['der', 'subject.der', 'subjectPublicKeyInfo.publicKey.bytes']);
    // Asked for its own names only, and before anything is hashed with the wrong one.
    if (typeof algorithm !== 'string' || !Object.prototype.hasOwnProperty.call(HASH_OID, algorithm)) {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: the CertID digest must be 'SHA-1' or 'SHA-256', got ${describeValue(algorithm)}`);
    }
    const digest = algorithm === 'SHA-1' ? sha1 : sha256;
    // The encoded Name, tag and length included. RFC 6960 §4.1.1: "the hash of
    // the issuer's distinguished name (DN)", and the DN is the encoded field.
    const nameHash = digest(issuer.subject.der);
    // The BIT STRING's content WITHOUT its unused-bits octet — not the SPKI.
    // `subjectPublicKey.bytes` is already that content in this library, and this
    // is byte for byte the RFC 5280 §4.2.1.2 key identifier: one value, named
    // once, so the two callers cannot drift into hashing different things.
    const keyHash = computeKeyIdentifier(issuer.subjectPublicKeyInfo.publicKey.bytes, algorithm);
    return encodeSequence([
        encodeAlgorithmIdentifier(HASH_OID[algorithm], NULL_PARAMETERS),
        encodeOctetString(nameHash),
        encodeOctetString(keyHash),
        encodeTlv('universal', 2, false, certificate.serialNumber.bytes),
    ]);
}

/**
 * The explicit NULL a digest `AlgorithmIdentifier` carries here.
 *
 * RFC 5754 §2 says implementations SHOULD omit the parameters for SHA
 * algorithms and MUST accept both forms. Real OCSP responders are less
 * forgiving than that sentence: the absent form is answered `unknown` by
 * enough of them that writing NULL is the interoperable choice, and an
 * `unknown` a client misreads is worse than a redundant two octets.
 */
const NULL_PARAMETERS = /*#__PURE__*/ encodeTlv('universal', 5, false, new Uint8Array(0));

/**
 * Build an OCSP request for one certificate.
 *
 * ```ts
 * const body = createOcspRequest(certificate, issuer, { nonce: crypto.getRandomValues(new Uint8Array(16)) });
 * await fetch(url, { method: 'POST', headers: { 'content-type': 'application/ocsp-request' }, body: body.slice() });
 * ```
 *
 * The request is **unsigned**. RFC 6960 §4.1.2 makes the signature optional,
 * almost no responder requires it, and signing would mean this library holding
 * a key — which it does not do. A responder that answers `sigRequired` is
 * telling you to sign, and that is the caller's own `signData` call plus the
 * `[0] EXPLICIT Signature` wrapper.
 *
 * @param certificate The certificate being asked about.
 * @param issuer      The certificate that issued it.
 * @param options     See {@link CreateOcspRequestOptions}.
 * @returns The encoded `OCSPRequest`, ready to POST.
 * @throws {PkiError} `PKI_INVALID_INPUT` when either certificate is not parsed,
 *   or the nonce is not bytes; `PKI_INVALID_OPTION` for options that are not an object.
 */
export function createOcspRequest(certificate: Certificate, issuer: Certificate, options?: CreateOcspRequestOptions): Uint8Array {
    assertOptions(options, 'options');
    const certId = encodeOcspCertId(certificate, issuer, options?.hashAlgorithm ?? 'SHA-1');
    const requestList = encodeSequence([encodeSequence([certId])]);

    const fields: Uint8Array[] = [requestList];
    const nonce = options?.nonce;
    if (nonce !== undefined) {
        if (!isBytes(nonce)) {
            throw new PkiError('PKI_INVALID_INPUT', 'pkinative: the OCSP nonce must be a Uint8Array of random bytes — pkinative generates none, so this is yours to produce with crypto.getRandomValues');
        }
        // RFC 9654 §2.1 — which obsoletes RFC 8954, where the bound was 32 — types the nonce as 1 to 128 octets.
        // This writer keeps to the 1 to 32 it has always written: a nonce a responder written to either RFC accepts,
        // and one whose echo this library's own checkOcspStatus reads back (review of 2026-10-04).
        if (nonce.length < 1 || nonce.length > 32) {
            throw new PkiError('PKI_API_MISUSE', `pkinative: the OCSP nonce must be 1 to 32 octets, got ${String(nonce.length)} — RFC 9654 §2.1 allows up to 128, but 32 is the most a responder written to RFC 8954 accepts; 16 random octets is the usual choice`);
        }
        // requestExtensions [2] EXPLICIT Extensions, holding id-pkix-ocsp-nonce
        // (1.3.6.1.5.5.7.48.1.2). The nonce value is itself an OCTET STRING
        // inside the extension's OCTET STRING — two layers, and getting that
        // wrong is a nonce a responder silently ignores.
        fields.push(encodeTlv('context', 2, true, encodeSequence([
            encodeSequence([
                encodeTlv('universal', 6, false, Uint8Array.of(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02)),
                encodeOctetString(encodeOctetString(nonce)),
            ]),
        ])));
    }
    // version [0] takes its DEFAULT v1 and is omitted, as DER requires.
    return encodeSequence([encodeSequence(fields)]);
}

// ── Reading a request ────────────────────────────────────────────────

const OID_NONCE = '1.3.6.1.5.5.7.48.1.2';
/** RFC 9654 §2.1: `Nonce ::= OCTET STRING(SIZE(1..128))`. */
const NONCE_MAX_OCTETS = 128;

const fieldsOf = (der: Uint8Array, parent: TlvHeader, path: string, max: number): TlvHeader[] => _fieldsOf('OCSPRequest', der, parent, path, max);
const requestError = (path: string, offset: number, why: string): PkiCertificateError => _ocspError('OCSPRequest', path, offset, why);
const isSequence = (field: TlvHeader): boolean => field.tagClass === 'universal' && field.tagNumber === 16;
const isContext = (field: TlvHeader, tagNumber: number): boolean => field.tagClass === 'context' && field.tagNumber === tagNumber;

/**
 * Parse an `OCSPRequest` (RFC 6960 §4.1) — the request `createOcspRequest`
 * writes, or the one another client wrote.
 *
 * ```ts
 * const asked = parseOcspRequest(createOcspRequest(certificate, issuer, { nonce }));
 * for (const { certId } of asked.requests) console.log(certId.serialNumber.hex, asked.nonce);
 * ```
 *
 * It reads what is **asked**. pkinative is not a responder: nothing here
 * answers the request, and nothing verifies its signature — `signature`
 * exposes the algorithm, the value and the certificates of a signed request,
 * and `tbsDer` the bytes they cover, for a caller who does.
 *
 * `certIdDer` is each `CertID` exactly as encoded: compare it with
 * `encodeOcspCertId(certificate, issuer)` to know which certificate a
 * request is about without re-deriving the two hashes.
 *
 * The nonce (RFC 9654 §2.1, which obsoletes RFC 8954) is 1 to 128 octets. One
 * outside that range is returned as it is and reported: a responder must
 * refuse such a request, and this reader is not the responder.
 *
 * @param der     The complete OCSPRequest.
 * @param options Encoding rules, limits, diagnostics.
 * @returns The parsed request, with zero-copy views of `der`.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID` when the bytes are
 *   not an RFC 6960 OCSPRequest; `PKI_X509_EXTENSION_MALFORMED` when the nonce
 *   extension does not hold an OCTET STRING, or a recognised extension does
 *   not match its definition; `PKI_X509_GENERAL_NAME_INVALID` for a malformed
 *   `requestorName`.
 * @throws {PkiEncodingError} For any DER violation, `PKI_ASN1_TRAILING_DATA`
 *   for octets after the request included.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxInputBytes`,
 *   `maxOcspSingleResponses` (the `requestList`), `maxExtensions` or
 *   `maxChainLength` (the certificates of a signed request).
 * @throws {PkiError} `PKI_INVALID_INPUT` when `der` is not a Uint8Array;
 *   `PKI_STRICT_DIAGNOSTIC` under `strict: true`.
 */
export function parseOcspRequest(der: Uint8Array, options?: PkiParseOptions): OcspRequest {
    der = assertBytes(der, 'parseOcspRequest input');
    const ctx = createAsn1Context(options);
    enforceLimit(ctx.limits, 'maxInputBytes', der.length, 'the input size');
    const outer = readTlvHeader(der, 0, 'OCSPRequest');
    if (!isSequence(outer)) throw requestError('OCSPRequest', 0, 'is not a SEQUENCE');
    if (outer.end !== der.length) {
        throw new PkiEncodingError('PKI_ASN1_TRAILING_DATA',
            `pkinative: OCSPRequest is followed by ${String(der.length - outer.end)} octet(s) that are not part of it — pass the request alone, as it was POSTed`, outer.end);
    }
    const parts = fieldsOf(der, outer, 'OCSPRequest', 2);
    const tbs = parts[0];
    if (tbs === undefined || !isSequence(tbs)) throw requestError('OCSPRequest.tbsRequest', outer.offset, 'is missing or not a SEQUENCE');
    const body = readTbsRequest(der, tbs, ctx);

    // optionalSignature [0] EXPLICIT Signature.
    const signatureField = parts[1];
    let signature: OcspRequestSignature | undefined;
    if (signatureField !== undefined) {
        if (!isContext(signatureField, 0)) throw requestError('OCSPRequest.optionalSignature', signatureField.offset, 'is not [0] EXPLICIT');
        signature = readSignature(der, signatureField, ctx);
        // RFC 6960 §4.1.2: "If the request is signed, the requestor SHALL
        // specify its name in the requestorName field."
        if (body.requestorName === undefined) ctx.emitter.emit(ocspRequestSignedUnnamedDiagnostic(signatureField.offset));
    }

    return Object.freeze({
        der,
        tbsDer: der.subarray(tbs.offset, tbs.end),
        version: 1,
        requestorName: body.requestorName,
        requests: body.requests,
        extensions: body.extensions,
        nonce: body.nonce,
        signature,
        diagnostics: Object.freeze([...ctx.emitter.diagnostics]),
    });
}

interface TbsRequest {
    readonly requestorName: GeneralName | undefined;
    readonly requests: readonly OcspRequestEntry[];
    readonly extensions: readonly Extension[];
    readonly nonce: Uint8Array | undefined;
}

/**
 * `TBSRequest ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1,
 * requestorName [1] EXPLICIT GeneralName OPTIONAL, requestList SEQUENCE OF
 * Request, requestExtensions [2] EXPLICIT Extensions OPTIONAL }`.
 */
function readTbsRequest(der: Uint8Array, tbs: TlvHeader, ctx: Asn1Context): TbsRequest {
    const fields = fieldsOf(der, tbs, 'TBSRequest', 4);
    let at = 0;
    const versionField = fields[at];
    if (versionField !== undefined && isContext(versionField, 0)) {
        _readOcspVersion('OCSPRequest', der, versionField, ctx, 'TBSRequest.version');
        at += 1;
    }

    let requestorName: GeneralName | undefined;
    const nameField = fields[at];
    if (nameField !== undefined && isContext(nameField, 1)) {
        const inner = fieldsOf(der, nameField, 'TBSRequest.requestorName', 1)[0];
        if (inner === undefined) throw requestError('TBSRequest.requestorName', nameField.offset, 'is empty');
        requestorName = _readGeneralName(_decodeAt(der, inner, ctx), ctx, 'TBSRequest.requestorName', false);
        at += 1;
    }

    const listField = fields[at];
    if (listField === undefined || !isSequence(listField)) throw requestError('TBSRequest.requestList', tbs.offset, 'is missing or not a SEQUENCE');
    at += 1;
    const requests: OcspRequestEntry[] = [];
    for (const entry of walkChildren(der, listField, 'TBSRequest.requestList')) {
        const where = `TBSRequest.requestList[${String(requests.length)}]`;
        // Charged before each Request is read, so nothing is kept past the bound.
        enforceLimit(ctx.limits, 'maxOcspSingleResponses', requests.length + 1, where);
        requests.push(readRequest(der, entry, ctx, where));
    }

    let extensions: readonly Extension[] = Object.freeze([]);
    let nonce: Uint8Array | undefined;
    const extensionsField = fields[at];
    if (extensionsField !== undefined) {
        // Whatever follows the requestList is the requestExtensions, and it is last.
        if (!isContext(extensionsField, 2) || fields[at + 1] !== undefined) {
            throw requestError('TBSRequest', extensionsField.offset, 'holds a field TBSRequest does not define, or holds its fields twice or out of order');
        }
        extensions = readRequestExtensions(der, extensionsField, ctx, 'TBSRequest.requestExtensions');
        nonce = readNonce(der, extensions, ctx);
    }
    return { requestorName, requests: Object.freeze(requests), extensions, nonce };
}

/** `Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }`. */
function readRequest(der: Uint8Array, entry: TlvHeader, ctx: Asn1Context, path: string): OcspRequestEntry {
    if (!isSequence(entry)) throw requestError(path, entry.offset, 'is not a SEQUENCE');
    const fields = fieldsOf(der, entry, path, 2);
    const idField = fields[0];
    if (idField === undefined || !isSequence(idField)) throw requestError(`${path}.reqCert`, entry.offset, 'is missing or not a SEQUENCE');
    const extensionsField = fields[1];
    if (extensionsField !== undefined && !isContext(extensionsField, 0)) {
        throw requestError(`${path}.singleRequestExtensions`, extensionsField.offset, 'is not [0] EXPLICIT');
    }
    return Object.freeze({
        certId: _readCertId('OCSPRequest', der, idField, ctx, `${path}.reqCert`),
        certIdDer: der.subarray(idField.offset, idField.end),
        extensions: extensionsField === undefined ? Object.freeze([]) : readRequestExtensions(der, extensionsField, ctx, `${path}.singleRequestExtensions`),
    });
}

/**
 * The extensions of a request, or of one `Request` in it.
 *
 * RFC 6960 §4.1.2 says of them: "The critical flag SHOULD NOT be set for any
 * of them." One that sets it is read all the same, and said — beside the
 * diagnostic the extension reader raises when it is also one nobody here
 * recognises, which is the case §4.1.2 lets a responder refuse.
 */
function readRequestExtensions(der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): readonly Extension[] {
    const extensions = _readExtensions('OCSPRequest', der, field, ctx, path);
    for (const [index, extension] of extensions.entries()) {
        if (extension.critical) ctx.emitter.emit(ocspRequestExtensionCriticalDiagnostic(extension.oid, `${path}[${String(index)}]`));
    }
    return extensions;
}

/**
 * The nonce of `requestExtensions`, when there is one.
 *
 * `id-pkix-ocsp-nonce` holds an OCTET STRING inside the extension's own OCTET
 * STRING — two layers, and the value is the inner one's content. Anything
 * else in that place is not a nonce a responder could echo, so it is refused
 * rather than returned as if it were.
 */
function readNonce(der: Uint8Array, extensions: readonly Extension[], ctx: Asn1Context): Uint8Array | undefined {
    const index = extensions.findIndex((extension) => extension.oid === OID_NONCE);
    const extension = extensions[index];
    if (extension === undefined) return undefined;
    const path = `TBSRequest.requestExtensions[${String(index)}]`;
    const value = extension.valueDer;
    // Where the value sits in the request: `valueDer` is a view of `der`.
    const offset = value.byteOffset - der.byteOffset;
    let header: TlvHeader;
    try {
        header = readTlvHeader(value, 0, path);
    } catch (error) {
        throw nonceError(path, offset, `is not DER (${_pkiError(error).code})`);
    }
    if (header.tagClass !== 'universal' || header.tagNumber !== 4 || header.end !== value.length) {
        throw nonceError(path, offset, 'is not one OCTET STRING');
    }
    const nonce = value.subarray(header.contentStart, header.end);
    if (nonce.length < 1 || nonce.length > NONCE_MAX_OCTETS) ctx.emitter.emit(ocspNonceLengthDiagnostic(nonce.length, path, offset));
    return nonce;
}

function nonceError(path: string, offset: number, why: string): PkiCertificateError {
    return new PkiCertificateError('PKI_X509_EXTENSION_MALFORMED',
        `pkinative: ${path} is id-pkix-ocsp-nonce and its value ${why} — RFC 9654 §2.1 defines the nonce as an OCTET STRING inside the extnValue`, path, offset);
}

/**
 * `Signature ::= SEQUENCE { signatureAlgorithm AlgorithmIdentifier, signature
 * BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }`, under the
 * `[0] EXPLICIT` of `optionalSignature`.
 *
 * Read, never verified: the certificates are **attached, not trusted**, as
 * those of a response are.
 */
function readSignature(der: Uint8Array, field: TlvHeader, ctx: Asn1Context): OcspRequestSignature {
    const wrapper = fieldsOf(der, field, 'OCSPRequest.optionalSignature', 1)[0];
    if (wrapper === undefined || !isSequence(wrapper)) throw requestError('OCSPRequest.optionalSignature', field.offset, 'does not hold a Signature');
    const parts = fieldsOf(der, wrapper, 'Signature', 3);
    const algorithmField = parts[0];
    const signatureField = parts[1];
    if (algorithmField === undefined || signatureField === undefined) {
        throw requestError('Signature', wrapper.offset, 'holds fewer than the two required fields');
    }
    const signatureNode = _decodeAt(der, signatureField, ctx);
    if (signatureNode.tagClass !== 'universal' || signatureNode.tagNumber !== 3) {
        throw requestError('Signature.signature', signatureField.offset, 'is not a BIT STRING');
    }

    const certificates: Uint8Array[] = [];
    const certsField = parts[2];
    if (certsField !== undefined) {
        if (!isContext(certsField, 0)) throw requestError('Signature.certs', certsField.offset, 'is not [0] EXPLICIT');
        const list = fieldsOf(der, certsField, 'Signature.certs', 1)[0];
        if (list === undefined || !isSequence(list)) throw requestError('Signature.certs', certsField.offset, 'does not hold a SEQUENCE OF Certificate');
        // Walked lazily: the limit is charged before each certificate is kept.
        for (const certificate of walkChildren(der, list, 'Signature.certs')) {
            enforceLimit(ctx.limits, 'maxChainLength', certificates.length + 1, 'Signature.certs');
            certificates.push(der.subarray(certificate.offset, certificate.end));
        }
    }
    return Object.freeze({
        signatureAlgorithm: _readAlgorithmIdentifier(_decodeAt(der, algorithmField, ctx), ctx, 'Signature.signatureAlgorithm', _OCSP_STRUCTURE, wrapper.offset),
        signatureValue: _readBitString(signatureNode, ctx),
        certificates: Object.freeze(certificates),
    });
}
