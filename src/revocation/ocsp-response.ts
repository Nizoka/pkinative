/**
 * pkinative — RFC 6960 OCSP responses
 * ===================================
 * Read what a responder said, and keep its three answers apart.
 *
 * `good`, `revoked` and `unknown` are three states because RFC 6960 §2.2 makes
 * them three. `unknown` means the responder does not know about this
 * certificate — an absence of evidence, not a clean bill of health — and the
 * six non-`successful` response statuses are the responder declining to answer
 * at all. A client that reduced any of that to a boolean would report "I have
 * never heard of this serial" as "not revoked", which is the OCSP equivalent of
 * the soft-fail mistake `PKI_REASON_REVOCATION_UNKNOWN` exists to name.
 *
 * Nothing here verifies a signature and nothing here decides a status. Parsing
 * is parsing: `verifyOcspSignature` and `checkOcspStatus` are separate for the
 * same reason `parseCertificate` and `verifyCertificateSignature` are.
 *
 * @module revocation/ocsp-response
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { readTlvHeader, walkChildren, type TlvHeader } from '../asn1/asn1-cursor.js';
import { readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readTime } from '../asn1/asn1-time.js';
import { assertBytes } from '../core/bytes.js';
import { ocspCertsEmptyDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { CrlReason } from '../types/crl-types.js';
import type {
    OcspBasicResponse,
    OcspCertId,
    OcspCertStatus,
    OcspResponderId,
    OcspResponse,
    OcspResponseStatus,
    OcspSingleResponse,
} from '../types/ocsp-types.js';
import type { PkiCertificateError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { Extension } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from '../x509/x509-algorithm.js';
import { _OCSP_STRUCTURE, _decodeAt, _fieldsOf, _ocspError, _readCertId, _readExtensions, _readOcspVersion } from './ocsp-shared.js';

const OID_BASIC_RESPONSE = '1.3.6.1.5.5.7.48.1.1';
const OID_CRL_REASON = '2.5.29.21';

/** RFC 6960 §4.2.1: the six ways a responder declines, plus success. */
const STATUSES: Readonly<Record<number, OcspResponseStatus>> = Object.freeze({
    0: 'successful', 1: 'malformedRequest', 2: 'internalError',
    3: 'tryLater', 5: 'sigRequired', 6: 'unauthorized',
});

/** RFC 5280 §5.3.1, shared with CRL entries. Index 7 is unassigned. */
const REASONS: Readonly<Record<number, CrlReason>> = Object.freeze({
    0: 'unspecified', 1: 'keyCompromise', 2: 'cACompromise', 3: 'affiliationChanged',
    4: 'superseded', 5: 'cessationOfOperation', 6: 'certificateHold',
    8: 'removeFromCRL', 9: 'privilegeWithdrawn', 10: 'aACompromise',
});

// The shared readers, bound to the message this module reads: a refusal here names an OCSPResponse.
const fieldsOf = (der: Uint8Array, parent: TlvHeader, path: string, max: number): TlvHeader[] => _fieldsOf('OCSPResponse', der, parent, path, max);
const ocspError = (path: string, offset: number, why: string): PkiCertificateError => _ocspError('OCSPResponse', path, offset, why);
const decodeAt = _decodeAt;
const readCertId = (der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): OcspCertId => _readCertId('OCSPResponse', der, field, ctx, path);
const readExtensions = (der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): readonly Extension[] => _readExtensions('OCSPResponse', der, field, ctx, path);

/**
 * Parse an `OCSPResponse`.
 *
 * ```ts
 * const response = parseOcspResponse(bytes);
 * if (response.status !== 'successful') return `the responder declined: ${response.status}`;
 * for (const single of response.basicResponse?.responses ?? []) console.log(single.status.kind);
 * ```
 *
 * A non-`successful` status has **no** `basicResponse`, and that is the
 * protocol rather than this parser being careful: RFC 6960 §4.2.1 only carries
 * a response body on success. The six other statuses are the responder
 * declining, and each is a reason to look elsewhere rather than a statement
 * about any certificate.
 *
 * @param der     The complete OCSPResponse, as returned by a responder.
 * @param options Encoding rules, limits, diagnostics.
 * @returns The parsed response, with zero-copy views of `der`.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID` when the bytes are
 *   not an RFC 6960 OCSPResponse.
 * @throws {PkiEncodingError} For any DER violation.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxOcspSingleResponses` or `maxExtensions`.
 */
export function parseOcspResponse(der: Uint8Array, options?: PkiParseOptions): OcspResponse {
    der = assertBytes(der, 'parseOcspResponse input');
    const ctx = createAsn1Context(options);
    enforceLimit(ctx.limits, 'maxInputBytes', der.length, 'the input size');
    const outer = readTlvHeader(der, 0, 'OCSPResponse');
    if (!outer.constructed || outer.tagClass !== 'universal' || outer.tagNumber !== 16) {
        throw ocspError('OCSPResponse', 0, 'is not a SEQUENCE');
    }
    const parts = fieldsOf(der, outer, 'OCSPResponse', 2);
    const statusField = parts[0];
    if (statusField === undefined || statusField.tagClass !== 'universal' || statusField.tagNumber !== 10) {
        throw ocspError('OCSPResponse.responseStatus', outer.offset, 'is not an ENUMERATED');
    }
    if (statusField.length !== 1) {
        throw ocspError('OCSPResponse.responseStatus', statusField.offset, 'is wider than one octet; RFC 6960 defines seven values');
    }
    const code = der[statusField.contentStart] as number;
    const status = STATUSES[code];
    if (status === undefined) {
        throw ocspError('OCSPResponse.responseStatus', statusField.offset, `is ${String(code)}, which RFC 6960 §4.2.1 does not define (4 is unassigned)`);
    }

    // responseBytes [0] EXPLICIT, present only on success.
    const bytesField = parts[1];
    let basicResponse: OcspBasicResponse | undefined;
    if (bytesField !== undefined) {
        if (bytesField.tagClass !== 'context' || bytesField.tagNumber !== 0) {
            throw ocspError('OCSPResponse.responseBytes', bytesField.offset, 'is not [0] EXPLICIT');
        }
        basicResponse = readResponseBytes(der, bytesField, ctx);
    }
    if (status === 'successful' && basicResponse === undefined) {
        throw ocspError('OCSPResponse', outer.offset, 'says successful and carries no responseBytes; RFC 6960 §4.2.1 requires one');
    }
    if (status !== 'successful' && basicResponse !== undefined) {
        throw ocspError('OCSPResponse', outer.offset, `says ${status} and still carries responseBytes; only a successful response has a body`);
    }

    return Object.freeze({
        der: der.subarray(outer.offset, outer.end),
        status,
        basicResponse,
        diagnostics: Object.freeze([...ctx.emitter.diagnostics]),
    });
}

/** `ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }`. */
function readResponseBytes(der: Uint8Array, field: TlvHeader, ctx: Asn1Context): OcspBasicResponse {
    const wrapper = fieldsOf(der, field, 'OCSPResponse.responseBytes', 1)[0];
    if (wrapper === undefined) throw ocspError('OCSPResponse.responseBytes', field.offset, 'is empty');
    const inner = fieldsOf(der, wrapper, 'ResponseBytes', 2);
    const typeField = inner[0];
    const valueField = inner[1];
    if (typeField === undefined || valueField === undefined) {
        throw ocspError('ResponseBytes', wrapper.offset, 'does not hold a responseType and a response');
    }
    const responseType = readObjectIdentifier(decodeAt(der, typeField, ctx));
    if (responseType !== OID_BASIC_RESPONSE) {
        // Refused rather than ignored: a response type nobody here understands
        // is a response nobody here can read, and returning "no answer" for it
        // would look like `unknown` — a status, when it is an inability.
        throw ocspError('ResponseBytes.responseType', typeField.offset, `is ${responseType}; only id-pkix-ocsp-basic (${OID_BASIC_RESPONSE}) is defined by RFC 6960`);
    }
    const body = der.subarray(valueField.contentStart, valueField.end);
    return readBasicResponse(body, ctx);
}

/** `BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm, signature, certs [0] OPTIONAL }`. */
function readBasicResponse(der: Uint8Array, ctx: Asn1Context): OcspBasicResponse {
    const outer = readTlvHeader(der, 0, 'BasicOCSPResponse');
    const parts = fieldsOf(der, outer, 'BasicOCSPResponse', 4);
    const tbs = parts[0];
    const algorithmField = parts[1];
    const signatureField = parts[2];
    if (tbs === undefined || algorithmField === undefined || signatureField === undefined) {
        throw ocspError('BasicOCSPResponse', outer.offset, 'holds fewer than the three required fields');
    }
    const signatureNode = decodeAt(der, signatureField, ctx);
    if (signatureNode.tagClass !== 'universal' || signatureNode.tagNumber !== 3) {
        throw ocspError('BasicOCSPResponse.signature', signatureField.offset, 'is not a BIT STRING');
    }

    const certificates: Uint8Array[] = [];
    const certsField = parts[3];
    if (certsField !== undefined) {
        const seq = fieldsOf(der, certsField, 'BasicOCSPResponse.certs', 1)[0];
        // Walked lazily: the limit is charged before each certificate is kept, so nothing is allocated past it.
        if (seq !== undefined) {
            for (const certificate of walkChildren(der, seq, 'BasicOCSPResponse.certs')) {
                enforceLimit(ctx.limits, 'maxChainLength', certificates.length + 1, 'BasicOCSPResponse.certs');
                certificates.push(der.subarray(certificate.offset, certificate.end));
            }
        }
        // RFC 6960 §4.2.1: "If no certificates are included, then certs SHOULD
        // be absent." Present and empty reads exactly as absent, and is said.
        if (certificates.length === 0) ctx.emitter.emit(ocspCertsEmptyDiagnostic(certsField.offset));
    }

    const data = readResponseData(der, tbs, ctx);
    return Object.freeze({
        tbsDer: der.subarray(tbs.offset, tbs.end),
        responderId: data.responderId,
        producedAt: data.producedAt,
        responses: data.responses,
        signatureAlgorithm: _readAlgorithmIdentifier(decodeAt(der, algorithmField, ctx), ctx, 'BasicOCSPResponse.signatureAlgorithm', _OCSP_STRUCTURE, outer.offset),
        signatureValue: Object.freeze({ bytes: signatureNode.content.subarray(1), unusedBits: signatureNode.content[0] ?? 0 }),
        certificates: Object.freeze(certificates),
        extensions: data.extensions,
    });
}

interface ResponseData {
    readonly responderId: OcspResponderId;
    readonly producedAt: ReturnType<typeof _readTime>;
    readonly responses: readonly OcspSingleResponse[];
    readonly extensions: readonly Extension[];
}

/**
 * `ResponseData ::= SEQUENCE { version [0] DEFAULT v1, responderID, producedAt,
 * responses SEQUENCE OF SingleResponse, responseExtensions [1] OPTIONAL }`.
 */
function readResponseData(der: Uint8Array, tbs: TlvHeader, ctx: Asn1Context): ResponseData {
    const fields = fieldsOf(der, tbs, 'ResponseData', 5);
    let at = 0;
    // version [0] EXPLICIT is the only context-0 field here, and responderID
    // is context 1 or 2, so one tag test separates them.
    if (fields[0]?.tagClass === 'context' && fields[0].tagNumber === 0) {
        _readOcspVersion('OCSPResponse', der, fields[0], ctx, 'ResponseData.version');
        at += 1;
    }

    const idField = fields[at];
    if (idField === undefined || idField.tagClass !== 'context' || (idField.tagNumber !== 1 && idField.tagNumber !== 2)) {
        throw ocspError('ResponseData.responderID', tbs.offset, 'is neither byName [1] nor byKey [2]');
    }
    at += 1;
    const responderId = readResponderId(der, idField, ctx);

    const producedAtField = fields[at];
    if (producedAtField === undefined) throw ocspError('ResponseData.producedAt', tbs.offset, 'is missing');
    at += 1;
    const producedAt = _readTime(decodeAt(der, producedAtField, ctx), ctx, undefined);

    const responsesField = fields[at];
    if (responsesField === undefined || responsesField.tagClass !== 'universal' || responsesField.tagNumber !== 16) {
        throw ocspError('ResponseData.responses', tbs.offset, 'is not a SEQUENCE');
    }
    at += 1;
    const responses: OcspSingleResponse[] = [];
    let index = 0;
    for (const single of walkChildren(der, responsesField, 'ResponseData.responses')) {
        enforceLimit(ctx.limits, 'maxOcspSingleResponses', index + 1, `ResponseData.responses[${String(index)}]`);
        responses.push(readSingleResponse(der, single, ctx, `ResponseData.responses[${String(index)}]`));
        index += 1;
    }

    const extensionsField = fields[at];
    const extensions = extensionsField === undefined ? Object.freeze([]) : readExtensions(der, extensionsField, ctx, 'ResponseData.responseExtensions');
    return { responderId, producedAt, responses: Object.freeze(responses), extensions };
}

function readResponderId(der: Uint8Array, field: TlvHeader, ctx: Asn1Context): OcspResponderId {
    const inner = fieldsOf(der, field, 'ResponseData.responderID', 1)[0];
    if (inner === undefined) throw ocspError('ResponseData.responderID', field.offset, 'is empty');
    if (field.tagNumber === 1) return Object.freeze({ kind: 'byName', nameDer: der.subarray(inner.offset, inner.end) });
    const node = decodeAt(der, inner, ctx);
    if (node.tagClass !== 'universal' || node.tagNumber !== 4) {
        throw ocspError('ResponseData.responderID', inner.offset, 'byKey is not an OCTET STRING');
    }
    return Object.freeze({ kind: 'byKey', keyHash: node.content });
}

/**
 * `SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate,
 * nextUpdate [0] OPTIONAL, singleExtensions [1] OPTIONAL }`.
 */
function readSingleResponse(der: Uint8Array, single: TlvHeader, ctx: Asn1Context, path: string): OcspSingleResponse {
    const fields = fieldsOf(der, single, path, 5);
    const idField = fields[0];
    const statusField = fields[1];
    const thisUpdateField = fields[2];
    if (idField === undefined || statusField === undefined || thisUpdateField === undefined) {
        throw ocspError(path, single.offset, 'holds fewer than the three required fields');
    }
    let at = 3;
    let nextUpdate: ReturnType<typeof _readTime> | undefined;
    if (fields[at]?.tagClass === 'context' && fields[at]?.tagNumber === 0) {
        const inner = fieldsOf(der, fields[at] as TlvHeader, `${path}.nextUpdate`, 1)[0];
        if (inner !== undefined) nextUpdate = _readTime(decodeAt(der, inner, ctx), ctx, undefined);
        at += 1;
    }
    const extensionsField = fields[at];
    return Object.freeze({
        certId: readCertId(der, idField, ctx, `${path}.certID`),
        status: readCertStatus(der, statusField, ctx, `${path}.certStatus`),
        thisUpdate: _readTime(decodeAt(der, thisUpdateField, ctx), ctx, undefined),
        nextUpdate,
        extensions: extensionsField === undefined ? Object.freeze([]) : readExtensions(der, extensionsField, ctx, `${path}.singleExtensions`),
    });
}

/**
 * `CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT
 * RevokedInfo, unknown [2] IMPLICIT UnknownInfo }`.
 *
 * Three states, kept three. A parser that folded `unknown` into `good` — or
 * into an error — would be the place the whole protocol's safety is lost.
 */
function readCertStatus(der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): OcspCertStatus {
    if (field.tagClass !== 'context') throw ocspError(path, field.offset, 'is not a context-tagged CHOICE');
    if (field.tagNumber === 0) return Object.freeze({ kind: 'good' });
    if (field.tagNumber === 2) return Object.freeze({ kind: 'unknown' });
    if (field.tagNumber !== 1) throw ocspError(path, field.offset, `is [${String(field.tagNumber)}]; RFC 6960 defines [0] good, [1] revoked and [2] unknown`);

    // RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime,
    //                            revocationReason [0] EXPLICIT CRLReason OPTIONAL }
    const parts = fieldsOf(der, field, path, 2);
    const timeField = parts[0];
    if (timeField === undefined) throw ocspError(path, field.offset, 'is revoked and carries no revocationTime');
    let reason: CrlReason | undefined;
    const reasonField = parts[1];
    if (reasonField !== undefined && reasonField.tagClass === 'context' && reasonField.tagNumber === 0) {
        const inner = fieldsOf(der, reasonField, `${path}.revocationReason`, 1)[0];
        if (inner !== undefined && inner.length === 1) reason = REASONS[der[inner.contentStart] as number];
    }
    return Object.freeze({ kind: 'revoked', revocationTime: _readTime(decodeAt(der, timeField, ctx), ctx, undefined), reason });
}

/** The OID of `cRLReason`, re-exported so a caller can find it on an extension. */
export const OCSP_CRL_REASON_OID = OID_CRL_REASON;
