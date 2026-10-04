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
import { decodeValueAt } from '../asn1/asn1-decode.js';
import { readObjectIdentifier } from '../asn1/asn1-oid.js';
import { readInteger } from '../asn1/asn1-read.js';
import { _readTime } from '../asn1/asn1-time.js';
import { assertBytes, toHex } from '../core/bytes.js';
import { defaultEncodedDiagnostic, ocspCertsEmptyDiagnostic, ocspVersionNotV1Diagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node } from '../types/asn1-types.js';
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
import { PkiCertificateError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { Extension, SerialNumber } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from '../x509/x509-algorithm.js';
import { _decodeExtension } from '../x509/x509-extensions.js';

const STRUCTURE = 'PKI_X509_STRUCTURE_INVALID';
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

/**
 * The children of `parent`, refused past `max` — the most the field can hold by its ASN.1 definition,
 * which bounds the walk before anything is allocated (see the same helper in crl-parse.ts; review of 2026-10-04).
 */
function fieldsOf(der: Uint8Array, parent: TlvHeader, path: string, max: number): TlvHeader[] {
    const fields: TlvHeader[] = [];
    for (const field of walkChildren(der, parent, path)) {
        if (fields.length === max) throw ocspError(path, field.offset, `holds more than ${String(max)} values, where RFC 6960 §4.2.1 defines at most ${String(max)}`);
        fields.push(field);
    }
    return fields;
}

function ocspError(path: string, offset: number, why: string): PkiCertificateError {
    return new PkiCertificateError(STRUCTURE, `pkinative: ${path} ${why} — the input is not an RFC 6960 OCSPResponse`, path, offset);
}

const decodeAt = (der: Uint8Array, header: TlvHeader, ctx: Asn1Context): Asn1Node => decodeValueAt(der, header.offset, ctx);

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
        diagnostics: ctx.emitter.diagnostics,
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
        // One past the limit, so that `maxChainLength` below is the refusal a caller sees, not the shape.
        const entries = seq === undefined ? [] : fieldsOf(der, seq, 'BasicOCSPResponse.certs', ctx.limits.maxChainLength + 1);
        // RFC 6960 §4.2.1: "If no certificates are included, then certs SHOULD
        // be absent." Present and empty reads exactly as absent, and is said.
        if (entries.length === 0) ctx.emitter.emit(ocspCertsEmptyDiagnostic(certsField.offset));
        for (const certificate of entries) {
            enforceLimit(ctx.limits, 'maxChainLength', certificates.length + 1, 'BasicOCSPResponse.certs');
            certificates.push(der.subarray(certificate.offset, certificate.end));
        }
    }

    const data = readResponseData(der, tbs, ctx);
    return Object.freeze({
        tbsDer: der.subarray(tbs.offset, tbs.end),
        responderId: data.responderId,
        producedAt: data.producedAt,
        responses: data.responses,
        signatureAlgorithm: _readAlgorithmIdentifier(decodeAt(der, algorithmField, ctx), ctx, 'BasicOCSPResponse.signatureAlgorithm', STRUCTURE, outer.offset),
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
        readVersion(der, fields[0], ctx);
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
    const extensions = extensionsField === undefined ? [] : readExtensions(der, extensionsField, ctx, 'ResponseData.responseExtensions');
    return { responderId, producedAt, responses: Object.freeze(responses), extensions };
}

/**
 * `version [0] EXPLICIT Version DEFAULT v1`, when the responder wrote it out.
 *
 * Two sentences meet here and neither refuses. Written as v1, the field
 * encodes its DEFAULT, which DER omits (X.690 §11.5): the same diagnostic a
 * certificate gets for an explicit v1. Written as anything else — another
 * value, or not the INTEGER the syntax calls for — it violates RFC 6960
 * §4.2.2.3, which defines v1 alone; the response is read with the v1 syntax
 * because there is no other, and the reader says so. Compared on the bytes,
 * not decoded: a version is one octet, and reading a stranger's INTEGER here
 * could only add a refusal where a diagnostic was promised.
 */
function readVersion(der: Uint8Array, field: TlvHeader, ctx: Asn1Context): void {
    const inner = fieldsOf(der, field, 'ResponseData.version', 1)[0];
    if (inner === undefined || inner.tagClass !== 'universal' || inner.tagNumber !== 2) {
        ctx.emitter.emit(ocspVersionNotV1Diagnostic('holds no INTEGER', field.offset));
        return;
    }
    const content = der.subarray(inner.contentStart, inner.end);
    if (content.length === 1 && content[0] === 0) {
        ctx.emitter.emit(defaultEncodedDiagnostic('ResponseData.version', 'v1 (0)', field.offset));
        return;
    }
    ctx.emitter.emit(ocspVersionNotV1Diagnostic(`declares the version 0x${toHex(content)}`, field.offset));
}

function readResponderId(der: Uint8Array, field: TlvHeader, ctx: Asn1Context): OcspResponderId {
    const inner = fieldsOf(der, field, 'ResponseData.responderID', 1)[0];
    if (inner === undefined) throw ocspError('ResponseData.responderID', field.offset, 'is empty');
    if (field.tagNumber === 1) return { kind: 'byName', nameDer: der.subarray(inner.offset, inner.end) };
    const node = decodeAt(der, inner, ctx);
    if (node.tagClass !== 'universal' || node.tagNumber !== 4) {
        throw ocspError('ResponseData.responderID', inner.offset, 'byKey is not an OCTET STRING');
    }
    return { kind: 'byKey', keyHash: node.content };
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
        extensions: extensionsField === undefined ? [] : readExtensions(der, extensionsField, ctx, `${path}.singleExtensions`),
    });
}

function readCertId(der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): OcspCertId {
    const parts = fieldsOf(der, field, path, 4);
    const [algorithmField, nameHashField, keyHashField, serialField] = parts;
    if (parts.length !== 4 || algorithmField === undefined || nameHashField === undefined || keyHashField === undefined || serialField === undefined) {
        throw ocspError(path, field.offset, `holds ${String(parts.length)} values where a CertID has four`);
    }
    const serialContent = der.subarray(serialField.contentStart, serialField.end);
    return Object.freeze({
        hashAlgorithm: _readAlgorithmIdentifier(decodeAt(der, algorithmField, ctx), ctx, `${path}.hashAlgorithm`, STRUCTURE, field.offset),
        issuerNameHash: decodeAt(der, nameHashField, ctx).content,
        issuerKeyHash: decodeAt(der, keyHashField, ctx).content,
        serialNumber: Object.freeze({
            bytes: serialContent,
            hex: toHex(serialContent),
            value: readInteger(decodeAt(der, serialField, ctx)),
        }) as SerialNumber,
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
    if (field.tagNumber === 0) return { kind: 'good' };
    if (field.tagNumber === 2) return { kind: 'unknown' };
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
    return { kind: 'revoked', revocationTime: _readTime(decodeAt(der, timeField, ctx), ctx, undefined), reason };
}

/**
 * A `[n] EXPLICIT Extensions` field.
 *
 * Every extensions field in RFC 6960 is explicitly tagged, so a bare SEQUENCE
 * here is refused rather than unwrapped one level short — which would read the
 * *extensions* as if they were the wrapper and hand back their innards.
 */
function readExtensions(der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): readonly Extension[] {
    if (field.tagClass !== 'context') throw ocspError(path, field.offset, 'is not a context-tagged Extensions field');
    const wrapper = fieldsOf(der, field, path, 1)[0];
    if (wrapper === undefined) return [];
    const out: Extension[] = [];
    let index = 0;
    for (const entry of walkChildren(der, wrapper, path)) {
        const where = `${path}[${String(index)}]`;
        enforceLimit(ctx.limits, 'maxExtensions', index + 1, where);
        const node = decodeAt(der, entry, ctx);
        const oidNode = node.children[0];
        const valueNode = node.children[node.children.length - 1];
        if (oidNode === undefined || valueNode === undefined || node.children.length < 2) {
            throw ocspError(where, entry.offset, 'is not an Extension');
        }
        const criticalNode = node.children.length === 3 ? node.children[1] : undefined;
        // `extnValue OCTET STRING` and `critical BOOLEAN` (RFC 5280 §4.1): any
        // other tag is not the wrapper the value is read out of, whatever its
        // content looks like — read as the certificate parser reads them.
        if (valueNode.tagClass !== 'universal' || valueNode.tagNumber !== 4) {
            throw ocspError(`${where}.extnValue`, valueNode.offset, 'is not an OCTET STRING, the extnValue RFC 5280 §4.1 defines');
        }
        if (criticalNode !== undefined && (criticalNode.tagClass !== 'universal' || criticalNode.tagNumber !== 1 || criticalNode.contentLength !== 1)) {
            throw ocspError(`${where}.critical`, criticalNode.offset, 'is not a BOOLEAN, the critical flag RFC 5280 §4.1 defines');
        }
        // In place, from a view that ends where the extnValue ends, starting at
        // its content — the only way the reader can tell trailing octets inside
        // the value from a well-formed one. The CRL parser shipped this wrong in
        // 0.5 and refused every list carrying a recognised extension; this
        // reader had the same mistake, hidden because the extension an OCSP
        // response usually carries — the nonce — is one the certificate reader
        // does not recognise and so never decodes.
        const start = valueNode.offset + valueNode.headerLength;
        out.push(_decodeExtension(
            der.subarray(0, start + valueNode.contentLength), start,
            readObjectIdentifier(oidNode),
            criticalNode !== undefined && criticalNode.content[0] !== 0x00,
            valueNode.content,
            ctx, where,
        ));
        index += 1;
    }
    return Object.freeze(out);
}

/** The OID of `cRLReason`, re-exported so a caller can find it on an extension. */
export const OCSP_CRL_REASON_OID = OID_CRL_REASON;
