/**
 * pkinative — RFC 6960, what a request and a response share
 * =========================================================
 * The readers both OCSP messages are made of: the bounded walk of a field's
 * values, the `version` each may write out, the `CertID` that names a
 * certificate in a question and in its answer, and the explicitly tagged
 * `Extensions` field.
 *
 * They live here, and not in either reader, for the reason the `CertID` is
 * one type: a client matches an answer to its question by comparing the two,
 * and two readers that decoded it differently would be two opinions about
 * which certificate was meant. A refusal names the message it was found in —
 * an `OCSPRequest` or an `OCSPResponse` — so the caller of one reader is never
 * told about the other.
 *
 * @module revocation/ocsp-shared
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { walkChildren, type TlvHeader } from '../asn1/asn1-cursor.js';
import { decodeValueAt } from '../asn1/asn1-decode.js';
import { readObjectIdentifier } from '../asn1/asn1-oid.js';
import { readInteger } from '../asn1/asn1-read.js';
import { toHex } from '../core/bytes.js';
import { defaultEncodedDiagnostic, ocspVersionNotV1Diagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type { OcspCertId } from '../types/ocsp-types.js';
import { PkiCertificateError } from '../types/pki-errors.js';
import type { Extension, SerialNumber } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from '../x509/x509-algorithm.js';
import { _decodeExtension } from '../x509/x509-extensions.js';

/** The code of every structural refusal of an OCSP message. */
export const _OCSP_STRUCTURE = 'PKI_X509_STRUCTURE_INVALID';

/** Which of the two RFC 6960 messages is being read. */
export type _OcspMessage = 'OCSPRequest' | 'OCSPResponse';

/** The section that defines each message's syntax, for the refusals that count its fields. */
const SYNTAX: Readonly<Record<_OcspMessage, string>> = /*#__PURE__*/ Object.freeze({
    OCSPRequest: '§4.1.1',
    OCSPResponse: '§4.2.1',
});

/**
 * The refusal of one field of an OCSP message.
 *
 * @internal
 */
export function _ocspError(message: _OcspMessage, path: string, offset: number, why: string): PkiCertificateError {
    return new PkiCertificateError(_OCSP_STRUCTURE, `pkinative: ${path} ${why} — the input is not an RFC 6960 ${message}`, path, offset);
}

/**
 * The children of `parent`, refused past `max` — the most the field can hold by its ASN.1 definition,
 * which bounds the walk before anything is allocated (see the same helper in crl-parse.ts; review of 2026-10-04).
 *
 * @internal
 */
export function _fieldsOf(message: _OcspMessage, der: Uint8Array, parent: TlvHeader, path: string, max: number): TlvHeader[] {
    const fields: TlvHeader[] = [];
    for (const field of walkChildren(der, parent, path)) {
        if (fields.length === max) throw _ocspError(message, path, field.offset, `holds more than ${String(max)} values, where RFC 6960 ${SYNTAX[message]} defines at most ${String(max)}`);
        fields.push(field);
    }
    return fields;
}

/**
 * The node of the value a cursor header points at.
 *
 * @internal
 */
export const _decodeAt = (der: Uint8Array, header: TlvHeader, ctx: Asn1Context): Asn1Node => decodeValueAt(der, header.offset, ctx);

/**
 * `version [0] EXPLICIT Version DEFAULT v1`, when the sender wrote it out —
 * the first field of a `ResponseData` and of a `TBSRequest` alike.
 *
 * Two sentences meet here and neither refuses. Written as v1, the field
 * encodes its DEFAULT, which DER omits (X.690 §11.5): the same diagnostic a
 * certificate gets for an explicit v1. Written as anything else — another
 * value, or not the INTEGER the syntax calls for — it violates RFC 6960,
 * which defines v1 alone; the message is read with the v1 syntax because
 * there is no other, and the reader says so. Compared on the bytes, not
 * decoded: a version is one octet, and reading a stranger's INTEGER here
 * could only add a refusal where a diagnostic was promised.
 *
 * @internal
 */
export function _readOcspVersion(message: _OcspMessage, der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): void {
    const inner = _fieldsOf(message, der, field, path, 1)[0];
    if (inner === undefined || inner.tagClass !== 'universal' || inner.tagNumber !== 2) {
        ctx.emitter.emit(ocspVersionNotV1Diagnostic('holds no INTEGER', field.offset, path));
        return;
    }
    const content = der.subarray(inner.contentStart, inner.end);
    if (content.length === 1 && content[0] === 0) {
        ctx.emitter.emit(defaultEncodedDiagnostic(path, 'v1 (0)', field.offset));
        return;
    }
    ctx.emitter.emit(ocspVersionNotV1Diagnostic(`declares the version 0x${toHex(content)}`, field.offset, path));
}

/**
 * `CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }` (RFC 6960 §4.1.1).
 *
 * @internal
 */
export function _readCertId(message: _OcspMessage, der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): OcspCertId {
    const parts = _fieldsOf(message, der, field, path, 4);
    const [algorithmField, nameHashField, keyHashField, serialField] = parts;
    if (parts.length !== 4 || algorithmField === undefined || nameHashField === undefined || keyHashField === undefined || serialField === undefined) {
        throw _ocspError(message, path, field.offset, `holds ${String(parts.length)} values where a CertID has four`);
    }
    const serialContent = der.subarray(serialField.contentStart, serialField.end);
    return Object.freeze({
        hashAlgorithm: _readAlgorithmIdentifier(_decodeAt(der, algorithmField, ctx), ctx, `${path}.hashAlgorithm`, _OCSP_STRUCTURE, field.offset),
        issuerNameHash: _decodeAt(der, nameHashField, ctx).content,
        issuerKeyHash: _decodeAt(der, keyHashField, ctx).content,
        serialNumber: Object.freeze({
            bytes: serialContent,
            hex: toHex(serialContent),
            value: readInteger(_decodeAt(der, serialField, ctx)),
        }) as SerialNumber,
    });
}

/**
 * A `[n] EXPLICIT Extensions` field.
 *
 * Every extensions field in RFC 6960 is explicitly tagged, so a bare SEQUENCE
 * here is refused rather than unwrapped one level short — which would read the
 * *extensions* as if they were the wrapper and hand back their innards.
 *
 * @internal
 */
export function _readExtensions(message: _OcspMessage, der: Uint8Array, field: TlvHeader, ctx: Asn1Context, path: string): readonly Extension[] {
    if (field.tagClass !== 'context') throw _ocspError(message, path, field.offset, 'is not a context-tagged Extensions field');
    const wrapper = _fieldsOf(message, der, field, path, 1)[0];
    if (wrapper === undefined) return Object.freeze([]);
    const out: Extension[] = [];
    let index = 0;
    for (const entry of walkChildren(der, wrapper, path)) {
        const where = `${path}[${String(index)}]`;
        enforceLimit(ctx.limits, 'maxExtensions', index + 1, where);
        const node = _decodeAt(der, entry, ctx);
        const oidNode = node.children[0];
        const valueNode = node.children[node.children.length - 1];
        if (oidNode === undefined || valueNode === undefined || node.children.length < 2) {
            throw _ocspError(message, where, entry.offset, 'is not an Extension');
        }
        const criticalNode = node.children.length === 3 ? node.children[1] : undefined;
        // `extnValue OCTET STRING` and `critical BOOLEAN` (RFC 5280 §4.1): any
        // other tag is not the wrapper the value is read out of, whatever its
        // content looks like — read as the certificate parser reads them.
        if (valueNode.tagClass !== 'universal' || valueNode.tagNumber !== 4) {
            throw _ocspError(message, `${where}.extnValue`, valueNode.offset, 'is not an OCTET STRING, the extnValue RFC 5280 §4.1 defines');
        }
        if (criticalNode !== undefined && (criticalNode.tagClass !== 'universal' || criticalNode.tagNumber !== 1 || criticalNode.contentLength !== 1)) {
            throw _ocspError(message, `${where}.critical`, criticalNode.offset, 'is not a BOOLEAN, the critical flag RFC 5280 §4.1 defines');
        }
        // In place, from a view that ends where the extnValue ends, starting at
        // its content — the only way the reader can tell trailing octets inside
        // the value from a well-formed one. The CRL parser shipped this wrong in
        // 0.5 and refused every list carrying a recognised extension; this
        // reader had the same mistake, hidden because the extension an OCSP
        // message usually carries — the nonce — is one the certificate reader
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
