/**
 * pkinative — X.509 certificate
 * =============================
 * RFC 5280 §4.1: the Certificate envelope and every TBSCertificate field.
 * A structural violation of the ASN.1 module throws `PkiCertificateError`;
 * a profile violation real issuers commit is a diagnostic, recorded on
 * `certificate.diagnostics`. Recognised extensions are decoded
 * (x509-extensions.ts) unless `decodeExtensions: false` keeps them raw.
 *
 * Parsing reads; it does not verify the signature and does not validate a
 * chain.
 *
 * @module x509/x509-certificate
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString, _readBoolean, _readInteger, _readOctetString } from '../asn1/asn1-read.js';
import {
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_GENERALIZED_TIME,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_UTC_TIME,
    tagLabel,
} from '../asn1/asn1-tags.js';
import { _readTime } from '../asn1/asn1-time.js';
import { assertBytes, bytesEqual, toHex } from '../core/bytes.js';
import {
    defaultEncodedDiagnostic,
    emptyIssuerDiagnostic,
    emptySubjectSanNotCriticalDiagnostic,
    extensionsRequireV3Diagnostic,
    generalizedTimeBefore2050Diagnostic,
    generalizedTimeFractionDiagnostic,
    serialNotPositiveDiagnostic,
    serialTooLongDiagnostic,
    signatureAlgorithmMismatchDiagnostic,
    uniqueIdRequiresV2Diagnostic,
    validityInvertedDiagnostic,
} from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, BitString, PkiTime } from '../types/asn1-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { Certificate, Extension, ParseCertificateOptions, RawExtension, SerialNumber, Validity } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from './x509-algorithm.js';
import { _decodeExtension } from './x509-extensions.js';
import { certificateError, expectUniversalField } from './x509-fields.js';
import { _readName } from './x509-name.js';
import { _readSubjectPublicKeyInfo } from './x509-spki.js';

const STRUCTURE = 'PKI_X509_STRUCTURE_INVALID';
const OID_SUBJECT_ALT_NAME = '2.5.29.17';
const NO_EXTENSIONS: readonly Extension[] = /*#__PURE__*/ Object.freeze([]);

// ── TBSCertificate fields ────────────────────────────────────────────

function readVersion(field: Asn1Node, ctx: Asn1Context): 1 | 2 | 3 {
    const path = 'tbsCertificate.version';
    if (!field.constructed || field.children.length !== 1) {
        throw certificateError(STRUCTURE, path, field.offset, 'is not one INTEGER under the explicit [0] tag');
    }
    const node = expectUniversalField(field.children[0], TAG_INTEGER, path, STRUCTURE, field.offset);
    const value = _readInteger(node, ctx);
    if (value !== 0n && value !== 1n && value !== 2n) {
        throw certificateError('PKI_X509_VERSION_INVALID', path, node.offset, `is ${String(value)}; RFC 5280 defines v1 (0), v2 (1) and v3 (2)`);
    }
    if (value === 0n) ctx.emitter.emit(defaultEncodedDiagnostic(path, 'v1', field.offset));
    return (Number(value) + 1) as 1 | 2 | 3;
}

function readValidityTime(node: Asn1Node, ctx: Asn1Context, path: string): PkiTime {
    if (node.tagClass !== 'universal' || (node.tagNumber !== TAG_UTC_TIME && node.tagNumber !== TAG_GENERALIZED_TIME)) {
        throw certificateError('PKI_X509_VALIDITY_INVALID', path, node.offset, `is ${tagLabel(node.tagClass, node.tagNumber)}; a certificate time is a UTCTime or a GeneralizedTime`);
    }
    const time = _readTime(node, ctx, undefined);
    if (time.type === 'GeneralizedTime') {
        if (Number(time.text.slice(0, 4)) < 2050) ctx.emitter.emit(generalizedTimeBefore2050Diagnostic(path, time.text, node.offset));
        if (/[.,]/.test(time.text)) ctx.emitter.emit(generalizedTimeFractionDiagnostic(path, time.text, node.offset));
    }
    return time;
}

function readValidity(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): Validity {
    const path = 'tbsCertificate.validity';
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, 'PKI_X509_VALIDITY_INVALID', parentOffset);
    if (seq.children.length !== 2) {
        throw certificateError('PKI_X509_VALIDITY_INVALID', path, seq.offset, `holds ${seq.children.length} values; Validity is notBefore and notAfter`);
    }
    const notBefore = readValidityTime(seq.children[0] as Asn1Node, ctx, `${path}.notBefore`);
    const notAfter = readValidityTime(seq.children[1] as Asn1Node, ctx, `${path}.notAfter`);
    if (notBefore.epochMilliseconds > notAfter.epochMilliseconds) ctx.emitter.emit(validityInvertedDiagnostic(notBefore.text, notAfter.text));
    const validity: Validity = { notBefore, notAfter };
    return Object.freeze(validity);
}

function readExtensions(field: Asn1Node, ctx: Asn1Context, input: Uint8Array, decode: boolean): readonly Extension[] {
    const path = 'tbsCertificate.extensions';
    if (!field.constructed || field.children.length !== 1) {
        throw certificateError(STRUCTURE, path, field.offset, 'is not one SEQUENCE under the explicit [3] tag');
    }
    const seq = expectUniversalField(field.children[0], TAG_SEQUENCE, path, STRUCTURE, field.offset);
    if (seq.children.length === 0) {
        throw certificateError('PKI_X509_EXTENSIONS_EMPTY', path, seq.offset, 'is present but holds no extension; RFC 5280 requires at least one');
    }
    enforceLimit(ctx.limits, 'maxExtensions', seq.children.length, 'the extensions of the certificate');
    const seen = new Set<string>();
    const extensions: Extension[] = [];
    for (let i = 0; i < seq.children.length; i++) {
        const extPath = `${path}[${i}]`;
        const ext = expectUniversalField(seq.children[i], TAG_SEQUENCE, extPath, STRUCTURE, seq.offset);
        if (ext.children.length < 2 || ext.children.length > 3) {
            throw certificateError(STRUCTURE, extPath, ext.offset, `holds ${ext.children.length} values; an Extension is extnID, an optional critical flag and extnValue`);
        }
        const oid = _readObjectIdentifier(expectUniversalField(ext.children[0], TAG_OID, `${extPath}.extnID`, STRUCTURE, ext.offset), ctx);
        let critical = false;
        if (ext.children.length === 3) {
            const flag = expectUniversalField(ext.children[1], TAG_BOOLEAN, `${extPath}.critical`, STRUCTURE, ext.offset);
            critical = _readBoolean(flag, ctx);
            if (!critical) ctx.emitter.emit(defaultEncodedDiagnostic(`${extPath}.critical`, 'FALSE', flag.offset));
        }
        const valueNode = expectUniversalField(ext.children[ext.children.length - 1], TAG_OCTET_STRING, `${extPath}.extnValue`, STRUCTURE, ext.offset);
        const valueDer = _readOctetString(valueNode, ctx);
        if (seen.has(oid)) {
            throw certificateError('PKI_X509_EXTENSION_DUPLICATE', extPath, ext.offset, `repeats the extension ${oid}; RFC 5280 §4.2 allows each extension once`);
        }
        seen.add(oid);
        if (!decode) {
            const extension: RawExtension = { kind: 'raw', oid, critical, valueDer };
            extensions.push(Object.freeze(extension));
        } else if (valueNode.constructed) {
            // A BER segmented extnValue was joined into a copy: decode the copy.
            extensions.push(_decodeExtension(valueDer, 0, oid, critical, valueDer, ctx, extPath));
        } else {
            const start = valueNode.offset + valueNode.headerLength;
            extensions.push(_decodeExtension(input.subarray(0, start + valueNode.contentLength), start, oid, critical, valueDer, ctx, extPath));
        }
    }
    return Object.freeze(extensions);
}

// ── Certificate ──────────────────────────────────────────────────────

/**
 * Parse a DER-encoded X.509 certificate (RFC 5280 §4.1). Parsing checks the
 * structure and records profile concerns as diagnostics; it does not verify
 * the signature and does not validate a chain.
 *
 * @param der     The certificate encoding. The result holds zero-copy views of it: do not mutate it while you use the result.
 * @param options Encoding rules (`'der'` by default), limits, `strict`, `onDiagnostic` and `decodeExtensions` (default `true`).
 * @returns The frozen certificate, with every diagnostic of the parse on `diagnostics`.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID`, `PKI_X509_VERSION_INVALID`, `PKI_X509_NAME_INVALID`,
 *   `PKI_X509_VALIDITY_INVALID`, `PKI_X509_SPKI_INVALID`, `PKI_X509_UNIQUE_ID_INVALID`, `PKI_X509_EXTENSIONS_EMPTY`,
 *   `PKI_X509_EXTENSION_DUPLICATE`, `PKI_X509_EXTENSION_MALFORMED` or `PKI_X509_GENERAL_NAME_INVALID`
 *   when the DER is not an RFC 5280 certificate.
 * @throws {PkiEncodingError} For every X.690 violation (`PKI_ASN1_*`, `PKI_OID_INVALID`).
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond a configured limit.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a wrong argument; `PKI_STRICT_DIAGNOSTIC` under `strict: true`.
 */
export function parseCertificate(der: Uint8Array, options?: ParseCertificateOptions): Certificate {
    const bytes = assertBytes(der, 'parseCertificate input');
    const ctx = createAsn1Context(options);
    const decode = options?.decodeExtensions ?? true;
    if (typeof decode !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: decodeExtensions must be a boolean, got ${typeof decode}`);
    }
    const cert = expectUniversalField(decodeWithContext(bytes, ctx, false), TAG_SEQUENCE, 'certificate', STRUCTURE, 0);
    if (cert.children.length !== 3) {
        throw certificateError(STRUCTURE, 'certificate', cert.offset, `holds ${cert.children.length} values; a Certificate is tbsCertificate, signatureAlgorithm and signatureValue`);
    }
    const tbs = expectUniversalField(cert.children[0], TAG_SEQUENCE, 'tbsCertificate', STRUCTURE, cert.offset);
    const fields = tbs.children;
    let index = 0;

    let version: 1 | 2 | 3 = 1;
    const first = fields[0];
    if (first !== undefined && first.tagClass === 'context' && first.tagNumber === 0) {
        version = readVersion(first, ctx);
        index = 1;
    }

    const serialNode = expectUniversalField(fields[index++], TAG_INTEGER, 'tbsCertificate.serialNumber', STRUCTURE, tbs.offset);
    const serialValue = _readInteger(serialNode, ctx);
    if (serialNode.contentLength > 20) ctx.emitter.emit(serialTooLongDiagnostic(serialNode.contentLength, serialNode.offset));
    if (serialValue <= 0n) ctx.emitter.emit(serialNotPositiveDiagnostic(serialNode.offset));

    const tbsSignatureAlgorithm = _readAlgorithmIdentifier(fields[index++], ctx, 'tbsCertificate.signature', STRUCTURE, tbs.offset);
    const issuer = _readName(fields[index++], ctx, 'tbsCertificate.issuer', tbs.offset);
    if (issuer.rdns.length === 0) ctx.emitter.emit(emptyIssuerDiagnostic());
    const validity = readValidity(fields[index++], ctx, tbs.offset);
    const subject = _readName(fields[index++], ctx, 'tbsCertificate.subject', tbs.offset);
    const subjectPublicKeyInfo = _readSubjectPublicKeyInfo(fields[index++], ctx, 'tbsCertificate.subjectPublicKeyInfo', tbs.offset);

    let issuerUniqueId: BitString | undefined;
    let subjectUniqueId: BitString | undefined;
    let extensions = NO_EXTENSIONS;
    let extensionsPresent = false;
    let rank = 0;
    for (; index < fields.length; index++) {
        const field = fields[index] as Asn1Node;
        const tag = field.tagClass === 'context' ? field.tagNumber : -1;
        if (tag !== 1 && tag !== 2 && tag !== 3) {
            throw certificateError(STRUCTURE, `tbsCertificate[${index}]`, field.offset,
                `is ${tagLabel(field.tagClass, field.tagNumber)}, where only issuerUniqueID [1], subjectUniqueID [2] or extensions [3] may follow the public key`);
        }
        const path = tag === 1 ? 'tbsCertificate.issuerUniqueID' : tag === 2 ? 'tbsCertificate.subjectUniqueID' : 'tbsCertificate.extensions';
        if (tag <= rank) {
            throw certificateError(tag === 3 ? STRUCTURE : 'PKI_X509_UNIQUE_ID_INVALID', path, field.offset,
                'appears twice or out of order; TBSCertificate orders issuerUniqueID, subjectUniqueID, then extensions');
        }
        rank = tag;
        if (tag === 3) {
            extensions = readExtensions(field, ctx, bytes, decode);
            extensionsPresent = true;
            continue;
        }
        if (field.constructed && ctx.rules === 'der') {
            throw certificateError('PKI_X509_UNIQUE_ID_INVALID', path, field.offset, 'is constructed; a unique identifier is a primitive BIT STRING under its implicit tag');
        }
        const id = _readBitString(field, ctx);
        if (tag === 1) issuerUniqueId = id;
        else subjectUniqueId = id;
    }
    if ((issuerUniqueId !== undefined || subjectUniqueId !== undefined) && version === 1) ctx.emitter.emit(uniqueIdRequiresV2Diagnostic(version));
    if (extensionsPresent && version !== 3) ctx.emitter.emit(extensionsRequireV3Diagnostic(version));
    if (subject.rdns.length === 0 && extensions.find((e) => e.oid === OID_SUBJECT_ALT_NAME)?.critical !== true) {
        ctx.emitter.emit(emptySubjectSanNotCriticalDiagnostic());
    }

    const signatureAlgorithm = _readAlgorithmIdentifier(cert.children[1], ctx, 'signatureAlgorithm', STRUCTURE, cert.offset);
    if (!bytesEqual(signatureAlgorithm.der, tbsSignatureAlgorithm.der)) {
        ctx.emitter.emit(signatureAlgorithmMismatchDiagnostic(signatureAlgorithm.oid, tbsSignatureAlgorithm.oid));
    }
    const signatureValue = _readBitString(expectUniversalField(cert.children[2], TAG_BIT_STRING, 'signatureValue', STRUCTURE, cert.offset), ctx);

    const serialNumber: SerialNumber = { bytes: serialNode.content, hex: toHex(serialNode.content), value: serialValue };
    const certificate: Certificate = {
        der: cert.bytes,
        tbsDer: tbs.bytes,
        version,
        serialNumber: Object.freeze(serialNumber),
        signatureAlgorithm,
        tbsSignatureAlgorithm,
        signatureValue,
        issuer,
        validity,
        subject,
        subjectPublicKeyInfo,
        issuerUniqueId,
        subjectUniqueId,
        extensions,
        diagnostics: Object.freeze([...ctx.emitter.diagnostics]),
    };
    return Object.freeze(certificate);
}
