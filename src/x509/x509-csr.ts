/**
 * pkinative — PKCS#10 certification request
 * =========================================
 * RFC 2986 §4: the CertificationRequest envelope and every
 * CertificationRequestInfo field, read with the same readers that read a
 * certificate — the name, the public key, the algorithm identifier and the
 * extensions requested through the PKCS#9 `extensionRequest` attribute
 * (RFC 2985 §5.4.2). What `createCertificationRequest` writes, this reads
 * back with zero diagnostics; that is the one rule holding `build/` and
 * `x509/` together.
 *
 * Parsing reads; it does not verify the signature. A request is a proof of
 * possession — the signature is made with the private half of the key it
 * carries — and `verifyCertificationRequest` is the call that checks it.
 *
 * @module x509/x509-csr
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString, _readInteger, _readString } from '../asn1/asn1-read.js';
import { TAG_BIT_STRING, TAG_INTEGER, TAG_OID, TAG_SEQUENCE, TAG_SET, stringTypeOfTag, tagLabel } from '../asn1/asn1-tags.js';
import { assertBytes } from '../core/bytes.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node } from '../types/asn1-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { CertificationRequest, CsrAttribute, Extension, ParseCertificateOptions } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from './x509-algorithm.js';
import { _readExtensionSequence } from './x509-certificate.js';
import { certificateError, expectUniversalField } from './x509-fields.js';
import { _readName } from './x509-name.js';
import { _readSubjectPublicKeyInfo } from './x509-spki.js';

const STRUCTURE = 'PKI_X509_STRUCTURE_INVALID';
/** PKCS#9 `extensionRequest` (RFC 2985 §5.4.2): the extensions a request asks for. */
const OID_EXTENSION_REQUEST = '1.2.840.113549.1.9.14';
/** PKCS#9 `challengePassword` (RFC 2985 §5.4.1): a DirectoryString. */
const OID_CHALLENGE_PASSWORD = '1.2.840.113549.1.9.7';

// ── Attributes ───────────────────────────────────────────────────────

/** What the attribute loop collects, beyond the attributes themselves. */
interface ReadAttributes {
    readonly attributes: readonly CsrAttribute[];
    readonly extensions: readonly Extension[] | undefined;
    readonly challengePassword: string | undefined;
}

/**
 * The one value an attribute with a defined syntax holds, or the structural
 * error of one that holds another number (RFC 2985 §5.4: both PKCS#9
 * attributes of a request are single-valued).
 */
function singleValue(set: Asn1Node, path: string, what: string): Asn1Node {
    if (set.children.length !== 1) {
        throw certificateError(STRUCTURE, path, set.offset, `holds ${set.children.length} values; ${what} is single-valued (RFC 2985 §5.4)`);
    }
    return set.children[0] as Asn1Node;
}

/**
 * `attributes [0] IMPLICIT SET OF Attribute` — RFC 2986's module is IMPLICIT
 * TAGS, so the context tag replaces the SET's own and the SET's content sits
 * directly under it. The field is not OPTIONAL: an empty SET is present and
 * empty, an absent field is a malformed request.
 *
 * Two bounds, both `maxExtensions`: the attribute count, and the value count
 * of each attribute. Attributes are the structure that carries a request's
 * extensions, so the bound a caller sets for one is the bound that fits the
 * other, and a request carrying more attributes than a certificate may carry
 * extensions is not a request anybody meant to send.
 */
function readAttributes(field: Asn1Node, ctx: Asn1Context, input: Uint8Array, decode: boolean): ReadAttributes {
    const path = 'certificationRequestInfo.attributes';
    if (field.tagClass !== 'context' || field.tagNumber !== 0 || !field.constructed) {
        throw certificateError(STRUCTURE, path, field.offset, `is ${tagLabel(field.tagClass, field.tagNumber)}; RFC 2986 §4.1 requires a constructed [0] IMPLICIT SET OF Attribute, present even when empty`);
    }
    enforceLimit(ctx.limits, 'maxExtensions', field.children.length, 'the attributes of the certification request');
    const seen = new Set<string>();
    const attributes: CsrAttribute[] = [];
    let extensions: readonly Extension[] | undefined;
    let challengePassword: string | undefined;
    for (let i = 0; i < field.children.length; i++) {
        const attrPath = `${path}[${i}]`;
        const attribute = expectUniversalField(field.children[i], TAG_SEQUENCE, attrPath, STRUCTURE, field.offset);
        if (attribute.children.length !== 2) {
            throw certificateError(STRUCTURE, attrPath, attribute.offset, `holds ${attribute.children.length} values; an Attribute is a type OID and a SET OF values`);
        }
        const oid = _readObjectIdentifier(expectUniversalField(attribute.children[0], TAG_OID, `${attrPath}.type`, STRUCTURE, attribute.offset), ctx);
        const set = expectUniversalField(attribute.children[1], TAG_SET, `${attrPath}.values`, STRUCTURE, attribute.offset);
        enforceLimit(ctx.limits, 'maxExtensions', set.children.length, `the values of the attribute ${oid}`);
        if (seen.has(oid)) {
            throw certificateError('PKI_X509_EXTENSION_DUPLICATE', attrPath, attribute.offset, `repeats the attribute ${oid}; a request carries each attribute type once (RFC 2985 §5.4)`);
        }
        seen.add(oid);
        const entry: CsrAttribute = { oid, values: Object.freeze(set.children.map((value) => value.bytes)) };
        attributes.push(Object.freeze(entry));
        if (oid === OID_EXTENSION_REQUEST) {
            const value = singleValue(set, `${attrPath}.values`, 'extensionRequest');
            const valuePath = `${attrPath}.values[0]`;
            const seq = expectUniversalField(value, TAG_SEQUENCE, valuePath, STRUCTURE, set.offset);
            extensions = _readExtensionSequence(seq, ctx, input, decode, valuePath, 'the extensions requested by the certification request');
        } else if (oid === OID_CHALLENGE_PASSWORD) {
            const value = singleValue(set, `${attrPath}.values`, 'challengePassword');
            const valuePath = `${attrPath}.values[0]`;
            if (value.tagClass !== 'universal' || stringTypeOfTag(value.tagNumber) === undefined) {
                throw certificateError(STRUCTURE, valuePath, value.offset, `is ${tagLabel(value.tagClass, value.tagNumber)}; a challengePassword is a DirectoryString`);
            }
            challengePassword = _readString(value, ctx, undefined, valuePath).value;
        }
    }
    return { attributes: Object.freeze(attributes), extensions, challengePassword };
}

// ── CertificationRequest ─────────────────────────────────────────────

/**
 * Parse a DER-encoded PKCS#10 certification request (RFC 2986 §4). Parsing
 * checks the structure and records profile concerns as diagnostics; it does
 * not verify the signature — `verifyCertificationRequest` does, with the key
 * the request carries.
 *
 * ```ts
 * import { parseCertificationRequest } from 'pkinative';
 *
 * const request = parseCertificationRequest(csrDer);
 * console.log(formatDistinguishedName(request.subject), request.subjectPublicKeyInfo.kind);
 * for (const extension of request.extensions ?? []) console.log('asks for', extension.oid);
 * ```
 *
 * The extensions a request asks for travel inside the PKCS#9 `extensionRequest`
 * attribute and are decoded exactly as a certificate's are, with the same
 * decoders, the same codes and the same `decodeExtensions` option; the
 * `challengePassword` attribute is exposed as text. Every other attribute is
 * kept as DER on `attributes`. The attribute count and the value count of
 * each attribute are bounded by `maxExtensions`, the structure they carry.
 *
 * @param der     The request encoding. The result holds zero-copy views of it: do not mutate it while you use the result.
 * @param options Encoding rules (`'der'` by default), limits, `strict`, `onDiagnostic` and `decodeExtensions` (default `true`).
 * @returns The frozen request, with every diagnostic of the parse on `diagnostics`.
 * @throws {PkiCertificateError} `PKI_X509_STRUCTURE_INVALID` when the DER is not an RFC 2986 request, `PKI_X509_VERSION_INVALID`
 *   for a version other than 0, `PKI_X509_NAME_INVALID`, `PKI_X509_SPKI_INVALID`, `PKI_X509_EXTENSIONS_EMPTY`,
 *   `PKI_X509_EXTENSION_DUPLICATE` (a repeated attribute type, or a repeated extension inside `extensionRequest`),
 *   `PKI_X509_EXTENSION_MALFORMED` or `PKI_X509_GENERAL_NAME_INVALID`.
 * @throws {PkiEncodingError} For every X.690 violation (`PKI_ASN1_*`, `PKI_OID_INVALID`).
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond a configured limit.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a wrong argument; `PKI_STRICT_DIAGNOSTIC` under `strict: true`.
 */
export function parseCertificationRequest(der: Uint8Array, options?: ParseCertificateOptions): CertificationRequest {
    const bytes = assertBytes(der, 'parseCertificationRequest input');
    const ctx = createAsn1Context(options);
    const decode = options?.decodeExtensions ?? true;
    if (typeof decode !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: decodeExtensions must be a boolean, got ${typeof decode}`);
    }
    const request = expectUniversalField(decodeWithContext(bytes, ctx, false), TAG_SEQUENCE, 'certificationRequest', STRUCTURE, 0);
    if (request.children.length !== 3) {
        throw certificateError(STRUCTURE, 'certificationRequest', request.offset, `holds ${request.children.length} values; a CertificationRequest is certificationRequestInfo, signatureAlgorithm and signature`);
    }
    const info = expectUniversalField(request.children[0], TAG_SEQUENCE, 'certificationRequestInfo', STRUCTURE, request.offset);
    if (info.children.length !== 4) {
        throw certificateError(STRUCTURE, 'certificationRequestInfo', info.offset, `holds ${info.children.length} values; CertificationRequestInfo is version, subject, subjectPKInfo and attributes`);
    }

    // version INTEGER { v1(0) }: written even when zero, because it is not
    // DEFAULT — so no default-encoded diagnostic, unlike a certificate's.
    const versionNode = expectUniversalField(info.children[0], TAG_INTEGER, 'certificationRequestInfo.version', STRUCTURE, info.offset);
    const version = _readInteger(versionNode, ctx);
    if (version !== 0n) {
        throw certificateError('PKI_X509_VERSION_INVALID', 'certificationRequestInfo.version', versionNode.offset, `is ${String(version)}; RFC 2986 defines v1 (0) and nothing else`);
    }
    const subject = _readName(info.children[1], ctx, 'certificationRequestInfo.subject', info.offset);
    const subjectPublicKeyInfo = _readSubjectPublicKeyInfo(info.children[2], ctx, 'certificationRequestInfo.subjectPKInfo', info.offset);
    const { attributes, extensions, challengePassword } = readAttributes(info.children[3] as Asn1Node, ctx, bytes, decode);

    // One algorithm field, outside the signed bytes: RFC 2986 has no inner
    // copy for it to disagree with, so there is no mismatch to diagnose.
    const signatureAlgorithm = _readAlgorithmIdentifier(request.children[1], ctx, 'signatureAlgorithm', STRUCTURE, request.offset);
    const signatureValue = _readBitString(expectUniversalField(request.children[2], TAG_BIT_STRING, 'signature', STRUCTURE, request.offset), ctx);

    const parsed: CertificationRequest = {
        der: request.bytes,
        tbsDer: info.bytes,
        version: 0,
        subject,
        subjectPublicKeyInfo,
        attributes,
        extensions,
        challengePassword,
        signatureAlgorithm,
        signatureValue,
        diagnostics: Object.freeze([...ctx.emitter.diagnostics]),
    };
    return Object.freeze(parsed);
}
