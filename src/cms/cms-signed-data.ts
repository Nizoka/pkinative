/**
 * pkinative — RFC 5652 SignedData
 * ===============================
 * A `ContentInfo` carrying `id-signedData`, parsed into what a verifier needs:
 * the content or the fact that it is detached, the bag of certificates and
 * revocation evidence as DER, and each signer with the exact bytes its
 * signature covers.
 *
 * Parsing is parsing. Nothing here checks a signature, a digest or a
 * certificate; that is `verifySignedData`, for the reason `parseCertificate` and
 * `verifyCertificateSignature` are separate. What this module decides is only
 * whether the bytes are a SignedData at all, and it decides that strictly:
 * a structure RFC 5652's ASN.1 module does not describe is refused, and a
 * concern that changes nothing a verifier decides — a version number that does
 * not match its derivation, an unsorted unsigned SET — is a diagnostic.
 *
 * The whole message is decoded once, with the ordinary decoder, because CMS is
 * the one structure in the library that is legitimately BER: streaming signers
 * write indefinite lengths at every level, and the lazy cursor accepts none.
 * The node budget bounds that decode as it bounds a certificate's.
 *
 * @module cms/cms-signed-data
 */

import { createAsn1Context, type Asn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readInteger, _readOctetString } from '../asn1/asn1-read.js';
import { TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET } from '../asn1/asn1-tags.js';
import { assertBytes } from '../core/bytes.js';
import {
    cmsDigestAlgorithmNotListedDiagnostic,
    cmsSetNotSortedDiagnostic,
    cmsSignedAttributesNotDerDiagnostic,
    cmsVersionMismatchDiagnostic,
} from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type { ParseSignedDataOptions, SignedData, SignerIdentifier, SignerInfo } from '../types/cms-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { AlgorithmIdentifier } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from '../x509/x509-algorithm.js';
import { _readName } from '../x509/x509-name.js';
import {
    _assertDerEncoded,
    _cmsError,
    _collectTimeStampTokens,
    _expectUniversal,
    _inDerSetOrder,
    _readAttributes,
    _readSerialNumber,
    _readSignedAttributeFields,
    _viaX509,
} from './cms-attributes.js';
import {
    OID_AUTH_DATA,
    OID_DATA,
    OID_DIGESTED_DATA,
    OID_ENCRYPTED_DATA,
    OID_ENVELOPED_DATA,
    OID_RI_OCSP_RESPONSE,
    OID_SIGNED_DATA,
    OID_TST_INFO,
} from './cms-oids.js';

/** The content types a caller may plausibly hand over by mistake, named so the refusal can say which one it was. */
const CONTENT_TYPE_NAMES: ReadonlyMap<string, string> = /*#__PURE__*/ new Map([
    [OID_DATA, 'data, which carries no signature'],
    [OID_ENVELOPED_DATA, 'enveloped-data, which pkinative does not decrypt'],
    [OID_DIGESTED_DATA, 'digested-data, which carries no signature'],
    [OID_ENCRYPTED_DATA, 'encrypted-data, which pkinative does not decrypt'],
    [OID_AUTH_DATA, 'authenticated-data, a MAC pkinative does not check'],
    [OID_TST_INFO, 'a bare TSTInfo; a timestamp token is the SignedData around it'],
]);

/** What the `certificates` and `crls` fields carry, beyond the DER kept for the caller. */
interface Bag {
    readonly certificates: readonly Uint8Array[];
    readonly crls: readonly Uint8Array[];
    readonly ocspResponses: readonly Uint8Array[];
    /** The §5.1 facts the version derivation needs. */
    readonly hasOtherFormat: boolean;
    readonly hasV2AttrCert: boolean;
    readonly hasV1AttrCert: boolean;
}

/**
 * Parse a CMS `ContentInfo` whose content is a `SignedData`.
 *
 * ```ts
 * import { parseSignedData } from 'pkinative';
 *
 * const signed = parseSignedData(der);
 * if (signed.content === undefined) console.log('detached: the signed bytes travel separately');
 * for (const signer of signed.signerInfos) console.log(signer.sid.kind, signer.messageDigest);
 * ```
 *
 * The result is the structure and nothing more: whether any signature holds
 * is `verifySignedData`'s question. A SignedData with **no** signers — a
 * `.p7b` certificate bundle — parses as an ordinary value.
 *
 * Bytes after the `ContentInfo` are refused unless `allowTrailingData` is set.
 * A PDF signature's `/Contents` is the case that needs it: the DER is written
 * into a fixed-size, zero-padded placeholder, so pass either the exact DER or
 * the whole placeholder with `allowTrailingData: true`.
 *
 * Under `encodingRules: 'ber'` indefinite lengths and a segmented `eContent`
 * are accepted, as RFC 5652 §5.2 allows; the signed attributes must still be
 * DER (§5.3), because that is what the signature covers.
 *
 * @param der     The DER (or, with `encodingRules: 'ber'`, BER) of the ContentInfo.
 * @param options Encoding rules, limits, diagnostics and `allowTrailingData`.
 * @returns The parsed SignedData, with zero-copy views of `der` — except
 *   `signedAttributesDer`, which is a copy with its tag replaced, and a
 *   segmented BER `eContent`, which is the concatenation of its segments.
 *   The caller must not mutate `der` while the result is in use.
 * @throws {PkiCmsError} `PKI_CMS_STRUCTURE_INVALID` when the bytes do not match
 *   the RFC 5652 ASN.1 module; `PKI_CMS_CONTENT_TYPE_UNEXPECTED` for a
 *   ContentInfo of another type; `PKI_CMS_VERSION_UNSUPPORTED` for a SignedData
 *   version outside 1, 3, 4, 5 or a SignerInfo version outside 1, 3;
 *   `PKI_CMS_CONTENT_NOT_OCTET_STRING` for PKCS #7 content that is not an
 *   OCTET STRING.
 * @throws {PkiEncodingError} For any DER violation (any BER one under `'ber'`),
 *   including `PKI_ASN1_TRAILING_DATA`.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxSignerInfos`,
 *   `maxCmsAttributes`, `maxCmsBagEntries` or a decoder limit.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a wrong
 *   argument; `PKI_STRICT_DIAGNOSTIC` under `strict: true`.
 */
export function parseSignedData(der: Uint8Array, options?: ParseSignedDataOptions): SignedData {
    const bytes = assertBytes(der, 'parseSignedData input');
    const ctx = createAsn1Context(options);
    const allow = options?.allowTrailingData;
    if (allow !== undefined && typeof allow !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: allowTrailingData must be a boolean, got ${typeof allow}`);
    }
    const root = decodeWithContext(bytes, ctx, allow === true);

    // ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT ANY }.
    const contentInfo = _expectUniversal(root, TAG_SEQUENCE, 'ContentInfo', 0, 'a SEQUENCE');
    const typeNode = _expectUniversal(contentInfo.children[0], TAG_OID, 'contentType', contentInfo.offset, 'an OBJECT IDENTIFIER');
    const contentType = _readObjectIdentifier(typeNode, ctx);
    if (contentType !== OID_SIGNED_DATA) {
        const known = CONTENT_TYPE_NAMES.get(contentType);
        throw _cmsError('PKI_CMS_CONTENT_TYPE_UNEXPECTED', 'contentType', typeNode.offset,
            `is ${known === undefined ? contentType : `${contentType} (${known})`}, not id-signedData`);
    }
    const wrapper = contentInfo.children[1];
    if (wrapper === undefined || wrapper.tagClass !== 'context' || wrapper.tagNumber !== 0 || !wrapper.constructed) {
        // RFC 5652 §3 made `content` mandatory; PKCS #7 had it OPTIONAL, and a
        // SignedData with no content is no message at all.
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', 'content', wrapper?.offset ?? contentInfo.offset, 'is not the [0] EXPLICIT content RFC 5652 §3 requires');
    }
    if (wrapper.children.length !== 1 || contentInfo.children.length !== 2) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', 'content', wrapper.offset, 'is not exactly one SignedData under [0], the last field of ContentInfo');
    }
    const signedData = _expectUniversal(wrapper.children[0], TAG_SEQUENCE, 'content', wrapper.offset, 'a SignedData SEQUENCE');
    return readSignedData(root, signedData, ctx);
}

/** `SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, certificates [0] OPT, crls [1] OPT, signerInfos }`. */
function readSignedData(root: Asn1Node, seq: Asn1Node, ctx: Asn1Context): SignedData {
    const fields = seq.children;
    const versionNode = _expectUniversal(fields[0], TAG_INTEGER, 'content.version', seq.offset, 'an INTEGER');
    const declared = _readInteger(versionNode, ctx);
    if (declared !== 1n && declared !== 3n && declared !== 4n && declared !== 5n) {
        throw _cmsError('PKI_CMS_VERSION_UNSUPPORTED', 'content.version', versionNode.offset,
            `is ${String(declared)}; RFC 5652 §5.1 defines SignedData versions 1, 3, 4 and 5 only`);
    }

    const digestAlgorithms = readDigestAlgorithms(fields[1], ctx, seq.offset);
    const encap = readEncapsulatedContent(fields[2], ctx, seq.offset);

    // The two optional bags are told apart by their tags, and whatever follows
    // them must be the signerInfos SET — so a walk, not an index.
    let at = 3;
    const certificatesField = isContext(fields[at], 0) ? fields[at++] : undefined;
    const crlsField = isContext(fields[at], 1) ? fields[at++] : undefined;
    const bag = readBag(certificatesField, crlsField, ctx);
    const signerSet = _expectUniversal(fields[at], TAG_SET, 'content.signerInfos', seq.offset, 'a SET OF SignerInfo');
    if (fields.length !== at + 1) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', 'content', seq.offset, `holds ${String(fields.length - at - 1)} value(s) after signerInfos, where RFC 5652 §5.1 defines none`);
    }

    const listed = new Set(digestAlgorithms.map((algorithm) => algorithm.oid));
    const signerInfos: SignerInfo[] = [];
    for (let i = 0; i < signerSet.children.length; i++) {
        const path = `content.signerInfos[${String(i)}]`;
        enforceLimit(ctx.limits, 'maxSignerInfos', i + 1, path);
        signerInfos.push(readSignerInfo(signerSet.children[i] as Asn1Node, ctx, path, listed));
    }
    if (!_inDerSetOrder(signerSet.children)) ctx.emitter.emit(cmsSetNotSortedDiagnostic('content.signerInfos', signerSet.offset));

    // RFC 5652 §5.1, top-down, first match wins.
    const derived: SignedData['version'] = bag.hasOtherFormat ? 5
        : bag.hasV2AttrCert ? 4
            : bag.hasV1AttrCert || signerInfos.some((signer) => signer.version === 3) || encap.contentType !== OID_DATA ? 3
                : 1;
    const version = Number(declared) as SignedData['version'];
    if (version !== derived) ctx.emitter.emit(cmsVersionMismatchDiagnostic('content.version', version, derived, versionNode.offset));

    return Object.freeze({
        der: root.bytes,
        version,
        digestAlgorithms,
        contentType: encap.contentType,
        content: encap.content,
        certificates: bag.certificates,
        crls: bag.crls,
        ocspResponses: bag.ocspResponses,
        signerInfos: Object.freeze(signerInfos),
        diagnostics: ctx.emitter.diagnostics,
    });
}

/** A constructed context-specific `[tag]`. */
function isContext(node: Asn1Node | undefined, tag: number): boolean {
    return node !== undefined && node.tagClass === 'context' && node.tagNumber === tag;
}

/** `DigestAlgorithmIdentifiers ::= SET OF AlgorithmIdentifier` — which may be empty (§5.1). */
function readDigestAlgorithms(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): readonly AlgorithmIdentifier[] {
    const set = _expectUniversal(node, TAG_SET, 'content.digestAlgorithms', parentOffset, 'a SET OF DigestAlgorithmIdentifier');
    const out: AlgorithmIdentifier[] = [];
    for (let i = 0; i < set.children.length; i++) {
        const path = `content.digestAlgorithms[${String(i)}]`;
        // Every digest listed is one some signer used (§5.1), so the signer
        // bound is the one that applies.
        enforceLimit(ctx.limits, 'maxSignerInfos', i + 1, path);
        const child = set.children[i] as Asn1Node;
        out.push(_viaX509(path, child.offset, () => _readAlgorithmIdentifier(child, ctx, path, 'PKI_X509_STRUCTURE_INVALID', set.offset)));
    }
    if (!_inDerSetOrder(set.children)) ctx.emitter.emit(cmsSetNotSortedDiagnostic('content.digestAlgorithms', set.offset));
    return Object.freeze(out);
}

/** `EncapsulatedContentInfo ::= SEQUENCE { eContentType, eContent [0] EXPLICIT OCTET STRING OPTIONAL }`. */
function readEncapsulatedContent(node: Asn1Node | undefined, ctx: Asn1Context, parentOffset: number): { readonly contentType: string; readonly content: Uint8Array | undefined } {
    const path = 'content.encapContentInfo';
    const seq = _expectUniversal(node, TAG_SEQUENCE, path, parentOffset, 'an EncapsulatedContentInfo SEQUENCE');
    const contentType = _readObjectIdentifier(_expectUniversal(seq.children[0], TAG_OID, `${path}.eContentType`, seq.offset, 'an OBJECT IDENTIFIER'), ctx);
    const wrapper = seq.children[1];
    if (wrapper === undefined) {
        // Detached (§5.2): the signature was computed over content that
        // travels elsewhere. Not the same thing as empty content.
        return { contentType, content: undefined };
    }
    if (!isContext(wrapper, 0) || !wrapper.constructed || wrapper.children.length !== 1 || seq.children.length !== 2) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', `${path}.eContent`, wrapper.offset, 'is not one value under [0] EXPLICIT, the last field of EncapsulatedContentInfo');
    }
    const inner = wrapper.children[0] as Asn1Node;
    if (inner.tagClass !== 'universal' || inner.tagNumber !== TAG_OCTET_STRING) {
        throw _cmsError('PKI_CMS_CONTENT_NOT_OCTET_STRING', `${path}.eContent`, inner.offset,
            'is not an OCTET STRING; RFC 5652 §5.2.1 notes that PKCS #7 allowed any type here, and the digest of such content is not defined the same way');
    }
    // Zero-copy when primitive; under BER a segmented value is joined, which
    // is the only way to present the octets the content digest runs over.
    return { contentType, content: _readOctetString(inner, ctx) };
}

/**
 * `certificates [0] IMPLICIT CertificateSet` and `crls [1] IMPLICIT
 * RevocationInfoChoices`, kept as DER.
 *
 * The alternatives nobody verifies with — attribute certificates, the obsolete
 * PKCS #6 form, `other` formats — are accepted and not returned, but still
 * counted: §5.1 derives the version from them, and a bag that carries one is
 * no less a valid SignedData for pkinative not reading it.
 */
function readBag(certificatesField: Asn1Node | undefined, crlsField: Asn1Node | undefined, ctx: Asn1Context): Bag {
    const certificates: Uint8Array[] = [];
    const crls: Uint8Array[] = [];
    const ocspResponses: Uint8Array[] = [];
    let hasOtherFormat = false;
    let hasV2AttrCert = false;
    let hasV1AttrCert = false;
    let entries = 0;

    const children = (field: Asn1Node | undefined, path: string): readonly Asn1Node[] => {
        if (field === undefined) return [];
        if (!field.constructed) throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, field.offset, 'is primitive; it is a SET OF under an implicit tag');
        if (!_inDerSetOrder(field.children)) ctx.emitter.emit(cmsSetNotSortedDiagnostic(path, field.offset));
        return field.children;
    };

    const certificateNodes = children(certificatesField, 'content.certificates');
    for (let i = 0; i < certificateNodes.length; i++) {
        const path = `content.certificates[${String(i)}]`;
        entries += 1;
        enforceLimit(ctx.limits, 'maxCmsBagEntries', entries, path);
        const node = certificateNodes[i] as Asn1Node;
        if (node.tagClass === 'universal' && node.tagNumber === TAG_SEQUENCE) {
            // Not parsed: the bag is a claim by whoever assembled the message,
            // and one malformed stranger in it must not make the signature
            // unreadable. The verifier parses the certificates it uses.
            certificates.push(node.bytes);
        } else if (node.tagClass === 'context' && node.tagNumber <= 3 && node.constructed) {
            if (node.tagNumber === 1) hasV1AttrCert = true;
            if (node.tagNumber === 2) hasV2AttrCert = true;
            if (node.tagNumber === 3) hasOtherFormat = true;
        } else {
            throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, node.offset,
                'is not a CertificateChoices value: a Certificate SEQUENCE or a constructed [0] to [3] (RFC 5652 §10.2.2)');
        }
    }

    const crlNodes = children(crlsField, 'content.crls');
    for (let i = 0; i < crlNodes.length; i++) {
        const path = `content.crls[${String(i)}]`;
        entries += 1;
        enforceLimit(ctx.limits, 'maxCmsBagEntries', entries, path);
        const node = crlNodes[i] as Asn1Node;
        if (node.tagClass === 'universal' && node.tagNumber === TAG_SEQUENCE) {
            crls.push(node.bytes);
            continue;
        }
        // other [1] IMPLICIT OtherRevocationInfoFormat ::= SEQUENCE { otherRevInfoFormat OID, otherRevInfo ANY }.
        if (!isContext(node, 1) || !node.constructed || node.children.length !== 2) {
            throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, node.offset,
                'is not a RevocationInfoChoice: a CertificateList SEQUENCE or an OtherRevocationInfoFormat under [1] (RFC 5652 §10.2.1)');
        }
        hasOtherFormat = true;
        const format = _readObjectIdentifier(_expectUniversal(node.children[0], TAG_OID, `${path}.otherRevInfoFormat`, node.offset, 'an OBJECT IDENTIFIER'), ctx);
        // RFC 5940 §3: where CAdES and long-term PDF signatures keep the OCSP
        // answers they were validated with. Any other format is carried by no
        // one pkinative serves, and is ignored.
        if (format === OID_RI_OCSP_RESPONSE) ocspResponses.push((node.children[1] as Asn1Node).bytes);
    }

    return {
        certificates: Object.freeze(certificates),
        crls: Object.freeze(crls),
        ocspResponses: Object.freeze(ocspResponses),
        hasOtherFormat,
        hasV2AttrCert,
        hasV1AttrCert,
    };
}

/**
 * `SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm, signedAttrs [0] OPT,
 * signatureAlgorithm, signature, unsignedAttrs [1] OPT }`.
 */
function readSignerInfo(node: Asn1Node, ctx: Asn1Context, path: string, listed: ReadonlySet<string>): SignerInfo {
    const seq = _expectUniversal(node, TAG_SEQUENCE, path, node.offset, 'a SignerInfo SEQUENCE');
    const fields = seq.children;
    const versionNode = _expectUniversal(fields[0], TAG_INTEGER, `${path}.version`, seq.offset, 'an INTEGER');
    const declared = _readInteger(versionNode, ctx);
    if (declared !== 1n && declared !== 3n) {
        // Refused rather than skipped. RFC 5652 §5.1 asks a reader to handle an
        // unknown SignerInfo version gracefully, but a parser that dropped the
        // signer would hand a caller whose policy is "every signer verifies" a
        // message with one signer fewer — a more permissive answer than the
        // message deserves.
        throw _cmsError('PKI_CMS_VERSION_UNSUPPORTED', `${path}.version`, versionNode.offset,
            `is ${String(declared)}; RFC 5652 §5.3 defines SignerInfo versions 1 and 3 only`);
    }
    const version = declared === 1n ? 1 : 3;

    const sidNode = fields[1];
    const sid = readSignerIdentifier(sidNode, ctx, `${path}.sid`, seq.offset);
    // The tag of `sid`, not the version, says which alternative it is; the
    // version is not signed and decides nothing.
    const expected = sid.kind === 'issuerAndSerialNumber' ? 1 : 3;
    if (version !== expected) ctx.emitter.emit(cmsVersionMismatchDiagnostic(`${path}.version`, version, expected, versionNode.offset));

    const digestNode = fields[2];
    const digestAlgorithm = _viaX509(`${path}.digestAlgorithm`, digestNode?.offset ?? seq.offset, () =>
        _readAlgorithmIdentifier(digestNode, ctx, `${path}.digestAlgorithm`, 'PKI_X509_STRUCTURE_INVALID', seq.offset));
    if (!listed.has(digestAlgorithm.oid)) {
        ctx.emitter.emit(cmsDigestAlgorithmNotListedDiagnostic(`${path}.digestAlgorithm`, digestAlgorithm.oid, (digestNode as Asn1Node).offset));
    }

    let at = 3;
    const signedNode = isContext(fields[at], 0) ? fields[at++] : undefined;
    const algorithmNode = fields[at++];
    const signatureAlgorithm = _viaX509(`${path}.signatureAlgorithm`, algorithmNode?.offset ?? seq.offset, () =>
        _readAlgorithmIdentifier(algorithmNode, ctx, `${path}.signatureAlgorithm`, 'PKI_X509_STRUCTURE_INVALID', seq.offset));
    const signature = _readOctetString(_expectUniversal(fields[at++], TAG_OCTET_STRING, `${path}.signature`, seq.offset, 'an OCTET STRING'), ctx);
    const unsignedNode = isContext(fields[at], 1) ? fields[at++] : undefined;
    if (fields.length !== at) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, seq.offset, `holds ${String(fields.length - at)} value(s) after the signature that RFC 5652 §5.3 does not define`);
    }

    let signedEntries: ReturnType<typeof _readAttributes> | undefined;
    let signedAttributesDer: Uint8Array | undefined;
    if (signedNode !== undefined) {
        _assertDerEncoded(signedNode, ctx, `${path}.signedAttrs`);
        signedEntries = _readAttributes(signedNode, ctx, `${path}.signedAttrs`);
        if (!_inDerSetOrder(signedNode.children)) ctx.emitter.emit(cmsSignedAttributesNotDerDiagnostic(`${path}.signedAttrs`, signedNode.offset));
        // RFC 5652 §5.4: the signature covers the EXPLICIT SET OF tag, not the
        // IMPLICIT [0] that was transmitted. A copy, because writing 0x31 into
        // the caller's buffer would corrupt their message for every later reader.
        signedAttributesDer = signedNode.bytes.slice();
        signedAttributesDer[0] = 0x31;
    }
    const unsignedEntries = unsignedNode === undefined ? undefined : _readAttributes(unsignedNode, ctx, `${path}.unsignedAttrs`);
    const convenience = _readSignedAttributeFields(signedEntries ?? [], ctx, `${path}.signedAttrs`);

    return Object.freeze({
        version,
        sid,
        digestAlgorithm,
        signedAttributes: signedEntries === undefined ? undefined : Object.freeze(signedEntries.map((entry) => entry.attribute)),
        signedAttributesDer,
        signatureAlgorithm,
        signature,
        unsignedAttributes: unsignedEntries === undefined ? undefined : Object.freeze(unsignedEntries.map((entry) => entry.attribute)),
        contentType: convenience.contentType,
        messageDigest: convenience.messageDigest,
        signingTime: convenience.signingTime,
        signingCertificate: convenience.signingCertificate,
        algorithmProtection: convenience.algorithmProtection,
        timeStampTokens: _collectTimeStampTokens(unsignedEntries),
        der: seq.bytes,
    });
}

/**
 * `SignerIdentifier ::= CHOICE { issuerAndSerialNumber, subjectKeyIdentifier [0] }`.
 *
 * `[0]` carries no keyword in RFC 5652, so it is IMPLICIT by the module's
 * default: `80 len keyId`, a primitive value, not a wrapped OCTET STRING.
 */
function readSignerIdentifier(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): SignerIdentifier {
    if (node !== undefined && node.tagClass === 'context' && node.tagNumber === 0 && !node.constructed) {
        return Object.freeze({ kind: 'subjectKeyIdentifier', keyIdentifier: node.content });
    }
    if (node === undefined || node.tagClass !== 'universal' || node.tagNumber !== TAG_SEQUENCE) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, node?.offset ?? parentOffset,
            'is not a SignerIdentifier: an IssuerAndSerialNumber SEQUENCE or a primitive [0] subjectKeyIdentifier (RFC 5652 §5.3)');
    }
    if (node.children.length !== 2) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, node.offset, `holds ${String(node.children.length)} values where IssuerAndSerialNumber holds an issuer and a serial number`);
    }
    const issuerNode = node.children[0] as Asn1Node;
    const issuer = _viaX509(`${path}.issuer`, issuerNode.offset, () => _readName(issuerNode, ctx, `${path}.issuer`, node.offset));
    const serialNumber = _readSerialNumber(node.children[1], ctx, `${path}.serialNumber`, node.offset);
    return Object.freeze({ kind: 'issuerAndSerialNumber', issuer, serialNumber });
}
