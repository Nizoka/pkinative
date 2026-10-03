/**
 * pkinative — CMS attributes
 * ==========================
 * The `Attribute` lists of a SignerInfo, and the five signed attributes whose
 * values the parser reads for the caller.
 *
 * Two rules shape everything here. The first is that an attribute list is
 * kept **as encoded**: order, duplicates, multi-valued sets and all. A
 * verifier that is told "the messageDigest" when the signer's set carries two
 * has been told a lie of convenience, so the raw list is always there and the
 * convenience fields are set only when the answer is unambiguous.
 *
 * The second is that RFC 5652 §5.3 requires the signed attributes to be DER
 * "even if the rest of the structure is BER encoded", because the signature is
 * computed over their DER. Under `encodingRules: 'ber'` the rest of a message
 * may be indefinite-length; the signed attributes may not, and
 * {@link _assertDerEncoded} is where that is refused — re-encoding them would
 * produce bytes the signer may never have signed.
 *
 * @internal
 * @module cms/cms-attributes
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readInteger, _readOctetString } from '../asn1/asn1-read.js';
import { isStringTag, TAG_GENERALIZED_TIME, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET, TAG_UTC_TIME } from '../asn1/asn1-tags.js';
import { _readTime } from '../asn1/asn1-time.js';
import { bytesEqual, compareOctets, toHex } from '../core/bytes.js';
import {
    cmsCountersignatureContentTypeDiagnostic,
    cmsCountersignatureEmptyDiagnostic,
    cmsCountersignatureNoMessageDigestDiagnostic,
    cmsSigningTimeFractionDiagnostic,
    cmsSigningTimeNotUtcDiagnostic,
    defaultEncodedDiagnostic,
} from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, PkiTime } from '../types/asn1-types.js';
import type { Attribute, EssCertId, SignerInfo, SigningCertificateAttribute } from '../types/cms-types.js';
import { PkiCertificateError, PkiCmsError, PkiEncodingError, type PkiCmsErrorCode } from '../types/pki-errors.js';
import type { SerialNumber } from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from '../x509/x509-algorithm.js';
import { _readGeneralNames } from '../x509/x509-general-name.js';
import {
    OID_ATTR_ALGORITHM_PROTECTION,
    OID_ATTR_CONTENT_TYPE,
    OID_ATTR_COUNTERSIGNATURE,
    OID_ATTR_MESSAGE_DIGEST,
    OID_ATTR_SIGNING_CERTIFICATE,
    OID_ATTR_SIGNING_CERTIFICATE_V2,
    OID_ATTR_SIGNING_TIME,
    OID_ATTR_TIMESTAMP_TOKEN,
} from '../core/cms-oids.js';

// ── Errors ──

/** What the caller can do about each code, appended to every message. */
const REMEDIES: Readonly<Record<PkiCmsErrorCode, string>> = /*#__PURE__*/ Object.freeze({
    PKI_CMS_STRUCTURE_INVALID: 'the input is not an RFC 5652 SignedData; check that it is the DER of a CMS ContentInfo and not its PEM or base64 text',
    PKI_CMS_CONTENT_TYPE_UNEXPECTED: 'pass a ContentInfo of type id-signedData',
    PKI_CMS_VERSION_UNSUPPORTED: 'RFC 5652 defines no such version, so the syntax that follows cannot be read; ask the producer for a conforming message',
    PKI_CMS_CONTENT_NOT_OCTET_STRING: 'this is PKCS #7 content outside RFC 5652 §5.2 (Authenticode is the usual case); pkinative does not read it',
});

/**
 * The error of one CMS field.
 *
 * @internal
 */
export function _cmsError(code: PkiCmsErrorCode, path: string, offset: number, why: string): PkiCmsError {
    return new PkiCmsError(code, `pkinative: ${path} at offset ${String(offset)} ${why} — ${REMEDIES[code]}`, path, offset);
}

/**
 * Run an x509 reader on a field of a CMS structure, and report its refusal as
 * a CMS one.
 *
 * The Name, GeneralNames and AlgorithmIdentifier readers are shared with the
 * certificate parser and throw `PkiCertificateError`. Inside a SignedData that
 * class would tell a caller catching certificate errors about a structure that
 * is not a certificate, so the refusal is carried over — with the field the
 * CMS parser handed in, and the reader's own explanation kept in the message.
 *
 * @internal
 */
export function _viaX509<T>(path: string, offset: number, read: () => T): T {
    try {
        return read();
    } catch (error) {
        if (error instanceof PkiCertificateError) {
            throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, offset, `does not match its ASN.1 definition (${error.code}: ${error.message.slice('pkinative: '.length)})`);
        }
        throw error;
    }
}

/**
 * A field that must be present and carry one universal tag.
 *
 * @internal
 */
export function _expectUniversal(node: Asn1Node | undefined, tagNumber: number, path: string, parentOffset: number, what: string): Asn1Node {
    if (node === undefined) throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, parentOffset, `is missing; expected ${what}`);
    if (node.tagClass !== 'universal' || node.tagNumber !== tagNumber) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, node.offset, `is not ${what}`);
    }
    return node;
}

// ── DER checks ──

/**
 * X.690 §11.6 order over the component encodings.
 *
 * The zero padding §11.6 prescribes is unreachable: two complete TLVs are never
 * a strict prefix of one another, because a difference in total length shows
 * up in the length octets before the content is reached.
 *
 * @internal
 */
export function _inDerSetOrder(elements: readonly Asn1Node[]): boolean {
    for (let k = 1; k < elements.length; k++) {
        if (compareOctets((elements[k - 1] as Asn1Node).bytes, (elements[k] as Asn1Node).bytes) > 0) return false;
    }
    return true;
}

/** The header length DER gives a value with this tag number and content length. */
function derHeaderLength(tagNumber: number, contentLength: number): number {
    let identifier = 1;
    if (tagNumber >= 31) for (let rest = tagNumber; rest > 0; rest = Math.floor(rest / 128)) identifier += 1;
    let length = 1;
    if (contentLength >= 0x80) for (let rest = contentLength; rest > 0; rest = Math.floor(rest / 256)) length += 1;
    return identifier + length;
}

/**
 * Refuse a subtree that is not DER, whatever `encodingRules` says.
 *
 * Under `'der'` the decoder has already refused every such form, so this only
 * does work under `'ber'` — and there it is the difference between verifying
 * the bytes the signer signed and verifying bytes nobody signed. SET OF order is
 * the one DER rule left out: an unsorted set is still the bytes the signature
 * covers, and the caller is told about it with a diagnostic instead.
 *
 * @internal
 */
export function _assertDerEncoded(root: Asn1Node, ctx: Asn1Context, path: string): void {
    if (ctx.rules === 'der') return;
    // The nodes were counted against maxNodes when they were decoded, so this
    // walk is bounded by the budget that produced them.
    const stack: Asn1Node[] = [root];
    while (stack.length > 0) {
        const node = stack.pop() as Asn1Node;
        const why = node.indefinite
            ? 'uses an indefinite length'
            : node.headerLength !== derHeaderLength(node.tagNumber, node.contentLength)
                ? 'uses a length that is not in its shortest form'
                : node.constructed && node.tagClass === 'universal' && isStringTag(node.tagNumber)
                    ? 'is a constructed string'
                    : undefined;
        if (why !== undefined) {
            throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, node.offset,
                `${why}; RFC 5652 §5.3 requires the signed attributes to be DER even when the rest of the message is BER, because the signature is computed over their DER`);
        }
        for (const child of node.children) stack.push(child);
    }
}

// ── Attribute lists ──

/** One decoded attribute, with the value nodes the convenience readers need. */
export interface _AttributeEntry {
    readonly attribute: Attribute;
    readonly valueNodes: readonly Asn1Node[];
    /** Absolute offset of the Attribute SEQUENCE, for a diagnostic about it. */
    readonly offset: number;
}

/**
 * Read `SignedAttributes` or `UnsignedAttributes`: a `SET SIZE (1..MAX) OF
 * Attribute` under an implicit tag.
 *
 * An empty `attrValues` set is kept as it is. It breaks `Attribute`'s intent
 * but not its syntax (`SET OF AttributeValue` has no size constraint in RFC
 * 5652), and whether it matters depends on which attribute it is — the
 * convenience fields below already treat it as "not exactly one value".
 *
 * @internal
 */
export function _readAttributes(container: Asn1Node, ctx: Asn1Context, path: string): readonly _AttributeEntry[] {
    if (!container.constructed) throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, container.offset, 'is primitive; an attribute set is a constructed SET OF Attribute');
    if (container.children.length === 0) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, container.offset, 'is empty; RFC 5652 §5.3 declares it SIZE (1..MAX), so an absent set is omitted rather than sent empty');
    }
    const out: _AttributeEntry[] = [];
    for (let i = 0; i < container.children.length; i++) {
        const where = `${path}[${String(i)}]`;
        enforceLimit(ctx.limits, 'maxAttributes', i + 1, where);
        const node = _expectUniversal(container.children[i], TAG_SEQUENCE, where, container.offset, 'an Attribute SEQUENCE');
        if (node.children.length !== 2) {
            throw _cmsError('PKI_CMS_STRUCTURE_INVALID', where, node.offset, `holds ${String(node.children.length)} values where an Attribute holds a type and a set of values`);
        }
        const oid = _readObjectIdentifier(_expectUniversal(node.children[0], TAG_OID, `${where}.attrType`, node.offset, 'an OBJECT IDENTIFIER'), ctx);
        const set = _expectUniversal(node.children[1], TAG_SET, `${where}.attrValues`, node.offset, 'a SET OF AttributeValue');
        // One bound for attributes and for the values of one attribute: both
        // are what a hostile signer would multiply to make a verifier loop.
        enforceLimit(ctx.limits, 'maxAttributes', set.children.length, `${where}.attrValues`);
        const attribute: Attribute = {
            oid,
            values: Object.freeze(set.children.map((value) => value.bytes)),
            der: node.bytes,
        };
        out.push(Object.freeze({ attribute: Object.freeze(attribute), valueNodes: set.children, offset: node.offset }));
    }
    return Object.freeze(out);
}

/** The value of an attribute that appears exactly once with exactly one value; `undefined` otherwise. */
function singleValue(entries: readonly _AttributeEntry[], oid: string): Asn1Node | undefined {
    const matching = entries.filter((entry) => entry.attribute.oid === oid);
    if (matching.length !== 1) return undefined;
    const values = (matching[0] as _AttributeEntry).valueNodes;
    return values.length === 1 ? values[0] : undefined;
}

// ── Recognised attribute values ──

/** The convenience fields of a SignerInfo, read from its signed attributes. */
export interface _SignedAttributeFields {
    readonly contentType: string | undefined;
    readonly messageDigest: Uint8Array | undefined;
    readonly signingTime: PkiTime | undefined;
    readonly signingCertificate: SigningCertificateAttribute | undefined;
    readonly algorithmProtection: SignerInfo['algorithmProtection'];
}

/**
 * Read one recognised attribute value, and refuse a malformed one.
 *
 * Refused rather than left `undefined`, as a malformed recognised X.509
 * extension is: `undefined` already means "absent or ambiguous", and a verifier
 * reading it for a value that is *present but unreadable* would report a
 * missing attribute when the truth is a broken one. A DER violation inside the
 * value is reported the same way, with its own code kept in the message.
 */
function readRecognised<T>(node: Asn1Node | undefined, path: string, read: (value: Asn1Node) => T): T | undefined {
    if (node === undefined) return undefined;
    try {
        return read(node);
    } catch (error) {
        if (error instanceof PkiEncodingError) {
            throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, node.offset, `does not match its ASN.1 definition (${error.code})`);
        }
        throw error;
    }
}

/**
 * Read the convenience fields from the signed attributes.
 *
 * `signingCertificate` takes v2 whenever a v2 attribute is present at all, even
 * a repeated one that leaves it `undefined`: falling back to v1 there would let
 * a second, conflicting v2 quietly promote the weaker SHA-1 binding.
 *
 * @internal
 */
export function _readSignedAttributeFields(entries: readonly _AttributeEntry[], ctx: Asn1Context, path: string): _SignedAttributeFields {
    const contentType = readRecognised(singleValue(entries, OID_ATTR_CONTENT_TYPE), `${path}.contentType`, (node) =>
        _readObjectIdentifier(_expectUniversal(node, TAG_OID, `${path}.contentType`, node.offset, 'an OBJECT IDENTIFIER'), ctx));
    const messageDigest = readRecognised(singleValue(entries, OID_ATTR_MESSAGE_DIGEST), `${path}.messageDigest`, (node) =>
        _readOctetString(_expectUniversal(node, TAG_OCTET_STRING, `${path}.messageDigest`, node.offset, 'an OCTET STRING'), ctx));
    const signingTimeNode = singleValue(entries, OID_ATTR_SIGNING_TIME);
    const signingTime = readRecognised(signingTimeNode, `${path}.signingTime`, (node) => {
        if (node.tagClass !== 'universal' || (node.tagNumber !== TAG_UTC_TIME && node.tagNumber !== TAG_GENERALIZED_TIME)) {
            throw _cmsError('PKI_CMS_STRUCTURE_INVALID', `${path}.signingTime`, node.offset, 'is not a UTCTime or a GeneralizedTime');
        }
        return _readTime(node, ctx, undefined);
    });
    if (signingTime?.type === 'GeneralizedTime') {
        // RFC 5652 §11.3 draws the same line RFC 5280 §4.1.2.5 draws for a
        // certificate: UTCTime through 2049, GeneralizedTime after, and never a
        // fraction. The instant is read as written either way — the signature
        // covers these bytes, so nothing here may change them.
        const year = Number(signingTime.text.slice(0, 4));
        const offset = (signingTimeNode as Asn1Node).offset;
        if (year >= 1950 && year <= 2049) ctx.emitter.emit(cmsSigningTimeNotUtcDiagnostic(`${path}.signingTime`, signingTime.text, offset));
        if (/[.,]/.test(signingTime.text)) ctx.emitter.emit(cmsSigningTimeFractionDiagnostic(`${path}.signingTime`, signingTime.text, offset));
    }
    const v1 = readRecognised(singleValue(entries, OID_ATTR_SIGNING_CERTIFICATE), `${path}.signingCertificate`, (node) =>
        readSigningCertificate(node, ctx, `${path}.signingCertificate`, 1));
    const v2 = readRecognised(singleValue(entries, OID_ATTR_SIGNING_CERTIFICATE_V2), `${path}.signingCertificateV2`, (node) =>
        readSigningCertificate(node, ctx, `${path}.signingCertificateV2`, 2));
    const hasV2 = entries.some((entry) => entry.attribute.oid === OID_ATTR_SIGNING_CERTIFICATE_V2);
    const algorithmProtection = readRecognised(singleValue(entries, OID_ATTR_ALGORITHM_PROTECTION), `${path}.CMSAlgorithmProtection`, (node) =>
        readAlgorithmProtection(node, ctx, `${path}.CMSAlgorithmProtection`));
    return { contentType, messageDigest, signingTime, signingCertificate: hasV2 ? v2 : v1, algorithmProtection };
}

// ── CMSAlgorithmProtection (RFC 6211) ──

/**
 * `CMSAlgorithmProtection ::= SEQUENCE { digestAlgorithm, signatureAlgorithm
 * [1] OPTIONAL, macAlgorithm [2] OPTIONAL }`, with the RFC 6211 §2 constraint
 * that makes it a SignedData attribute: the signature algorithm present, the
 * MAC algorithm absent.
 *
 * Decoded here rather than by the verifier, because it is a recognised
 * attribute and a malformed recognised attribute is refused at parse — the rule
 * every other one follows. A verifier that decoded it itself would have to turn
 * a decoding failure into a verdict, which only the composition layer may do.
 */
function readAlgorithmProtection(node: Asn1Node, ctx: Asn1Context, path: string): NonNullable<SignerInfo['algorithmProtection']> {
    const seq = _expectUniversal(node, TAG_SEQUENCE, path, node.offset, 'a SEQUENCE');
    const [digestNode, signatureNode, ...rest] = seq.children;
    if (rest.length > 0 || signatureNode === undefined || signatureNode.tagClass !== 'context' || signatureNode.tagNumber !== 1 || !signatureNode.constructed) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, seq.offset,
            'is not a digest algorithm followed by a [1] signature algorithm; RFC 6211 §2 requires exactly that in a SignedData, and no MAC algorithm');
    }
    const digestAlgorithm = _viaX509(`${path}.digestAlgorithm`, seq.offset, () =>
        _readAlgorithmIdentifier(digestNode, ctx, `${path}.digestAlgorithm`, 'PKI_X509_STRUCTURE_INVALID', seq.offset));
    // The [1] is IMPLICIT: it replaces the AlgorithmIdentifier's SEQUENCE tag,
    // so its children are the OID and the optional parameters themselves.
    const [oidNode, parameters, ...extra] = signatureNode.children;
    if (oidNode?.tagClass !== 'universal' || oidNode.tagNumber !== TAG_OID || extra.length > 0) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', `${path}.signatureAlgorithm`, signatureNode.offset, 'is not an algorithm OID with optional parameters');
    }
    const signatureAlgorithm = Object.freeze({ oid: _readObjectIdentifier(oidNode, ctx), parameters, der: signatureNode.bytes });
    return Object.freeze({ digestAlgorithm, signatureAlgorithm });
}

/**
 * Every value of every `id-aa-timeStampToken` among the unsigned attributes, as DER.
 *
 * @internal
 */
export function _collectTimeStampTokens(entries: readonly _AttributeEntry[] | undefined): readonly Uint8Array[] {
    const tokens: Uint8Array[] = [];
    for (const entry of entries ?? []) {
        if (entry.attribute.oid === OID_ATTR_TIMESTAMP_TOKEN) tokens.push(...entry.attribute.values);
    }
    return Object.freeze(tokens);
}

// ── Countersignatures (RFC 5652 §11.4) ──

/** The DER content of `id-contentType` and `id-messageDigest`: compared as bytes, so a malformed OID in a countersignature is passed over, never thrown on. */
const CONTENT_TYPE_OID_CONTENT = /*#__PURE__*/ Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03);
const MESSAGE_DIGEST_OID_CONTENT = /*#__PURE__*/ Uint8Array.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04);

/**
 * What RFC 5652 §11.4 says a countersignature's own SignerInfo must and must
 * not carry, as diagnostics.
 *
 * A countersignature is carried, not verified: its SignerInfo stays in the
 * attribute's values as received, and nothing here reads it further than the
 * tags needed to find its signed attributes. Three sentences of §11.4 are
 * decidable from those tags alone — the value SET must not be empty, the
 * signed attributes must not hold a content-type attribute, and must hold a
 * message-digest attribute when they hold anything — and each is a
 * diagnostic, never a refusal: a value that is not a SignerInfo at all is
 * passed over, because the message's own signature does not depend on it.
 *
 * @internal
 */
export function _countersignatureDiagnostics(entries: readonly _AttributeEntry[] | undefined, ctx: Asn1Context, path: string): void {
    for (const [index, entry] of (entries ?? []).entries()) {
        if (entry.attribute.oid !== OID_ATTR_COUNTERSIGNATURE) continue;
        const where = `${path}[${String(index)}]`;
        if (entry.valueNodes.length === 0) {
            ctx.emitter.emit(cmsCountersignatureEmptyDiagnostic(where, entry.offset));
            continue;
        }
        for (const [v, value] of entry.valueNodes.entries()) {
            // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm, signedAttrs [0] IMPLICIT OPTIONAL, … }:
            // the signed attributes are the fourth field when they are there,
            // and `sid` as [0] is primitive, so a constructed [0] in that
            // position is the set and nothing else.
            if (value.tagClass !== 'universal' || value.tagNumber !== TAG_SEQUENCE) continue;
            const signed = value.children[3];
            if (signed === undefined || signed.tagClass !== 'context' || signed.tagNumber !== 0 || !signed.constructed) continue;
            let others = false;
            let contentType = false;
            let messageDigest = false;
            for (let i = 0; i < signed.children.length; i++) {
                enforceLimit(ctx.limits, 'maxAttributes', i + 1, `${where}[${String(v)}].signedAttrs`);
                const attribute = signed.children[i] as Asn1Node;
                const type = attribute.children[0];
                // Anything that is not `SEQUENCE { OID, … }` is no attribute, and
                // is passed over: a malformed countersignature is still carried.
                if (attribute.tagClass !== 'universal' || attribute.tagNumber !== TAG_SEQUENCE || type?.tagClass !== 'universal' || type.tagNumber !== TAG_OID) continue;
                others = true;
                if (bytesEqual(type.content, CONTENT_TYPE_OID_CONTENT)) contentType = true;
                if (bytesEqual(type.content, MESSAGE_DIGEST_OID_CONTENT)) messageDigest = true;
            }
            const valuePath = `${where}[${String(v)}].signedAttrs`;
            if (contentType) ctx.emitter.emit(cmsCountersignatureContentTypeDiagnostic(valuePath, signed.offset));
            if (others && !messageDigest) ctx.emitter.emit(cmsCountersignatureNoMessageDigestDiagnostic(valuePath, signed.offset));
        }
    }
}

// ── signingCertificate (RFC 2634 §5.4) and signingCertificateV2 (RFC 5035 §3) ──

/** Web Crypto's names for the digests pkinative computes, by OID. */
const HASH_NAMES: ReadonlyMap<string, string> = /*#__PURE__*/ new Map([
    ['1.3.14.3.2.26', 'SHA-1'],
    ['2.16.840.1.101.3.4.2.1', 'SHA-256'],
    ['2.16.840.1.101.3.4.2.2', 'SHA-384'],
    ['2.16.840.1.101.3.4.2.3', 'SHA-512'],
]);
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

/** `SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies SEQUENCE OF PolicyInformation OPTIONAL }`. */
function readSigningCertificate(node: Asn1Node, ctx: Asn1Context, path: string, version: 1 | 2): SigningCertificateAttribute {
    const seq = _expectUniversal(node, TAG_SEQUENCE, path, node.offset, 'a SEQUENCE');
    const certs = _expectUniversal(seq.children[0], TAG_SEQUENCE, `${path}.certs`, seq.offset, 'a SEQUENCE OF ESSCertID');
    const policies = seq.children[1];
    // `policies` is kept out of the result — it constrains path validation in
    // a way RFC 5035 §3 leaves to the relying party — but its shape is checked,
    // so that a value this parser calls well formed is one.
    if (policies !== undefined) _expectUniversal(policies, TAG_SEQUENCE, `${path}.policies`, seq.offset, 'a SEQUENCE OF PolicyInformation');
    if (seq.children.length > 2) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, seq.offset, `holds ${String(seq.children.length)} values where RFC ${version === 1 ? '2634 §5.4' : '5035 §3'} defines at most two`);
    }
    if (certs.children.length === 0) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', `${path}.certs`, certs.offset, 'is empty; its first entry is what names the signing certificate');
    }
    const certIds: EssCertId[] = [];
    for (let i = 0; i < certs.children.length; i++) {
        // The entries after the first constrain the certification path (RFC
        // 5035 §3), so the bound is the one a path already has.
        enforceLimit(ctx.limits, 'maxChainLength', i + 1, `${path}.certs[${String(i)}]`);
        certIds.push(readEssCertId(certs.children[i] as Asn1Node, ctx, `${path}.certs[${String(i)}]`, version));
    }
    return Object.freeze({ version, certIds: Object.freeze(certIds) });
}

/**
 * `ESSCertID ::= SEQUENCE { certHash, issuerSerial OPTIONAL }` (v1) or
 * `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash, issuerSerial OPTIONAL }` (v2).
 */
function readEssCertId(node: Asn1Node, ctx: Asn1Context, path: string, version: 1 | 2): EssCertId {
    const seq = _expectUniversal(node, TAG_SEQUENCE, path, node.offset, version === 1 ? 'an ESSCertID SEQUENCE' : 'an ESSCertIDv2 SEQUENCE');
    let at = 0;
    let hashAlgorithm = version === 1 ? 'SHA-1' : 'SHA-256';
    // hashAlgorithm is a SEQUENCE and certHash an OCTET STRING, so one tag test
    // decides whether the DEFAULT was written out.
    const first = seq.children[0];
    if (version === 2 && first !== undefined && first.tagClass === 'universal' && first.tagNumber === TAG_SEQUENCE) {
        const algorithm = _viaX509(`${path}.hashAlgorithm`, first.offset, () =>
            _readAlgorithmIdentifier(first, ctx, `${path}.hashAlgorithm`, 'PKI_X509_STRUCTURE_INVALID', seq.offset));
        // The DEFAULT is `{ algorithm id-sha256 }` with no parameters; SHA-256
        // with NULL parameters is a different value, which DER must encode.
        if (algorithm.oid === OID_SHA256 && algorithm.parameters === undefined) {
            ctx.emitter.emit(defaultEncodedDiagnostic(`${path}.hashAlgorithm`, 'sha256', first.offset));
        }
        hashAlgorithm = HASH_NAMES.get(algorithm.oid) ?? algorithm.oid;
        at = 1;
    }
    const certHash = _readOctetString(_expectUniversal(seq.children[at], TAG_OCTET_STRING, `${path}.certHash`, seq.offset, 'an OCTET STRING'), ctx);
    const issuerSerialNode = seq.children[at + 1];
    const issuerSerial = issuerSerialNode === undefined ? undefined : readIssuerSerial(issuerSerialNode, ctx, `${path}.issuerSerial`);
    if (seq.children.length > at + 2) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, seq.offset, 'holds a value after issuerSerial');
    }
    return Object.freeze({ hashAlgorithm, certHash, issuerSerial });
}

/** `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }`. */
function readIssuerSerial(node: Asn1Node, ctx: Asn1Context, path: string): EssCertId['issuerSerial'] {
    const seq = _expectUniversal(node, TAG_SEQUENCE, path, node.offset, 'an IssuerSerial SEQUENCE');
    if (seq.children.length !== 2) {
        throw _cmsError('PKI_CMS_STRUCTURE_INVALID', path, seq.offset, `holds ${String(seq.children.length)} values where IssuerSerial holds an issuer and a serial number`);
    }
    const issuerNode = _expectUniversal(seq.children[0], TAG_SEQUENCE, `${path}.issuer`, seq.offset, 'a GeneralNames SEQUENCE');
    const issuer = _viaX509(`${path}.issuer`, issuerNode.offset, () => _readGeneralNames(issuerNode, ctx, `${path}.issuer`, false));
    return Object.freeze({ issuer, serialNumber: _readSerialNumber(seq.children[1], ctx, `${path}.serialNumber`, seq.offset) });
}

/**
 * A `CertificateSerialNumber`, as the certificate parser exposes one.
 *
 * @internal
 */
export function _readSerialNumber(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): SerialNumber {
    const serial = _expectUniversal(node, TAG_INTEGER, path, parentOffset, 'an INTEGER');
    const value = _readInteger(serial, ctx);
    const serialNumber: SerialNumber = { bytes: serial.content, hex: toHex(serial.content), value };
    return Object.freeze(serialNumber);
}
