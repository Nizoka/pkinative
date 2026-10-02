/**
 * pkinative — CMS SignedData creation
 * ===================================
 * An RFC 5652 `SignedData`, wrapped in its `ContentInfo`, signed by a key the
 * caller holds — and the one edit a signed message legitimately receives
 * afterwards, an unsigned attribute such as an RFC 3161 signature timestamp.
 *
 * Signed attributes are always written. Every modern profile requires them
 * (S/MIME, CAdES, PAdES, RFC 3161 itself), and they are what makes a detached
 * signature over a digest possible at all: with them the signature covers the
 * attributes, and the content enters only through `messageDigest`. The
 * attribute SET is built in DER order from the start (X.690 §11.6) and the
 * signature covers exactly those bytes under the `SET OF` tag, before the
 * first octet is changed to the `[0]` the structure transmits (§5.4). Nothing
 * is ever re-sorted after signing, because the signed bytes are the signed
 * bytes.
 *
 * `build` never parses: the signer's certificate arrives as the parsed
 * `Certificate` data, and `addUnsignedAttribute` works on the encoding with
 * the TLV cursor, copying every byte it does not have to change.
 *
 * @module build/build-signed-data
 */

import { readTlvHeader, walkChildren, type TlvHeader } from '../asn1/asn1-cursor.js';
import {
    encodeExplicit,
    encodeImplicit,
    encodeInteger,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeSequence,
    encodeSetOf,
    encodeTime,
    encodeTlv,
} from '../asn1/asn1-encode.js';
import { decodeOid } from '../asn1/asn1-oid.js';
import { TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET } from '../asn1/asn1-tags.js';
import { assertBytes, byteView, bytesEqual, concatBytes } from '../core/bytes.js';
import { _pkiError } from '../core/pki-error-guard.js';
import { DEFAULT_PKI_LIMITS, enforceLimit, resolveLimits } from '../core/pki-limits.js';
import { computeFingerprintAsync } from '../hash/fingerprint.js';
import type { TagClass } from '../types/asn1-types.js';
import type { PkiBuildOptions } from '../types/build-types.js';
import type { SignatureHash, Signer } from '../types/crypto-types.js';
import { PkiCmsError, PkiCryptoError, PkiError } from '../types/pki-errors.js';
import type { PkiLimits } from '../types/pki-types.js';
import type { Certificate, Extension, SubjectKeyIdentifierExtension } from '../types/x509-types.js';
import {
    OID_ATTR_ALGORITHM_PROTECTION,
    OID_ATTR_CONTENT_TYPE,
    OID_ATTR_COUNTERSIGNATURE,
    OID_ATTR_MESSAGE_DIGEST,
    OID_ATTR_SIGNING_CERTIFICATE_V2,
    OID_ATTR_SIGNING_TIME,
    OID_ATTR_TIMESTAMP_TOKEN,
    OID_DATA,
    OID_SIGNED_DATA,
    SIGNED_ONLY_ATTRIBUTES,
} from '../core/cms-oids.js';
import { computeSignatureValue, encodeSignatureAlgorithm } from './build-certificate.js';
import { encodeAlgorithmIdentifier, encodeAttribute } from './build-structures.js';

/** Attributes RFC 5652 §11, RFC 2634, RFC 5035 and RFC 6211 allow only among the signed attributes. */
const SIGNED_ONLY = SIGNED_ONLY_ATTRIBUTES;

/**
 * The digests a signer can name, keyed by the literal union so the lookup is
 * total. Their AlgorithmIdentifiers are written with **absent** parameters:
 * RFC 5754 §2 says an implementation "MUST generate" them that way.
 */
const DIGESTS: Readonly<Record<SignatureHash, { readonly oid: string; readonly length: number }>> = /*#__PURE__*/ Object.freeze({
    'SHA-1': { oid: '1.3.14.3.2.26', length: 20 },
    'SHA-256': { oid: '2.16.840.1.101.3.4.2.1', length: 32 },
    'SHA-384': { oid: '2.16.840.1.101.3.4.2.2', length: 48 },
    'SHA-512': { oid: '2.16.840.1.101.3.4.2.3', length: 64 },
});

/**
 * The `SignedData.version` each `CertificateChoices` alternative forces, by
 * identifier octet (RFC 5652 §5.1): a certificate or an obsolete PKCS #6
 * extended certificate leaves it at 1, an attribute certificate v1 makes it
 * 3, v2 makes it 4, and `other` makes it 5.
 */
const CERTIFICATE_CHOICES: ReadonlyMap<number, number> = /*#__PURE__*/ new Map([[0x30, 1], [0xa0, 1], [0xa1, 3], [0xa2, 4], [0xa3, 5]]);

/** The same for `RevocationInfoChoice`: a CRL leaves it at 1, `other` (an OCSP response, RFC 5940) makes it 5. */
const CRL_CHOICES: ReadonlyMap<number, number> = /*#__PURE__*/ new Map([[0x30, 1], [0xa1, 5]]);

// ── Input ────────────────────────────────────────────────────────────

/** What `createSignedData` signs, and what it writes around the signature. */
export interface CreateSignedDataInput {
    /**
     * The content to sign. Exactly one of `content` and `contentDigest` is
     * given. It is hashed with the signer's digest and, unless `detached`, embedded.
     */
    readonly content?: Uint8Array | undefined;
    /**
     * The content's digest, already computed with the signer's digest — the
     * detached, pre-hashed case of a PDF signature, whose signer hashes the
     * `/ByteRange` itself. Its length must be the digest's. Implies `detached`.
     */
    readonly contentDigest?: Uint8Array | undefined;
    /**
     * Omit `eContent`, so the signature travels without what it signs.
     * Defaults to `false` with `content`; `contentDigest` makes it `true`,
     * and `detached: false` beside a `contentDigest` is refused.
     */
    readonly detached?: boolean | undefined;
    /**
     * `eContentType`, and the value of the `contentType` attribute. Defaults
     * to `id-data`; any other type makes the SignedData version 3.
     */
    readonly contentType?: string | undefined;
    /**
     * The signer's parsed certificate. Its `issuer.der` and
     * `serialNumber.bytes` go into the signer identifier byte for byte, its
     * `der` is embedded in `certificates` and hashed for SigningCertificateV2.
     */
    readonly certificate: Certificate;
    /**
     * How the SignerInfo names the certificate. `issuerAndSerialNumber`
     * (default) gives a version 1 SignerInfo; `subjectKeyIdentifier` reads
     * the certificate's decoded subjectKeyIdentifier extension, and gives
     * version 3.
     *
     * Keep the default unless the reader is known: `issuerAndSerialNumber` is
     * what every CMS reader parses, while some deployed ones cannot parse a
     * `subjectKeyIdentifier` signer at all — libksba 1.6.7 (gpgsm 2.4.9)
     * fails with "TLV length too large" and pyca/cryptography's
     * `pkcs7.load_der_pkcs7_certificates` with "Unable to parse PKCS7 data",
     * on OpenSSL's output exactly as on pkinative's.
     */
    readonly sid?: 'issuerAndSerialNumber' | 'subjectKeyIdentifier' | undefined;
    /**
     * Further certificates to embed verbatim, typically the chain. The
     * signer's certificate is always embedded once, whether or not it is
     * listed here. Each is one `CertificateChoices` encoding.
     */
    readonly certificates?: readonly Uint8Array[] | undefined;
    /** Revocation lists to embed verbatim, each a `CertificateList` or an `other [1]` RevocationInfoChoice. */
    readonly crls?: readonly Uint8Array[] | undefined;
    /**
     * The time the signer claims, in epoch milliseconds, truncated to whole
     * seconds (RFC 5652 §11.3 forbids a fraction). Omitted by default: the
     * PAdES baseline forbids the attribute and S/MIME expects it, so the
     * caller decides.
     */
    readonly signingTime?: number | undefined;
    /**
     * Write SigningCertificateV2 (RFC 5035), binding the signature to this
     * certificate and not merely to its key. Defaults to `true`; CAdES,
     * PAdES and RFC 3161 require it.
     */
    readonly signingCertificateV2?: boolean | undefined;
    /**
     * Write CMSAlgorithmProtection (RFC 6211), the signer's own signed
     * statement of the algorithms it used. Defaults to `true` (RFC 8933 §4).
     */
    readonly algorithmProtection?: boolean | undefined;
    /**
     * Further signed attributes, each one `Attribute` encoding, written
     * verbatim — e.g. adbe-revocationInfoArchival. A type the builder writes
     * itself, a repeated type, or a countersignature is refused.
     */
    readonly signedAttributes?: readonly Uint8Array[] | undefined;
    /**
     * Unsigned attributes, each one `Attribute` encoding, written verbatim —
     * e.g. a timestamp token already in hand. A type RFC 5652 allows only
     * signed is refused.
     */
    readonly unsignedAttributes?: readonly Uint8Array[] | undefined;
}

// ── Helpers ──────────────────────────────────────────────────────────

function misuse(message: string): PkiError {
    return new PkiError('PKI_API_MISUSE', `pkinative: ${message}`);
}

// A plain boolean, not a type predicate: a predicate would narrow the
// header to `never` on the false side, where the offset is still needed.
function isTag(header: TlvHeader | undefined, tagClass: TagClass, tagNumber: number, constructed: boolean): boolean {
    return header !== undefined && header.tagClass === tagClass && header.tagNumber === tagNumber && header.constructed === constructed;
}

/** The type OID of a caller's `Attribute`, or `null` when it is not one complete Attribute encoding. */
function readAttributeType(bytes: Uint8Array): string | null {
    const outer = readTlvHeader(bytes, 0, 'attribute');
    if (outer.end !== bytes.length || !isTag(outer, 'universal', TAG_SEQUENCE, true)) return null;
    const fields: TlvHeader[] = [];
    for (const field of walkChildren(bytes, outer, 'attribute')) {
        fields.push(field);
        // An Attribute has two fields; stopping at the third bounds the walk.
        if (fields.length > 2) return null;
    }
    const [type, values] = fields;
    if (type === undefined || !isTag(type, 'universal', TAG_OID, false) || !isTag(values, 'universal', TAG_SET, true)) return null;
    return decodeOid(bytes.subarray(type.contentStart, type.end));
}

/**
 * Check that the caller's bytes are one `Attribute` — a SEQUENCE of an
 * OBJECT IDENTIFIER and a SET — and return its type.
 *
 * Whatever is wrong with them, the remedy is the same, so every failure is
 * one `PKI_API_MISUSE`: these bytes are an argument, not an input to parse.
 */
function attributeType(der: unknown, what: string): string {
    const bytes = assertBytes(der, what);
    let type: string | null;
    try {
        type = readAttributeType(bytes);
    } catch (error) {
        // A PkiError is the bytes' fault and becomes the one misuse below;
        // anything else is a bug and goes on as one.
        _pkiError(error);
        type = null;
    }
    if (type === null) {
        throw misuse(`${what} is not a DER Attribute — one SEQUENCE of an OBJECT IDENTIFIER and a SET OF values (RFC 5652 §5.3); pass one complete encoding, e.g. from encodeAttribute`);
    }
    return type;
}

/**
 * The SignedData version one caller-supplied bag entry forces, after checking
 * it is one complete encoding of an alternative the field allows.
 */
function bagEntryVersion(der: Uint8Array, what: string, choices: ReadonlyMap<number, number>): number {
    let header: TlvHeader | null;
    try {
        header = readTlvHeader(der, 0, what);
    } catch (error) {
        _pkiError(error);
        header = null;
    }
    const version = header !== null && header.end === der.length ? choices.get(byteView(der).getUint8(0)) : undefined;
    if (version === undefined) {
        throw misuse(`${what} is not one complete DER encoding of an alternative the field allows (RFC 5652 §10.2) — pass each certificate or revocation list as its own DER, e.g. certificate.der`);
    }
    return version;
}

/** The digest the SignerInfo names, which hashes the content and — through the signature — the attributes. */
function signerDigest(signer: Signer): SignatureHash {
    const algorithm = signer.algorithm;
    // RFC 8419 §3.1: Ed25519 is pure, and SHA-512 hashes only what the
    // messageDigest attribute carries. Ed448 needs SHAKE256, which neither
    // Web Crypto nor the hash layer provides.
    if (algorithm.name === 'Ed448') {
        throw new PkiCryptoError('PKI_CRYPTO_ALGORITHM_UNSUPPORTED',
            'pkinative: a CMS signature with Ed448 names SHAKE256 as its digest (RFC 8419 §3.1), which neither Web Crypto nor pkinative computes — sign with Ed25519, ECDSA or RSA instead', '1.3.101.113');
    }
    return algorithm.name === 'Ed25519' ? 'SHA-512' : algorithm.hash;
}

function isSubjectKeyIdentifier(extension: Extension): extension is SubjectKeyIdentifierExtension {
    return extension.kind === 'subjectKeyIdentifier';
}

/** `SignerIdentifier` and the `SignerInfo.version` it implies (RFC 5652 §5.3). */
function signerIdentifier(certificate: Certificate, sid: CreateSignedDataInput['sid'], serial: Uint8Array): { readonly der: Uint8Array; readonly version: 1 | 3 } {
    if (sid === 'subjectKeyIdentifier') {
        const extension = certificate.extensions.find(isSubjectKeyIdentifier);
        if (extension === undefined) {
            throw misuse('sid \'subjectKeyIdentifier\' needs a certificate with a decoded subjectKeyIdentifier extension, and this one has none — use \'issuerAndSerialNumber\', or parse the certificate with decodeExtensions left on');
        }
        // `[0] SubjectKeyIdentifier`, implicit by the module default: the
        // OCTET STRING re-tagged, primitive (RFC 4134 §4.7 shows `80 14 …`).
        return { der: encodeImplicit(0, encodeOctetString(extension.keyIdentifier)), version: 3 };
    }
    if (sid !== undefined && sid !== 'issuerAndSerialNumber') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: sid must be 'issuerAndSerialNumber' or 'subjectKeyIdentifier', got ${String(sid)}`);
    }
    return { der: encodeSequence([assertBytes(certificate.issuer.der, 'certificate.issuer.der'), serial]), version: 1 };
}

/** The signingTime value: UTCTime through 2049, GeneralizedTime from 2050, whole seconds (RFC 5652 §11.3). */
function signingTimeValue(time: number): Uint8Array {
    if (typeof time !== 'number' || !Number.isFinite(time)) {
        throw misuse(`signingTime is an instant in epoch milliseconds and must be a finite number, got ${String(time)}`);
    }
    // Truncated rather than refused: `Date.now()` almost always carries
    // milliseconds, and a claimed signing time is not precise to one anyway.
    return encodeTime(Math.floor(time / 1000) * 1000);
}

/** The content octets to embed, if any, and the digest the messageDigest attribute commits to. */
async function resolveContent(input: CreateSignedDataInput, digest: SignatureHash): Promise<{ readonly eContent: Uint8Array | undefined; readonly messageDigest: Uint8Array }> {
    if ((input.content === undefined) === (input.contentDigest === undefined)) {
        throw misuse('createSignedData takes exactly one of content and contentDigest — content to have it hashed (and embedded unless detached), contentDigest for a detached signature over bytes you have already hashed');
    }
    if (input.contentDigest !== undefined) {
        if (input.detached === false) {
            throw misuse('contentDigest makes the signature detached, since there is no content to embed — drop detached: false, or pass the content itself');
        }
        const messageDigest = assertBytes(input.contentDigest, 'contentDigest');
        if (messageDigest.length !== DIGESTS[digest].length) {
            throw misuse(`contentDigest is ${String(messageDigest.length)} octets, and a ${digest} digest is ${String(DIGESTS[digest].length)} — hash the content with ${digest}, the digest the signer's algorithm implies`);
        }
        return { eContent: undefined, messageDigest };
    }
    const content = assertBytes(input.content, 'content');
    return { eContent: input.detached === true ? undefined : content, messageDigest: await computeFingerprintAsync(content, digest) };
}

// ── createSignedData ─────────────────────────────────────────────────

/**
 * Build and sign an RFC 5652 SignedData, returned as a DER `ContentInfo`.
 *
 * ```ts
 * import { createSignedData, parseCertificate } from 'pkinative';
 *
 * const p7s = await createSignedData(
 *     { content: message, detached: true, certificate: parseCertificate(certDer), signingTime: Date.now() },
 *     { key: privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } },
 * );
 * ```
 *
 * One SignerInfo, with signed attributes always: `contentType` and
 * `messageDigest`, then `signingCertificateV2` and `CMSAlgorithmProtection`
 * unless turned off, `signingTime` when given, and the caller's extras. The
 * digest is the signer's own hash, SHA-512 for Ed25519 (RFC 8419); the
 * signature algorithm is written in full, parameters included, never as a
 * bare `rsaEncryption`. The version fields follow RFC 5652 §5.1 and §5.3
 * from what the structure carries.
 *
 * For a PDF signature, pass `contentDigest` — the `/ByteRange` hashed with
 * the signer's digest — and embed the result in `/Contents`; add a signature
 * timestamp afterwards with {@link addUnsignedAttribute}.
 *
 * Where the reader is unknown, sign with ECDSA or RSA: an Ed25519 SignerInfo
 * is correct RFC 8419, and not every deployed reader verifies it — gpgsm
 * 2.4.9 refuses one ("DSA requires the hash length to be a multiple of 8
 * bits") whether OpenSSL or pkinative wrote it.
 *
 * @param input   What is signed and what is written around it; see {@link CreateSignedDataInput}.
 * @param signer  The key that signs: a `SigningKey` for Web Crypto, or an `ExternalSigner` for a key held elsewhere.
 * @param options `limits`: `maxAttributes` bounds each attribute list, `maxCmsCertificatesAndCrls` the certificates and revocation lists.
 * @returns The `ContentInfo` (id-signedData), in DER.
 * @throws {PkiError} `PKI_API_MISUSE` for both or neither of `content` and
 *   `contentDigest`, a digest of the wrong length, `detached: false` with a
 *   digest, `sid: 'subjectKeyIdentifier'` on a certificate without the
 *   extension, a malformed or duplicated extra attribute, a signed-only type
 *   among the unsigned attributes, a bag entry that is not one DER value, or
 *   an `ExternalSigner` that returns other than what `crypto.subtle.sign`
 *   would; `PKI_INVALID_OPTION` for an unknown `sid`; `PKI_INVALID_INPUT`
 *   where bytes are expected and something else is given.
 * @throws {PkiCryptoError} `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` for Ed448 or an
 *   algorithm with no OID; `PKI_CRYPTO_UNAVAILABLE` and
 *   `PKI_CRYPTO_KEY_UNSUPPORTED` as for `createCertificate`.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed `contentType`;
 *   `PKI_ASN1_VALUE_OUT_OF_RANGE` for a `signingTime` outside 0000–9999.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxAttributes` or `maxCmsCertificatesAndCrls`.
 */
export async function createSignedData(input: CreateSignedDataInput, signer: Signer, options?: PkiBuildOptions): Promise<Uint8Array> {
    const limits: PkiLimits = options?.limits === undefined ? DEFAULT_PKI_LIMITS : resolveLimits(options.limits);
    const digest = signerDigest(signer);
    // Before the digest table is read: resolveSigner is what refuses a hash
    // the table does not hold.
    const signatureAlgorithm = encodeSignatureAlgorithm(signer);
    const digestAlgorithm = encodeAlgorithmIdentifier(DIGESTS[digest].oid);
    const contentType = input.contentType ?? OID_DATA;
    const certificate = input.certificate;
    const certificateDer = assertBytes(certificate.der, 'certificate.der');
    const serial = encodeTlv('universal', TAG_INTEGER, false, assertBytes(certificate.serialNumber.bytes, 'certificate.serialNumber.bytes'));
    const sid = signerIdentifier(certificate, input.sid, serial);

    // ── The bag, checked before any hashing is spent on the call ──
    const extraCertificates = input.certificates ?? [];
    const crls = input.crls ?? [];
    enforceLimit(limits, 'maxCmsCertificatesAndCrls', extraCertificates.length + crls.length, 'the certificates and revocation lists given');
    let version = sid.version === 3 || contentType !== OID_DATA ? 3 : 1;
    const certificates: Uint8Array[] = [certificateDer];
    extraCertificates.forEach((entry, index) => {
        const bytes = assertBytes(entry, `certificates[${String(index)}]`);
        version = Math.max(version, bagEntryVersion(bytes, `certificates[${String(index)}]`, CERTIFICATE_CHOICES));
        if (!certificates.some((held) => bytesEqual(held, bytes))) certificates.push(bytes);
    });
    const revocation = crls.map((entry, index) => {
        const bytes = assertBytes(entry, `crls[${String(index)}]`);
        version = Math.max(version, bagEntryVersion(bytes, `crls[${String(index)}]`, CRL_CHOICES));
        return bytes;
    });
    // Again on what is written, which the signer's certificate may have
    // made one longer than what was given.
    enforceLimit(limits, 'maxCmsCertificatesAndCrls', certificates.length + revocation.length, 'the certificates and revocation lists being embedded');

    // ── The caller's attributes, checked before anything is hashed ──
    const written = new Set([OID_ATTR_CONTENT_TYPE, OID_ATTR_MESSAGE_DIGEST]);
    if (input.signingTime !== undefined) written.add(OID_ATTR_SIGNING_TIME);
    if (input.signingCertificateV2 !== false) written.add(OID_ATTR_SIGNING_CERTIFICATE_V2);
    if (input.algorithmProtection !== false) written.add(OID_ATTR_ALGORITHM_PROTECTION);
    const extraSigned = input.signedAttributes ?? [];
    enforceLimit(limits, 'maxAttributes', written.size + extraSigned.length, 'the signed attributes being built');
    extraSigned.forEach((attribute, index) => {
        const what = `signedAttributes[${String(index)}]`;
        const type = attributeType(attribute, what);
        if (type === OID_ATTR_COUNTERSIGNATURE) {
            throw misuse(`${what} is a countersignature, which RFC 5652 §11.4 allows only among the unsigned attributes — pass it in unsignedAttributes`);
        }
        if (written.has(type)) {
            // One instance of each: a verifier that meets two messageDigest
            // attributes cannot know which one the signer meant.
            throw misuse(`${what} is a second ${type} attribute; the signed attributes carry one of each — createSignedData writes contentType and messageDigest itself, and signingTime, signingCertificateV2 and algorithmProtection when their options ask, so drop this one or turn that option off`);
        }
        written.add(type);
    });
    const unsigned = input.unsignedAttributes ?? [];
    enforceLimit(limits, 'maxAttributes', unsigned.length, 'the unsigned attributes being built');
    unsigned.forEach((attribute, index) => {
        const what = `unsignedAttributes[${String(index)}]`;
        const type = attributeType(attribute, what);
        if (SIGNED_ONLY.has(type)) {
            throw misuse(`${what} is a ${type} attribute, which RFC 5652 §11, RFC 5035 and RFC 6211 allow only among the signed attributes — a verifier rejects it unsigned; pass it in signedAttributes, or use the option that writes it`);
        }
    });

    // ── The signed attributes ──
    const { eContent, messageDigest } = await resolveContent(input, digest);
    const signed: Uint8Array[] = [
        encodeAttribute(OID_ATTR_CONTENT_TYPE, [encodeObjectIdentifier(contentType)]),
        encodeAttribute(OID_ATTR_MESSAGE_DIGEST, [encodeOctetString(messageDigest)]),
    ];
    if (input.signingTime !== undefined) signed.push(encodeAttribute(OID_ATTR_SIGNING_TIME, [signingTimeValue(input.signingTime)]));
    if (input.signingCertificateV2 !== false) {
        const essCertIdV2 = encodeSequence([
            // hashAlgorithm DEFAULT id-sha256: DER omits a DEFAULT (X.690 §11.5).
            ...(digest === 'SHA-256' ? [] : [digestAlgorithm]),
            encodeOctetString(await computeFingerprintAsync(certificateDer, digest)),
            // IssuerSerial: the issuer as the one directoryName [4] — explicit,
            // because Name is a CHOICE — and the serial (RFC 5035 §4).
            encodeSequence([encodeSequence([encodeExplicit(4, certificate.issuer.der)]), serial]),
        ]);
        signed.push(encodeAttribute(OID_ATTR_SIGNING_CERTIFICATE_V2, [encodeSequence([encodeSequence([essCertIdV2])])]));
    }
    if (input.algorithmProtection !== false) {
        // `signatureAlgorithm [1]` is implicit by the module default: the
        // AlgorithmIdentifier's contents under A1, no inner SEQUENCE (RFC 6211 §2).
        signed.push(encodeAttribute(OID_ATTR_ALGORITHM_PROTECTION, [encodeSequence([digestAlgorithm, encodeImplicit(1, signatureAlgorithm)])]));
    }
    for (const attribute of extraSigned) signed.push(attribute);

    // RFC 5652 §5.4: the signature covers the DER SET OF, tag 0x31; the
    // structure transmits the same length and content under [0] IMPLICIT.
    // encodeSetOf sorts, so the bytes signed are already the DER ones, and
    // the transmitted copy differs from them in its first octet only.
    const signedSet = encodeSetOf(signed);
    const signature = await computeSignatureValue(signedSet, signer);
    const transmitted = signedSet.slice();
    transmitted[0] = 0xa0;

    const signerInfo = encodeSequence([
        encodeInteger(sid.version),
        sid.der,
        digestAlgorithm,
        transmitted,
        signatureAlgorithm,
        encodeOctetString(signature),
        ...(unsigned.length > 0 ? [encodeImplicit(1, encodeSetOf(unsigned))] : []),
    ]);

    const encapContentInfo = encodeSequence([
        encodeObjectIdentifier(contentType),
        ...(eContent === undefined ? [] : [encodeExplicit(0, encodeOctetString(eContent))]),
    ]);
    const signedData = encodeSequence([
        encodeInteger(version),
        encodeSetOf([digestAlgorithm]),
        encapContentInfo,
        encodeImplicit(0, encodeSetOf(certificates)),
        ...(revocation.length > 0 ? [encodeImplicit(1, encodeSetOf(revocation))] : []),
        encodeSetOf([signerInfo]),
    ]);
    return encodeSequence([encodeObjectIdentifier(OID_SIGNED_DATA), encodeExplicit(0, signedData)]);
}

// ── addUnsignedAttribute ─────────────────────────────────────────────

function structure(path: string, expected: string, offset: number): PkiCmsError {
    return new PkiCmsError('PKI_CMS_STRUCTURE_INVALID',
        `pkinative: ${path} is not ${expected} (RFC 5652 §3, §5) — pass the DER ContentInfo of a SignedData, as createSignedData returns it`, path, offset);
}

/** The children of `parent`, refused past `max` — the most the field can hold, which bounds the walk. */
function fieldsOf(data: Uint8Array, parent: TlvHeader, path: string, max: number): TlvHeader[] {
    const fields: TlvHeader[] = [];
    for (const field of walkChildren(data, parent, path)) {
        if (fields.length === max) throw structure(path, `a value of at most ${String(max)} fields`, field.offset);
        fields.push(field);
    }
    return fields;
}

function expectTag(header: TlvHeader | undefined, tagClass: TagClass, tagNumber: number, constructed: boolean, path: string, expected: string, parent: TlvHeader): TlvHeader {
    if (header === undefined) throw structure(path, expected, parent.end);
    if (!isTag(header, tagClass, tagNumber, constructed)) throw structure(path, expected, header.offset);
    return header;
}

/**
 * Add one unsigned attribute to one signer of a SignedData.
 *
 * ```ts
 * import { addUnsignedAttribute, encodeAttribute } from 'pkinative';
 *
 * // Any unsigned attribute; for a timestamp token, addTimeStampToken writes it for you.
 * const extended = addUnsignedAttribute(p7s, 0, encodeAttribute('1.2.3.4', [valueDer]));
 * ```
 *
 * This is how a signature timestamp — PAdES-T, CAdES-T — is added after
 * signing, and it is done by surgery on the encoding rather than by a parse
 * and a rebuild: every octet of the SignerInfo other than its
 * `unsignedAttrs [1]` is copied as it is, above all the signed attributes and
 * the signature, and only the lengths of the enclosing values are written
 * again. Re-encoding the signed attributes from decoded values would re-sort a
 * set some other signer never sorted, and break a signature that was good.
 *
 * `unsignedAttrs` is created when absent, and it and `signerInfos` are
 * re-sorted into DER order; neither is covered by any signature.
 *
 * @param signedDataDer The DER `ContentInfo` of a SignedData. It is not modified.
 * @param signerIndex   Which `signerInfos` entry, counted from 0 in encoded order.
 * @param attributeDer  One `Attribute` encoding, e.g. from `encodeAttribute`.
 * @param options       `limits`: `maxInputBytes`, `maxSignerInfos` and `maxAttributes` apply.
 * @returns A new `ContentInfo`, in DER.
 * @throws {PkiError} `PKI_API_MISUSE` when `attributeDer` is not one Attribute,
 *   names a type RFC 5652 allows only signed, or `signerIndex` is not the index
 *   of a signer; `PKI_INVALID_INPUT` when an argument that must be bytes is not.
 * @throws {PkiCmsError} `PKI_CMS_CONTENT_TYPE_UNEXPECTED` for a ContentInfo
 *   that is not id-signedData; `PKI_CMS_STRUCTURE_INVALID`, with a path, for
 *   one that does not have the SignedData shape.
 * @throws {PkiEncodingError} For input that is not DER.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxInputBytes`, `maxSignerInfos` or `maxAttributes`.
 */
export function addUnsignedAttribute(signedDataDer: Uint8Array, signerIndex: number, attributeDer: Uint8Array, options?: PkiBuildOptions): Uint8Array {
    const limits: PkiLimits = options?.limits === undefined ? DEFAULT_PKI_LIMITS : resolveLimits(options.limits);
    const der = assertBytes(signedDataDer, 'signedDataDer');
    const attribute = assertBytes(attributeDer, 'attributeDer');
    const type = attributeType(attribute, 'attributeDer');
    if (SIGNED_ONLY.has(type)) {
        throw misuse(`attributeDer is a ${type} attribute, which RFC 5652 §11, RFC 5035 and RFC 6211 allow only among the signed attributes — it cannot be added after signing; sign again with it`);
    }
    if (!Number.isSafeInteger(signerIndex) || signerIndex < 0) {
        throw misuse(`signerIndex is the position of a signer in signerInfos, a non-negative integer, got ${String(signerIndex)}`);
    }
    enforceLimit(limits, 'maxInputBytes', der.length, 'the SignedData');

    // ── ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT content } ──
    const contentInfo = readTlvHeader(der, 0, 'contentInfo');
    if (!isTag(contentInfo, 'universal', TAG_SEQUENCE, true)) throw structure('contentInfo', 'a SEQUENCE', 0);
    if (contentInfo.end !== der.length) throw structure('contentInfo', 'the whole input — bytes follow it', contentInfo.end);
    const [typeField, contentField] = fieldsOf(der, contentInfo, 'contentInfo', 2);
    const contentTypeField = expectTag(typeField, 'universal', TAG_OID, false, 'contentInfo.contentType', 'an OBJECT IDENTIFIER', contentInfo);
    const contentType = decodeOid(der.subarray(contentTypeField.contentStart, contentTypeField.end));
    if (contentType !== OID_SIGNED_DATA) {
        throw new PkiCmsError('PKI_CMS_CONTENT_TYPE_UNEXPECTED',
            `pkinative: this ContentInfo holds ${contentType}, not id-signedData (${OID_SIGNED_DATA}) — only a SignedData has signers to add an attribute to`, 'contentInfo.contentType', contentTypeField.offset);
    }
    const explicit = expectTag(contentField, 'context', 0, true, 'contentInfo.content', 'a [0] EXPLICIT value', contentInfo);
    const signedData = expectTag(fieldsOf(der, explicit, 'contentInfo.content', 1)[0], 'universal', TAG_SEQUENCE, true, 'signedData', 'a SEQUENCE', explicit);

    // ── SignedData: version, digestAlgorithms, encapContentInfo, [0]?, [1]?, signerInfos ──
    const fields = fieldsOf(der, signedData, 'signedData', 6);
    expectTag(fields[0], 'universal', TAG_INTEGER, false, 'signedData.version', 'an INTEGER', signedData);
    expectTag(fields[1], 'universal', TAG_SET, true, 'signedData.digestAlgorithms', 'a SET', signedData);
    expectTag(fields[2], 'universal', TAG_SEQUENCE, true, 'signedData.encapContentInfo', 'a SEQUENCE', signedData);
    const last = fields.length - 1;
    for (let index = 3; index < last; index++) {
        const field = fields[index] as TlvHeader;
        if (!isTag(field, 'context', 0, true) && !isTag(field, 'context', 1, true)) {
            throw structure(`signedData[${String(index)}]`, 'certificates [0] or crls [1]', field.offset);
        }
    }
    const signerInfos = expectTag(last < 3 ? undefined : fields[last], 'universal', TAG_SET, true, 'signedData.signerInfos', 'a SET', signedData);

    const infos: TlvHeader[] = [];
    for (const info of walkChildren(der, signerInfos, 'signerInfos')) {
        infos.push(expectTag(info, 'universal', TAG_SEQUENCE, true, `signerInfos[${String(infos.length)}]`, 'a SEQUENCE', signerInfos));
        enforceLimit(limits, 'maxSignerInfos', infos.length, 'the signerInfos of the SignedData');
    }
    const target = infos[signerIndex];
    if (target === undefined) {
        throw misuse(`signerIndex ${String(signerIndex)} is out of range — this SignedData has ${String(infos.length)} signer(s), counted from 0`);
    }

    // ── SignerInfo: version, sid, digestAlgorithm, [0]?, signatureAlgorithm, signature, [1]? ──
    const path = `signerInfos[${String(signerIndex)}]`;
    const parts = fieldsOf(der, target, path, 7);
    expectTag(parts[0], 'universal', TAG_INTEGER, false, `${path}.version`, 'an INTEGER', target);
    if (!isTag(parts[1], 'context', 0, false)) expectTag(parts[1], 'universal', TAG_SEQUENCE, true, `${path}.sid`, 'an IssuerAndSerialNumber or a [0] SubjectKeyIdentifier', target);
    expectTag(parts[2], 'universal', TAG_SEQUENCE, true, `${path}.digestAlgorithm`, 'an AlgorithmIdentifier', target);
    let at = isTag(parts[3], 'context', 0, true) ? 4 : 3;
    expectTag(parts[at], 'universal', TAG_SEQUENCE, true, `${path}.signatureAlgorithm`, 'an AlgorithmIdentifier', target);
    at += 1;
    expectTag(parts[at], 'universal', TAG_OCTET_STRING, false, `${path}.signature`, 'an OCTET STRING', target);
    at += 1;
    const existing = parts[at];
    if (existing !== undefined && (!isTag(existing, 'context', 1, true) || at !== parts.length - 1)) {
        throw structure(`${path}.unsignedAttrs`, 'a [1] SET OF Attribute, the last field of a SignerInfo', existing.offset);
    }

    const attributes: Uint8Array[] = [];
    if (existing !== undefined) {
        for (const held of walkChildren(der, existing, `${path}.unsignedAttrs`)) {
            expectTag(held, 'universal', TAG_SEQUENCE, true, `${path}.unsignedAttrs[${String(attributes.length)}]`, 'an Attribute', existing);
            attributes.push(der.subarray(held.offset, held.end));
            enforceLimit(limits, 'maxAttributes', attributes.length + 1, `the unsigned attributes of ${path}`);
        }
    }
    attributes.push(attribute);

    // Every octet before unsignedAttrs is kept as it is — version, sid,
    // digestAlgorithm, signedAttrs, signatureAlgorithm, signature — and only
    // the lengths around the new [1] are written again.
    const kept = der.subarray(target.contentStart, existing === undefined ? target.end : existing.offset);
    const rebuilt = encodeTlv('universal', TAG_SEQUENCE, true, concatBytes([kept, encodeImplicit(1, encodeSetOf(attributes))]));
    const newInfos = encodeSetOf(infos.map((info) => (info === target ? rebuilt : der.subarray(info.offset, info.end))));
    const newSignedData = encodeTlv('universal', TAG_SEQUENCE, true, concatBytes([der.subarray(signedData.contentStart, signerInfos.offset), newInfos]));
    return encodeSequence([der.subarray(contentTypeField.offset, contentTypeField.end), encodeExplicit(0, newSignedData)]);
}

/**
 * Add an RFC 3161 timestamp to a signer — the step that turns a signature into
 * one whose time is proved (CAdES-T, PAdES B-T).
 *
 * ```ts
 * const signerInfo = parseSignedData(p7s).signerInfos[0];
 * const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', signerInfo.signature));
 * const response = parseTimeStampResponse(await askYourTsa(createTimeStampRequest(hash, { nonce })));
 * const stamped = addTimeStampToken(p7s, 0, response.tokenDer);
 * ```
 *
 * What the token must stamp is the hash of the signer's **signature value**,
 * the OCTET STRING's content without its tag and length (RFC 3161 Appendix A)
 * — not the content, and not the signed attributes. `verifySignedData` checks
 * exactly that, and a token over anything else is reported as stamping the
 * wrong hash.
 *
 * It is {@link addUnsignedAttribute} with the attribute written for you, so the
 * OID `1.2.840.113549.1.9.16.2.14` is typed once, here, and not at every call
 * site that needs it.
 *
 * @param signedDataDer The DER ContentInfo to add the timestamp to; not modified.
 * @param signerIndex   Which signer, counted from 0 in encoded order.
 * @param tokenDer      The TimeStampToken, as `parseTimeStampResponse` hands it back in `tokenDer`.
 * @param options       Limits, as `addUnsignedAttribute` takes them.
 * @returns A new DER ContentInfo, every signed octet unchanged.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `tokenDer` is not bytes; everything
 *   {@link addUnsignedAttribute} throws.
 */
export function addTimeStampToken(signedDataDer: Uint8Array, signerIndex: number, tokenDer: Uint8Array, options?: PkiBuildOptions): Uint8Array {
    if (!(tokenDer instanceof Uint8Array)) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: tokenDer must be the TimeStampToken bytes — the tokenDer of a parsed TimeStampResponse');
    }
    return addUnsignedAttribute(signedDataDer, signerIndex, encodeAttribute(OID_ATTR_TIMESTAMP_TOKEN, [tokenDer]), options);
}