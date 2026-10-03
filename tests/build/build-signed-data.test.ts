import { createHash, KeyObject, sign as nodeSign, webcrypto } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { describe, expect, it, vi } from 'vitest';
import { addTimeStampToken, addUnsignedAttribute, createSignedData, type CreateSignedDataInput } from '../../src/build/build-signed-data.js';
import { parseSignedData } from '../../src/cms/cms-signed-data.js';
import {
    createCertificate,
    decodeAsn1,
    encodeAttribute,
    encodeInteger,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeSequence,
    encodeSetOf,
    encodeSubjectKeyIdentifier,
    parseCertificate,
    readObjectIdentifier,
    readTime,
    encodeSignatureAlgorithm,
    type Asn1Node,
    type Certificate,
    type SignatureAlgorithm,
    type SigningKey,
} from '../../src/index.js';
import type { ExternalSigner } from '../../src/types/crypto-types.js';
import { PkiCmsError, PkiEncodingError, PkiError } from '../../src/types/pki-errors.js';
import { verifySignedData } from '../../src/verify/verify-signed-data.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';
import { issue, issueTsa, keyPair, makeRoot, makeToken, tstInfo } from '../verify/_cms-pki.js';

/**
 * CMS SignedData creation, checked without the CMS parser (written in
 * parallel): the structure is read back with the generic DER decoder, every
 * signature is verified with node:crypto's Web Crypto over the 0x31-tagged
 * signed attributes, and every digest is recomputed with node:crypto.
 */

const CN = '2.5.4.3';
const NOW = Date.UTC(2026, 0, 1);
const DAY = 86_400_000;

const OID = {
    data: '1.2.840.113549.1.7.1',
    signedData: '1.2.840.113549.1.7.2',
    contentType: '1.2.840.113549.1.9.3',
    messageDigest: '1.2.840.113549.1.9.4',
    signingTime: '1.2.840.113549.1.9.5',
    countersignature: '1.2.840.113549.1.9.6',
    signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
    timeStampToken: '1.2.840.113549.1.9.16.2.14',
    algorithmProtection: '1.2.840.113549.1.9.52',
    tstInfo: '1.2.840.113549.1.9.16.1.4',
    sha256: '2.16.840.1.101.3.4.2.1',
    sha384: '2.16.840.1.101.3.4.2.2',
    sha512: '2.16.840.1.101.3.4.2.3',
    adbeRevocation: '1.2.840.113583.1.1.8',
} as const;

type GeneratedPair = webcrypto.CryptoKeyPair;

interface Material {
    readonly signer: SigningKey;
    readonly publicKey: webcrypto.CryptoKey;
    readonly privateKey: webcrypto.CryptoKey;
    readonly certificate: Certificate;
    readonly verifyParams: object;
    /** The ECDSA coordinate size, when the family is ECDSA. */
    readonly curveSize: number | undefined;
    /** node:crypto's name for the digest the SignerInfo names. */
    readonly digest: string;
}

const RSA = { modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };
const SKI = Uint8Array.from({ length: 20 }, (_, i) => i + 1);

async function material(keyParams: object, algorithm: SignatureAlgorithm, verifyParams: object, digest: string, curveSize?: number): Promise<Material> {
    const pair = await webcrypto.subtle.generateKey(keyParams as never, true, ['sign', 'verify']) as GeneratedPair;
    const signer: SigningKey = { key: pair.privateKey as never, algorithm };
    const der = await createCertificate({
        serialNumber: 0x00c0ffeen,
        subject: [[{ type: CN, value: 'pkinative CMS signer' }]],
        notBefore: NOW,
        notAfter: NOW + 365 * DAY,
        subjectPublicKey: new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey)),
        extensions: [{ oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(SKI) }],
    }, signer);
    return {
        signer,
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        certificate: parseCertificate(der, { onDiagnostic: () => undefined }),
        verifyParams,
        curveSize,
        digest,
    };
}

function once<T>(make: () => Promise<T>): () => Promise<T> {
    let made: Promise<T> | undefined;
    return () => (made ??= make());
}

const FAMILIES = {
    'RSA PKCS#1 v1.5 / SHA-256': once(() => material({ name: 'RSASSA-PKCS1-v1_5', ...RSA, hash: 'SHA-256' }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, { name: 'RSASSA-PKCS1-v1_5' }, 'sha256')),
    'RSASSA-PSS / SHA-384': once(() => material({ name: 'RSA-PSS', ...RSA, hash: 'SHA-384' }, { name: 'RSA-PSS', hash: 'SHA-384' }, { name: 'RSA-PSS', saltLength: 48 }, 'sha384')),
    'ECDSA P-256 / SHA-256': once(() => material({ name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256' }, 'sha256', 32)),
    'ECDSA P-384 / SHA-384': once(() => material({ name: 'ECDSA', namedCurve: 'P-384' }, { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }, { name: 'ECDSA', hash: 'SHA-384' }, 'sha384', 48)),
    'ECDSA P-521 / SHA-512': once(() => material({ name: 'ECDSA', namedCurve: 'P-521' }, { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }, { name: 'ECDSA', hash: 'SHA-512' }, 'sha512', 66)),
    // RFC 8419 §3.1: Ed25519 is pure, and the SignerInfo's digest is SHA-512.
    Ed25519: once(() => material({ name: 'Ed25519' }, { name: 'Ed25519' }, { name: 'Ed25519' }, 'sha512')),
} as const;

const p256 = FAMILIES['ECDSA P-256 / SHA-256'];
const CONTENT = new TextEncoder().encode('pkinative signs this');

// ── Reading the output back ──────────────────────────────────────────

function child(node: Asn1Node | undefined, index: number): Asn1Node {
    const found = node?.children[index];
    if (found === undefined) throw new Error(`no child ${String(index)}`);
    return found;
}

const isContext = (node: Asn1Node, tagNumber: number): boolean => node.tagClass === 'context' && node.tagNumber === tagNumber;

interface Dissected {
    readonly signedData: Asn1Node;
    readonly version: number;
    readonly encap: Asn1Node;
    readonly certificates: Asn1Node | undefined;
    readonly crls: Asn1Node | undefined;
    readonly signerInfos: Asn1Node;
    readonly signerInfo: Asn1Node;
    readonly signedAttrs: Asn1Node;
    /** The bytes the signature covers: the [0] with its tag replaced by 0x31. */
    readonly signedBytes: Uint8Array;
    readonly signatureAlgorithm: Asn1Node;
    readonly signature: Uint8Array;
    readonly unsignedAttrs: Asn1Node | undefined;
    /** Signed attribute values by type. */
    readonly attributes: ReadonlyMap<string, readonly Asn1Node[]>;
}

function dissect(der: Uint8Array, signerIndex = 0): Dissected {
    // decodeAsn1 is strict DER by default: a non-minimal length or an
    // indefinite form anywhere in the output fails here.
    const contentInfo = decodeAsn1(der);
    expect(readObjectIdentifier(child(contentInfo, 0))).toBe(OID.signedData);
    const signedData = child(child(contentInfo, 1), 0);
    const fields = signedData.children;
    const signerInfos = child(signedData, fields.length - 1);
    const signerInfo = child(signerInfos, signerIndex);
    const signedAttrs = signerInfo.children.find((c) => isContext(c, 0) && c.constructed);
    if (signedAttrs === undefined) throw new Error('no signed attributes');
    const at = signerInfo.children.indexOf(signedAttrs);
    const signedBytes = signedAttrs.bytes.slice();
    signedBytes[0] = 0x31;
    const attributes = new Map<string, Asn1Node[]>();
    for (const attribute of signedAttrs.children) {
        const type = readObjectIdentifier(child(attribute, 0));
        attributes.set(type, [...(attributes.get(type) ?? []), ...child(attribute, 1).children]);
    }
    return {
        signedData,
        version: Number(child(signedData, 0).content[0]),
        encap: child(signedData, 2),
        certificates: fields.find((c) => isContext(c, 0)),
        crls: fields.find((c) => isContext(c, 1)),
        signerInfos,
        signerInfo,
        signedAttrs,
        signedBytes,
        signatureAlgorithm: child(signerInfo, at + 1),
        signature: child(signerInfo, at + 2).content,
        unsignedAttrs: signerInfo.children.find((c) => isContext(c, 1)),
        attributes,
    };
}

function value(d: Dissected, type: string): Asn1Node {
    const values = d.attributes.get(type);
    expect(values).toHaveLength(1);
    return child({ children: values } as unknown as Asn1Node, 0);
}

/** An ECDSA Ecdsa-Sig-Value to r ‖ s, independently of the library's converter. */
function rawFromDer(der: Uint8Array, size: number): Uint8Array {
    const node = decodeAsn1(der);
    const raw = new Uint8Array(size * 2);
    [0, 1].forEach((i) => {
        let integer = child(node, i).content;
        while (integer.length > size && integer[0] === 0) integer = integer.subarray(1);
        raw.set(integer, size * (i + 1) - integer.length);
    });
    return raw;
}

async function verifies(m: Material, d: Dissected): Promise<boolean> {
    const signature = m.curveSize === undefined ? d.signature : rawFromDer(d.signature, m.curveSize);
    return webcrypto.subtle.verify(m.verifyParams as never, m.publicKey, signature, d.signedBytes);
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const input = (m: Material, extra?: Partial<CreateSignedDataInput>): CreateSignedDataInput => ({ content: CONTENT, certificate: m.certificate, ...extra });

// ── createSignedData ─────────────────────────────────────────────────

describe('createSignedData', () => {
    it.each(Object.keys(FAMILIES) as Array<keyof typeof FAMILIES>)('should write a %s SignedData whose signature verifies over the SET-tagged signed attributes', async (family) => {
        const m = await FAMILIES[family]();
        const d = dissect(await createSignedData(input(m), m.signer));

        // RFC 5652 §5.4: the signature covers 31 len contents, while the
        // structure carries A0 len contents — the same octets but the first.
        expect(d.signedAttrs.bytes[0]).toBe(0xa0);
        expect(hex(d.signedAttrs.bytes.subarray(1))).toBe(hex(d.signedBytes.subarray(1)));
        expect(await verifies(m, d)).toBe(true);

        // messageDigest, recomputed with node:crypto.
        expect(hex(value(d, OID.messageDigest).content)).toBe(createHash(m.digest).update(CONTENT).digest('hex'));
        expect(readObjectIdentifier(value(d, OID.contentType))).toBe(OID.data);

        // The signature algorithm is the signer's full one — never a bare
        // rsaEncryption, and PSS with its parameters written out.
        expect(hex(d.signatureAlgorithm.bytes)).toBe(hex(encodeSignatureAlgorithm(m.signer)));
    }, 60_000);

    it.each([
        ['RSA PKCS#1 v1.5 / SHA-256', OID.sha256],
        ['RSASSA-PSS / SHA-384', OID.sha384],
        ['ECDSA P-521 / SHA-512', OID.sha512],
        ['Ed25519', OID.sha512],
    ] as const)('should name the %s digest with absent parameters, in the SignerInfo and in digestAlgorithms (RFC 5754 §2, RFC 8419)', async (family, oid) => {
        const m = await FAMILIES[family]();
        const d = dissect(await createSignedData(input(m), m.signer));
        const digestAlgorithm = child(d.signerInfo, 2);
        expect(readObjectIdentifier(child(digestAlgorithm, 0))).toBe(oid);
        expect(digestAlgorithm.children).toHaveLength(1);
        expect(hex(child(d.signedData, 1).content)).toBe(hex(digestAlgorithm.bytes));
    }, 60_000);

    it('should embed the content by default, and omit it when detached', async () => {
        const m = await p256();
        const attached = dissect(await createSignedData(input(m), m.signer));
        expect(readObjectIdentifier(child(attached.encap, 0))).toBe(OID.data);
        expect(hex(child(child(attached.encap, 1), 0).content)).toBe(hex(CONTENT));

        const detached = dissect(await createSignedData(input(m, { detached: true }), m.signer));
        expect(detached.encap.children).toHaveLength(1);
        // The digest still commits to the content that is no longer carried.
        expect(hex(value(detached, OID.messageDigest).content)).toBe(createHash('sha256').update(CONTENT).digest('hex'));
        expect(await verifies(m, detached)).toBe(true);
    });

    it('should sign a pre-computed digest, detached, as a PDF signature does', async () => {
        const m = await p256();
        const digest = new Uint8Array(createHash('sha256').update(CONTENT).digest());
        const d = dissect(await createSignedData({ contentDigest: digest, certificate: m.certificate }, m.signer));
        expect(d.encap.children).toHaveLength(1);
        expect(hex(value(d, OID.messageDigest).content)).toBe(hex(digest));
        expect(await verifies(m, d)).toBe(true);
    });

    it('should identify the signer by issuer and serial, as a version 1 SignerInfo, by default', async () => {
        const m = await p256();
        for (const sid of [undefined, 'issuerAndSerialNumber'] as const) {
            const d = dissect(await createSignedData(input(m, { sid }), m.signer));
            expect(child(d.signerInfo, 0).content[0]).toBe(1);
            expect(d.version).toBe(1);
        }
        const d = dissect(await createSignedData(input(m), m.signer));
        const sid = child(d.signerInfo, 1);
        expect(hex(child(sid, 0).bytes)).toBe(hex(m.certificate.issuer.der));
        expect(hex(child(sid, 1).content)).toBe(hex(m.certificate.serialNumber.bytes));
        expect(d.version).toBe(1);
    });

    it('should identify the signer by subjectKeyIdentifier as [0] primitive, making both versions 3', async () => {
        const m = await p256();
        const d = dissect(await createSignedData(input(m, { sid: 'subjectKeyIdentifier' }), m.signer));
        expect(child(d.signerInfo, 0).content[0]).toBe(3);
        const sid = child(d.signerInfo, 1);
        // RFC 4134 §4.7: `80 14 …` — implicit by the module default.
        expect(sid.bytes[0]).toBe(0x80);
        expect(hex(sid.content)).toBe(hex(SKI));
        expect(d.version).toBe(3);
        expect(await verifies(m, d)).toBe(true);
    });

    it('should make a SignedData of another content type version 3, and say the type in both places', async () => {
        const m = await p256();
        const d = dissect(await createSignedData(input(m, { contentType: OID.tstInfo }), m.signer));
        expect(d.version).toBe(3);
        expect(readObjectIdentifier(child(d.encap, 0))).toBe(OID.tstInfo);
        expect(readObjectIdentifier(value(d, OID.contentType))).toBe(OID.tstInfo);
    });

    describe('signingTime', () => {
        it('should be omitted by default, which the PAdES baseline requires', async () => {
            const m = await p256();
            expect(dissect(await createSignedData(input(m), m.signer)).attributes.has(OID.signingTime)).toBe(false);
        });

        it.each([
            ['UTCTime within 1950–2049', Date.UTC(2026, 4, 6, 7, 8, 9, 999), 23, Date.UTC(2026, 4, 6, 7, 8, 9)],
            ['GeneralizedTime from 2050', Date.UTC(2050, 0, 1, 0, 0, 0, 500), 24, Date.UTC(2050, 0, 1)],
            ['GeneralizedTime before 1950', Date.UTC(1949, 11, 31, 23, 59, 59), 24, Date.UTC(1949, 11, 31, 23, 59, 59)],
        ])('should encode %s, in whole seconds (RFC 5652 §11.3)', async (_label, time, tag, expected) => {
            const m = await p256();
            const node = value(dissect(await createSignedData(input(m, { signingTime: time }), m.signer)), OID.signingTime);
            expect(node.tagNumber).toBe(tag);
            expect(readTime(node).epochMilliseconds).toBe(expected);
        });

        it('should refuse a signingTime that is not a finite number', async () => {
            const m = await p256();
            await expect(createSignedData(input(m, { signingTime: Number.NaN }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
            await expect(createSignedData(input(m, { signingTime: '2026' as never }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        // A caller's own signingTime attribute, a UTCTime built byte by byte.
        const callerTime = (): Uint8Array => encodeAttribute(OID.signingTime, [universal(23, ascii('260101000000Z'))]);

        it('should refuse a signingTime attribute among the extras when the option writes one', async () => {
            const m = await p256();
            await expect(createSignedData(input(m, { signingTime: NOW, signedAttributes: [callerTime()] }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        it('should carry a signingTime attribute given as an extra when the option is not set, once and verbatim', async () => {
            const m = await p256();
            const d = dissect(await createSignedData(input(m, { signedAttributes: [callerTime()] }), m.signer));
            expect(readTime(value(d, OID.signingTime)).epochMilliseconds).toBe(NOW);
            expect(d.signedAttrs.children.map((a) => hex(a.bytes))).toContain(hex(callerTime()));
        });

        it('should count signingTime against maxAttributes only when it is written', async () => {
            const m = await p256();
            // contentType, messageDigest, signingCertificateV2 and algorithmProtection are four.
            await expect(createSignedData(input(m), m.signer, { limits: { maxAttributes: 4 } }))
                .resolves.toBeInstanceOf(Uint8Array);
            await expect(createSignedData(input(m, { signingTime: NOW }), m.signer, { limits: { maxAttributes: 4 } }))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxAttributes' }));
        });
    });

    describe('signingCertificateV2', () => {
        it('should bind the certificate with SHA-256, the hashAlgorithm DEFAULT left out, and name issuer and serial', async () => {
            const m = await p256();
            const d = dissect(await createSignedData(input(m), m.signer));
            const essCertId = child(child(value(d, OID.signingCertificateV2), 0), 0);
            // X.690 §11.5: a DEFAULT value is absent in DER.
            expect(child(essCertId, 0).tagNumber).toBe(4);
            expect(hex(child(essCertId, 0).content)).toBe(createHash('sha256').update(m.certificate.der).digest('hex'));
            const issuerSerial = child(essCertId, 1);
            const directoryName = child(child(issuerSerial, 0), 0);
            expect(isContext(directoryName, 4)).toBe(true);
            expect(hex(child(directoryName, 0).bytes)).toBe(hex(m.certificate.issuer.der));
            expect(hex(child(issuerSerial, 1).content)).toBe(hex(m.certificate.serialNumber.bytes));
        });

        it('should write the hashAlgorithm when it is not SHA-256', async () => {
            const m = await FAMILIES['ECDSA P-384 / SHA-384']();
            const essCertId = child(child(value(dissect(await createSignedData(input(m), m.signer)), OID.signingCertificateV2), 0), 0);
            expect(readObjectIdentifier(child(child(essCertId, 0), 0))).toBe(OID.sha384);
            expect(hex(child(essCertId, 1).content)).toBe(createHash('sha384').update(m.certificate.der).digest('hex'));
        });

        it('should be left out on request', async () => {
            const m = await p256();
            expect(dissect(await createSignedData(input(m, { signingCertificateV2: false }), m.signer)).attributes.has(OID.signingCertificateV2)).toBe(false);
        });
    });

    describe('algorithmProtection', () => {
        it('should restate both algorithms, the signature one under an implicit [1] (RFC 6211 §2)', async () => {
            const m = await FAMILIES['RSASSA-PSS / SHA-384']();
            const d = dissect(await createSignedData(input(m), m.signer));
            const protection = value(d, OID.algorithmProtection);
            expect(hex(child(protection, 0).bytes)).toBe(hex(child(d.signerInfo, 2).bytes));
            const signatureAlgorithm = child(protection, 1);
            expect(signatureAlgorithm.bytes[0]).toBe(0xa1);
            expect(hex(signatureAlgorithm.content)).toBe(hex(d.signatureAlgorithm.content));
        }, 60_000);

        it('should be left out on request', async () => {
            const m = await p256();
            expect(dissect(await createSignedData(input(m, { algorithmProtection: false }), m.signer)).attributes.has(OID.algorithmProtection)).toBe(false);
        });

        it('should accept algorithmProtection as an extra once the builder is told not to write it', async () => {
            const m = await p256();
            const attribute = encodeAttribute(OID.algorithmProtection, [encodeSequence([encodeSequence([encodeObjectIdentifier(OID.sha256)])])]);
            const d = dissect(await createSignedData(input(m, { algorithmProtection: false, signedAttributes: [attribute] }), m.signer));
            expect(d.attributes.get(OID.algorithmProtection)).toHaveLength(1);
            expect(d.signedAttrs.children.map((a) => hex(a.bytes))).toContain(hex(attribute));
        });
    });

    it('should carry extra signed and unsigned attributes verbatim, the signed ones under the signature', async () => {
        const m = await p256();
        const archival = encodeAttribute(OID.adbeRevocation, [encodeSequence([])]);
        const token = encodeAttribute(OID.timeStampToken, [encodeSequence([encodeObjectIdentifier(OID.signedData)])]);
        const d = dissect(await createSignedData(input(m, { signedAttributes: [archival], unsignedAttributes: [token] }), m.signer));
        expect(d.signedAttrs.children.map((a) => hex(a.bytes))).toContain(hex(archival));
        expect(d.unsignedAttrs?.bytes[0]).toBe(0xa1);
        expect(d.unsignedAttrs?.children.map((a) => hex(a.bytes))).toEqual([hex(token)]);
        expect(await verifies(m, d)).toBe(true);
    });

    it('should write every attribute SET OF in DER order (X.690 §11.6)', async () => {
        const m = await p256();
        const extra = [encodeAttribute('1.2.3.4', [encodeInteger(1)]), encodeAttribute('1.2.3', [encodeInteger(2)])];
        const d = dissect(await createSignedData(input(m, {
            signingTime: NOW,
            signedAttributes: extra,
            unsignedAttributes: [encodeAttribute('2.5.4.3', [encodeInteger(3)]), encodeAttribute('1.2.3.5', [encodeInteger(4)])],
        }), m.signer));
        const sorted = (node: Asn1Node | undefined): void => {
            const encodings = (node?.children ?? []).map((c) => Buffer.from(c.bytes));
            expect(encodings.length).toBeGreaterThan(1);
            expect(encodings).toEqual([...encodings].sort(Buffer.compare));
        };
        sorted(d.signedAttrs);
        sorted(d.unsignedAttrs);
        expect(d.signedAttrs.children).toHaveLength(7);
    });

    describe('the certificate bag', () => {
        it('should embed the signer\'s certificate once, the chain after it, and the CRLs', async () => {
            const m = await p256();
            const other = (await FAMILIES.Ed25519()).certificate.der;
            const crl = encodeSequence([encodeInteger(7)]);
            const d = dissect(await createSignedData(input(m, { certificates: [m.certificate.der, other, other.slice()], crls: [crl] }), m.signer));
            const certificates = (d.certificates?.children ?? []).map((c) => hex(c.bytes));
            expect(certificates.sort()).toEqual([hex(m.certificate.der), hex(other)].sort());
            expect(d.certificates?.bytes[0]).toBe(0xa0);
            expect(d.crls?.bytes[0]).toBe(0xa1);
            expect(d.crls?.children.map((c) => hex(c.bytes))).toEqual([hex(crl)]);
            expect(d.version).toBe(1);
        }, 60_000);

        it('should leave the crls field out when no CRL is given, rather than write an empty [1]', async () => {
            const m = await p256();
            const d = dissect(await createSignedData(input(m), m.signer));
            expect(d.crls).toBeUndefined();
            // version, digestAlgorithms, encapContentInfo, certificates [0], signerInfos.
            expect(d.signedData.children.map((c) => c.bytes[0])).toEqual([0x02, 0x31, 0x30, 0xa0, 0x31]);
        });

        it.each([
            ['an extended certificate [0] leaves it 1', { certificates: [tlv(2, true, 0, [0x05, 0x00])] }, 1],
            ['an attribute certificate v1 [1] makes it 3', { certificates: [tlv(2, true, 1, [0x05, 0x00])] }, 3],
            ['an attribute certificate v2 [2] makes it 4', { certificates: [tlv(2, true, 2, [0x05, 0x00])] }, 4],
            ['an other certificate [3] makes it 5', { certificates: [tlv(2, true, 3, [0x05, 0x00])] }, 5],
            ['an other revocation [1] (RFC 5940) makes it 5', { crls: [tlv(2, true, 1, [0x05, 0x00])] }, 5],
        ])('should compute the version from the bag: %s (RFC 5652 §5.1)', async (_label, extra, version) => {
            const m = await p256();
            expect(dissect(await createSignedData(input(m, extra), m.signer)).version).toBe(version);
        });

        it.each([
            ['truncated', Uint8Array.of(0x30, 0x05, 0x02)],
            ['followed by bytes', Uint8Array.of(0x30, 0x00, 0x00)],
            ['not a choice the field allows', Uint8Array.of(0x04, 0x00)],
        ])('should refuse a certificate that is %s', async (_label, entry) => {
            const m = await p256();
            await expect(createSignedData(input(m, { certificates: [entry] }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        it('should refuse a CRL entry that is a certificate choice only', async () => {
            const m = await p256();
            await expect(createSignedData(input(m, { crls: [tlv(2, true, 3, [])] }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        it('should bound the bag by maxCmsCertificatesAndCrls, as given and as written', async () => {
            const m = await p256();
            const crl = encodeSequence([]);
            await expect(createSignedData(input(m, { crls: [crl, crl] }), m.signer, { limits: { maxCmsCertificatesAndCrls: 1 } }))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxCmsCertificatesAndCrls' }));
            // One given, but the signer's own certificate makes it two.
            await expect(createSignedData(input(m, { crls: [crl] }), m.signer, { limits: { maxCmsCertificatesAndCrls: 1 } }))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxCmsCertificatesAndCrls' }));
            await expect(createSignedData(input(m, { certificates: [m.certificate.der] }), m.signer, { limits: { maxCmsCertificatesAndCrls: 1 } }))
                .resolves.toBeInstanceOf(Uint8Array);
        });
    });

    describe('what it refuses', () => {
        it.each([
            ['both content and contentDigest', { contentDigest: new Uint8Array(32) }],
            ['neither content nor contentDigest', { content: undefined }],
            ['a contentDigest of the wrong length', { content: undefined, contentDigest: new Uint8Array(20) }],
            ['a contentDigest with detached: false', { content: undefined, contentDigest: new Uint8Array(32), detached: false }],
        ])('should refuse %s', async (_label, extra) => {
            const m = await p256();
            await expect(createSignedData(input(m, extra), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        it('should refuse a subjectKeyIdentifier sid when the certificate has none', async () => {
            const m = await p256();
            const bare = { ...m.certificate, extensions: [] };
            await expect(createSignedData(input(m, { certificate: bare, sid: 'subjectKeyIdentifier' }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        it('should refuse an unknown sid', async () => {
            const m = await p256();
            await expect(createSignedData(input(m, { sid: 'serial' as never }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION' }));
        });

        it.each([
            ['contentType, which the builder owns', encodeAttribute(OID.contentType, [encodeObjectIdentifier(OID.data)])],
            ['messageDigest, which the builder owns', encodeAttribute(OID.messageDigest, [encodeOctetString(new Uint8Array(32))])],
            ['a second signingCertificateV2', encodeAttribute(OID.signingCertificateV2, [encodeSequence([])])],
            ['a countersignature, which is unsigned only', encodeAttribute(OID.countersignature, [encodeSequence([])])],
        ])('should refuse an extra signed attribute that is %s', async (_label, attribute) => {
            const m = await p256();
            await expect(createSignedData(input(m, { signedAttributes: [attribute] }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        it('should refuse the same extra signed attribute twice', async () => {
            const m = await p256();
            const attribute = encodeAttribute('1.2.3.4', [encodeInteger(1)]);
            await expect(createSignedData(input(m, { signedAttributes: [attribute, attribute] }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        it('should accept signingCertificateV2 as an extra once the builder is told not to write it', async () => {
            const m = await p256();
            const attribute = encodeAttribute(OID.signingCertificateV2, [encodeSequence([encodeSequence([])])]);
            const d = dissect(await createSignedData(input(m, { signingCertificateV2: false, signedAttributes: [attribute] }), m.signer));
            expect(d.signedAttrs.children.map((a) => hex(a.bytes))).toContain(hex(attribute));
        });

        it.each([OID.contentType, OID.messageDigest, OID.signingTime, OID.signingCertificateV2, OID.algorithmProtection])(
            'should refuse %s among the unsigned attributes, where RFC 5652 forbids it', async (type) => {
                const m = await p256();
                await expect(createSignedData(input(m, { unsignedAttributes: [encodeAttribute(type, [encodeInteger(0)])] }), m.signer))
                    .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
            });

        it.each(MALFORMED_ATTRIBUTES())('should refuse an attribute that is %s', async (_label, attribute) => {
            const m = await p256();
            await expect(createSignedData(input(m, { signedAttributes: [attribute] }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
            await expect(createSignedData(input(m, { unsignedAttributes: [attribute] }), m.signer))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });

        describe('an Ed448 signer, digesting with SHAKE256 (RFC 8419 §3.1)', () => {
            const SHAKE256 = '2.16.840.1.101.3.4.2.12';
            /** An Ed448 holder under an Ed25519 root, as the verifier's own Ed448 tests build it; the signer names Ed448 itself. */
            const ed448 = once(async () => {
                const root = await makeRoot();
                const holder = await issue(root, { pair: await keyPair('Ed25519', { name: 'Ed448' }), family: 'Ed25519' });
                const signer = { key: holder.pair.privateKey, algorithm: { name: 'Ed448' } } as const;
                const input: CreateSignedDataInput = { content: CONTENT, certificate: holder.certificate };
                return { root, holder, signer, input };
            });
            const shake = (data: Uint8Array): string => createHash('shake256', { outputLength: 64 }).update(data).digest('hex');

            it('should write a SignedData whose signature verifies, under id-shake256 and id-Ed448 both without parameters', async () => {
                const { holder, signer, input } = await ed448();
                const d = dissect(await createSignedData(input, signer));
                expect(await webcrypto.subtle.verify({ name: 'Ed448' }, holder.pair.publicKey as never, d.signature, d.signedBytes)).toBe(true);
                // messageDigest: SHAKE256 with a 512-bit output, recomputed with node:crypto.
                expect(hex(value(d, OID.messageDigest).content)).toBe(shake(CONTENT));
                // SignerInfo.digestAlgorithm is SEQUENCE { id-shake256 } with no parameters (RFC 8419 §2.1), listed once in the SignedData.
                const digestAlgorithm = child(d.signerInfo, 2);
                expect(digestAlgorithm.children).toHaveLength(1);
                expect(readObjectIdentifier(child(digestAlgorithm, 0))).toBe(SHAKE256);
                expect(hex(child(d.signedData, 1).bytes)).toBe(`310d${hex(digestAlgorithm.bytes)}`);
                // id-Ed448 with absent parameters (RFC 8410 §3).
                expect(hex(d.signatureAlgorithm.bytes)).toBe('300506032b6571');
                // ESSCertIDv2 keeps its default hash: SHA-256 of the certificate, hashAlgorithm absent.
                const essCertId = child(child(value(d, OID.signingCertificateV2), 0), 0);
                expect(essCertId.children).toHaveLength(2);
                expect(hex(child(essCertId, 0).content)).toBe(createHash('sha256').update(holder.certificate.der).digest('hex'));
            });

            it('should verify with verifySignedData — valid, the signature and the issuing one checked — and parse back with zero diagnostics', async () => {
                const { root, signer, input } = await ed448();
                const der = await createSignedData(input, signer);
                const report = await verifySignedData({ signedData: der, trustAnchors: [root.certificate], at: Date.UTC(2026, 0, 15) });
                expect(report.reasons).toEqual([]);
                expect(report.valid).toBe(true);
                expect(report.signers[0]?.intact).toBe(true);
                expect(report.signers[0]?.certificate?.subjectPublicKeyInfo.kind).toBe('ed448');
                // The signer's signature, and the root's over the signer's certificate.
                expect(report.signatureVerifications).toBe(2);
                const diagnostics: string[] = [];
                parseSignedData(der, { onDiagnostic: (diagnostic) => { diagnostics.push(diagnostic.code); } });
                expect(diagnostics).toEqual([]);
            });

            it('should take a 64-octet contentDigest for a detached signature and refuse another length, naming SHAKE256', async () => {
                const { holder, signer } = await ed448();
                const digest = Buffer.from(shake(CONTENT), 'hex');
                const d = dissect(await createSignedData({ contentDigest: new Uint8Array(digest), certificate: holder.certificate }, signer));
                expect(await webcrypto.subtle.verify({ name: 'Ed448' }, holder.pair.publicKey as never, d.signature, d.signedBytes)).toBe(true);
                expect(hex(value(d, OID.messageDigest).content)).toBe(shake(CONTENT));
                expect(d.encap.children).toHaveLength(1);
                await expect(createSignedData({ contentDigest: new Uint8Array(32), certificate: holder.certificate }, signer))
                    .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('a SHAKE256 digest is 64') }));
            });

            it('should refuse with PKI_CRYPTO_KEY_UNSUPPORTED on a host without Ed448 — Bun, Chromium — as for every key the host rejects', async () => {
                const { signer, input } = await ed448();
                const subtle = globalThis.crypto.subtle;
                const real = subtle.sign.bind(subtle);
                const spy = vi.spyOn(subtle, 'sign').mockImplementation(((algorithm, key, data) =>
                    (algorithm as { readonly name: string }).name === 'Ed448'
                        ? Promise.reject(new DOMException('Unrecognized algorithm name', 'NotSupportedError'))
                        : real(algorithm as never, key as never, data as never)) as typeof subtle.sign);
                try {
                    await expect(createSignedData(input, signer)).rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED', algorithm: 'Ed448' }));
                } finally {
                    spy.mockRestore();
                }
            });
        });

        it('should refuse a digest with no signature OID before reading its own table', async () => {
            const m = await p256();
            await expect(createSignedData(input(m), { key: m.signer.key, algorithm: { name: 'ECDSA', hash: 'SHA-3' as never, namedCurve: 'P-256' } }))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' }));
        });

        it('should bound each attribute list by maxAttributes', async () => {
            const m = await p256();
            // contentType, messageDigest, signingCertificateV2 and algorithmProtection are four.
            await expect(createSignedData(input(m), m.signer, { limits: { maxAttributes: 3 } }))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxAttributes' }));
            const token = encodeAttribute(OID.timeStampToken, [encodeInteger(0)]);
            await expect(createSignedData(input(m, { algorithmProtection: false, signingCertificateV2: false, unsignedAttributes: [token, token, token] }), m.signer, { limits: { maxAttributes: 2 } }))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxAttributes' }));
        });
    });

    describe('with an ExternalSigner', () => {
        /** A key held "elsewhere": node:crypto's synchronous signer, standing in for an HSM binding. */
        const synchronous = (m: Material, digest: string | null, dsaEncoding: 'ieee-p1363' | 'der' = 'ieee-p1363'): ExternalSigner => ({
            algorithm: m.signer.algorithm,
            produceSignature: (data) => new Uint8Array(nodeSign(digest, data, { key: KeyObject.from(m.privateKey), dsaEncoding })),
        });
        /** A remote signer: asynchronous, returning what crypto.subtle.sign returns. */
        const asynchronous = (m: Material): ExternalSigner => ({
            algorithm: m.signer.algorithm,
            produceSignature: async (data) => new Uint8Array(await webcrypto.subtle.sign(m.verifyParams as never, m.privateKey, data)),
        });

        it.each(['ECDSA P-384 / SHA-384', 'RSASSA-PSS / SHA-384', 'Ed25519'] as const)('should sign through an asynchronous %s signer', async (family) => {
            const m = await FAMILIES[family]();
            expect(await verifies(m, dissect(await createSignedData(input(m), asynchronous(m))))).toBe(true);
        }, 60_000);

        it.each([
            ['ECDSA P-256 / SHA-256', 'sha256'],
            ['RSA PKCS#1 v1.5 / SHA-256', 'sha256'],
            ['Ed25519', null],
        ] as const)('should sign through a synchronous %s signer', async (family, digest) => {
            const m = await FAMILIES[family]();
            expect(await verifies(m, dissect(await createSignedData(input(m), synchronous(m, digest))))).toBe(true);
        }, 60_000);

        it('should refuse an ECDSA signature handed back as DER, the usual mistake', async () => {
            const m = await p256();
            await expect(createSignedData(input(m), synchronous(m, 'sha256', 'der')))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('exactly 64 octets') }));
        });

        it('should hand the signer a copy, so that it cannot change what is embedded', async () => {
            const m = await p256();
            const der = await createSignedData(input(m), {
                algorithm: m.signer.algorithm,
                produceSignature: async (data) => {
                    const signature = new Uint8Array(await webcrypto.subtle.sign(m.verifyParams as never, m.privateKey, data));
                    data.fill(0);
                    return signature;
                },
            });
            expect(await verifies(m, dissect(der))).toBe(true);
        });

        it.each([
            ['an ArrayBuffer', (): unknown => new ArrayBuffer(64)],
            ['an empty Uint8Array', (): unknown => new Uint8Array(0)],
            ['nothing', (): unknown => undefined],
        ])('should refuse a signer that returns %s', async (_label, produce) => {
            const m = await FAMILIES.Ed25519();
            await expect(createSignedData(input(m), { algorithm: m.signer.algorithm, produceSignature: produce as never }))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        });
    });
});

function MALFORMED_ATTRIBUTES(): Array<[string, Uint8Array]> {
    const type = encodeObjectIdentifier('1.2.3.4');
    const values = encodeSetOf([encodeInteger(1)]);
    return [
        ['truncated', Uint8Array.of(0x30, 0x05, 0x06)],
        ['followed by bytes', concat(sequence(type, values), [0x00])],
        ['not a SEQUENCE', encodeSetOf([type, values])],
        ['an empty SEQUENCE', sequence()],
        ['a type without values', sequence(type)],
        ['three fields', sequence(type, values, values)],
        ['a type that is not an OID', sequence(encodeInteger(1), values)],
        ['values that are not a SET', sequence(type, encodeSequence([]))],
        ['an OID with malformed content', sequence(Uint8Array.of(0x06, 0x01, 0x80), values)],
    ];
}

// ── addUnsignedAttribute ─────────────────────────────────────────────

const TOKEN = encodeAttribute(OID.timeStampToken, [encodeSequence([encodeObjectIdentifier(OID.signedData), encodeInteger(42)])]);

/** A SignedData with the signerInfos SET replaced — how a multi-signer message is assembled here. */
function withSignerInfos(der: Uint8Array, signerInfos: readonly Uint8Array[]): Uint8Array {
    const contentInfo = decodeAsn1(der);
    const signedData = child(child(contentInfo, 1), 0);
    const fields = signedData.children.slice(0, -1).map((c) => c.bytes);
    return encodeSequence([child(contentInfo, 0).bytes, tlv(2, true, 0, encodeSequence([...fields, encodeSetOf(signerInfos)]))]);
}

/** A ContentInfo of id-signedData around arbitrary SignedData content. */
const around = (...fields: Uint8Array[]): Uint8Array =>
    encodeSequence([encodeObjectIdentifier(OID.signedData), tlv(2, true, 0, encodeSequence(fields))]);

describe('addUnsignedAttribute', () => {
    it('should add [1] to a signer that has none, copying the signed attributes and the signature byte for byte', async () => {
        const m = await p256();
        const before = await createSignedData(input(m), m.signer);
        const pristine = before.slice();
        const after = addUnsignedAttribute(before, 0, TOKEN);

        const b = dissect(before);
        const a = dissect(after);
        expect(b.unsignedAttrs).toBeUndefined();
        expect(hex(a.signedAttrs.bytes)).toBe(hex(b.signedAttrs.bytes));
        expect(hex(a.signature)).toBe(hex(b.signature));
        // Every content octet of the old SignerInfo leads the new one.
        expect(hex(a.signerInfo.content).startsWith(hex(b.signerInfo.content))).toBe(true);
        expect(a.unsignedAttrs?.children.map((c) => hex(c.bytes))).toEqual([hex(TOKEN)]);
        expect(await verifies(m, a)).toBe(true);
        // The input is never written to.
        expect(hex(before)).toBe(hex(pristine));
    });

    it('should keep every other field of the SignedData as it was', async () => {
        const m = await p256();
        const der = await createSignedData(input(m, { crls: [encodeSequence([])] }), m.signer);
        const before = dissect(der).signedData.children.map((c) => hex(c.bytes));
        const after = dissect(addUnsignedAttribute(der, 0, TOKEN)).signedData.children.map((c) => hex(c.bytes));
        expect(after).toHaveLength(6);
        expect(after.slice(0, -1)).toEqual(before.slice(0, -1));
    });

    it('should work on a signer identified by subjectKeyIdentifier', async () => {
        const m = await p256();
        const der = await createSignedData(input(m, { sid: 'subjectKeyIdentifier' }), m.signer);
        const a = dissect(addUnsignedAttribute(der, 0, TOKEN));
        expect(hex(a.signerInfo.content).startsWith(hex(dissect(der).signerInfo.content))).toBe(true);
        expect(await verifies(m, a)).toBe(true);
    });

    it('should add to existing unsigned attributes, in DER order', async () => {
        const m = await p256();
        const existing = encodeAttribute('2.5.4.3', [encodeInteger(1)]);
        const before = await createSignedData(input(m, { unsignedAttributes: [existing] }), m.signer);
        const b = dissect(before);
        const a = dissect(addUnsignedAttribute(before, 0, TOKEN));
        expect(hex(a.signedAttrs.bytes)).toBe(hex(b.signedAttrs.bytes));
        expect(hex(a.signature)).toBe(hex(b.signature));
        const encodings = (a.unsignedAttrs?.children ?? []).map((c) => Buffer.from(c.bytes));
        expect(encodings.map((e) => e.toString('hex')).sort()).toEqual([hex(existing), hex(TOKEN)].sort());
        expect(encodings).toEqual([...encodings].sort(Buffer.compare));
    });

    it('should add to the signer asked for in a multi-signer message, and leave the other untouched', async () => {
        const m = await p256();
        const e = await FAMILIES.Ed25519();
        const first = dissect(await createSignedData(input(m), m.signer)).signerInfo.bytes;
        const second = dissect(await createSignedData(input(e), e.signer)).signerInfo.bytes;
        const message = withSignerInfos(await createSignedData(input(m), m.signer), [first, second]);
        const order = dissect(message).signerInfos.children;

        for (const index of [0, 1]) {
            const target = hex(child(dissect(message).signerInfos, index).content);
            const other = hex(child(dissect(message).signerInfos, 1 - index).bytes);
            const result = dissect(addUnsignedAttribute(message, index, TOKEN));
            const infos = result.signerInfos.children;
            expect(infos).toHaveLength(order.length);
            // The untouched signer is byte-identical; the other gained [1]
            // after every octet it had.
            expect(infos.map((c) => hex(c.bytes))).toContain(other);
            const changed = infos.find((c) => hex(c.bytes) !== other);
            expect(hex(changed?.content ?? new Uint8Array(0)).startsWith(target)).toBe(true);
            expect(changed?.children.at(-1)?.bytes[0]).toBe(0xa1);
            // signerInfos is re-sorted into DER order.
            const encodings = infos.map((c) => Buffer.from(c.bytes));
            expect(encodings).toEqual([...encodings].sort(Buffer.compare));
        }
    }, 60_000);

    it('should refuse a signerIndex that names no signer', async () => {
        const m = await p256();
        const der = await createSignedData(input(m), m.signer);
        for (const index of [1, -1, 0.5, Number.NaN]) {
            expect(() => addUnsignedAttribute(der, index, TOKEN)).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
        }
    });

    it('should refuse a signerIndex that is not a non-negative integer before reading the SignedData', () => {
        // Truncated bytes: had the index been accepted, the encoding error would come first.
        const truncated = Uint8Array.of(0x30, 0x05, 0x06);
        for (const index of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY]) {
            const thrown = catchError(() => addUnsignedAttribute(truncated, index, TOKEN));
            expect(thrown).not.toBeInstanceOf(PkiEncodingError);
            expect(thrown).toMatchObject({ code: 'PKI_API_MISUSE' });
        }
    });

    it('should add to a SignedData that carries neither certificates nor crls', async () => {
        const d = dissect(await BASE());
        const fields = d.signedData.children.filter((c) => !isContext(c, 0)).map((c) => c.bytes);
        expect(fields).toHaveLength(4);
        const a = dissect(addUnsignedAttribute(around(...fields), 0, TOKEN));
        // version, digestAlgorithms, encapContentInfo, signerInfos — RFC 5652 §5.1 makes both bags OPTIONAL.
        expect(a.signedData.children.map((c) => c.bytes[0])).toEqual([0x02, 0x31, 0x30, 0x31]);
        expect(a.unsignedAttrs?.children.map((c) => hex(c.bytes))).toEqual([hex(TOKEN)]);
    });

    it('should point a missing signerInfos at the end of the SignedData', async () => {
        const d = dissect(await BASE());
        const der = around(...d.signedData.children.slice(0, 3).map((c) => c.bytes));
        expect(catchError(() => addUnsignedAttribute(der, 0, TOKEN)))
            .toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path: 'signedData.signerInfos', offset: der.length });
    });

    it('should admit exactly maxAttributes unsigned attributes, the added one included', async () => {
        const m = await p256();
        const der = await createSignedData(input(m, { unsignedAttributes: [encodeAttribute('2.5.4.3', [encodeInteger(1)])] }), m.signer);
        const a = dissect(addUnsignedAttribute(der, 0, TOKEN, { limits: { maxAttributes: 2 } }));
        expect(a.unsignedAttrs?.children).toHaveLength(2);
    });

    it.each(MALFORMED_ATTRIBUTES())('should refuse an attribute that is %s', async (_label, attribute) => {
        const der = await BASE();
        expect(() => addUnsignedAttribute(der, 0, attribute))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });

    it('should refuse an attribute RFC 5652 allows only signed', () => {
        expect(() => addUnsignedAttribute(new Uint8Array(0), 0, encodeAttribute(OID.signingTime, [encodeInteger(0)])))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });

    it('should refuse a ContentInfo that is not id-signedData', () => {
        const data = encodeSequence([encodeObjectIdentifier(OID.data), tlv(2, true, 0, encodeOctetString(CONTENT))]);
        const thrown = catchError(() => addUnsignedAttribute(data, 0, TOKEN));
        expect(thrown).toBeInstanceOf(PkiCmsError);
        expect(thrown).toMatchObject({ code: 'PKI_CMS_CONTENT_TYPE_UNEXPECTED', path: 'contentInfo.contentType' });
    });

    it('should refuse input that is not DER with the encoding error', () => {
        expect(catchError(() => addUnsignedAttribute(Uint8Array.of(0x30, 0x05, 0x06), 0, TOKEN))).toBeInstanceOf(PkiEncodingError);
    });

    it.each(STRUCTURES())('should refuse a structure where %s', async (_label, build, path) => {
        const valid = dissect(await BASE());
        const thrown = catchError(() => addUnsignedAttribute(build(valid), 0, TOKEN));
        expect(thrown).toBeInstanceOf(PkiCmsError);
        expect(thrown).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path });
    });

    it('should bound what it walks by maxInputBytes, maxSignerInfos and maxAttributes', async () => {
        const m = await p256();
        const der = await createSignedData(input(m, { unsignedAttributes: [encodeAttribute('2.5.4.3', [encodeInteger(1)])] }), m.signer);
        const info = dissect(der).signerInfo.bytes;
        expect(() => addUnsignedAttribute(der, 0, TOKEN, { limits: { maxInputBytes: 10 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxInputBytes' }));
        expect(() => addUnsignedAttribute(withSignerInfos(der, [info, info]), 0, TOKEN, { limits: { maxSignerInfos: 1 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxSignerInfos' }));
        expect(() => addUnsignedAttribute(der, 0, TOKEN, { limits: { maxAttributes: 1 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxAttributes' }));
    });
});

const BASE = once(async () => {
    const m = await p256();
    return createSignedData(input(m), m.signer);
});

function catchError(run: () => unknown): unknown {
    try {
        run();
    } catch (error) {
        return error;
    }
    throw new Error('expected a throw');
}

type Build = (d: Dissected) => Uint8Array;

/** Every structural refusal, each built from the parts of a valid SignedData. */
function STRUCTURES(): Array<[string, Build, string]> {
    const fields = (d: Dissected): Uint8Array[] => d.signedData.children.map((c) => c.bytes);
    const infoParts = (d: Dissected): Uint8Array[] => d.signerInfo.children.map((c) => c.bytes);
    const withInfo = (d: Dissected, parts: Uint8Array[]): Uint8Array => around(...fields(d).slice(0, -1), encodeSetOf([encodeSequence(parts)]));
    const signedDataOid = encodeObjectIdentifier(OID.signedData);
    return [
        ['the ContentInfo is not a SEQUENCE', () => encodeSetOf([signedDataOid]), 'contentInfo'],
        ['bytes follow the ContentInfo', (d) => concat(around(...fields(d)), [0x00]), 'contentInfo'],
        ['the ContentInfo has three fields', (d) => encodeSequence([signedDataOid, tlv(2, true, 0, encodeSequence(fields(d))), encodeInteger(0)]), 'contentInfo'],
        ['the content type is not an OID', () => encodeSequence([encodeInteger(1)]), 'contentInfo.contentType'],
        ['the content type is missing', () => encodeSequence([]), 'contentInfo.contentType'],
        ['the content is not [0]', (d) => encodeSequence([signedDataOid, tlv(2, true, 1, encodeSequence(fields(d)))]), 'contentInfo.content'],
        ['the content is missing', () => encodeSequence([signedDataOid]), 'contentInfo.content'],
        ['[0] is empty', () => encodeSequence([signedDataOid, tlv(2, true, 0, [])]), 'signedData'],
        ['[0] holds two values', (d) => encodeSequence([signedDataOid, tlv(2, true, 0, concat(encodeSequence(fields(d)), encodeSequence([])))]), 'contentInfo.content'],
        ['the SignedData is not a SEQUENCE', (d) => encodeSequence([signedDataOid, tlv(2, true, 0, encodeSetOf(fields(d)))]), 'signedData'],
        ['the SignedData has seven fields', (d) => around(...fields(d), encodeSetOf([]), encodeSetOf([])), 'signedData'],
        ['the version is not an INTEGER', (d) => around(encodeOctetString(Uint8Array.of(1)), ...fields(d).slice(1)), 'signedData.version'],
        ['digestAlgorithms is not a SET', (d) => around(...fields(d).slice(0, 1), encodeSequence([]), ...fields(d).slice(2)), 'signedData.digestAlgorithms'],
        ['encapContentInfo is not a SEQUENCE', (d) => around(...fields(d).slice(0, 2), encodeSetOf([]), ...fields(d).slice(3)), 'signedData.encapContentInfo'],
        ['signerInfos is missing', (d) => around(...fields(d).slice(0, 3)), 'signedData.signerInfos'],
        ['signerInfos is not a SET', (d) => around(...fields(d).slice(0, -1), encodeSequence([])), 'signedData.signerInfos'],
        ['a field between is neither [0] nor [1]', (d) => around(...fields(d).slice(0, 3), tlv(2, true, 2, []), ...fields(d).slice(-1)), 'signedData[3]'],
        ['a SignerInfo is not a SEQUENCE', (d) => around(...fields(d).slice(0, -1), encodeSetOf([encodeSetOf(infoParts(d))])), 'signerInfos[0]'],
        ['the SignerInfo version is not an INTEGER', (d) => withInfo(d, [encodeOctetString(Uint8Array.of(1)), ...infoParts(d).slice(1)]), 'signerInfos[0].version'],
        ['the sid is neither alternative', (d) => withInfo(d, [...infoParts(d).slice(0, 1), encodeOctetString(SKI), ...infoParts(d).slice(2)]), 'signerInfos[0].sid'],
        ['the sid is missing', (d) => withInfo(d, infoParts(d).slice(0, 1)), 'signerInfos[0].sid'],
        ['the digestAlgorithm is not a SEQUENCE', (d) => withInfo(d, [...infoParts(d).slice(0, 2), encodeSetOf([]), ...infoParts(d).slice(3)]), 'signerInfos[0].digestAlgorithm'],
        ['the signatureAlgorithm is not a SEQUENCE', (d) => withInfo(d, [...infoParts(d).slice(0, 4), encodeSetOf([]), ...infoParts(d).slice(5)]), 'signerInfos[0].signatureAlgorithm'],
        ['the signature is not an OCTET STRING', (d) => withInfo(d, [...infoParts(d).slice(0, 5), encodeInteger(1)]), 'signerInfos[0].signature'],
        ['a field follows the signature that is not [1]', (d) => withInfo(d, [...infoParts(d), tlv(2, true, 2, [])]), 'signerInfos[0].unsignedAttrs'],
        ['a field follows [1]', (d) => withInfo(d, [...infoParts(d).slice(0, 3), ...infoParts(d).slice(4), tlv(2, true, 1, []), encodeInteger(0)]), 'signerInfos[0].unsignedAttrs'],
        ['the SignerInfo has eight fields', (d) => withInfo(d, [...infoParts(d), tlv(2, true, 1, []), encodeInteger(0)]), 'signerInfos[0]'],
        ['an unsigned attribute is not a SEQUENCE', (d) => withInfo(d, [...infoParts(d), tlv(2, true, 1, encodeSetOf([]))]), 'signerInfos[0].unsignedAttrs[0]'],
    ];
}

// ── addTimeStampToken ────────────────────────────────────────────────

/** A real RFC 3161 token over `imprint`, signed by a TSA made for it. */
async function timeStampToken(imprint: Uint8Array): Promise<Uint8Array> {
    const root = await makeRoot();
    const tsa = await issueTsa(root);
    return makeToken(tsa, tstInfo({ imprint }));
}

describe('addTimeStampToken', () => {
    it('should add the token as id-aa-signatureTimeStampToken, readable back and leaving the signature good', async () => {
        const m = await p256();
        const before = await createSignedData(input(m), m.signer);
        const signature = parseSignedData(before).signerInfos[0]?.signature as Uint8Array;
        const token = await timeStampToken(new Uint8Array(createHash('sha256').update(signature).digest()));
        const after = addTimeStampToken(before, 0, token);

        // The attribute, read back with the generic decoder.
        const a = dissect(after);
        const attribute = child(a.unsignedAttrs, 0);
        expect(readObjectIdentifier(child(attribute, 0))).toBe(OID.timeStampToken);
        expect(hex(child(child(attribute, 1), 0).bytes)).toBe(hex(token));
        // Every signed octet unchanged, and the signature still verifies.
        expect(hex(a.signedAttrs.bytes)).toBe(hex(dissect(before).signedAttrs.bytes));
        expect(await verifies(m, a)).toBe(true);
        // The CMS reader hands it back where a verifier looks for it.
        expect(parseSignedData(after).signerInfos[0]?.timeStampTokens.map(hex)).toEqual([hex(token)]);
    });

    it('should add a second token beside the first', async () => {
        const m = await p256();
        const token = await timeStampToken(new Uint8Array(32));
        const twice = addTimeStampToken(addTimeStampToken(await BASE(), 0, token), 0, token);
        // One attribute per call; each holds one token.
        expect(dissect(twice).unsignedAttrs?.children).toHaveLength(2);
        expect(parseSignedData(twice).signerInfos[0]?.timeStampTokens).toHaveLength(2);
        expect(await verifies(m, dissect(twice))).toBe(true);
    });

    it('should refuse a signerIndex that names no signer with PKI_API_MISUSE', async () => {
        const der = await BASE();
        for (const index of [1, -1, 0.5]) {
            const error = catchError(() => addTimeStampToken(der, index, TOKEN));
            expect(error).toBeInstanceOf(PkiError);
            expect(error).toMatchObject({ code: 'PKI_API_MISUSE' });
        }
    });

    it('should refuse a token that is not bytes with PKI_INVALID_INPUT', async () => {
        const der = await BASE();
        expect(catchError(() => addTimeStampToken(der, 0, 'MIIB' as unknown as Uint8Array))).toMatchObject({ code: 'PKI_INVALID_INPUT' });
    });

    it('should accept a token made in another realm, as every other byte argument is', async () => {
        const token = encodeSequence([encodeObjectIdentifier(OID.signedData), encodeInteger(42)]);
        const foreign = runInNewContext('Uint8Array.from(source)', { source: Array.from(token) }) as Uint8Array;
        expect(foreign instanceof Uint8Array).toBe(false);
        const attribute = child(dissect(addTimeStampToken(await BASE(), 0, foreign)).unsignedAttrs, 0);
        expect(readObjectIdentifier(child(attribute, 0))).toBe(OID.timeStampToken);
        expect(hex(child(child(attribute, 1), 0).bytes)).toBe(hex(token));
    });

    it('should refuse a ContentInfo that is not id-signedData with PKI_CMS_CONTENT_TYPE_UNEXPECTED', () => {
        const data = encodeSequence([encodeObjectIdentifier(OID.data), tlv(2, true, 0, encodeOctetString(CONTENT))]);
        const error = catchError(() => addTimeStampToken(data, 0, TOKEN));
        expect(error).toBeInstanceOf(PkiCmsError);
        expect(error).toMatchObject({ code: 'PKI_CMS_CONTENT_TYPE_UNEXPECTED' });
    });

    it('should refuse a malformed SignedData with PKI_CMS_STRUCTURE_INVALID, and input that is not DER with the encoding error', async () => {
        const valid = dissect(await BASE());
        const [, build, path] = STRUCTURES().find(([label]) => label === 'signerInfos is missing') as [string, Build, string];
        expect(catchError(() => addTimeStampToken(build(valid), 0, TOKEN))).toMatchObject({ code: 'PKI_CMS_STRUCTURE_INVALID', path });
        expect(catchError(() => addTimeStampToken(Uint8Array.of(0x30, 0x05, 0x06), 0, TOKEN))).toBeInstanceOf(PkiEncodingError);
    });

    it('should apply the caller\'s limits', async () => {
        const der = await BASE();
        expect(catchError(() => addTimeStampToken(der, 0, TOKEN, { limits: { maxInputBytes: 10 } })))
            .toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxInputBytes' });
    });
});
