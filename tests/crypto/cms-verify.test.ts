import type { webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { createCertificate } from '../../src/build/build-certificate.js';
import { verifySignerInfoSignature } from '../../src/crypto/cms-verify.js';
import { ecdsaRawToDer } from '../../src/crypto/crypto-signature.js';
import { parseCertificate } from '../../src/index.js';
import type { SignerInfo } from '../../src/types/cms-types.js';
import type { SignatureAlgorithm } from '../../src/types/crypto-types.js';
import { PkiCryptoError, PkiError } from '../../src/types/pki-errors.js';
import type { AlgorithmIdentifier, Certificate } from '../../src/types/x509-types.js';
import { algorithm, nullValue, octetString, oid, set } from '../helpers/cert-builder.js';
import { concat, sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * The CMS signature primitive. Every signature below is made in the test by
 * the host's own Web Crypto over bytes assembled here, independently of the
 * engine — so a `true` is Node's arithmetic agreeing with pkinative's choice
 * of algorithm, input and key, and a `false` is that choice being refused.
 */

const SHA1 = '1.3.14.3.2.26';
const SHA256 = '2.16.840.1.101.3.4.2.1';
const SHA384 = '2.16.840.1.101.3.4.2.2';
const SHA512 = '2.16.840.1.101.3.4.2.3';
const SHA224 = '2.16.840.1.101.3.4.2.4';
const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
const SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
const PSS = '1.2.840.113549.1.1.10';
const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const ED25519 = '1.3.101.112';

/** An AlgorithmIdentifier as the parser would hand one over. */
function identifier(dotted: string, parameters?: Uint8Array): AlgorithmIdentifier {
    const der = algorithm(dotted, parameters);
    return { oid: dotted, parameters: decodeAsn1(der).children[1], der };
}

const tagged = (tag: number, child: Uint8Array): Uint8Array => concat([0xa0 + tag, child.length], child);
const PSS_SHA256 = identifier(PSS, sequence(
    tagged(0, algorithm(SHA256)),
    tagged(1, algorithm('1.2.840.113549.1.1.8', algorithm(SHA256))),
    tagged(2, universal(2, [32])),
));

/**
 * The signed attributes as RFC 5652 §5.4 signs them — `SET OF`, tag 0x31 —
 * holding a content-type and a message-digest. Their values do not matter
 * here: this primitive checks the signature over them, not what they say.
 */
const SIGNED_ATTRIBUTES = set(
    sequence(oid('1.2.840.113549.1.9.3'), set(oid('1.2.840.113549.1.7.1'))),
    sequence(oid('1.2.840.113549.1.9.4'), set(octetString(new Uint8Array(32).fill(0x5a)))),
);

/** The same bytes as transmitted, under the IMPLICIT `[0]` tag. */
const TRANSMITTED_ATTRIBUTES = Uint8Array.from(SIGNED_ATTRIBUTES, (byte, i) => (i === 0 ? 0xa0 : byte));

const CONTENT = new TextEncoder().encode('the content a signer without signed attributes signs directly');

interface SignerInfoParts {
    readonly digest: AlgorithmIdentifier;
    readonly signatureAlgorithm: AlgorithmIdentifier;
    readonly signature: Uint8Array;
    /** Defaults to {@link SIGNED_ATTRIBUTES}; `null` for a signer without signed attributes. */
    readonly signedAttributesDer?: Uint8Array | null;
}

/** A SignerInfo as the parser would hand one over, reduced to what the signature depends on. */
function signerInfo(parts: SignerInfoParts): SignerInfo {
    const signedAttributesDer = parts.signedAttributesDer === null ? undefined : parts.signedAttributesDer ?? SIGNED_ATTRIBUTES;
    return Object.freeze({
        version: 3,
        sid: { kind: 'subjectKeyIdentifier' as const, keyIdentifier: Uint8Array.of(1, 2, 3, 4) },
        digestAlgorithm: parts.digest,
        signedAttributes: signedAttributesDer === undefined ? undefined : [],
        signedAttributesDer,
        signatureAlgorithm: parts.signatureAlgorithm,
        signature: parts.signature,
        unsignedAttributes: undefined,
        contentType: undefined,
        messageDigest: undefined,
        signingTime: undefined,
        signingCertificate: undefined,
        timeStampTokens: [],
        der: new Uint8Array(0),
    });
}

type Key = Awaited<ReturnType<typeof crypto.subtle.importKey>>;
type GenerateParams = webcrypto.RsaHashedKeyGenParams | webcrypto.EcKeyGenParams;
type ImportParams = Parameters<typeof crypto.subtle.importKey>[2];
type SignParams = Parameters<typeof crypto.subtle.sign>[0];

interface Signer {
    readonly certificate: Certificate;
    readonly privateKey: Key;
}

/** A self-signed certificate over a fresh key, and the private half to sign CMS content with. */
async function makeSigner(generate: GenerateParams, certAlgorithm: SignatureAlgorithm): Promise<Signer> {
    const pair = await crypto.subtle.generateKey(generate, true, ['sign', 'verify']) as { publicKey: Key; privateKey: Key };
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const der = await createCertificate({
        serialNumber: 1n,
        issuer: [[{ type: '2.5.4.3', value: 'CMS Signer' }]],
        subject: [[{ type: '2.5.4.3', value: 'CMS Signer' }]],
        notBefore: Date.UTC(2025, 0, 1),
        notAfter: Date.UTC(2035, 0, 1),
        subjectPublicKey: spki,
    }, { key: pair.privateKey, algorithm: certAlgorithm });
    return { certificate: parseCertificate(der, { onDiagnostic: () => undefined }), privateKey: pair.privateKey };
}

/**
 * The RSA key re-imported for one PKCS#1 v1.5 or PSS hash. A Web Crypto RSA
 * key is bound to one hash; the key material is not, and the signer
 * certificate stays the same whichever the CMS signer chose.
 */
async function rsaSign(signer: Signer, params: ImportParams, sign: SignParams, data: Uint8Array): Promise<Uint8Array> {
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', signer.privateKey);
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, params, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign(sign, key, data));
}

async function ecdsaSign(signer: Signer, hash: string, size: number, data: Uint8Array): Promise<Uint8Array> {
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash }, signer.privateKey, data));
    return ecdsaRawToDer(raw, size);
}

let rsa: Signer;
let p256: Signer;
let p384: Signer;
let ed25519: Signer;

beforeAll(async () => {
    [rsa, p256, p384, ed25519] = await Promise.all([
        makeSigner({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' },
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }),
        makeSigner({ name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }),
        makeSigner({ name: 'ECDSA', namedCurve: 'P-384' }, { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }),
        makeSigner({ name: 'Ed25519' } as GenerateParams, { name: 'Ed25519' }),
    ]);
});

const pkcs1 = (hash: string, data: Uint8Array = SIGNED_ATTRIBUTES): Promise<Uint8Array> =>
    rsaSign(rsa, { name: 'RSASSA-PKCS1-v1_5', hash }, { name: 'RSASSA-PKCS1-v1_5' }, data);

describe('verifySignerInfoSignature', () => {
    describe('every family, over the 0x31-tagged signed attributes', () => {
        it('should verify rsaEncryption with the hash from digestAlgorithm (RFC 3370 §3.2)', async () => {
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: await pkcs1('SHA-256') });
            await expect(verifySignerInfoSignature(info, rsa.certificate)).resolves.toBe(true);
        });

        it('should verify rsaEncryption over SHA-384, a hash the certificate itself does not use', async () => {
            const info = signerInfo({ digest: identifier(SHA384, nullValue()), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: await pkcs1('SHA-384') });
            await expect(verifySignerInfoSignature(info, rsa.certificate)).resolves.toBe(true);
        });

        it('should verify sha256WithRSAEncryption', async () => {
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(SHA256_WITH_RSA, nullValue()), signature: await pkcs1('SHA-256') });
            await expect(verifySignerInfoSignature(info, rsa.certificate)).resolves.toBe(true);
        });

        it('should verify RSASSA-PSS with its parameters written out (RFC 4056)', async () => {
            const signature = await rsaSign(rsa, { name: 'RSA-PSS', hash: 'SHA-256' }, { name: 'RSA-PSS', saltLength: 32 }, SIGNED_ATTRIBUTES);
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: PSS_SHA256, signature });
            await expect(verifySignerInfoSignature(info, rsa.certificate)).resolves.toBe(true);
        });

        it('should verify ECDSA on P-256, converting the DER Ecdsa-Sig-Value (RFC 5753 §2.1.1)', async () => {
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(ECDSA_SHA256), signature: await ecdsaSign(p256, 'SHA-256', 32, SIGNED_ATTRIBUTES) });
            await expect(verifySignerInfoSignature(info, p256.certificate)).resolves.toBe(true);
        });

        it('should verify ECDSA on P-384', async () => {
            const info = signerInfo({ digest: identifier(SHA384), signatureAlgorithm: identifier(ECDSA_SHA384), signature: await ecdsaSign(p384, 'SHA-384', 48, SIGNED_ATTRIBUTES) });
            await expect(verifySignerInfoSignature(info, p384.certificate)).resolves.toBe(true);
        });

        it('should verify Ed25519 with the SHA-512 digestAlgorithm RFC 8419 §3.1 requires', async () => {
            const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, ed25519.privateKey, SIGNED_ATTRIBUTES));
            const info = signerInfo({ digest: identifier(SHA512), signatureAlgorithm: identifier(ED25519), signature });
            await expect(verifySignerInfoSignature(info, ed25519.certificate)).resolves.toBe(true);
        });
    });

    describe('signatures that do not stand up', () => {
        it('should answer false for a tampered signature', async () => {
            const signature = await pkcs1('SHA-256');
            signature[10] = (signature[10] ?? 0) ^ 0x01;
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature });
            await expect(verifySignerInfoSignature(info, rsa.certificate)).resolves.toBe(false);
        });

        it('should answer false for a signature over the transmitted [0] tag rather than SET OF (RFC 5652 §5.4)', async () => {
            // The classic CMS bug, made by a signer: one octet different,
            // and the signature covers bytes no conforming verifier checks.
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: await pkcs1('SHA-256', TRANSMITTED_ATTRIBUTES) });
            await expect(verifySignerInfoSignature(info, rsa.certificate)).resolves.toBe(false);
        });

        it('should answer false for Ed25519 over a SHA-256 digestAlgorithm, even with a good signature', async () => {
            const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, ed25519.privateKey, SIGNED_ATTRIBUTES));
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(ED25519), signature });
            await expect(verifySignerInfoSignature(info, ed25519.certificate)).resolves.toBe(false);
        });

        it('should answer false when the signature algorithm names another hash than digestAlgorithm (RFC 8933)', async () => {
            // Good arithmetic, inconsistent SignerInfo: the SHA-256 digest field
            // is unsigned, so accepting this would let it be rewritten.
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(ECDSA_SHA384), signature: await ecdsaSign(p384, 'SHA-384', 48, SIGNED_ATTRIBUTES) });
            await expect(verifySignerInfoSignature(info, p384.certificate)).resolves.toBe(false);
        });

        it('should answer false for MD5, rather than report it unsupported', async () => {
            const info = signerInfo({ digest: identifier('1.2.840.113549.2.5', nullValue()), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: await pkcs1('SHA-256') });
            await expect(verifySignerInfoSignature(info, rsa.certificate)).resolves.toBe(false);
        });

        it('should answer false for an ECDSA signature that is not a canonical Ecdsa-Sig-Value', async () => {
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(ECDSA_SHA256), signature: Uint8Array.of(0x05, 0x00) });
            await expect(verifySignerInfoSignature(info, p256.certificate)).resolves.toBe(false);
        });

        it.each([
            ['an ECDSA signer against an RSA certificate', ECDSA_SHA256, (): Certificate => rsa.certificate],
            ['an rsaEncryption signer against an EC certificate', RSA_ENCRYPTION, (): Certificate => p256.certificate],
        ])('should answer false for %s: that key cannot have signed', async (_what, dotted, certificate) => {
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(dotted), signature: await pkcs1('SHA-256') });
            await expect(verifySignerInfoSignature(info, certificate())).resolves.toBe(false);
        });

        it('should answer false against a certificate whose key did not sign', async () => {
            const other = await makeSigner({ name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(ECDSA_SHA256), signature: await ecdsaSign(p256, 'SHA-256', 32, SIGNED_ATTRIBUTES) });
            await expect(verifySignerInfoSignature(info, other.certificate)).resolves.toBe(false);
        });
    });

    describe('a signer without signed attributes', () => {
        it('should verify the signature over the content the caller passes', async () => {
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: await pkcs1('SHA-256', CONTENT), signedAttributesDer: null });
            await expect(verifySignerInfoSignature(info, rsa.certificate, { content: CONTENT })).resolves.toBe(true);
        });

        it('should refuse to guess at the content when none is passed', async () => {
            // Absent content is not empty content: verifying over zero bytes
            // would be a verdict about a message nobody supplied.
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: await pkcs1('SHA-256', CONTENT), signedAttributesDer: null });
            await expect(verifySignerInfoSignature(info, rsa.certificate))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
            await expect(verifySignerInfoSignature(info, rsa.certificate, {})).rejects.toBeInstanceOf(PkiError);
        });

        it('should verify the signed attributes, not the content, when both exist', async () => {
            const info = signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: await pkcs1('SHA-256') });
            await expect(verifySignerInfoSignature(info, rsa.certificate, { content: CONTENT })).resolves.toBe(true);
        });
    });

    describe('SHA-1', () => {
        const sha1Signer = async (): Promise<SignerInfo> =>
            signerInfo({ digest: identifier(SHA1, nullValue()), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: await pkcs1('SHA-1') });

        it('should refuse to answer rather than return a boolean', async () => {
            const info = await sha1Signer();
            await expect(verifySignerInfoSignature(info, rsa.certificate))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_REFUSED', algorithm: RSA_ENCRYPTION }));
            await expect(verifySignerInfoSignature(info, rsa.certificate, { allowSha1: false })).rejects.toBeInstanceOf(PkiCryptoError);
        });

        it('should verify one when the caller asks explicitly, for an archival reading', async () => {
            await expect(verifySignerInfoSignature(await sha1Signer(), rsa.certificate, { allowSha1: true })).resolves.toBe(true);
        });
    });

    describe('algorithms Web Crypto does not run', () => {
        it.each([
            ['Ed448, whose CMS digest is SHAKE256', SHA512, '1.3.101.113'],
            ['DSA', SHA256, '2.16.840.1.101.3.4.3.2'],
            ['rsaEncryption over SHA-224', SHA224, RSA_ENCRYPTION],
        ])('should refuse %s by code rather than answer', async (_what, digest, dotted) => {
            const info = signerInfo({ digest: identifier(digest), signatureAlgorithm: identifier(dotted), signature: new Uint8Array(64) });
            await expect(verifySignerInfoSignature(info, ed25519.certificate))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' }));
        });
    });

    describe('arguments that are not parsed values', () => {
        const valid = (): SignerInfo => signerInfo({ digest: identifier(SHA256), signatureAlgorithm: identifier(RSA_ENCRYPTION, nullValue()), signature: new Uint8Array(1) });

        it.each([
            ['null', null],
            ['raw DER', new Uint8Array(4)],
            ['a SignerInfo without its signature bytes', { ...valid(), signature: 'bytes' }],
            ['a SignerInfo without a digestAlgorithm', { ...valid(), digestAlgorithm: undefined }],
            ['a SignerInfo with a null digestAlgorithm', { ...valid(), digestAlgorithm: null }],
            ['a SignerInfo without a signatureAlgorithm', { ...valid(), signatureAlgorithm: 'rsa' }],
            ['a SignerInfo with a null signatureAlgorithm', { ...valid(), signatureAlgorithm: null }],
        ])('should reject %s as the signerInfo', async (_what, value) => {
            await expect(verifySignerInfoSignature(value as unknown as SignerInfo, rsa.certificate))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
        });

        it.each([
            ['undefined', undefined],
            ['raw DER', new Uint8Array(4)],
            ['a certificate without a key', { tbsDer: new Uint8Array(1) }],
            ['a certificate with a null key', { subjectPublicKeyInfo: null }],
            ['a key without its DER', { subjectPublicKeyInfo: { kind: 'rsa' } }],
        ])('should reject %s as the signer', async (_what, value) => {
            await expect(verifySignerInfoSignature(valid(), value as unknown as Certificate))
                .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
        });
    });
});
