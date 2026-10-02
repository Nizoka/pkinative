import { constants, generateKeyPairSync, sign as nodeSign, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { decodeAsn1, encodeBitString, encodeInteger, encodeSequence, parseCertificate } from '../../src/index.js';
import type { ExternalSigner } from '../../src/types/crypto-types.js';
import { PkiCryptoError, PkiError } from '../../src/types/pki-errors.js';
import type { Certificate } from '../../src/types/x509-types.js';
import type { CertificateList } from '../../src/types/crl-types.js';
import type { OcspBasicResponse } from '../../src/types/ocsp-types.js';
import { verifyCertificateSignature, verifyCrlSignature, verifyOcspSignature, verifySelfSignature } from '../../src/crypto/x509-verify.js';
import { canVerify } from '../../src/crypto/webcrypto.js';
import { createCertificate } from '../../src/build/build-certificate.js';
import { algorithm, bitString, certificate, ecKey, nullValue, tbsCertificate } from '../helpers/cert-builder.js';

/**
 * Verification against the committed fixtures — foreign certificates whose
 * provenance is recorded in tests/fixtures/PROVENANCE.md. Their signatures
 * were made by Let's Encrypt, not by anything in this repository, which is
 * what makes a `true` here worth something: the library's own encoder is
 * never the oracle for its own verifier.
 */

const CERTS = resolve(import.meta.dirname, '..', 'fixtures', 'certs');
const load = (name: string): Certificate =>
    parseCertificate(readFileSync(join(CERTS, `${name}.der`)), { onDiagnostic: () => undefined });

describe('verifyCertificateSignature', () => {
    it.each([
        ["Let's Encrypt R12 was signed by ISRG Root X1 (RSA-4096, SHA-256)", 'lets-encrypt-r12', 'isrg-root-x1'],
        ["Let's Encrypt E7 was signed by ISRG Root X2 (P-384, SHA-384)", 'lets-encrypt-e7', 'isrg-root-x2'],
    ])('should confirm that %s', async (_what, subject, issuer) => {
        await expect(verifyCertificateSignature(load(subject), load(issuer))).resolves.toBe(true);
    });

    it.each([
        ['the issuer is the other root of the same hierarchy', 'lets-encrypt-r12', 'isrg-root-x2'],
        ['the issuer signed nothing in this chain', 'lets-encrypt-e7', 'isrg-root-x1'],
    ])('should answer false, not throw, when %s', async (_what, subject, issuer) => {
        await expect(verifyCertificateSignature(load(subject), load(issuer))).resolves.toBe(false);
    });

    it('should refuse a certificate whose signed bytes were altered', async () => {
        const real = readFileSync(join(CERTS, 'lets-encrypt-r12.der'));
        const tampered = Uint8Array.from(real);
        // Inside a text value, not a header: the point is a certificate
        // that still parses and no longer verifies. Changing a length
        // octet would only prove the decoder works.
        const at = real.indexOf(0x52, real.indexOf(0x0a) + 1); // an 'R' somewhere in a name
        tampered[at] = 0x53;
        const cert = parseCertificate(tampered, { onDiagnostic: () => undefined });
        await expect(verifyCertificateSignature(cert, load('isrg-root-x1'))).resolves.toBe(false);
    });

    it('should refuse a certificate whose signature was altered', async () => {
        const real = readFileSync(join(CERTS, 'lets-encrypt-r12.der'));
        const tampered = Uint8Array.from(real);
        tampered[real.length - 1] = (tampered[real.length - 1] ?? 0) ^ 0xff;
        const cert = parseCertificate(tampered, { onDiagnostic: () => undefined });
        await expect(verifyCertificateSignature(cert, load('isrg-root-x1'))).resolves.toBe(false);
    });

    it('should reject a certificate argument that is not a parsed certificate', async () => {
        const real = load('isrg-root-x1');
        await expect(verifyCertificateSignature(null as unknown as Certificate, real)).rejects.toThrow(PkiError);
        await expect(verifyCertificateSignature(real, { tbsDer: 'not bytes' } as unknown as Certificate))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT', message: expect.stringContaining('issuer') }));
    });

    it('should answer false when the two signatureAlgorithm fields disagree', async () => {
        // Only tbsCertificate.signature is covered by the signature, so a
        // mismatch means the outer field may have been rewritten. The
        // algorithm named here is one pkinative does not support, so a
        // `false` — rather than PKI_CRYPTO_ALGORITHM_UNSUPPORTED — also
        // proves the comparison happens before anything is resolved.
        const der = certificate({
            tbs: tbsCertificate({ signature: algorithm('1.2.840.113549.1.1.4', nullValue()) }),
            signatureAlgorithm: algorithm('1.2.840.113549.1.1.11', nullValue()),
        });
        const cert = parseCertificate(der, { onDiagnostic: () => undefined });
        await expect(verifyCertificateSignature(cert, cert)).resolves.toBe(false);
    });

    it('should let a tool look past the mismatch when it asks to', async () => {
        const der = certificate({
            tbs: tbsCertificate({ signature: algorithm('1.2.840.113549.1.1.4', nullValue()) }),
            signatureAlgorithm: algorithm('1.2.840.113549.1.1.11', nullValue()),
        });
        const cert = parseCertificate(der, { onDiagnostic: () => undefined });
        // The outer algorithm is now honoured: RSA over an EC key is a
        // decided no, and the answer is still false — but by another route.
        await expect(verifyCertificateSignature(cert, cert, { requireAlgorithmMatch: false })).resolves.toBe(false);
    });

    it('should answer false when the signature BIT STRING declares unused bits', async () => {
        // A signature is a whole number of octets, so a non-zero
        // unused-bits count is a rewritten certificate and not a short
        // signature. Strict DER already refuses it at parse time
        // (X.690 §11.2.1); this check exists for the BER path, which is
        // the only way such a certificate reaches a verifier at all.
        const der = certificate({ signatureValue: bitString([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], 1) });
        const cert = parseCertificate(der, { encodingRules: 'ber', onDiagnostic: () => undefined });
        expect(cert.signatureValue.unusedBits).toBe(1);
        await expect(verifyCertificateSignature(cert, cert)).resolves.toBe(false);
    });

    it('should answer false when an ECDSA signature is not a canonical Ecdsa-Sig-Value', async () => {
        const der = certificate({
            tbs: tbsCertificate({ subjectPublicKeyInfo: ecKey() }),
            signatureValue: bitString([0x05, 0x00]),
        });
        const cert = parseCertificate(der, { onDiagnostic: () => undefined });
        await expect(verifyCertificateSignature(cert, cert)).resolves.toBe(false);
    });

    it('should refuse an algorithm outside the supported set, rather than guess', async () => {
        const der = certificate({
            tbs: tbsCertificate({ signature: algorithm('1.2.840.113549.1.1.4', nullValue()), subjectPublicKeyInfo: ecKey() }),
            signatureAlgorithm: algorithm('1.2.840.113549.1.1.4', nullValue()),
        });
        const cert = parseCertificate(der, { onDiagnostic: () => undefined });
        await expect(verifyCertificateSignature(cert, cert)).rejects.toThrow(PkiCryptoError);
    });

    it('should refuse a key this runtime will not import', async () => {
        // The point of the EC fixture is a real SPKI with a key the host
        // cannot use: the coordinates are 1..64, not a point on P-256.
        const der = certificate({ tbs: tbsCertificate({ subjectPublicKeyInfo: ecKey() }) });
        const cert = parseCertificate(der, { onDiagnostic: () => undefined });
        await expect(verifyCertificateSignature(cert, cert, { requireAlgorithmMatch: false }))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED' }));
    });
});

describe('SHA-1 signatures', () => {
    /** A self-signed certificate over SHA-1, which Web Crypto signs quite happily. */
    async function sha1SelfSigned(): Promise<Certificate> {
        const pair = await crypto.subtle.generateKey(
            { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-1' },
            true, ['sign', 'verify'],
        );
        const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
        const der = await createCertificate({
            serialNumber: 1n,
            issuer: [[{ type: '2.5.4.3', value: 'Legacy CA' }]],
            subject: [[{ type: '2.5.4.3', value: 'Legacy CA' }]],
            notBefore: Date.UTC(2012, 0, 1),
            notAfter: Date.UTC(2032, 0, 1),
            subjectPublicKey: spki,
        }, { key: pair.privateKey, algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' } });
        return parseCertificate(der, { onDiagnostic: () => undefined });
    }

    it('should refuse to answer rather than return a boolean', async () => {
        // Neither boolean is true: the arithmetic checks out, and a chosen-prefix
        // collision has been practical since 2017, so the signature does not bind
        // the bytes it covers. "This question cannot be put" is the third answer,
        // and it is what the PkiCryptoError family means.
        const cert = await sha1SelfSigned();
        await expect(verifyCertificateSignature(cert, cert))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_REFUSED' }));
        await expect(verifyCertificateSignature(cert, cert)).rejects.toBeInstanceOf(PkiCryptoError);
    });

    it('should name the algorithm OID, so a report can say which certificate', async () => {
        const cert = await sha1SelfSigned();
        await expect(verifyCertificateSignature(cert, cert))
            .rejects.toThrow(expect.objectContaining({ algorithm: '1.2.840.113549.1.1.5' }));
    });

    it('should verify one when the caller asks explicitly, for an archival reading', async () => {
        const cert = await sha1SelfSigned();
        await expect(verifyCertificateSignature(cert, cert, { allowSha1: true })).resolves.toBe(true);
    });

    it('should still answer false for a bad SHA-1 signature under the opt-in', async () => {
        // The opt-in relaxes the policy, never the arithmetic.
        const cert = await sha1SelfSigned();
        const other = await sha1SelfSigned();
        await expect(verifyCertificateSignature(cert, other, { allowSha1: true })).resolves.toBe(false);
    });

    it('should refuse a SHA-1 self-signature through verifySelfSignature too', async () => {
        const cert = await sha1SelfSigned();
        await expect(verifySelfSignature(cert)).rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_REFUSED' }));
        await expect(verifySelfSignature(cert, { allowSha1: true })).resolves.toBe(true);
    });
});

describe('verifySelfSignature', () => {
    it.each([
        ['ISRG Root X1', 'isrg-root-x1'],
        ['ISRG Root X2', 'isrg-root-x2'],
    ])('should confirm that %s signed itself', async (_name, fixture) => {
        await expect(verifySelfSignature(load(fixture))).resolves.toBe(true);
    });

    it('should answer false for a certificate whose subject and issuer differ', async () => {
        await expect(verifySelfSignature(load('lets-encrypt-r12'))).resolves.toBe(false);
    });

    it('should answer false when the names match but the key cannot have signed', async () => {
        // RFC 8410 §10.2: the subject key is X25519, a key-agreement key,
        // while the signature is Ed25519. Self-issued by name, signed by
        // something else in fact.
        await expect(verifySelfSignature(load('rfc8410-x25519'))).resolves.toBe(false);
    });

    it('should reject an argument that is not a parsed certificate', async () => {
        await expect(verifySelfSignature(undefined as unknown as Certificate)).rejects.toThrow(PkiError);
    });

    describe('a certificate its own key signed, under an issuer name that is not its subject', () => {
        // A fresh P-256 key signs both certificates, so the signature check
        // alone answers true for each: only the name comparison separates a
        // self-signed certificate from one that merely carries its own key.
        const make = async (issuer?: string): Promise<Certificate> => {
            const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as webcrypto.CryptoKeyPair;
            const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey));
            return parseCertificate(await createCertificate({
                serialNumber: 11n,
                subject: [[{ type: '2.5.4.3', value: 'Subject A' }]],
                ...(issuer === undefined ? {} : { issuer: [[{ type: '2.5.4.3', value: issuer }]] }),
                notBefore: Date.UTC(2026, 0, 1),
                notAfter: Date.UTC(2027, 0, 1),
                subjectPublicKey: spki,
            }, {
                algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
                produceSignature: async (data) => new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data)),
            }), { onDiagnostic: () => undefined });
        };

        it('should answer false although the key verifies the signature', async () => {
            const cert = await make('Issuer B');
            await expect(verifyCertificateSignature(cert, cert)).resolves.toBe(true);
            await expect(verifySelfSignature(cert)).resolves.toBe(false);
        });

        it('should answer true for the same construction with the names equal', async () => {
            await expect(verifySelfSignature(await make())).resolves.toBe(true);
        });
    });

    describe('a value shaped like a certificate with one field wrong', () => {
        // Each shape fails exactly one clause of the guard and passes every
        // other, so each clause is shown to refuse on its own.
        it.each<[string, (real: Certificate) => unknown]>([
            ['tbsDer is an array of numbers, not a Uint8Array', (real) => ({ ...real, tbsDer: Array.from(real.tbsDer) })],
            ['signatureAlgorithm is missing', (real) => ({ ...real, signatureAlgorithm: undefined })],
            ['signatureAlgorithm is null', (real) => ({ ...real, signatureAlgorithm: null })],
            ['subjectPublicKeyInfo is missing', (real) => ({ ...real, subjectPublicKeyInfo: undefined })],
        ])('should reject with PKI_INVALID_INPUT when %s', async (_what, reshape) => {
            const value = reshape(load('isrg-root-x1')) as Certificate;
            await expect(verifySelfSignature(value)).rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
        });
    });
});

describe('verifyCrlSignature and verifyOcspSignature', () => {
    it('should reject a null CRL with PKI_INVALID_INPUT, not a TypeError', async () => {
        await expect(verifyCrlSignature(null as unknown as CertificateList, load('isrg-root-x1')))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should reject a null basicResponse with PKI_INVALID_INPUT, not a TypeError', async () => {
        await expect(verifyOcspSignature(null as unknown as OcspBasicResponse, load('isrg-root-x1')))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});

describe('a runtime without Web Crypto', () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');

    afterEach(() => {
        if (original !== undefined) Object.defineProperty(globalThis, 'crypto', original);
    });

    function withoutSubtle(value: unknown): void {
        Object.defineProperty(globalThis, 'crypto', { value, configurable: true, writable: true });
    }

    it.each([
        ['no crypto at all', undefined],
        ['crypto without subtle', {}],
        ['subtle without importKey', { subtle: {} }],
        ['subtle without verify', { subtle: { importKey: (): void => undefined } }],
    ])('should report that it cannot verify when there is %s', (_what, value) => {
        withoutSubtle(value);
        expect(canVerify()).toBe(false);
    });

    it('should say so with a code, rather than fail somewhere deeper', async () => {
        const cert = load('isrg-root-x1');
        withoutSubtle(undefined);
        await expect(verifyCertificateSignature(cert, cert))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_UNAVAILABLE' }));
    });

    it('should report that it can verify on a runtime that can', () => {
        expect(canVerify()).toBe(true);
    });
});

describe('a host that misbehaves', () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    afterEach(() => {
        if (original !== undefined) Object.defineProperty(globalThis, 'crypto', original);
    });

    it('should treat a host that throws from verify as a refusal, not an incident', async () => {
        // Several runtimes throw rather than return false for a signature of
        // the wrong length. Failing closed here keeps that from becoming an
        // exception a caller swallows into a success path.
        const cert = load('isrg-root-x1');
        Object.defineProperty(globalThis, 'crypto', {
            configurable: true,
            writable: true,
            value: {
                subtle: {
                    importKey: (): Promise<unknown> => Promise.resolve({ type: 'public' }),
                    verify: (): Promise<boolean> => Promise.reject(new Error('signature length')),
                },
            },
        });
        await expect(verifyCertificateSignature(cert, cert)).resolves.toBe(false);
    });
});

describe('an id-RSASSA-PSS issuer key (RFC 4055)', () => {
    // What `openssl genpkey -algorithm RSA-PSS` writes: the key restricted by
    // its OID, with its parameters in the SubjectPublicKeyInfo.
    const pss = generateKeyPairSync('rsa-pss', { modulusLength: 2048, hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha256' });
    const spki = new Uint8Array(pss.publicKey.export({ type: 'spki', format: 'der' }));
    const selfSigned = async (signer: ExternalSigner): Promise<Certificate> => parseCertificate(await createCertificate({
        serialNumber: 7n,
        subject: [[{ type: '2.5.4.3', value: 'PSS key' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2027, 0, 1),
        subjectPublicKey: spki,
    }, signer), { onDiagnostic: () => undefined });

    it('should say why the runtime refuses the key, instead of suggesting another runtime', async () => {
        const cert = await selfSigned({
            algorithm: { name: 'RSA-PSS', hash: 'SHA-256' },
            produceSignature: (data) => new Uint8Array(nodeSign('sha256', data, { key: pss.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 })),
        });
        expect(cert.subjectPublicKeyInfo.kind).toBe('rsa-pss');
        // The W3C Web Crypto specification imports an RSA SPKI only under
        // rsaEncryption; Node 22 answers "DataError: Invalid key type".
        await expect(verifySelfSignature(cert)).rejects.toThrow(expect.objectContaining({
            code: 'PKI_CRYPTO_KEY_UNSUPPORTED',
            message: expect.stringContaining('the key is id-RSASSA-PSS (RFC 4055 §1.2)'),
        }));
    });

    it('should answer false for a PKCS#1 v1.5 signature under it, before asking the host (RFC 4055 §1.2)', async () => {
        // No tool will make this signature (OpenSSL refuses PKCS#1 padding
        // with an RSA-PSS key), so its bytes do not matter: the key may only
        // be used for RSASSA-PSS, and the answer is decided before import.
        const cert = await selfSigned({ algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, produceSignature: () => new Uint8Array(256).fill(1) });
        await expect(verifySelfSignature(cert)).resolves.toBe(false);
    });
});

describe('ECDSA malleability', () => {
    const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const toBigInt = (bytes: Uint8Array): bigint => bytes.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);

    it('should accept the high-S twin of a valid signature, which X.509 does not forbid — so a DER is not unique to its tbsCertificate', async () => {
        const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        const der = await createCertificate({
            serialNumber: 9n,
            subject: [[{ type: '2.5.4.3', value: 'twin' }]],
            notBefore: Date.UTC(2026, 0, 1),
            notAfter: Date.UTC(2027, 0, 1),
            subjectPublicKey: new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey)),
        }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
        const original = parseCertificate(der, { onDiagnostic: () => undefined });
        const value = decodeAsn1(original.signatureValue.bytes);
        const r = toBigInt(value.children[0]?.content ?? new Uint8Array(0));
        const s = toBigInt(value.children[1]?.content ?? new Uint8Array(0));
        const twinSignature = encodeSequence([encodeInteger(r), encodeInteger(P256_ORDER - s)]);
        const twinDer = encodeSequence([original.tbsDer, original.signatureAlgorithm.der, encodeBitString(twinSignature, 0)]);
        const twin = parseCertificate(twinDer, { onDiagnostic: () => undefined });

        expect(await verifySelfSignature(original)).toBe(true);
        expect(await verifySelfSignature(twin)).toBe(true);
        expect(twin.der).not.toEqual(original.der);
        expect(twin.tbsDer).toEqual(original.tbsDer);
    });
});
