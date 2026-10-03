import { webcrypto } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCertificationRequest } from '../../src/build/build-csr.js';
import { encodeSubjectAltName } from '../../src/build/build-structures.js';
import type { SignatureAlgorithm } from '../../src/types/crypto-types.js';
import type { CertificationRequest } from '../../src/types/x509-types.js';
import { verifyCertificationRequest } from '../../src/verify/verify-csr.js';
import { parseCertificationRequest } from '../../src/x509/x509-csr.js';
import { samples } from '../../scripts/lib/samples.js';
import { ECDSA_SHA256, algorithm, bitString, context, ecKey, integer, name, nullValue, rsaKey, utf8 } from '../helpers/cert-builder.js';
import { sequence, tlv } from '../helpers/raw-der-builder.js';

/**
 * The proof of possession, judged. Every signature here is real — made by a
 * Web Crypto key generated for the test — so what is asserted is the verdict
 * and the reason behind it, never a stubbed answer; the one stub is the host
 * refusing a key, which is the case the `not-checked` reason exists for.
 */

const CN = '2.5.4.3';
const QUIET = { onDiagnostic: (): undefined => undefined };
const where = (report: { reasons: ReadonlyArray<{ code: string; path: string }> }): string[] => report.reasons.map((r) => `${r.code}@${r.path}`);

type GeneratedPair = webcrypto.CryptoKeyPair;

async function request(keyParams: object, signWith: SignatureAlgorithm): Promise<Uint8Array> {
    const pair = await webcrypto.subtle.generateKey(keyParams as never, true, ['sign', 'verify']) as GeneratedPair;
    const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey));
    return createCertificationRequest({
        subject: [[{ type: CN, value: 'host.example' }]],
        subjectPublicKey: spki,
        extensions: [{ oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'host.example' }]) }],
    }, { key: pair.privateKey as never, algorithm: signWith });
}

const P256 = (): Promise<Uint8Array> => request({ name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' });

/** A request whose algorithm and key are chosen by hand; the signature is never checked when they disagree. */
function synthetic(spki: Uint8Array, signatureAlgorithm: Uint8Array, signature = bitString([0x01, 0x02])): Uint8Array {
    return sequence(sequence(integer([0x00]), name([[CN, utf8('host.example')]]), spki, context(0, true, [])), signatureAlgorithm, signature);
}

describe('verifyCertificationRequest', () => {
    afterEach(() => { vi.restoreAllMocks(); });

    it.each([
        ['RSA PKCS#1 v1.5 / SHA-256', { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
        ['RSASSA-PSS / SHA-256', { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, { name: 'RSA-PSS', hash: 'SHA-256' }],
        ['ECDSA P-256 / SHA-256', { name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }],
        ['Ed25519', { name: 'Ed25519' }, { name: 'Ed25519' }],
    ])('should find a %s request valid, from its DER and from its parsed form', async (_label, keyParams, signWith) => {
        const der = await request(keyParams, signWith as SignatureAlgorithm);
        const fromDer = await verifyCertificationRequest(der);
        expect(fromDer.valid).toBe(true);
        expect(fromDer.reasons).toEqual([]);
        expect(fromDer.signatureVerifications).toBe(1);
        expect(fromDer.request?.subject.rdns[0]?.[0]?.value?.value).toBe('host.example');
        expect(fromDer.request?.extensions?.map((e) => e.kind)).toEqual(['subjectAltName']);

        const parsed = parseCertificationRequest(der, QUIET);
        const fromParsed = await verifyCertificationRequest(parsed);
        expect(fromParsed.valid).toBe(true);
        expect(fromParsed.request).toBe(parsed);
    });

    it('should find every frozen CSR sample valid', async () => {
        const catalogue = await samples();
        for (const [key, der] of catalogue) {
            if (!key.startsWith('csr/')) continue;
            expect(where(await verifyCertificationRequest(der)), key).toEqual([]);
        }
    }, 30_000);

    it('should report a request whose signed bytes were altered: one octet of the subject', async () => {
        const der = await P256();
        const at = Buffer.from(der).indexOf('host.example');
        expect(at).toBeGreaterThan(0);
        const tampered = der.slice();
        tampered[at] = 0x68 ^ 0x01; // 'h' → 'i', still a UTF8String
        const report = await verifyCertificationRequest(tampered);
        expect(report.valid).toBe(false);
        expect(where(report)).toEqual(['PKI_REASON_SIGNATURE_INVALID@certificationRequest.signature']);
        expect(report.request?.subject.rdns[0]?.[0]?.value?.value).toBe('iost.example');
        expect(report.signatureVerifications).toBe(1);
    });

    it('should report a signature BIT STRING with unused bits as invalid without asking the host', async () => {
        const der = await P256();
        const parsed = parseCertificationRequest(der, QUIET);
        const verify = vi.spyOn(webcrypto.subtle, 'verify');
        const rewritten = { ...parsed, signatureValue: { ...parsed.signatureValue, unusedBits: 3 } };
        const report = await verifyCertificationRequest(rewritten);
        expect(where(report)).toEqual(['PKI_REASON_SIGNATURE_INVALID@certificationRequest.signature']);
        expect(verify).not.toHaveBeenCalled();
    });

    describe('RFC 2986 §4.2: the algorithm must be one the request\'s own key can produce', () => {
        it.each([
            ['sha256WithRSAEncryption over an EC key', ecKey(), algorithm('1.2.840.113549.1.1.11', nullValue())],
            ['ecdsa-with-SHA256 over an RSA key', rsaKey([0x00, 0xc1, 0x02, 0x03, 0x04]), algorithm(ECDSA_SHA256)],
            ['Ed25519 over an EC key', ecKey(), algorithm('1.3.101.112')],
        ])('should report %s as an invalid signature at the algorithm, verifying nothing', async (_label, spki, signatureAlgorithm) => {
            const verify = vi.spyOn(webcrypto.subtle, 'verify');
            const report = await verifyCertificationRequest(synthetic(spki, signatureAlgorithm));
            expect(report.valid).toBe(false);
            expect(where(report)).toEqual(['PKI_REASON_SIGNATURE_INVALID@certificationRequest.signatureAlgorithm']);
            expect(report.signatureVerifications).toBe(0);
            expect(report.request).toBeDefined();
            expect(verify).not.toHaveBeenCalled();
        });

        it('should report an algorithm pkinative does not verify as not checked, naming the code', async () => {
            const report = await verifyCertificationRequest(synthetic(ecKey(), algorithm('1.2.3.4.5')));
            expect(report.valid).toBe(false);
            expect(report.reasons).toHaveLength(1);
            expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_SIGNATURE_NOT_CHECKED', path: 'certificationRequest.signatureAlgorithm', errorCode: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' });
            expect(report.signatureVerifications).toBe(0);
        });

        it('should report malformed algorithm parameters as malformed input, carrying the encoding code', async () => {
            // id-RSASSA-PSS whose hash AlgorithmIdentifier holds an OID ending in
            // a continuation octet: the parser leaves parameters undecoded, so
            // the resolution is the first reader to look inside them.
            const badOid = tlv(0, false, 6, [0x60, 0x86, 0x48, 0x80]);
            const params = sequence(context(0, true, sequence(badOid)));
            const report = await verifyCertificationRequest(synthetic(rsaKey([0x00, 0xc1, 0x02, 0x03, 0x04]), algorithm('1.2.840.113549.1.1.10', params)));
            expect(report.valid).toBe(false);
            expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_INPUT_MALFORMED', path: 'certificationRequest.signatureAlgorithm', errorCode: 'PKI_OID_INVALID' });
            expect(report.request).toBeDefined();
        });
    });

    describe('a host that cannot put the question', () => {
        it('should report a key the host refuses to import as not checked, never as invalid', async () => {
            const der = await P256();
            vi.spyOn(webcrypto.subtle, 'importKey').mockRejectedValueOnce(new Error('DataError: refused by the test'));
            const report = await verifyCertificationRequest(der);
            expect(report.valid).toBe(false);
            expect(report.reasons).toHaveLength(1);
            expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_SIGNATURE_NOT_CHECKED', path: 'certificationRequest.signature', errorCode: 'PKI_CRYPTO_KEY_UNSUPPORTED' });
            expect(report.reasons[0]?.message).toContain('refused by the test');
            expect(report.signatureVerifications).toBe(0);
            expect(report.request).toBeDefined();
        });

        it('should report a SHA-1 signature as not checked by default, and verify it under allowSha1', async () => {
            const der = await request({ name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-1', namedCurve: 'P-256' });
            const refused = await verifyCertificationRequest(der);
            expect(refused.reasons[0]).toMatchObject({ code: 'PKI_REASON_SIGNATURE_NOT_CHECKED', path: 'certificationRequest.signature', errorCode: 'PKI_CRYPTO_ALGORITHM_REFUSED' });
            expect(refused.signatureVerifications).toBe(0);
            const examined = await verifyCertificationRequest(der, { allowSha1: true });
            expect(examined.valid).toBe(true);
            expect(examined.signatureVerifications).toBe(1);
        });
    });

    describe('bytes that are not a request', () => {
        it('should report malformed DER as input malformed, with the code that would have been thrown', async () => {
            const report = await verifyCertificationRequest(Uint8Array.of(0x30, 0x00));
            expect(report.valid).toBe(false);
            expect(report.request).toBeUndefined();
            expect(report.signatureVerifications).toBe(0);
            expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_INPUT_MALFORMED', path: 'certificationRequest', errorCode: 'PKI_X509_STRUCTURE_INVALID' });
        });

        it('should report a request past a limit as malformed input carrying PKI_LIMIT_EXCEEDED', async () => {
            const report = await verifyCertificationRequest(await P256(), { limits: { maxNodes: 3 } });
            expect(report.reasons[0]).toMatchObject({ code: 'PKI_REASON_INPUT_MALFORMED', errorCode: 'PKI_LIMIT_EXCEEDED' });
        });

        it('should apply the reading options to the DER: decodeExtensions false keeps the extensions raw', async () => {
            const report = await verifyCertificationRequest(await P256(), { decodeExtensions: false });
            expect(report.valid).toBe(true);
            expect(report.request?.extensions?.map((e) => e.kind)).toEqual(['raw']);
        });
    });

    describe('API misuse, which is the one thing it throws for', () => {
        it('should throw for options that are not an object, or that the reader refuses', async () => {
            const der = await P256();
            await expect(verifyCertificationRequest(der, 'strict' as unknown as object)).rejects.toMatchObject({ code: 'PKI_INVALID_OPTION' });
            await expect(verifyCertificationRequest(der, { decodeExtensions: 'yes' as unknown as boolean })).rejects.toMatchObject({ code: 'PKI_INVALID_OPTION' });
            await expect(verifyCertificationRequest(der, { encodingRules: 'cer' as 'der' })).rejects.toMatchObject({ code: 'PKI_INVALID_OPTION' });
            await expect(verifyCertificationRequest(der, { limits: { maxNodes: 0 } })).rejects.toMatchObject({ code: 'PKI_LIMIT_INVALID' });
        });

        it('should throw for a value that is neither bytes nor a parsed request', async () => {
            for (const wrong of ['MIIB', null, 7, {}, { tbsDer: new Uint8Array(1) }, { tbsDer: new Uint8Array(1), signatureAlgorithm: {}, signatureValue: null }, { tbsDer: new Uint8Array(1), signatureAlgorithm: {}, signatureValue: {}, subjectPublicKeyInfo: 'rsa' }]) {
                await expect(verifyCertificationRequest(wrong as unknown as CertificationRequest), JSON.stringify(wrong)).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
            }
        });
    });
});
