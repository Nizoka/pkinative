import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import { createCertificate } from '../../src/build/build-certificate.js';
import { createCertificationRequest } from '../../src/build/build-csr.js';
import { createSignedData } from '../../src/build/build-signed-data.js';
import { resolveSigner } from '../../src/crypto/crypto-algorithms.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { SignatureAlgorithm, SigningKey } from '../../src/types/crypto-types.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';

// A JavaScript caller, or a TypeScript one through a cast, can hand a signing key whose ECDSA
// algorithm names no curve. The type requires it; the runtime must refuse it too, because the
// alternative — observed before 1.0.0 — was a well-formed certificate, request or SignedData
// whose signature verifies false everywhere: the host's raw r‖s written where DER was expected.

type Pair = webcrypto.CryptoKeyPair;

async function p256(): Promise<{ withCurve: SigningKey; withoutCurve: SigningKey; spki: Uint8Array }> {
    const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as Pair;
    const key = pair.privateKey as never;
    return {
        withCurve: { key, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } },
        withoutCurve: { key, algorithm: { name: 'ECDSA', hash: 'SHA-256' } as unknown as SignatureAlgorithm },
        spki: new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey)),
    };
}

const expectInvalidOption = async (p: Promise<unknown>): Promise<void> => {
    let caught: unknown;
    try { await p; } catch (err) { caught = err; }
    expect(caught).toBeInstanceOf(PkiError);
    expect(caught).toMatchObject({ code: 'PKI_INVALID_OPTION' });
    expect((caught as Error).message).toContain('namedCurve');
};

describe('resolveSigner', () => {
    it('should refuse an ECDSA algorithm without a curve, or with a curve outside P-256, P-384 and P-521', () => {
        for (const namedCurve of [undefined, 'secp256k1', 'P-192', '', 256]) {
            let caught: unknown;
            try { resolveSigner({ name: 'ECDSA', hash: 'SHA-256', namedCurve } as unknown as SignatureAlgorithm); } catch (err) { caught = err; }
            expect(caught, String(namedCurve)).toBeInstanceOf(PkiError);
            expect(caught).toMatchObject({ code: 'PKI_INVALID_OPTION' });
        }
        for (const namedCurve of ['P-256', 'P-384', 'P-521'] as const) {
            expect(resolveSigner({ name: 'ECDSA', hash: 'SHA-256', namedCurve }).curve).toBe(namedCurve);
        }
    });
});

describe('an ECDSA signing key without a curve', () => {
    const description = (spki: Uint8Array) => ({
        serialNumber: 1n,
        subject: [[{ type: '2.5.4.3', value: 'curve-less' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2027, 0, 1),
        subjectPublicKey: spki,
    });

    it('should be refused by createCertificate with PKI_INVALID_OPTION, where the same key with its curve issues', async () => {
        const m = await p256();
        await expectInvalidOption(createCertificate(description(m.spki), m.withoutCurve));
        const der = await createCertificate(description(m.spki), m.withCurve);
        expect(parseCertificate(der).signatureAlgorithm.oid).toBe('1.2.840.10045.4.3.2');
    });

    it('should be refused by createCertificationRequest with PKI_INVALID_OPTION', async () => {
        const m = await p256();
        await expectInvalidOption(createCertificationRequest({ subject: [[{ type: '2.5.4.3', value: 'curve-less' }]], subjectPublicKey: m.spki }, m.withoutCurve));
    });

    it('should be refused by createSignedData with PKI_INVALID_OPTION', async () => {
        const m = await p256();
        const certificate = parseCertificate(await createCertificate(description(m.spki), m.withCurve));
        await expectInvalidOption(createSignedData({ content: new Uint8Array([1, 2, 3]), certificate }, m.withoutCurve));
    });
});
