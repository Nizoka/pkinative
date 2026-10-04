import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createCertificate } from '../../src/build/build-certificate.js';
import { createCertificationRequest } from '../../src/build/build-csr.js';
import type { ExternalSigner, SignatureAlgorithm } from '../../src/types/crypto-types.js';

// Review of 2026-10-04: the writers hold every value the caller supplies to its shape before a
// signature is produced. A subjectPublicKey that is not one SEQUENCE, or an Edwards signature
// of the wrong size, is a structure that verifies nowhere — refused as misuse now, with the
// remedy named, rather than by a relying party later.

const CN = '2.5.4.3';
const NOW = Date.UTC(2026, 0, 1);
const DAY = 86_400_000;
/** One empty SEQUENCE: the shape a subjectPublicKey must have, for the tests about what comes after it. */
const EMPTY_SPKI = Uint8Array.of(0x30, 0x00);
const subject = [[{ type: CN, value: 'shape' }]];

const misuse = (fragment: string): unknown => expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining(fragment) });
const external = (algorithm: SignatureAlgorithm, octets: number): ExternalSigner => ({ algorithm, produceSignature: () => new Uint8Array(octets) });

describe('an ExternalSigner for an Edwards curve', () => {
    it.each([
        ['Ed25519', 63, 64],
        ['Ed25519', 65, 64],
        ['Ed448', 64, 114],
        ['Ed448', 115, 114],
    ] as const)('should refuse a %s signature of %i octets, naming the %i RFC 8032 fixes', async (name, produced, expected) => {
        await expect(createCertificationRequest({ subject, subjectPublicKey: EMPTY_SPKI }, external({ name }, produced)))
            .rejects.toThrow(misuse(`exactly ${String(expected)} octets`));
    });

    it('should refuse an empty signature from a signer of any family — a certificate that verifies nowhere has no safe falsy value', async () => {
        await expect(createCertificationRequest({ subject, subjectPublicKey: EMPTY_SPKI }, external({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, 0)))
            .rejects.toThrow(misuse('non-empty Uint8Array'));
    });

    it('should accept a signature of the right size from a key it never sees', async () => {
        const csr = await createCertificationRequest({ subject, subjectPublicKey: EMPTY_SPKI }, external({ name: 'Ed448' }, 114));
        expect(csr[0]).toBe(0x30);
    });
});

describe('subjectPublicKey', () => {
    const signer = external({ name: 'Ed25519' }, 64);

    it.each([
        ['a NULL', Uint8Array.of(0x05, 0x00)],
        ['a SET', Uint8Array.of(0x31, 0x00)],
        ['a SEQUENCE followed by a trailing octet', Uint8Array.of(0x30, 0x00, 0x00)],
        ['a truncated SEQUENCE', Uint8Array.of(0x30, 0x05, 0x02)],
        ['no bytes at all', new Uint8Array(0)],
    ])('should refuse %s as PKI_API_MISUSE in both writers — one SubjectPublicKeyInfo SEQUENCE or nothing', async (_what, subjectPublicKey) => {
        await expect(createCertificate({ serialNumber: 1n, subject, notBefore: NOW, notAfter: NOW + DAY, subjectPublicKey }, signer))
            .rejects.toThrow(misuse('subjectPublicKey'));
        await expect(createCertificationRequest({ subject, subjectPublicKey }, signer))
            .rejects.toThrow(misuse('subjectPublicKey'));
    });

    it('should accept what crypto.subtle.exportKey(\'spki\') returns', async () => {
        const pair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as webcrypto.CryptoKeyPair;
        const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey));
        const der = await createCertificate({ serialNumber: 1n, subject, notBefore: NOW, notAfter: NOW + DAY, subjectPublicKey: spki }, {
            key: pair.privateKey as never,
            algorithm: { name: 'Ed25519' },
        });
        expect(der[0]).toBe(0x30);
    });
});
