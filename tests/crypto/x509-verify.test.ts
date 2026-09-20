import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { parseCertificate } from '../../src/index.js';
import { PkiCryptoError, PkiError } from '../../src/types/pki-errors.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { verifyCertificateSignature, verifySelfSignature } from '../../src/crypto/x509-verify.js';
import { canVerify } from '../../src/crypto/webcrypto.js';
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
