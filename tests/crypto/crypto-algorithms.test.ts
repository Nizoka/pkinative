import { describe, expect, it } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { coordinateBytes, resolveAlgorithm } from '../../src/crypto/crypto-algorithms.js';
import { PkiCryptoError } from '../../src/types/pki-errors.js';
import type { AlgorithmIdentifier, SubjectPublicKeyInfo } from '../../src/types/x509-types.js';
import { algorithm, nullValue, oid } from '../helpers/cert-builder.js';
import { concat, sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * The OID → Web Crypto table. Its value is that it is closed: the tests
 * below care as much about what it refuses, and with which code, as about
 * what it resolves.
 */

/** An AlgorithmIdentifier as the parser would hand one over. */
function identifier(dotted: string, parameters?: Uint8Array): AlgorithmIdentifier {
    const der = algorithm(dotted, parameters);
    const node = decodeAsn1(der);
    return { oid: dotted, parameters: node.children[1], der };
}

const RSA_KEY = { kind: 'rsa', der: new Uint8Array(0) } as unknown as SubjectPublicKeyInfo;
const EC_KEY = (curve: string | undefined) => ({ kind: 'ec', curve, der: new Uint8Array(0) }) as unknown as SubjectPublicKeyInfo;
const ED_KEY = (kind: string) => ({ kind, der: new Uint8Array(0) }) as unknown as SubjectPublicKeyInfo;

/** `[0] EXPLICIT AlgorithmIdentifier` and friends, as RFC 4055 §3.1 writes them. */
const tagged = (tag: number, ...children: Uint8Array[]): Uint8Array =>
    concat([0xa0 + tag], lengthOf(concat(...children)), concat(...children));
const lengthOf = (body: Uint8Array): number[] => (body.length < 0x80 ? [body.length] : [0x81, body.length]);

const SHA256 = '2.16.840.1.101.3.4.2.1';
const PSS = '1.2.840.113549.1.1.10';

describe('resolveAlgorithm', () => {
    it.each([
        ['sha256WithRSAEncryption', '1.2.840.113549.1.1.11', 'RSASSA-PKCS1-v1_5', 'SHA-256'],
        ['sha1WithRSAEncryption', '1.2.840.113549.1.1.5', 'RSASSA-PKCS1-v1_5', 'SHA-1'],
        ['sha384WithRSAEncryption', '1.2.840.113549.1.1.12', 'RSASSA-PKCS1-v1_5', 'SHA-384'],
        ['sha512WithRSAEncryption', '1.2.840.113549.1.1.13', 'RSASSA-PKCS1-v1_5', 'SHA-512'],
    ])('should resolve %s to PKCS#1 v1.5 with its digest', (_name, dotted, expected, hash) => {
        const resolved = resolveAlgorithm(identifier(dotted, nullValue()), RSA_KEY);
        expect(resolved?.importParams).toEqual({ name: expected, hash: { name: hash } });
        expect(resolved?.verifyParams).toEqual({ name: expected });
        expect(resolved?.curve).toBeUndefined();
    });

    it.each([
        ['ecdsa-with-SHA1', '1.2.840.10045.4.1', 'SHA-1'],
        ['ecdsa-with-SHA256', '1.2.840.10045.4.3.2', 'SHA-256'],
        ['ecdsa-with-SHA384', '1.2.840.10045.4.3.3', 'SHA-384'],
        ['ecdsa-with-SHA512', '1.2.840.10045.4.3.4', 'SHA-512'],
    ])('should resolve %s and carry the curve so the signature can be converted', (_name, dotted, hash) => {
        const resolved = resolveAlgorithm(identifier(dotted), EC_KEY('P-384'));
        expect(resolved?.verifyParams).toEqual({ name: 'ECDSA', hash: { name: hash } });
        expect(resolved?.curve).toBe('P-384');
    });

    it.each([
        ['Ed25519', '1.3.101.112', 'ed25519'],
        ['Ed448', '1.3.101.113', 'ed448'],
    ])('should resolve %s by name alone', (name, dotted, kind) => {
        const resolved = resolveAlgorithm(identifier(dotted), ED_KEY(kind));
        expect(resolved?.importParams).toEqual({ name });
        expect(resolved?.verifyParams).toEqual({ name });
    });

    it.each([
        ['an ECDSA signature against an RSA key', '1.2.840.10045.4.3.2', RSA_KEY],
        ['a PKCS#1 v1.5 signature against an EC key', '1.2.840.113549.1.1.11', EC_KEY('P-256')],
        ['an RSASSA-PSS signature against an EC key', PSS, EC_KEY('P-256')],
        ['an Ed25519 signature against an X25519 key', '1.3.101.112', ED_KEY('x25519')],
        ['an Ed448 signature against an Ed25519 key', '1.3.101.113', ED_KEY('ed25519')],
    ])('should return null, not throw, for %s', (_what, dotted, key) => {
        // A decided "no": path building must be able to try the next
        // candidate issuer without writing a try.
        expect(resolveAlgorithm(identifier(dotted, nullValue()), key)).toBeNull();
    });

    it('should accept either RSA key OID under either RSA signature family (RFC 4055 §1.2)', () => {
        const pssKey = ED_KEY('rsa-pss');
        expect(resolveAlgorithm(identifier(PSS), pssKey)?.family).toBe('rsa-pss');
        expect(resolveAlgorithm(identifier('1.2.840.113549.1.1.11', nullValue()), pssKey)?.family).toBe('rsa-pkcs1');
        expect(resolveAlgorithm(identifier(PSS), RSA_KEY)?.family).toBe('rsa-pss');
    });

    it('should refuse an algorithm outside the table by name', () => {
        // md5WithRSAEncryption: real, and absent from Web Crypto.
        expect(() => resolveAlgorithm(identifier('1.2.840.113549.1.1.4', nullValue()), RSA_KEY))
            .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED', algorithm: '1.2.840.113549.1.1.4' }));
    });

    it('should refuse an EC key on a curve Web Crypto does not verify', () => {
        // secp256k1 is a real curve in real certificates; Web Crypto has it
        // on no platform, so the honest answer is "cannot decide".
        expect(() => resolveAlgorithm(identifier('1.2.840.10045.4.3.2'), EC_KEY(undefined)))
            .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED' }));
        expect(() => resolveAlgorithm(identifier('1.2.840.10045.4.3.2'), EC_KEY('brainpoolP256r1')))
            .toThrow(PkiCryptoError);
    });

    describe('RSASSA-PSS parameters (RFC 4055 §3.1)', () => {
        it('should take the DEFAULTs when the parameters are absent', () => {
            const resolved = resolveAlgorithm(identifier(PSS), RSA_KEY);
            expect(resolved?.importParams).toEqual({ name: 'RSA-PSS', hash: { name: 'SHA-1' } });
            expect(resolved?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 20 });
        });

        it('should read the hash, the salt length and an MGF1 that agrees', () => {
            const params = sequence(
                tagged(0, algorithm(SHA256)),
                tagged(1, algorithm('1.2.840.113549.1.1.8', algorithm(SHA256))),
                tagged(2, universal(2, [32])),
                tagged(3, universal(2, [1])),
            );
            const resolved = resolveAlgorithm(identifier(PSS, params), RSA_KEY);
            expect(resolved?.importParams).toEqual({ name: 'RSA-PSS', hash: { name: 'SHA-256' } });
            expect(resolved?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 32 });
        });

        it('should keep the salt DEFAULT at 20 even for SHA-256 — it is not the digest size', () => {
            const params = sequence(tagged(0, algorithm(SHA256)), tagged(1, algorithm('1.2.840.113549.1.1.8', algorithm(SHA256))));
            const resolved = resolveAlgorithm(identifier(PSS, params), RSA_KEY);
            expect(resolved?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 20 });
        });

        it('should refuse a SHA-256 hash left with the DEFAULT MGF1-SHA-1', () => {
            // RFC 4055 §3.1 defaults maskGenAlgorithm to mgf1SHA1, so
            // naming SHA-256 and omitting the MGF asks for a pairing Web
            // Crypto has no way to express. Verifying it anyway would use
            // MGF1-SHA-256 and answer a question nobody asked — either
            // accepting a signature nobody made, or rejecting a valid one.
            expect(() => resolveAlgorithm(identifier(PSS, sequence(tagged(0, algorithm(SHA256)))), RSA_KEY))
                .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED', message: expect.stringContaining('mask generation uses SHA-1') }));
        });

        it('should ignore a field that is neither a context tag nor one it knows', () => {
            const params = sequence(nullValue(), tagged(7, universal(2, [1])), tagged(2, universal(2, [48])));
            expect(resolveAlgorithm(identifier(PSS, params), RSA_KEY)?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 48 });
        });

        it('should ignore an empty context tag rather than read past it', () => {
            const params = sequence(concat([0xa0, 0x00]), tagged(2, universal(2, [24])));
            expect(resolveAlgorithm(identifier(PSS, params), RSA_KEY)?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 24 });
        });

        it.each([
            ['the parameters are not a SEQUENCE', nullValue(), 'not a SEQUENCE'],
            ['the hash parameter is not an AlgorithmIdentifier', sequence(tagged(0, nullValue())), 'not an AlgorithmIdentifier'],
            ['the digest is one Web Crypto does not implement', sequence(tagged(0, algorithm('1.2.840.113549.2.5'))), 'is not one Web Crypto implements'],
            ['the maskGenAlgorithm is not an AlgorithmIdentifier', sequence(tagged(1, nullValue())), 'maskGenAlgorithm is not an AlgorithmIdentifier'],
            ['the mask generation function is not MGF1', sequence(tagged(1, algorithm('1.2.840.113549.1.1.9'))), 'not MGF1'],
            ['the trailerField is not 1', sequence(tagged(3, universal(2, [2]))), 'trailerField is not 1'],
            ['the salt length is negative', sequence(tagged(2, universal(2, [0xff]))), 'salt length is negative'],
        ])('should refuse a certificate where %s', (_what, params, expected) => {
            expect(() => resolveAlgorithm(identifier(PSS, params), RSA_KEY))
                .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED', message: expect.stringContaining(expected) }));
        });

        it('should refuse MGF1 over a digest the signature does not use', () => {
            // Verifying this under Web Crypto would silently use MGF1-SHA-256
            // where the certificate asked for MGF1-SHA-1, and either accept a
            // signature nobody made or reject one that is valid.
            const params = sequence(tagged(0, algorithm(SHA256)), tagged(1, algorithm('1.2.840.113549.1.1.8', algorithm('1.3.14.3.2.26'))));
            expect(() => resolveAlgorithm(identifier(PSS, params), RSA_KEY))
                .toThrow(expect.objectContaining({ message: expect.stringContaining('mask generation uses SHA-1 while the signature uses SHA-256') }));
        });

        it('should read a bare MGF1 with no inner AlgorithmIdentifier as MGF1-SHA-1', () => {
            const params = sequence(tagged(1, algorithm('1.2.840.113549.1.1.8')));
            expect(resolveAlgorithm(identifier(PSS, params), RSA_KEY)?.importParams).toEqual({ name: 'RSA-PSS', hash: { name: 'SHA-1' } });
        });
    });
});

describe('coordinateBytes', () => {
    it('should give the field size of each curve, with P-521 at 66 and not 65', () => {
        // 521 bits is 65.125 bytes, and rounding it down silently truncates
        // every signature on that curve.
        expect([coordinateBytes('P-256'), coordinateBytes('P-384'), coordinateBytes('P-521')]).toEqual([32, 48, 66]);
    });
});

describe('the OID table', () => {
    it('should name a real OID in the refusal, so the message can be searched for', () => {
        try {
            resolveAlgorithm(identifier(oid('1.2.3.4') instanceof Uint8Array ? '1.2.3.4' : '', nullValue()), RSA_KEY);
            expect.unreachable('an unknown OID must be refused');
        } catch (error) {
            expect(error).toBeInstanceOf(PkiCryptoError);
            expect((error as PkiCryptoError).algorithm).toBe('1.2.3.4');
        }
    });
});
