import { describe, expect, it } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { _cmsAlgorithmProblem, _importableSpki, _pssKeyHash, coordinateBytes, ID_SHAKE256, resolveAlgorithm, resolveCmsAlgorithm } from '../../src/crypto/crypto-algorithms.js';
import { PkiCryptoError } from '../../src/types/pki-errors.js';
import type { AlgorithmIdentifier, SubjectPublicKeyInfo } from '../../src/types/x509-types.js';
import { algorithm, bitString, nullValue, oid } from '../helpers/cert-builder.js';
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

const RSA_KEY = { kind: 'rsa', der: new Uint8Array(0), publicExponent: 65537n } as unknown as SubjectPublicKeyInfo;
const EC_KEY = (curve: string | undefined) => ({ kind: 'ec', curve, der: new Uint8Array(0) }) as unknown as SubjectPublicKeyInfo;
const ED_KEY = (kind: string) => ({ kind, der: new Uint8Array(0) }) as unknown as SubjectPublicKeyInfo;
/** An `id-RSASSA-PSS` key, whose parameters — when present — restrict what it may verify (RFC 4055 §3.3). */
const PSS_KEY = (parameters?: Uint8Array) =>
    ({ kind: 'rsa-pss', algorithm: identifier(PSS, parameters), der: new Uint8Array(0), publicExponent: 65537n }) as unknown as SubjectPublicKeyInfo;

/** `[0] EXPLICIT AlgorithmIdentifier` and friends, as RFC 4055 §3.1 writes them. */
const tagged = (tag: number, ...children: Uint8Array[]): Uint8Array =>
    concat([0xa0 + tag], lengthOf(concat(...children)), concat(...children));
const lengthOf = (body: Uint8Array): number[] => (body.length < 0x80 ? [body.length] : [0x81, body.length]);

const SHA256 = '2.16.840.1.101.3.4.2.1';
const PSS = '1.2.840.113549.1.1.10';
const MGF1_OID = '1.2.840.113549.1.1.8';
const ED448 = '1.3.101.113';

describe('_importableSpki', () => {
    const KEY_BITS = Uint8Array.from({ length: 20 }, (_, i) => 0x30 + i);
    const pssSpki = (parameters?: Uint8Array): SubjectPublicKeyInfo => ({
        kind: 'rsa-pss', algorithm: identifier(PSS, parameters), publicKey: { bytes: KEY_BITS, unusedBits: 0 }, der: Uint8Array.of(0x30, 0x00), publicExponent: 65537n,
    }) as unknown as SubjectPublicKeyInfo;

    it('should hand every key but id-RSASSA-PSS to the host as the certificate published it', () => {
        expect(_importableSpki(RSA_KEY)).toBe(RSA_KEY.der);
        const ec = EC_KEY('P-256');
        expect(_importableSpki(ec)).toBe(ec.der);
        const ed = ED_KEY('ed25519');
        expect(_importableSpki(ed)).toBe(ed.der);
    });

    it('should re-wrap an id-RSASSA-PSS key under rsaEncryption with its subjectPublicKey copied as it stands (RFC 4055 §1.2)', () => {
        const expected = sequence(algorithm('1.2.840.113549.1.1.1', nullValue()), bitString(KEY_BITS));
        expect(_importableSpki(pssSpki(pssParams(SHA256, 32)))).toEqual(expected);
        // The key's own parameters do not travel: the host has no field for them, and resolveAlgorithm already held the signature to them.
        expect(_importableSpki(pssSpki())).toEqual(expected);
    });

    it('should copy the BIT STRING as it stands — unused-bits count included, with no DER judgement of its own', () => {
        // Under BER a key BIT STRING may carry an unused-bits count; the host
        // gets exactly what the certificate said, and judges it as it judges
        // every other key.
        const key = { ...pssSpki(), publicKey: { bytes: KEY_BITS, unusedBits: 3 } } as unknown as SubjectPublicKeyInfo;
        expect(_importableSpki(key)).toEqual(sequence(algorithm('1.2.840.113549.1.1.1', nullValue()), bitString(KEY_BITS, 3)));
    });
});

describe('_pssKeyHash', () => {
    it('should read the digest an id-RSASSA-PSS key\'s parameters bind it to', () => {
        expect(_pssKeyHash(PSS_KEY(pssParams(SHA384, 48)))).toBe('SHA-384');
        expect(_pssKeyHash(PSS_KEY(pssParams(SHA256, 32)))).toBe('SHA-256');
        expect(_pssKeyHash(PSS_KEY(sequence()))).toBe('SHA-1');
    });

    it('should answer undefined for a key without parameters, and for a key of another kind', () => {
        expect(_pssKeyHash(PSS_KEY())).toBeUndefined();
        expect(_pssKeyHash(RSA_KEY)).toBeUndefined();
        expect(_pssKeyHash(EC_KEY('P-256'))).toBeUndefined();
    });

    it('should refuse parameters Web Crypto cannot express, with the resolver\'s code', () => {
        expect(() => _pssKeyHash(PSS_KEY(sequence(tagged(0, algorithm(SHA256)), tagged(1, algorithm(MGF1_OID, algorithm(SHA1)))))))
            .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED', algorithm: PSS }));
    });
});

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

    it('should hold an id-RSASSA-PSS key to RSASSA-PSS, and let an rsaEncryption key sign either way (RFC 4055 §1.2)', () => {
        // "the certificate user MUST only use the certified RSA public key
        // for RSASSA-PSS operations" — a PKCS#1 v1.5 signature under such a
        // key is a decided no, which OpenSSL also refuses to make or check.
        expect(resolveAlgorithm(identifier(PSS), PSS_KEY())?.family).toBe('rsa-pss');
        expect(resolveAlgorithm(identifier('1.2.840.113549.1.1.11', nullValue()), PSS_KEY())).toBeNull();
        expect(resolveAlgorithm(identifier(PSS), RSA_KEY)?.family).toBe('rsa-pss');
        expect(resolveAlgorithm(identifier('1.2.840.113549.1.1.11', nullValue()), RSA_KEY)?.family).toBe('rsa-pkcs1');
    });

    describe('an id-RSASSA-PSS key with parameters (RFC 4055 §3.3, RFC 4056 §3)', () => {
        const SHA384_OID = '2.16.840.1.101.3.4.2.2';
        const full = (hash: string, salt: number): Uint8Array =>
            sequence(tagged(0, algorithm(hash)), tagged(1, algorithm('1.2.840.113549.1.1.8', algorithm(hash))), tagged(2, universal(2, [salt])));
        const KEY = PSS_KEY(full(SHA256, 32));

        it('should admit the same hash with an equal or longer salt', () => {
            expect(resolveAlgorithm(identifier(PSS, full(SHA256, 32)), KEY)?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 32 });
            expect(resolveAlgorithm(identifier(PSS, full(SHA256, 48)), KEY)?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 48 });
        });

        it('should return null for another hash or a shorter salt', () => {
            expect(resolveAlgorithm(identifier(PSS, full(SHA384_OID, 48)), KEY)).toBeNull();
            expect(resolveAlgorithm(identifier(PSS, full(SHA256, 31)), KEY)).toBeNull();
        });

        it('should compare DEFAULTs as the values they stand for', () => {
            // An empty SEQUENCE is SHA-1, MGF1-SHA-1, salt 20: the absent
            // signature parameters mean exactly that, and match.
            expect(resolveAlgorithm(identifier(PSS), PSS_KEY(sequence()))?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 20 });
            expect(resolveAlgorithm(identifier(PSS, full(SHA256, 32)), PSS_KEY(sequence()))).toBeNull();
            // The key's salt DEFAULT of 20 is a floor a SHA-256 signature may exceed.
            const keyWithoutSalt = PSS_KEY(sequence(tagged(0, algorithm(SHA256)), tagged(1, algorithm('1.2.840.113549.1.1.8', algorithm(SHA256)))));
            expect(resolveAlgorithm(identifier(PSS, full(SHA256, 32)), keyWithoutSalt)?.family).toBe('rsa-pss');
            expect(resolveAlgorithm(identifier(PSS, full(SHA256, 19)), keyWithoutSalt)).toBeNull();
        });

        it('should restrict nothing when the key carries no parameters (RFC 4055 §3.1)', () => {
            expect(resolveAlgorithm(identifier(PSS, full(SHA384_OID, 0)), PSS_KEY())?.hash).toBe('SHA-384');
        });

        it('should refuse key parameters Web Crypto cannot express, as it refuses a signature\'s', () => {
            expect(() => resolveAlgorithm(identifier(PSS, full(SHA256, 32)), PSS_KEY(sequence(tagged(0, algorithm(SHA256))))))
                .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' }));
        });
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

        it.each<[string, Uint8Array]>([
            ['a SET where the AlgorithmIdentifier SEQUENCE belongs', universal(17, concat(oid('1.2.840.113549.1.1.8'), algorithm(SHA256)), true)],
            ['an AlgorithmIdentifier whose first field is not an OID', sequence(universal(2, [1]), algorithm(SHA256))],
            ['an empty AlgorithmIdentifier', sequence()],
        ])('should refuse a maskGenAlgorithm that is %s, by code', (_what, maskGen) => {
            const params = sequence(tagged(0, algorithm(SHA256)), tagged(1, maskGen));
            expect(() => resolveAlgorithm(identifier(PSS, params), RSA_KEY))
                .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED', message: expect.stringContaining('maskGenAlgorithm is not an AlgorithmIdentifier') }));
        });

        // C-06 (CWE-436): RSASSA-PSS-params is SEQUENCE { [0]? [1]? [2]? [3]? },
        // each once, in order, each one value under an explicit tag; a hash
        // AlgorithmIdentifier's parameters are absent or NULL (RFC 4055 §2.1, §3.1).
        it.each<[string, Uint8Array]>([
            ['a universal child before the fields', sequence(nullValue(), tagged(2, universal(2, [48])))],
            ['a universal child after the fields', sequence(tagged(2, universal(2, [48])), nullValue())],
            ['a context tag beyond [3]', sequence(tagged(4, universal(2, [1])))],
            ['an application-class tag', sequence(concat([0x62, 0x03], universal(2, [48])))],
            ['a repeated [2], whose last value would win', sequence(tagged(2, universal(2, [32])), tagged(2, universal(2, [0])))],
            ['[2] before [0]', sequence(tagged(2, universal(2, [32])), tagged(0, algorithm(SHA256)))],
            ['[3] before [2]', sequence(tagged(3, universal(2, [1])), tagged(2, universal(2, [20])))],
            ['an empty [0], which would read as SHA-1', sequence(concat([0xa0, 0x00]))],
            ['a primitive [2]', sequence(concat([0x82, 0x01, 0x20]))],
            ['a [2] holding two values', sequence(tagged(2, universal(2, [32]), universal(2, [32])))],
            ['a salt length that is not an INTEGER', sequence(tagged(2, universal(4, [32])))],
            ['a trailerField that is not an INTEGER', sequence(tagged(3, universal(4, [1])))],
            ['a hash with parameters other than NULL', sequence(tagged(0, algorithm('1.3.14.3.2.26', universal(2, [0]))))],
            ['a hash with a NULL that has content', sequence(tagged(0, algorithm('1.3.14.3.2.26', universal(5, [0]))))],
            ['a hash AlgorithmIdentifier of three values', sequence(tagged(0, sequence(oid('1.3.14.3.2.26'), nullValue(), nullValue())))],
            ['an MGF1 hash with garbage parameters', sequence(tagged(1, algorithm(MGF1_OID, algorithm('1.3.14.3.2.26', universal(4, [1])))))],
            ['an MGF1 AlgorithmIdentifier of three values', sequence(tagged(1, sequence(oid(MGF1_OID), algorithm('1.3.14.3.2.26'), nullValue())))],
            ['a hash AlgorithmIdentifier that is a SET', sequence(tagged(0, universal(17, oid('1.3.14.3.2.26'), true)))],
            ['a hash AlgorithmIdentifier whose first field is an INTEGER', sequence(tagged(0, sequence(universal(2, [1]))))],
            ['a hash whose parameters are an empty OCTET STRING', sequence(tagged(0, algorithm('1.3.14.3.2.26', universal(4, []))))],
        ])('should refuse RSASSA-PSS parameters with %s', (_what, params) => {
            expect(() => resolveAlgorithm(identifier(PSS, params), RSA_KEY)).toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' }));
        });

        it('should read every field in order, with the hash parameters NULL as well as absent', () => {
            const params = sequence(
                tagged(0, algorithm(SHA256, nullValue())),
                tagged(1, algorithm(MGF1_OID, algorithm(SHA256))),
                tagged(2, universal(2, [32])),
                tagged(3, universal(2, [1])),
            );
            expect(resolveAlgorithm(identifier(PSS, params), RSA_KEY)?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 32 });
            expect(resolveAlgorithm(identifier(PSS, sequence(tagged(3, universal(2, [1])))), RSA_KEY)?.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 20 });
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

// ── CMS (RFC 5652 §5.3, RFC 8933) ────────────────────────────────────

const SHA1 = '1.3.14.3.2.26';
const SHA384 = '2.16.840.1.101.3.4.2.2';
const SHA512 = '2.16.840.1.101.3.4.2.3';
const SHA224 = '2.16.840.1.101.3.4.2.4';
const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
const MGF1 = '1.2.840.113549.1.1.8';

/** Full RSASSA-PSS-params over one hash, MGF1 over the same hash, as a conforming CMS signer writes them. */
const pssParams = (hash: string, salt: number): Uint8Array =>
    sequence(tagged(0, algorithm(hash)), tagged(1, algorithm(MGF1, algorithm(hash))), tagged(2, universal(2, [salt])));

describe('_cmsAlgorithmProblem', () => {
    it.each([
        ['rsaEncryption, the hash taken from digestAlgorithm (RFC 3370 §3.2)', SHA256, identifier(RSA_ENCRYPTION, nullValue())],
        ['sha256WithRSAEncryption over SHA-256', SHA256, identifier('1.2.840.113549.1.1.11', nullValue())],
        ['sha1WithRSAEncryption over SHA-1 — consistent, refused later as SHA-1', SHA1, identifier('1.2.840.113549.1.1.5', nullValue())],
        ['ecdsa-with-SHA384 over SHA-384 (RFC 5753 §2.1.1)', SHA384, identifier('1.2.840.10045.4.3.3')],
        ['RSASSA-PSS whose hash is the digest (RFC 4056 §3)', SHA256, identifier(PSS, pssParams(SHA256, 32))],
        ['RSASSA-PSS with an empty SEQUENCE over a SHA-1 digest — the DEFAULTs are SHA-1', SHA1, identifier(PSS, sequence())],
        ['Ed25519 over SHA-512 (RFC 8419 §3.1)', SHA512, identifier('1.3.101.112')],
    ])('should accept %s', (_what, digest, signature) => {
        expect(_cmsAlgorithmProblem(identifier(digest), signature)).toBeNull();
    });

    it.each([
        ['md5WithRSAEncryption', identifier(SHA256), identifier('1.2.840.113549.1.1.4', nullValue())],
        ['an MD5 digestAlgorithm', identifier('1.2.840.113549.2.5', nullValue()), identifier(RSA_ENCRYPTION, nullValue())],
        ['id-ecPublicKey as the signature algorithm', identifier(SHA256), identifier('1.2.840.10045.2.1')],
        ['sha256WithRSAEncryption over a SHA-384 digest', identifier(SHA384), identifier('1.2.840.113549.1.1.11', nullValue())],
        ['ecdsa-with-SHA384 over a SHA-256 digest', identifier(SHA256), identifier('1.2.840.10045.4.3.3')],
        ['RSASSA-PSS without parameters (RFC 4056 §2.2)', identifier(SHA256), identifier(PSS)],
        ['RSASSA-PSS with an empty SEQUENCE — SHA-1 — over a SHA-256 digest', identifier(SHA256), identifier(PSS, sequence())],
        ['RSASSA-PSS over SHA-384 with a SHA-256 digest', identifier(SHA256), identifier(PSS, pssParams(SHA384, 48))],
        ['Ed25519 over a SHA-256 digest', identifier(SHA256), identifier('1.3.101.112')],
        ['a digestAlgorithm whose parameters are neither absent nor NULL', identifier(SHA256, oid('1.2.3')), identifier(RSA_ENCRYPTION, nullValue())],
        ['RSASSA-PSS without parameters over a SHA-1 digest — mandatory whatever the DEFAULTs', identifier(SHA1), identifier(PSS)],
    ])('should name the problem with %s', (_what, digest, signature) => {
        expect(_cmsAlgorithmProblem(digest, signature)).not.toBeNull();
    });

    it('should treat absent and NULL SHA-2 parameters as the same algorithm (RFC 5754 §2)', () => {
        const signature = identifier('1.2.840.10045.4.3.2');
        expect(_cmsAlgorithmProblem(identifier(SHA256), signature)).toBeNull();
        expect(_cmsAlgorithmProblem(identifier(SHA256, nullValue()), signature)).toBeNull();
    });

    it('should not mistake a NULL with content octets for NULL', () => {
        // Strict DER cannot produce one; BER, or a hand-built value, can.
        const digest: AlgorithmIdentifier = { ...identifier(SHA256), parameters: { ...decodeAsn1(nullValue()), contentLength: 1 } };
        expect(_cmsAlgorithmProblem(digest, identifier(RSA_ENCRYPTION, nullValue()))).not.toBeNull();
    });

    it.each([
        ['a digest Web Crypto does not compute (SHA-224)', SHA224, identifier('1.2.840.113549.1.1.14', nullValue())],
        ['DSA, which Web Crypto does not run', SHA256, identifier('2.16.840.1.101.3.4.3.2')],
        ['RSASSA-PSS parameters Web Crypto cannot express', SHA256, identifier(PSS, sequence(tagged(0, algorithm(SHA256))))],
        ['a digest Web Crypto does not compute (SHA-224) under a signature it does', SHA224, identifier('1.2.840.113549.1.1.11', nullValue())],
    ])('should leave %s to resolution: unsupported is not inconsistent', (_what, digest, signature) => {
        expect(_cmsAlgorithmProblem(identifier(digest), signature)).toBeNull();
    });

    describe('an Ed448 signer, whose digest is SHAKE256 (RFC 8419 §3.1)', () => {
        it('should accept id-shake256 with absent or NULL parameters', () => {
            expect(_cmsAlgorithmProblem(identifier(ID_SHAKE256), identifier(ED448))).toBeNull();
            expect(_cmsAlgorithmProblem(identifier(ID_SHAKE256, nullValue()), identifier(ED448))).toBeNull();
        });

        it.each([
            ['a SHA-512 digest — Ed25519\'s, not Ed448\'s', identifier(SHA512)],
            ['a SHA-256 digest', identifier(SHA256)],
            ['id-shake256-len, another identifier whose INTEGER chooses the length', identifier('2.16.840.1.101.3.4.2.18', universal(2, [64]))],
            ['id-shake256 carrying parameters', identifier(ID_SHAKE256, oid('1.2.3'))],
        ])('should name the problem with %s', (_what, digest) => {
            expect(_cmsAlgorithmProblem(digest, identifier(ED448))).toMatch(/RFC 8419/u);
        });

        it('should still call MD5 the problem when an Ed448 signer names it', () => {
            expect(_cmsAlgorithmProblem(identifier('1.2.840.113549.2.5', nullValue()), identifier(ED448))).toMatch(/MD5/u);
        });
    });
});

describe('resolveCmsAlgorithm', () => {
    it('should map rsaEncryption to PKCS#1 v1.5 over the digestAlgorithm', () => {
        const resolved = resolveCmsAlgorithm(identifier(SHA384, nullValue()), identifier(RSA_ENCRYPTION, nullValue()), RSA_KEY);
        expect(resolved?.importParams).toEqual({ name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } });
        expect(resolved?.verifyParams).toEqual({ name: 'RSASSA-PKCS1-v1_5' });
        expect(resolved?.hash).toBe('SHA-384');
    });

    it('should return null for rsaEncryption against a key that is not RSA', () => {
        expect(resolveCmsAlgorithm(identifier(SHA256), identifier(RSA_ENCRYPTION, nullValue()), EC_KEY('P-256'))).toBeNull();
    });

    it('should return null for rsaEncryption — PKCS#1 v1.5 — against an id-RSASSA-PSS key (RFC 4055 §1.2)', () => {
        expect(resolveCmsAlgorithm(identifier(SHA256), identifier(RSA_ENCRYPTION, nullValue()), PSS_KEY())).toBeNull();
    });

    it('should hold an RSASSA-PSS signer to its certificate\'s key parameters (RFC 4056 §3)', () => {
        const key = PSS_KEY(pssParams(SHA256, 32));
        expect(resolveCmsAlgorithm(identifier(SHA256), identifier(PSS, pssParams(SHA256, 32)), key)?.family).toBe('rsa-pss');
        expect(resolveCmsAlgorithm(identifier(SHA256), identifier(PSS, pssParams(SHA256, 20)), key)).toBeNull();
    });

    it('should refuse rsaEncryption over a digest Web Crypto does not compute', () => {
        expect(() => resolveCmsAlgorithm(identifier(SHA224), identifier(RSA_ENCRYPTION, nullValue()), RSA_KEY))
            .toThrow(expect.objectContaining({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' }));
    });

    it('should resolve an Ed448 signer as the host\'s Ed448, its SHAKE256 digest being the verifier\'s to compute', () => {
        const resolved = resolveCmsAlgorithm(identifier(ID_SHAKE256), identifier(ED448), ED_KEY('ed448'));
        expect(resolved?.importParams).toEqual({ name: 'Ed448' });
        expect(resolved?.verifyParams).toEqual({ name: 'Ed448' });
        expect(resolved?.hash).toBeUndefined();
        expect(resolveCmsAlgorithm(identifier(ID_SHAKE256), identifier(ED448), ED_KEY('ed25519'))).toBeNull();
    });

    it('should resolve a combined OID through the X.509 table', () => {
        const resolved = resolveCmsAlgorithm(identifier(SHA256), identifier('1.2.840.10045.4.3.2'), EC_KEY('P-256'));
        expect(resolved?.verifyParams).toEqual({ name: 'ECDSA', hash: { name: 'SHA-256' } });
        expect(resolved?.curve).toBe('P-256');
    });
});

describe('the RSA public exponent (RFC 8017 §3.1)', () => {
    // Web Crypto imports e = 1 and verifies under it: the PKCS#1 encoding of
    // the digest *is* the signature, so anyone signs for the key. Refused
    // before the key reaches the host, under every scheme that takes an RSA key.
    const rsa = (e: bigint, kind: 'rsa' | 'rsa-pss' = 'rsa'): SubjectPublicKeyInfo =>
        ({ kind, der: new Uint8Array(0), publicExponent: e, ...(kind === 'rsa-pss' ? { algorithm: identifier(PSS) } : {}) }) as unknown as SubjectPublicKeyInfo;
    const refused = expect.objectContaining({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED' });

    it.each([[1n], [2n], [65536n]])('should refuse a key with public exponent %s under PKCS#1 v1.5, RSASSA-PSS and CMS rsaEncryption', (e) => {
        expect(() => resolveAlgorithm(identifier('1.2.840.113549.1.1.11', nullValue()), rsa(e))).toThrow(refused);
        expect(() => resolveAlgorithm(identifier(PSS), rsa(e))).toThrow(refused);
        expect(() => resolveAlgorithm(identifier(PSS), rsa(e, 'rsa-pss'))).toThrow(refused);
        expect(() => resolveCmsAlgorithm(identifier(SHA256), identifier('1.2.840.113549.1.1.1'), rsa(e))).toThrow(refused);
    });

    it('should accept 3, the smallest exponent RFC 8017 defines, and 65537', () => {
        expect(resolveAlgorithm(identifier('1.2.840.113549.1.1.11', nullValue()), rsa(3n))?.family).toBe('rsa-pkcs1');
        expect(resolveCmsAlgorithm(identifier(SHA256), identifier('1.2.840.113549.1.1.1'), rsa(65537n))?.family).toBe('rsa-pkcs1');
    });
});
