import { constants, generateKeyPairSync, verify as nodeVerify, type KeyObject, type webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { resolveSigner } from '../../src/crypto/crypto-algorithms.js';
import { signData } from '../../src/crypto/webcrypto.js';
import { decryptPrivateKey, importPrivateKey } from '../../src/keys/key-import.js';
import type { SignatureAlgorithm, SigningKey } from '../../src/types/crypto-types.js';
import { PkiCryptoError, PkiError, PkiKeyError } from '../../src/types/pki-errors.js';
import { alg, attribute, context, int, octets, oid } from '../helpers/cms-signed-data-builder.js';
import { sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * PKCS#8 keys written by an independent implementation — Node's OpenSSL,
 * through `KeyObject.export` — imported and decrypted into Web Crypto, and
 * proved by what matters: a signature made with the imported key verifies
 * under the original public key, checked by `node:crypto`, not by pkinative.
 *
 * `export({ cipher: 'aes-256-cbc', passphrase })` writes PBES2 with PBKDF2 and
 * hmacWithSHA256 (the OpenSSL default since 1.1), which is the scheme
 * `decryptPrivateKey` opens.
 */

type Pair = { readonly privateKey: KeyObject; readonly publicKey: KeyObject };

const PASSWORD = 'correct horse battery staple';
const DATA = new TextEncoder().encode('the bytes a certificate would cover');

const plain = (pair: Pair): Uint8Array => new Uint8Array(pair.privateKey.export({ format: 'der', type: 'pkcs8' }));
const sealed = (pair: Pair, cipher: string, passphrase: string = PASSWORD): Uint8Array =>
    new Uint8Array(pair.privateKey.export({ format: 'der', type: 'pkcs8', cipher, passphrase }));

const KEYS = {
    p256: generateKeyPairSync('ec', { namedCurve: 'P-256' }),
    p384: generateKeyPairSync('ec', { namedCurve: 'P-384' }),
    p521: generateKeyPairSync('ec', { namedCurve: 'P-521' }),
    rsa: generateKeyPairSync('rsa', { modulusLength: 2048 }),
    rsaPss: generateKeyPairSync('rsa-pss', { modulusLength: 2048 }),
    ed25519: generateKeyPairSync('ed25519'),
    ed448: generateKeyPairSync('ed448'),
    x25519: generateKeyPairSync('x25519'),
    secp256k1: generateKeyPairSync('ec', { namedCurve: 'secp256k1' }),
} as const;

const NODE_HASH: Readonly<Record<string, string>> = { 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' };

/** Sign through pkinative's door, verify with node:crypto against the original public key. */
async function signsFor(signer: SigningKey, publicKey: KeyObject): Promise<boolean> {
    const resolved = resolveSigner(signer.algorithm);
    const signature = await signData(signer.key, resolved.signParams, DATA);
    const algorithm = signer.algorithm;
    switch (algorithm.name) {
        case 'ECDSA':
            return nodeVerify(NODE_HASH[algorithm.hash] ?? '', DATA, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
        case 'RSASSA-PKCS1-v1_5':
            return nodeVerify(NODE_HASH[algorithm.hash] ?? '', DATA, publicKey, signature);
        case 'RSA-PSS':
            return nodeVerify(NODE_HASH[algorithm.hash] ?? '', DATA,
                { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: resolved.pss?.saltLength ?? -1 }, signature);
        default:
            return nodeVerify(null, DATA, publicKey, signature);
    }
}

function expectSigningHandle(signer: SigningKey): void {
    const key = signer.key as webcrypto.CryptoKey;
    expect(key.type).toBe('private');
    expect(key.extractable).toBe(false);
    expect(key.usages).toEqual(['sign']);
    expect(Object.isFrozen(signer)).toBe(true);
}

/** Whether this runtime's Web Crypto signs with Ed448 (Node 22 does, as an experiment; browsers mostly do not). */
async function hostHasEd448(): Promise<boolean> {
    try {
        await crypto.subtle.importKey('pkcs8', plain(KEYS.ed448), { name: 'Ed448' }, false, ['sign']);
        return true;
    } catch {
        return false;
    }
}

async function rejection(promise: Promise<unknown>): Promise<Error> {
    try {
        await promise;
    } catch (error) {
        return error as Error;
    }
    throw new Error('expected a rejection');
}

// ── importPrivateKey ──

describe('importPrivateKey — the key decides', () => {
    it.each([
        ['P-256', KEYS.p256, 'SHA-256'],
        ['P-384', KEYS.p384, 'SHA-384'],
        ['P-521', KEYS.p521, 'SHA-512'],
    ] as const)('should import an EC key on %s as ECDSA with its customary digest, and sign', async (curve, pair, hash) => {
        const signer = await importPrivateKey(plain(pair));
        expect(signer.algorithm).toEqual({ name: 'ECDSA', hash, namedCurve: curve });
        expectSigningHandle(signer);
        expect(await signsFor(signer, pair.publicKey)).toBe(true);
    });

    it('should import an Ed25519 key (RFC 8410), and sign', async () => {
        const signer = await importPrivateKey(plain(KEYS.ed25519));
        expect(signer.algorithm).toEqual({ name: 'Ed25519' });
        expectSigningHandle(signer);
        expect(await signsFor(signer, KEYS.ed25519.publicKey)).toBe(true);
    });

    it('should import an Ed448 key where the host implements it, and refuse it cleanly where not', async () => {
        const supported = await hostHasEd448();
        const pending = importPrivateKey(plain(KEYS.ed448));
        if (supported) {
            const signer = await pending;
            expect(signer.algorithm).toEqual({ name: 'Ed448' });
            expect(await signsFor(signer, KEYS.ed448.publicKey)).toBe(true);
        } else {
            expect(await rejection(pending)).toMatchObject({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED' });
        }
    });

    it('should import from a view into a larger buffer', async () => {
        const der = plain(KEYS.p256);
        const padded = new Uint8Array(der.length + 8);
        padded.set(der, 4);
        const signer = await importPrivateKey(padded.subarray(4, 4 + der.length));
        expect(await signsFor(signer, KEYS.p256.publicKey)).toBe(true);
    });
});

describe('importPrivateKey — the caller names the algorithm', () => {
    it.each([
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
        { name: 'RSA-PSS', hash: 'SHA-256' },
        { name: 'RSA-PSS', hash: 'SHA-384', saltLength: 20 },
    ] as const satisfies readonly SignatureAlgorithm[])('should import an rsaEncryption key for %o, and sign', async (algorithm) => {
        const signer = await importPrivateKey(plain(KEYS.rsa), { algorithm });
        expect(signer.algorithm).toBe(algorithm);
        expectSigningHandle(signer);
        expect(await signsFor(signer, KEYS.rsa.publicKey)).toBe(true);
    });

    it('should refuse an rsaEncryption key without an algorithm, because PKCS#1 v1.5 and PSS are both possible', async () => {
        const error = await rejection(importPrivateKey(plain(KEYS.rsa)));
        expect(error).toBeInstanceOf(PkiError);
        expect(error).toMatchObject({ code: 'PKI_API_MISUSE' });
        expect(error.message).toMatch(/^pkinative: .*RSASSA-PKCS1-v1_5.*RSA-PSS/u);
    });

    it('should accept an explicit digest other than the curve\'s customary one', async () => {
        const algorithm: SignatureAlgorithm = { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-256' };
        const signer = await importPrivateKey(plain(KEYS.p256), { algorithm });
        expect(signer.algorithm).toBe(algorithm);
        expect(await signsFor(signer, KEYS.p256.publicKey)).toBe(true);
    });

    it('should accept the Edwards algorithm the key already names', async () => {
        const signer = await importPrivateKey(plain(KEYS.ed25519), { algorithm: { name: 'Ed25519' } });
        expect(signer.algorithm).toEqual({ name: 'Ed25519' });
    });

    it.each([
        ['an EC key for ECDSA on another curve', KEYS.p256, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-384' }, /EC key on P-256.*ECDSA on P-384/u],
        ['an EC key for Ed25519', KEYS.p256, { name: 'Ed25519' }, /EC key on P-256.*Ed25519/u],
        ['an Ed25519 key for Ed448', KEYS.ed25519, { name: 'Ed448' }, /Ed25519 key.*Ed448/u],
        ['an Ed25519 key for ECDSA', KEYS.ed25519, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, /Ed25519 key.*ECDSA on P-256/u],
        ['an RSA key for ECDSA', KEYS.rsa, { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, /RSA key.*ECDSA/u],
        ['an RSA key for Ed25519', KEYS.rsa, { name: 'Ed25519' }, /RSA key.*Ed25519/u],
        ['an id-RSASSA-PSS key for PKCS#1 v1.5', KEYS.rsaPss, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, /PSS.*RSASSA-PKCS1-v1_5/u],
    ] as const satisfies ReadonlyArray<readonly [string, Pair, SignatureAlgorithm, RegExp]>)('should refuse %s with PKI_API_MISUSE naming both', async (_label, pair, algorithm, names) => {
        const error = await rejection(importPrivateKey(plain(pair), { algorithm }));
        expect(error).toMatchObject({ code: 'PKI_API_MISUSE' });
        expect(error.message).toMatch(names);
    });

    it('should refuse an id-RSASSA-PSS key without an algorithm', async () => {
        const error = await rejection(importPrivateKey(plain(KEYS.rsaPss)));
        expect(error).toMatchObject({ code: 'PKI_API_MISUSE' });
        expect(error.message).toMatch(/RSA-PSS/u);
    });

    it('should import an id-RSASSA-PSS key for RSA-PSS through its envelope re-wrapped as rsaEncryption, and sign with it', async () => {
        // Node 22 and the browsers refuse the id-RSASSA-PSS OID in Web Crypto
        // ("DataError: Invalid key type"); the same RSAPrivateKey under
        // rsaEncryption is the same key, RFC 4055 §1.2, and the restriction to
        // PSS is held by _signingAlgorithm before the host is asked.
        const signer = await importPrivateKey(plain(KEYS.rsaPss), { algorithm: { name: 'RSA-PSS', hash: 'SHA-256' } });
        expect(signer.algorithm).toEqual({ name: 'RSA-PSS', hash: 'SHA-256' });
        expect(await signsFor(signer, KEYS.rsaPss.publicKey)).toBe(true);
        expect(await signsFor(await importPrivateKey(plain(KEYS.rsaPss), { algorithm: { name: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 } }), KEYS.rsaPss.publicKey)).toBe(true);
    });

    it('should carry an id-RSASSA-PSS key\'s attributes through the re-wrap, and leave the caller\'s buffer untouched', async () => {
        const original = plain(KEYS.rsaPss);
        const fields = decodeAsn1(original).children.map((field) => field.bytes);
        // RFC 5958 §2: `attributes [0] IMPLICIT Attributes OPTIONAL` — a friendlyName, as PKCS#12 writers add.
        const withAttributes = sequence(fields[0] as Uint8Array, fields[1] as Uint8Array, fields[2] as Uint8Array,
            context(0, true, attribute('1.2.840.113549.1.9.20', universal(30, [0, 0x50, 0, 0x53, 0, 0x53]))));
        const copy = Uint8Array.from(withAttributes);
        const signer = await importPrivateKey(withAttributes, { algorithm: { name: 'RSA-PSS', hash: 'SHA-256' } });
        expect(await signsFor(signer, KEYS.rsaPss.publicKey)).toBe(true);
        expect(withAttributes).toEqual(copy);
    });

    it('should import an id-RSASSA-PSS key whose parameters restrict it, under the digest they name', async () => {
        const restricted = generateKeyPairSync('rsa-pss', { modulusLength: 2048, hashAlgorithm: 'sha384', mgf1HashAlgorithm: 'sha384' });
        const signer = await importPrivateKey(plain(restricted), { algorithm: { name: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 } });
        expect(await signsFor(signer, restricted.publicKey)).toBe(true);
    });

    it('should refuse an algorithm with no RFC 5280 OID', async () => {
        const algorithm = { name: 'ECDSA', hash: 'MD5', namedCurve: 'P-256' } as unknown as SignatureAlgorithm;
        expect(await rejection(importPrivateKey(plain(KEYS.p256), { algorithm }))).toMatchObject({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' });
    });

    it.each([
        ['null', null],
        ['a string', 'ECDSA'],
    ] as const)('should refuse an algorithm option that is %s with PKI_INVALID_OPTION', async (_label, algorithm) => {
        const error = await rejection(importPrivateKey(plain(KEYS.p256), { algorithm: algorithm as unknown as SignatureAlgorithm }));
        expect(error).toMatchObject({ code: 'PKI_INVALID_OPTION' });
    });
});

describe('importPrivateKey — keys Web Crypto does not sign with', () => {
    it('should refuse an X25519 key, which pkinative does not name, with PKI_CRYPTO_KEY_UNSUPPORTED', async () => {
        const error = await rejection(importPrivateKey(plain(KEYS.x25519)));
        expect(error).toBeInstanceOf(PkiCryptoError);
        expect(error).toMatchObject({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED', algorithm: '1.3.101.110' });
    });

    it('should refuse an EC key on secp256k1 with PKI_CRYPTO_KEY_UNSUPPORTED, even with an algorithm named', async () => {
        const algorithm: SignatureAlgorithm = { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' };
        const error = await rejection(importPrivateKey(plain(KEYS.secp256k1), { algorithm }));
        expect(error).toMatchObject({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED', algorithm: '1.2.840.10045.2.1' });
    });

    it('should pass on the host\'s refusal of a key that is not what its header says', async () => {
        // A P-256 key relabelled P-384: the reader believes the label, the host does not.
        const ecPrivateKey = new Uint8Array(KEYS.p256.privateKey.export({ format: 'der', type: 'sec1' }));
        const relabelled = sequence(int(0), alg('1.2.840.10045.2.1', oid('1.3.132.0.34')), octets(ecPrivateKey));
        const error = await rejection(importPrivateKey(relabelled));
        expect(error).toMatchObject({ code: 'PKI_CRYPTO_KEY_UNSUPPORTED' });
    });
});

describe('importPrivateKey — refusals before the host', () => {
    it('should refuse input that is not a Uint8Array', async () => {
        expect(await rejection(importPrivateKey('-----BEGIN PRIVATE KEY-----' as unknown as Uint8Array))).toMatchObject({ code: 'PKI_INVALID_INPUT' });
    });

    it('should refuse an encrypted key, which is not a PrivateKeyInfo', async () => {
        expect(await rejection(importPrivateKey(sealed(KEYS.p256, 'aes-256-cbc')))).toBeInstanceOf(PkiKeyError);
    });

    it('should refuse options that are not an object', async () => {
        expect(await rejection(importPrivateKey(plain(KEYS.p256), 'strict' as never))).toMatchObject({ code: 'PKI_INVALID_OPTION' });
    });
});

// ── decryptPrivateKey ──

const P256: SignatureAlgorithm = { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' };

describe('decryptPrivateKey — PBES2 as OpenSSL writes it', () => {
    it.each(['aes-256-cbc', 'aes-192-cbc', 'aes-128-cbc'])('should decrypt an EC key under %s, and sign', async (cipher) => {
        const signer = await decryptPrivateKey(sealed(KEYS.p256, cipher), { password: PASSWORD, algorithm: P256 });
        expect(signer.algorithm).toBe(P256);
        expectSigningHandle(signer);
        expect(await signsFor(signer, KEYS.p256.publicKey)).toBe(true);
    });

    it.each([
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        { name: 'RSA-PSS', hash: 'SHA-512' },
    ] as const satisfies readonly SignatureAlgorithm[])('should decrypt an RSA key for %o, and sign', async (algorithm) => {
        const signer = await decryptPrivateKey(sealed(KEYS.rsa, 'aes-128-cbc'), { password: PASSWORD, algorithm });
        expectSigningHandle(signer);
        expect(await signsFor(signer, KEYS.rsa.publicKey)).toBe(true);
    });

    it('should decrypt an Ed25519 key, and sign', async () => {
        const signer = await decryptPrivateKey(sealed(KEYS.ed25519, 'aes-256-cbc'), { password: PASSWORD, algorithm: { name: 'Ed25519' } });
        expect(await signsFor(signer, KEYS.ed25519.publicKey)).toBe(true);
    });

    it.each([
        ['P-384', KEYS.p384, 'SHA-384'],
        ['P-521', KEYS.p521, 'SHA-512'],
    ] as const)('should decrypt an EC key on %s, and sign', async (namedCurve, pair, hash) => {
        const signer = await decryptPrivateKey(sealed(pair, 'aes-256-cbc'), { password: PASSWORD, algorithm: { name: 'ECDSA', hash, namedCurve } });
        expect(await signsFor(signer, pair.publicKey)).toBe(true);
    });

    it('should decrypt an Ed448 key where the host implements it, and refuse it cleanly where not', async () => {
        const supported = await hostHasEd448();
        const pending = decryptPrivateKey(sealed(KEYS.ed448, 'aes-256-cbc'), { password: PASSWORD, algorithm: { name: 'Ed448' } });
        if (supported) {
            expect(await signsFor(await pending, KEYS.ed448.publicKey)).toBe(true);
        } else {
            expect(await rejection(pending)).toMatchObject({ code: 'PKI_CRYPTO_DECRYPTION_FAILED' });
        }
    });
});

describe('decryptPrivateKey — the password', () => {
    it('should take the password as the UTF-8 octets of a string, or as those octets given directly', async () => {
        const der = sealed(KEYS.p256, 'aes-256-cbc');
        const octets = new TextEncoder().encode(PASSWORD);
        const copy = octets.slice();
        const signer = await decryptPrivateKey(der, { password: octets, algorithm: P256 });
        expect(await signsFor(signer, KEYS.p256.publicKey)).toBe(true);
        expect(octets).toEqual(copy);
    });

    it('should encode a non-ASCII password as UTF-8, as Node and OpenSSL do', async () => {
        const password = 'pässwörd — 日本語 🔑';
        const der = sealed(KEYS.p256, 'aes-256-cbc', password);
        const signer = await decryptPrivateKey(der, { password, algorithm: P256 });
        expect(await signsFor(signer, KEYS.p256.publicKey)).toBe(true);
        // The same characters as Latin-1 octets are another password.
        const latin1 = Uint8Array.from('pässwörd', (c) => c.charCodeAt(0));
        const error = await rejection(decryptPrivateKey(sealed(KEYS.p256, 'aes-256-cbc', 'pässwörd'), { password: latin1, algorithm: P256 }));
        expect(error).toMatchObject({ code: 'PKI_CRYPTO_DECRYPTION_FAILED' });
    });

    it('should refuse a wrong password with PKI_CRYPTO_DECRYPTION_FAILED', async () => {
        const error = await rejection(decryptPrivateKey(sealed(KEYS.p256, 'aes-256-cbc'), { password: 'Tr0ub4dor&3', algorithm: P256 }));
        expect(error).toBeInstanceOf(PkiCryptoError);
        expect(error).toMatchObject({ code: 'PKI_CRYPTO_DECRYPTION_FAILED', algorithm: '1.2.840.113549.1.5.13' });
    });

    it('should refuse a password string with a lone surrogate, which has no UTF-8 form', async () => {
        const error = await rejection(decryptPrivateKey(sealed(KEYS.p256, 'aes-256-cbc'), { password: 'pw\uD800', algorithm: P256 }));
        expect(error).toMatchObject({ code: 'PKI_API_MISUSE' });
    });
});

describe('decryptPrivateKey — the algorithm named', () => {
    it.each([
        ['an EC key named Ed25519', KEYS.p256, { name: 'Ed25519' }],
        ['a P-256 key named ECDSA on P-384', KEYS.p256, { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }],
        ['an RSA key named ECDSA', KEYS.rsa, P256],
        ['an Ed25519 key named RSA', KEYS.ed25519, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
    ] as const satisfies ReadonlyArray<readonly [string, Pair, SignatureAlgorithm]>)('should refuse %s with PKI_CRYPTO_DECRYPTION_FAILED, which AES-CBC cannot tell from a wrong password', async (_label, pair, algorithm) => {
        const error = await rejection(decryptPrivateKey(sealed(pair, 'aes-256-cbc'), { password: PASSWORD, algorithm }));
        expect(error).toMatchObject({ code: 'PKI_CRYPTO_DECRYPTION_FAILED' });
    });

    it('should refuse an algorithm with no RFC 5280 OID before deriving anything', async () => {
        const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-224' } as unknown as SignatureAlgorithm;
        const error = await rejection(decryptPrivateKey(sealed(KEYS.rsa, 'aes-256-cbc'), { password: PASSWORD, algorithm }));
        expect(error).toMatchObject({ code: 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED' });
    });
});

describe('decryptPrivateKey — schemes it will not open', () => {
    it('should refuse PBES2 with 3DES (des-ede3-cbc) with PKI_KEY_ENCRYPTION_UNSUPPORTED, naming the scheme', async () => {
        const der = sealed(KEYS.p256, 'des-ede3-cbc');
        const error = await rejection(decryptPrivateKey(der, { password: PASSWORD, algorithm: P256 }));
        expect(error).toBeInstanceOf(PkiKeyError);
        expect(error).toMatchObject({ code: 'PKI_KEY_ENCRYPTION_UNSUPPORTED', path: 'encryptedPrivateKeyInfo.encryptionAlgorithm', offset: 3 });
        expect(error.message).toMatch(/cipher other than AES-CBC \(1\.2\.840\.113549\.3\.7\)/u);
    });

    it('should refuse an RFC 7292 Appendix C scheme, whose key only the Appendix B KDF derives', async () => {
        const der = sequence(alg('1.2.840.113549.1.12.1.3', sequence(octets(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8)), int(2048))), octets(new Uint8Array(32)));
        const error = await rejection(decryptPrivateKey(der, { password: PASSWORD, algorithm: P256 }));
        expect(error).toMatchObject({ code: 'PKI_KEY_ENCRYPTION_UNSUPPORTED', offset: 2 });
        expect(error.message).toMatch(/pbeWithSHAAnd3-KeyTripleDES-CBC/u);
    });

    it('should stop at maxKdfIterations before the host runs a single iteration', async () => {
        const error = await rejection(decryptPrivateKey(sealed(KEYS.p256, 'aes-256-cbc'), { password: PASSWORD, algorithm: P256, limits: { maxKdfIterations: 2047 } }));
        expect(error).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxKdfIterations' });
    });

    it('should refuse an unencrypted key, which is not an EncryptedPrivateKeyInfo', async () => {
        expect(await rejection(decryptPrivateKey(plain(KEYS.p256), { password: PASSWORD, algorithm: P256 }))).toMatchObject({ code: 'PKI_KEY_STRUCTURE_INVALID' });
    });
});

describe('decryptPrivateKey — options', () => {
    const der = (): Uint8Array => sealed(KEYS.p256, 'aes-256-cbc');

    it.each([
        ['missing', undefined],
        ['null', null],
        ['a string', PASSWORD],
    ])('should refuse options that are %s with PKI_INVALID_OPTION', async (_label, options) => {
        expect(await rejection(decryptPrivateKey(der(), options as never))).toMatchObject({ code: 'PKI_INVALID_OPTION' });
    });

    it.each([
        ['missing', undefined],
        ['null', null],
        ['a number', 1234],
        ['a DataView', new DataView(new ArrayBuffer(4))],
        ['an array of numbers', [0x70, 0x77]],
    ])('should refuse a password that is %s with PKI_INVALID_OPTION', async (_label, password) => {
        expect(await rejection(decryptPrivateKey(der(), { password: password as never, algorithm: P256 }))).toMatchObject({ code: 'PKI_INVALID_OPTION' });
    });

    it.each([
        ['missing', undefined],
        ['null', null],
        ['a string', 'ECDSA'],
    ])('should refuse an algorithm that is %s with PKI_INVALID_OPTION', async (_label, algorithm) => {
        expect(await rejection(decryptPrivateKey(der(), { password: PASSWORD, algorithm: algorithm as never }))).toMatchObject({ code: 'PKI_INVALID_OPTION' });
    });

    it('should refuse input that is not a Uint8Array', async () => {
        expect(await rejection(decryptPrivateKey([1, 2] as unknown as Uint8Array, { password: PASSWORD, algorithm: P256 }))).toMatchObject({ code: 'PKI_INVALID_INPUT' });
    });
});
