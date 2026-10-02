import { describe, expect, it } from 'vitest';
import { parseEncryptedPrivateKeyInfo, parsePrivateKeyInfo } from '../../src/keys/key-pkcs8.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';
import { PkiEncodingError, PkiError, PkiKeyError, PkiLimitError } from '../../src/types/pki-errors.js';
import { alg, attribute, context, int, octets, oid, set, sorted } from '../helpers/cms-signed-data-builder.js';
import { concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 5958 `OneAsymmetricKey` (§2) and `EncryptedPrivateKeyInfo` (§3), read
 * without exposing the secret. Every structure here is built by the
 * independent raw-DER helpers, never by the engine's own encoder.
 */

const OIDS = Object.freeze({
    rsa: '1.2.840.113549.1.1.1',
    rsaPss: '1.2.840.113549.1.1.10',
    ec: '1.2.840.10045.2.1',
    ed25519: '1.3.101.112',
    ed448: '1.3.101.113',
    x25519: '1.3.101.110',
    p256: '1.2.840.10045.3.1.7',
    p384: '1.3.132.0.34',
    p521: '1.3.132.0.35',
    secp256k1: '1.3.132.0.10',
    pbes2: '1.2.840.113549.1.5.13',
    pbkdf2: '1.2.840.113549.1.5.12',
    hmacSha256: '1.2.840.113549.2.9',
    aes256: '2.16.840.1.101.3.4.1.42',
    tripleDes: '1.2.840.113549.1.12.1.3',
    friendlyName: '1.2.840.113549.1.9.20',
    localKeyId: '1.2.840.113549.1.9.21',
});

/** Stand-in key octets: never interpreted, only required to be an OCTET STRING. */
const SECRET = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);
const PUBLIC = Uint8Array.from({ length: 33 }, (_, i) => 0x02 + i);
const SALT = Uint8Array.from({ length: 16 }, (_, i) => 0x10 + i);
const IV = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
const CIPHERTEXT = Uint8Array.from({ length: 48 }, (_, i) => 0x60 + i);

const bitString = (bytes: ArrayLike<number>): Uint8Array => universal(3, concat([0], bytes));
const ecAlg = (curve: string = OIDS.p256): Uint8Array => alg(OIDS.ec, oid(curve));

interface KeyParts {
    readonly version?: number;
    readonly algorithm?: Uint8Array;
    readonly key?: Uint8Array;
    readonly optional?: readonly Uint8Array[];
}

const pkcs8 = (parts: KeyParts = {}): Uint8Array => sequence(
    int(parts.version ?? 0),
    parts.algorithm ?? ecAlg(),
    parts.key ?? octets(SECRET),
    ...(parts.optional ?? []),
);

const attributes = (...entries: readonly Uint8Array[]): Uint8Array => context(0, true, concat(...entries));
const publicKey = (bytes: ArrayLike<number> = PUBLIC): Uint8Array => context(1, false, concat([0], bytes));

function keyError(run: () => unknown): PkiKeyError {
    try {
        run();
    } catch (error) {
        expect(error).toBeInstanceOf(PkiKeyError);
        return error as PkiKeyError;
    }
    throw new Error('expected a PkiKeyError');
}

describe('parsePrivateKeyInfo — what a key says about itself', () => {
    it('should read a version 0 EC key on P-256 (RFC 5208 PrivateKeyInfo)', () => {
        const der = pkcs8();
        const info = parsePrivateKeyInfo(der);
        expect(info.version).toBe(0);
        expect(info.kind).toBe('ec');
        expect(info.curve).toBe('P-256');
        expect(info.algorithm.oid).toBe(OIDS.ec);
        expect(info.attributes).toEqual([]);
        expect(info.publicKey).toBeUndefined();
        expect(info.diagnostics).toEqual([]);
        expect(info.der).toEqual(der);
    });

    it('should not expose the private key octets under any field', () => {
        const info = parsePrivateKeyInfo(pkcs8());
        expect(Object.keys(info).sort()).toEqual(['algorithm', 'attributes', 'curve', 'der', 'diagnostics', 'kind', 'publicKey', 'version']);
        expect('privateKey' in info).toBe(false);
        expect(Object.isFrozen(info)).toBe(true);
    });

    it('should keep der a zero-copy view of the input', () => {
        const der = pkcs8();
        const info = parsePrivateKeyInfo(der);
        expect(info.der.buffer).toBe(der.buffer);
    });

    it.each([
        ['rsaEncryption', alg(OIDS.rsa), 'rsa'],
        ['id-RSASSA-PSS (RFC 4055 §1.2)', alg(OIDS.rsaPss, null), 'rsa-pss'],
        ['id-Ed25519 (RFC 8410)', alg(OIDS.ed25519, null), 'ed25519'],
        ['id-Ed448 (RFC 8410)', alg(OIDS.ed448, null), 'ed448'],
        ['id-X25519, a key that does not sign', alg(OIDS.x25519, null), 'unknown'],
    ] as const)('should name the key type of %s', (_label, algorithm, kind) => {
        const info = parsePrivateKeyInfo(pkcs8({ algorithm }));
        expect(info.kind).toBe(kind);
        expect(info.curve).toBeUndefined();
    });

    it.each([
        [OIDS.p384, 'P-384'],
        [OIDS.p521, 'P-521'],
    ] as const)('should name the curve %s', (curve, name) => {
        expect(parsePrivateKeyInfo(pkcs8({ algorithm: ecAlg(curve) })).curve).toBe(name);
    });

    it.each([
        ['a curve Web Crypto does not implement (secp256k1)', ecAlg(OIDS.secp256k1)],
        ['absent parameters', alg(OIDS.ec, null)],
        ['NULL parameters', alg(OIDS.ec)],
        ['specified-curve parameters (a SEQUENCE)', alg(OIDS.ec, sequence(int(1)))],
    ] as const)('should leave curve undefined for an EC key with %s', (_label, algorithm) => {
        const info = parsePrivateKeyInfo(pkcs8({ algorithm }));
        expect(info.kind).toBe('ec');
        expect(info.curve).toBeUndefined();
    });

    it('should not read a curve from the parameters of a key that is not EC', () => {
        expect(parsePrivateKeyInfo(pkcs8({ algorithm: alg(OIDS.ed25519, oid(OIDS.p256)) })).curve).toBeUndefined();
    });
});

describe('parsePrivateKeyInfo — attributes and the public key (RFC 5958 §2)', () => {
    it('should read version 1 with attributes [0] and the public key [1]', () => {
        const name = attribute(OIDS.friendlyName, universal(30, [0, 0x6b]));
        const id = attribute(OIDS.localKeyId, ...sorted([octets([2]), octets([1])]));
        const info = parsePrivateKeyInfo(pkcs8({ version: 1, optional: [attributes(name, id), publicKey()] }));
        expect(info.version).toBe(1);
        expect(info.attributes.map((a) => a.oid)).toEqual([OIDS.friendlyName, OIDS.localKeyId]);
        expect(info.attributes[0]?.der).toEqual(name);
        expect(info.attributes[1]?.values).toEqual([octets([1]), octets([2])]);
        expect(info.publicKey).toEqual({ bytes: PUBLIC, unusedBits: 0 });
    });

    it('should read version 1 with the public key alone', () => {
        const info = parsePrivateKeyInfo(pkcs8({ version: 1, optional: [publicKey()] }));
        expect(info.attributes).toEqual([]);
        expect(info.publicKey?.bytes).toEqual(PUBLIC);
    });

    it('should read version 0 with attributes alone', () => {
        const info = parsePrivateKeyInfo(pkcs8({ optional: [attributes(attribute(OIDS.localKeyId, octets([7])))] }));
        expect(info.attributes).toHaveLength(1);
        expect(Object.isFrozen(info.attributes)).toBe(true);
        expect(Object.isFrozen(info.attributes[0])).toBe(true);
    });

    it('should accept an empty attributes [0]', () => {
        expect(parsePrivateKeyInfo(pkcs8({ optional: [attributes()] })).attributes).toEqual([]);
    });

    it('should refuse the public key in a version 0 structure', () => {
        const error = keyError(() => parsePrivateKeyInfo(pkcs8({ optional: [publicKey()] })));
        expect(error.code).toBe('PKI_KEY_STRUCTURE_INVALID');
        expect(error.path).toBe('privateKeyInfo.publicKey');
    });

    it.each([
        ['the public key before the attributes', [publicKey(), attributes()]],
        ['attributes twice', [attributes(), attributes()]],
        ['the public key twice', [publicKey(), publicKey()]],
        ['a context tag other than [0] and [1]', [context(2, false, [1])]],
        ['a universal value after the private key', [octets([1])]],
    ] as const)('should refuse %s', (_label, optional) => {
        const error = keyError(() => parsePrivateKeyInfo(pkcs8({ version: 1, optional })));
        expect(error.code).toBe('PKI_KEY_STRUCTURE_INVALID');
        expect(error.path).toBe('privateKeyInfo');
    });

    it('should refuse a primitive attributes [0]', () => {
        const error = keyError(() => parsePrivateKeyInfo(pkcs8({ optional: [context(0, false, [1])] })));
        expect(error.path).toBe('privateKeyInfo.attributes');
    });

    it.each([
        ['an attribute that is not a SEQUENCE', octets([1]), 'privateKeyInfo.attributes[0]'],
        ['an attribute with a type only', sequence(oid(OIDS.localKeyId)), 'privateKeyInfo.attributes[0]'],
        ['an attribute with three values', sequence(oid(OIDS.localKeyId), set(octets([1])), set(octets([2]))), 'privateKeyInfo.attributes[0]'],
        ['an attribute type that is not an OID', sequence(int(1), set(octets([1]))), 'privateKeyInfo.attributes[0].type'],
        ['attribute values that are not a SET', sequence(oid(OIDS.localKeyId), sequence(octets([1]))), 'privateKeyInfo.attributes[0].values'],
        ['an empty SET of values', sequence(oid(OIDS.localKeyId), set()), 'privateKeyInfo.attributes[0].values'],
    ] as const)('should refuse %s', (_label, entry, path) => {
        const error = keyError(() => parsePrivateKeyInfo(pkcs8({ optional: [attributes(entry)] })));
        expect(error.code).toBe('PKI_KEY_STRUCTURE_INVALID');
        expect(error.path).toBe(path);
    });

    it('should stop at maxAttributes', () => {
        const entry = attribute(OIDS.localKeyId, octets([1]));
        const der = pkcs8({ optional: [attributes(entry, entry, entry)] });
        expect(parsePrivateKeyInfo(der, { limits: { maxAttributes: 3 } }).attributes).toHaveLength(3);
        try {
            parsePrivateKeyInfo(der, { limits: { maxAttributes: 2 } });
            expect.unreachable();
        } catch (error) {
            expect(error).toBeInstanceOf(PkiLimitError);
            expect(error).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxAttributes', configured: 2, observed: 3 });
        }
    });
});

describe('parsePrivateKeyInfo — refusals', () => {
    it.each([
        ['a value that is not a SEQUENCE', octets(SECRET), 'privateKeyInfo'],
        ['an empty SEQUENCE', sequence(), 'privateKeyInfo.version'],
        ['a version that is not an INTEGER', sequence(octets([0]), ecAlg(), octets(SECRET)), 'privateKeyInfo.version'],
        ['a missing algorithm', sequence(int(0)), 'privateKeyInfo.privateKeyAlgorithm'],
        ['an algorithm that is not a SEQUENCE', pkcs8({ algorithm: oid(OIDS.ec) }), 'privateKeyInfo.privateKeyAlgorithm'],
        ['an algorithm with three values', pkcs8({ algorithm: sequence(oid(OIDS.ec), oid(OIDS.p256), int(1)) }), 'privateKeyInfo.privateKeyAlgorithm'],
        ['a missing private key', sequence(int(0), ecAlg()), 'privateKeyInfo.privateKey'],
        ['a private key that is not an OCTET STRING', pkcs8({ key: bitString(SECRET) }), 'privateKeyInfo.privateKey'],
    ] as const)('should refuse %s with PKI_KEY_STRUCTURE_INVALID', (_label, der, path) => {
        const error = keyError(() => parsePrivateKeyInfo(der));
        expect(error.code).toBe('PKI_KEY_STRUCTURE_INVALID');
        expect(error.path).toBe(path);
        expect(error.message.startsWith('pkinative: ')).toBe(true);
    });

    it.each([2, 3, 255])('should refuse version %i with PKI_KEY_VERSION_UNSUPPORTED', (version) => {
        const error = keyError(() => parsePrivateKeyInfo(pkcs8({ version })));
        expect(error.code).toBe('PKI_KEY_VERSION_UNSUPPORTED');
        expect(error.path).toBe('privateKeyInfo.version');
    });

    it('should refuse input that is not a Uint8Array', () => {
        expect(() => parsePrivateKeyInfo('MIGH' as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should refuse options that are not an object', () => {
        expect(() => parsePrivateKeyInfo(pkcs8(), 1 as never)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION' }));
    });

    it('should refuse trailing bytes after the structure', () => {
        expect(() => parsePrivateKeyInfo(concat(pkcs8(), [0]))).toThrow(PkiEncodingError);
    });

    it('should refuse a non-minimal length under DER', () => {
        const der = sequence(int(0), ecAlg(), tlv(0, false, 4, SECRET, { lengthOctets: 2 }));
        expect(() => parsePrivateKeyInfo(der)).toThrow(expect.objectContaining({ code: 'PKI_ASN1_LENGTH_NON_MINIMAL' }));
    });
});

describe('parsePrivateKeyInfo — diagnostics', () => {
    const berKey = (): Uint8Array => sequence(int(0), ecAlg(), tlv(0, false, 4, SECRET, { lengthOctets: 2 }));

    it('should report a BER construct through onDiagnostic and on the result', () => {
        const seen: PkiDiagnostic[] = [];
        const info = parsePrivateKeyInfo(berKey(), { encodingRules: 'ber', onDiagnostic: (d) => { seen.push(d); } });
        expect(seen.map((d) => d.code)).toEqual(['PKI_DIAG_BER_CONSTRUCT_ACCEPTED']);
        expect(info.diagnostics).toEqual(seen);
    });

    it('should still report it under strict, which refuses warnings and not the BER the caller allowed', () => {
        const seen: string[] = [];
        expect(parsePrivateKeyInfo(berKey(), { encodingRules: 'ber', strict: true, onDiagnostic: (d) => { seen.push(d.code); } }).version).toBe(0);
        expect(seen).toContain('PKI_DIAG_BER_CONSTRUCT_ACCEPTED');
    });
});

// ── EncryptedPrivateKeyInfo (RFC 5958 §3) ──

const pbes2 = (iterations = 2048): Uint8Array => alg(OIDS.pbes2, sequence(
    alg(OIDS.pbkdf2, sequence(octets(SALT), int(iterations), alg(OIDS.hmacSha256))),
    alg(OIDS.aes256, octets(IV)),
));

const encrypted = (scheme: Uint8Array = pbes2(), data: Uint8Array = octets(CIPHERTEXT)): Uint8Array => sequence(scheme, data);

describe('parseEncryptedPrivateKeyInfo', () => {
    it('should read a PBES2 scheme and the ciphertext', () => {
        const der = encrypted();
        const info = parseEncryptedPrivateKeyInfo(der);
        expect(info.encryption.scheme).toBe('PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)');
        expect(info.encryption.pbes2).toMatchObject({ salt: SALT, iterations: 2048, prf: 'SHA-256', keyBits: 256, iv: IV });
        expect(info.encryptedData).toEqual(CIPHERTEXT);
        expect(info.encryptedData.buffer).toBe(der.buffer);
        expect(info.der).toEqual(der);
        expect(info.diagnostics).toEqual([]);
        expect(Object.isFrozen(info)).toBe(true);
    });

    it('should describe a refused scheme without refusing to parse', () => {
        const info = parseEncryptedPrivateKeyInfo(encrypted(alg(OIDS.tripleDes, sequence(octets(SALT), int(2048)))));
        expect(info.encryption.pbes2).toBeUndefined();
        expect(info.encryption.scheme).toBe('pbeWithSHAAnd3-KeyTripleDES-CBC');
    });

    it('should report a low iteration count through onDiagnostic and on the result', () => {
        const seen: PkiDiagnostic[] = [];
        const info = parseEncryptedPrivateKeyInfo(encrypted(pbes2(100)), { onDiagnostic: (d) => { seen.push(d); } });
        expect(seen.map((d) => d.code)).toEqual(['PKI_DIAG_KEY_KDF_ITERATIONS_LOW']);
        expect(info.diagnostics).toEqual(seen);
    });

    it('should stop at maxKdfIterations before the host runs anything', () => {
        expect(() => parseEncryptedPrivateKeyInfo(encrypted(pbes2(5000)), { limits: { maxKdfIterations: 4999 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxKdfIterations' }));
    });

    it.each([
        ['a value that is not a SEQUENCE', octets(CIPHERTEXT), 'encryptedPrivateKeyInfo'],
        ['a scheme alone', sequence(pbes2()), 'encryptedPrivateKeyInfo'],
        ['three values', sequence(pbes2(), octets(CIPHERTEXT), octets(CIPHERTEXT)), 'encryptedPrivateKeyInfo'],
        ['a scheme that is not a SEQUENCE', encrypted(oid(OIDS.pbes2)), 'encryptedPrivateKeyInfo.encryptionAlgorithm'],
        ['ciphertext that is not an OCTET STRING', encrypted(pbes2(), bitString(CIPHERTEXT)), 'encryptedPrivateKeyInfo.encryptedData'],
    ] as const)('should refuse %s with PKI_KEY_STRUCTURE_INVALID', (_label, der, path) => {
        const error = keyError(() => parseEncryptedPrivateKeyInfo(der));
        expect(error.code).toBe('PKI_KEY_STRUCTURE_INVALID');
        expect(error.path).toBe(path);
    });

    it('should refuse input that is not a Uint8Array', () => {
        expect(() => parseEncryptedPrivateKeyInfo(null as unknown as Uint8Array)).toThrow(PkiError);
        expect(() => parseEncryptedPrivateKeyInfo(null as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });
});
