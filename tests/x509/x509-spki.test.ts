import { describe, it, expect } from 'vitest';
import { createAsn1Context } from '../../src/asn1/asn1-context.js';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { _readSubjectPublicKeyInfo } from '../../src/x509/x509-spki.js';
import { PkiCertificateError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiParseOptions } from '../../src/types/pki-types.js';
import type { SubjectPublicKeyInfo } from '../../src/types/x509-types.js';
import { algorithm, bitString, integer, nullValue, octetString, oid, rsaKey } from '../helpers/cert-builder.js';
import { sequence } from '../helpers/raw-der-builder.js';

const QUIET: PkiParseOptions = { onDiagnostic: () => undefined };
const RSA = '1.2.840.113549.1.1.1';
const EC = '1.2.840.10045.2.1';
const P256 = '1.2.840.10045.3.1.7';
const ED25519 = '1.3.101.112';

const readSpki = (bytes: Uint8Array, options: PkiParseOptions = QUIET): SubjectPublicKeyInfo =>
    _readSubjectPublicKeyInfo(decodeAsn1(bytes), createAsn1Context(options), 'spki', 0);

function thrown(fn: () => unknown): unknown {
    try {
        fn();
    } catch (error) {
        return error;
    }
    throw new Error('expected a throw');
}

function codeOf(fn: () => unknown): string {
    const error = thrown(fn);
    if (error instanceof PkiError) return error.code;
    throw error;
}

function diagnosticsOf(bytes: Uint8Array): string[] {
    const seen: string[] = [];
    readSpki(bytes, { onDiagnostic: (d) => { seen.push(d.code); } });
    return seen;
}

const spki = (alg: Uint8Array, key: Uint8Array): Uint8Array => sequence(alg, key);
const ecAlgorithm = (curve: string): Uint8Array => algorithm(EC, oid(curve));
const point = (length: number, first = 0x04, fill = 0x11): number[] => [first, ...new Array<number>(length - 1).fill(fill)];
const rsaPublicKey = (modulus: number[], exponent: number[]): Uint8Array => bitString(sequence(integer(modulus), integer(exponent)));

describe('_readSubjectPublicKeyInfo', () => {
    describe('RSA', () => {
        it('should read the modulus without its sign octet and the exponent', () => {
            const input = rsaKey([0x00, 0xc1, 0x02, 0x03]);
            const key = readSpki(input);
            expect(key).toMatchObject({ kind: 'rsa', modulusBits: 24, publicExponent: 65537n });
            expect(key.kind === 'rsa' ? [...key.modulus] : []).toEqual([0xc1, 0x02, 0x03]);
            expect(key.kind === 'rsa' ? key.modulus.buffer : undefined).toBe(input.buffer);
            expect(diagnosticsOf(input)).toEqual([]);
        });

        it('should read a modulus that needs no sign octet', () => {
            const key = readSpki(rsaKey([0x41, 0x02]));
            expect(key).toMatchObject({ modulusBits: 15 });
            expect(key.kind === 'rsa' ? [...key.modulus] : []).toEqual([0x41, 0x02]);
        });

        it('should report rsaEncryption parameters that are not NULL', () => {
            expect(diagnosticsOf(spki(algorithm(RSA), rsaPublicKey([0x41], [3])))).toEqual(['PKI_DIAG_RSA_PARAMETERS_NOT_NULL']);
        });

        it.each([
            ['1, under which a message is its own signature', [0x01]],
            ['2, an even exponent', [0x02]],
            ['65536, even however large', [0x01, 0x00, 0x00]],
        ])('should diagnose a public exponent of %s (RFC 8017 §3.1), and decode the key regardless', (_label, exponent) => {
            const input = rsaKey([0x41, 0x02, 0x03], exponent);
            expect(diagnosticsOf(input)).toEqual(['PKI_DIAG_SPKI_RSA_EXPONENT_WEAK']);
            expect(readSpki(input, QUIET).kind).toBe('rsa');
        });

        it('should say nothing about an odd exponent of at least 3', () => {
            expect(diagnosticsOf(rsaKey([0x41, 0x02, 0x03], [0x03]))).toEqual([]);
        });

        it('should read an RSASSA-PSS key with absent parameters', () => {
            const input = spki(algorithm('1.2.840.113549.1.1.10'), rsaPublicKey([0x41], [3]));
            expect(readSpki(input)).toMatchObject({ kind: 'rsa-pss', publicExponent: 3n });
            expect(diagnosticsOf(input)).toEqual([]);
        });

        it.each<[string, Uint8Array]>([
            ['a key that is not a SEQUENCE', bitString(integer([5]))],
            ['a truncated key', bitString([0x30, 0x05, 0x02])],
            ['a key of three INTEGERs', bitString(sequence(integer([5]), integer([3]), integer([1])))],
            ['a modulus that is not an INTEGER', bitString(sequence(octetString([5]), integer([3])))],
            ['a negative modulus', rsaPublicKey([0x80], [3])],
            ['a zero exponent', rsaPublicKey([0x41], [0])],
            ['a key with unused bits', bitString([0x30, 0x06, 0x02, 0x01, 0x41, 0x02, 0x01, 0x10], 4)],
        ])('should refuse %s', (_, key) => {
            expect(codeOf(() => readSpki(spki(algorithm(RSA, nullValue()), key)))).toBe('PKI_X509_SPKI_INVALID');
        });

        it('should let a limit error through', () => {
            expect(thrown(() => readSpki(rsaKey([0x41, 1, 2, 3]), { limits: { maxIntegerBytes: 2 } }))).toBeInstanceOf(PkiLimitError);
        });
    });

    describe('elliptic curves', () => {
        it.each<[string, string, number]>([
            [P256, 'P-256', 32],
            ['1.3.132.0.34', 'P-384', 48],
            ['1.3.132.0.35', 'P-521', 66],
        ])('should read uncompressed and compressed points on %s (%s)', (curve, name, size) => {
            expect(readSpki(spki(ecAlgorithm(curve), bitString(point(1 + 2 * size)))))
                .toMatchObject({ kind: 'ec', namedCurve: curve, curve: name, pointFormat: 'uncompressed' });
            expect(readSpki(spki(ecAlgorithm(curve), bitString(point(1 + size, 0x03))))).toMatchObject({ curve: name, pointFormat: 'compressed' });
            expect(readSpki(spki(ecAlgorithm(curve), bitString(point(1 + size, 0x02))))).toMatchObject({ curve: name, pointFormat: 'compressed' });
        });

        it('should read a point on a curve it does not name', () => {
            expect(readSpki(spki(ecAlgorithm('1.3.132.0.10'), bitString(point(65))))).toMatchObject({ namedCurve: '1.3.132.0.10', curve: undefined });
        });

        it('should read a key whose parameters are not a named curve', () => {
            expect(readSpki(spki(algorithm(EC, nullValue()), bitString(point(65))))).toMatchObject({ kind: 'ec', namedCurve: undefined, curve: undefined });
        });

        // P-16: RFC 5480 §2.1.1 — namedCurve only; implicitCurve and specifiedCurve MUST NOT be used.
        it.each<[string, Uint8Array]>([
            ['NULL parameters (implicitCurve)', algorithm(EC, nullValue())],
            ['explicit parameters (specifiedCurve)', algorithm(EC, sequence(integer([1])))],
            ['a namedCurve pkinative does not know (secp256k1)', ecAlgorithm('1.3.132.0.10')],
        ])('should diagnose %s at the parameters, and decode the key regardless', (_label, alg) => {
            const input = spki(alg, bitString(point(65)));
            const seen: { code: string; path: string; offset: number | undefined; standard: string }[] = [];
            const key = readSpki(input, { onDiagnostic: (d) => { seen.push({ code: d.code, path: d.path, offset: d.offset, standard: d.standard }); } });
            expect(seen).toEqual([{ code: 'PKI_DIAG_SPKI_EC_PARAMETERS_INVALID', path: 'spki.algorithm.parameters', offset: 2 + 2 + 9, standard: 'RFC 5480 §2.1.1' }]);
            expect(key).toMatchObject({ kind: 'ec', curve: undefined });
        });

        it.each([P256, '1.3.132.0.34', '1.3.132.0.35'])('should say nothing about the namedCurve %s', (curve) => {
            const size = curve === P256 ? 32 : curve === '1.3.132.0.34' ? 48 : 66;
            expect(diagnosticsOf(spki(ecAlgorithm(curve), bitString(point(1 + 2 * size))))).toEqual([]);
        });

        it('should refuse a malformed point without also diagnosing its parameters', () => {
            const seen: string[] = [];
            expect(() => readSpki(spki(algorithm(EC, nullValue()), bitString(point(64))), { onDiagnostic: (d) => { seen.push(d.code); } }))
                .toThrow(expect.objectContaining({ code: 'PKI_X509_SPKI_INVALID' }));
            expect(seen).toEqual([]);
        });

        it.each<[string, Uint8Array]>([
            ['a P-256 point of 64 octets', spki(ecAlgorithm(P256), bitString(point(64)))],
            ['a P-256 compressed point of 32 octets', spki(ecAlgorithm(P256), bitString(point(32, 0x02)))],
            ['a hybrid point', spki(ecAlgorithm(P256), bitString(point(65, 0x06)))],
            ['an empty point', spki(ecAlgorithm(P256), bitString([]))],
            ['an uncompressed point of even length on an unnamed curve', spki(ecAlgorithm('1.3.132.0.10'), bitString(point(64)))],
            ['a compressed point of one octet on an unnamed curve', spki(ecAlgorithm('1.3.132.0.10'), bitString([0x02]))],
            ['absent parameters', spki(algorithm(EC), bitString(point(65)))],
            ['a point with unused bits', spki(ecAlgorithm(P256), bitString(point(65, 0x04, 0x10), 4))],
        ])('should refuse %s', (_, bytes) => {
            expect(codeOf(() => readSpki(bytes))).toBe('PKI_X509_SPKI_INVALID');
        });
    });

    describe('octet-string keys', () => {
        it.each<[string, string, number]>([
            ['1.3.101.110', 'x25519', 32],
            ['1.3.101.111', 'x448', 56],
            [ED25519, 'ed25519', 32],
            ['1.3.101.113', 'ed448', 57],
            ['2.16.840.1.101.3.4.3.17', 'ml-dsa-44', 1312],
            ['2.16.840.1.101.3.4.3.18', 'ml-dsa-65', 1952],
            ['2.16.840.1.101.3.4.3.19', 'ml-dsa-87', 2592],
        ])('should read %s as %s', (algorithmOid, kind, length) => {
            const key = readSpki(spki(algorithm(algorithmOid), bitString(new Array<number>(length).fill(7))));
            expect(key.kind).toBe(kind);
            expect('key' in key ? key.key.length : 0).toBe(length);
        });

        it.each<[string, Uint8Array]>([
            ['a key of the wrong length', spki(algorithm(ED25519), bitString(new Array<number>(31).fill(7)))],
            ['present parameters', spki(algorithm(ED25519, nullValue()), bitString(new Array<number>(32).fill(7)))],
            ['a key with unused bits', spki(algorithm(ED25519), bitString(new Array<number>(32).fill(0x10), 4))],
        ])('should refuse %s', (_, bytes) => {
            expect(codeOf(() => readSpki(bytes))).toBe('PKI_X509_SPKI_INVALID');
        });

        it.each<[string, string]>([
            [ED25519, 'RFC 8410 §3'],
            ['1.3.101.110', 'RFC 8410 §3'],
            ['2.16.840.1.101.3.4.3.17', 'RFC 9881 §2'],
            ['2.16.840.1.101.3.4.3.19', 'RFC 9881 §2'],
        ])('should cite the clause that governs %s when its parameters are present', (algorithmOid, clause) => {
            // RFC 8410 covers the Edwards and Montgomery curves only; the
            // ML-DSA rule is RFC 9881 §2: "MUST be absent".
            expect(() => readSpki(spki(algorithm(algorithmOid, nullValue()), bitString([7]))))
                .toThrow(expect.objectContaining({ code: 'PKI_X509_SPKI_INVALID', message: expect.stringContaining(`(${clause})`) }));
        });
    });

    it('should keep the key of an algorithm it does not decode', () => {
        const key = readSpki(spki(algorithm('1.2.3.4', nullValue()), bitString([1, 2, 3])));
        expect(key).toMatchObject({ kind: 'unknown', algorithm: { oid: '1.2.3.4' } });
        expect([...key.publicKey.bytes]).toEqual([1, 2, 3]);
    });

    describe('structure', () => {
        const KEY = bitString(new Array<number>(32).fill(7));

        it.each<[string, Uint8Array]>([
            ['a SubjectPublicKeyInfo that is not a SEQUENCE', integer([1])],
            ['a SubjectPublicKeyInfo of three values', sequence(algorithm(ED25519), KEY, nullValue())],
            ['a missing key', sequence(algorithm(ED25519))],
            ['a key that is not a BIT STRING', sequence(algorithm(ED25519), octetString(new Array<number>(32).fill(7)))],
            ['an AlgorithmIdentifier of three values', sequence(sequence(oid(ED25519), nullValue(), nullValue()), KEY)],
            ['an algorithm that is not an OID', sequence(sequence(integer([1])), KEY)],
        ])('should refuse %s', (_, bytes) => {
            expect(codeOf(() => readSpki(bytes))).toBe('PKI_X509_SPKI_INVALID');
        });

        it('should refuse a missing SubjectPublicKeyInfo at the offset of its parent', () => {
            const error = thrown(() => _readSubjectPublicKeyInfo(undefined, createAsn1Context(undefined), 'spki', 9));
            expect(error).toBeInstanceOf(PkiCertificateError);
            expect(error).toMatchObject({ code: 'PKI_X509_SPKI_INVALID', offset: 9 });
        });
    });
});
