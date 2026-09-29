import { describe, expect, it } from 'vitest';
import { createAsn1Context } from '../../src/asn1/asn1-context.js';
import { decodeWithContext } from '../../src/asn1/asn1-decode.js';
import { decryptContent } from '../../src/crypto/webcrypto.js';
import {
    _derivePbes2Key,
    _expectField,
    _passwordOctets,
    _readPasswordEncryption,
    _requirePbes2,
} from '../../src/keys/key-pbes2.js';
import type { PasswordEncryption } from '../../src/types/key-types.js';
import { PkiError, PkiKeyError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic, PkiLimits } from '../../src/types/pki-types.js';
import { alg, int, octets, oid } from '../helpers/cms-signed-data-builder.js';
import { sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * PBES2 (RFC 8018 §6.2, §A.2, §A.4, §B.2.5) as `keys` reads it: accepted with
 * PBKDF2 and AES-CBC, described and refused for everything else, and bounded
 * before the host runs a single iteration. Every structure here is built by
 * the independent raw-DER helpers, never by the engine's own encoder.
 */

const PBES2 = '1.2.840.113549.1.5.13';
const PBKDF2 = '1.2.840.113549.1.5.12';
const HMAC = { 'SHA-1': '1.2.840.113549.2.7', 'SHA-224': '1.2.840.113549.2.8', 'SHA-256': '1.2.840.113549.2.9' } as const;
const AES = { 128: '2.16.840.1.101.3.4.1.2', 256: '2.16.840.1.101.3.4.1.42' } as const;
const SALT = Uint8Array.from({ length: 16 }, (_, i) => 0x10 + i);
const IV = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);

interface Pbkdf2Parts {
    readonly salt?: Uint8Array;
    readonly iterations?: number;
    readonly keyLength?: number;
    readonly prf?: Uint8Array | null;
    readonly extra?: readonly Uint8Array[];
}

const pbkdf2Params = (parts: Pbkdf2Parts = {}): Uint8Array => sequence(
    parts.salt ?? octets(SALT),
    int(parts.iterations ?? 2048),
    ...(parts.keyLength === undefined ? [] : [int(parts.keyLength)]),
    ...(parts.prf === null ? [] : [parts.prf ?? alg(HMAC['SHA-256'])]),
    ...(parts.extra ?? []),
);

const pbes2 = (kdf: Uint8Array = alg(PBKDF2, pbkdf2Params()), cipher: Uint8Array = alg(AES[256], octets(IV))): Uint8Array =>
    alg(PBES2, sequence(kdf, cipher));

function read(der: Uint8Array, limits: Partial<PkiLimits> = {}): { encryption: PasswordEncryption; diagnostics: PkiDiagnostic[] } {
    const diagnostics: PkiDiagnostic[] = [];
    const ctx = createAsn1Context({ limits, onDiagnostic: (d) => { diagnostics.push(d); } });
    const node = decodeWithContext(der, ctx, false);
    return { encryption: _readPasswordEncryption(node, ctx, 'encryptionAlgorithm', 0), diagnostics };
}

function refusal(der: Uint8Array): unknown {
    try {
        read(der);
    } catch (error) {
        return error;
    }
    throw new Error('expected a refusal');
}

describe('_readPasswordEncryption — what pkinative opens', () => {
    it('should read PBES2 with PBKDF2, HMAC-SHA-256 and AES-256-CBC, and name it', () => {
        const { encryption, diagnostics } = read(pbes2());
        expect(encryption.pbes2).toEqual({ salt: SALT, iterations: 2048, prf: 'SHA-256', keyBits: 256, iv: IV, cipherOid: AES[256] });
        expect(encryption.scheme).toBe('PBES2 (PBKDF2 with HMAC-SHA-256, AES-256-CBC)');
        expect(encryption.algorithm.oid).toBe(PBES2);
        expect(diagnostics).toEqual([]);
    });

    it('should default the PRF to HMAC-SHA-1 when it is absent (RFC 8018 §A.2), silently', () => {
        const { encryption, diagnostics } = read(pbes2(alg(PBKDF2, pbkdf2Params({ prf: null })), alg(AES[128], octets(IV))));
        expect(encryption.pbes2?.prf).toBe('SHA-1');
        expect(encryption.pbes2?.keyBits).toBe(128);
        expect(diagnostics).toEqual([]);
    });

    it('should diagnose HMAC-SHA-1 written out, which DER omits as the DEFAULT', () => {
        const { encryption, diagnostics } = read(pbes2(alg(PBKDF2, pbkdf2Params({ prf: alg(HMAC['SHA-1'], null) }))));
        expect(encryption.pbes2?.prf).toBe('SHA-1');
        expect(diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_DEFAULT_ENCODED']);
    });

    it('should accept a keyLength that agrees with the cipher', () => {
        expect(read(pbes2(alg(PBKDF2, pbkdf2Params({ keyLength: 32 })))).encryption.pbes2?.keyBits).toBe(256);
    });

    it('should diagnose an iteration count below the 1 000 RFC 8018 §4.2 recommends, and still read it', () => {
        const { encryption, diagnostics } = read(pbes2(alg(PBKDF2, pbkdf2Params({ iterations: 1 }))));
        expect(encryption.pbes2?.iterations).toBe(1);
        expect(diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_KEY_KDF_ITERATIONS_LOW']);
    });
});

describe('_readPasswordEncryption — what pkinative describes and refuses', () => {
    it.each([
        ['an RFC 7292 Appendix C scheme', alg('1.2.840.113549.1.12.1.3', sequence(octets(SALT), int(2048))), 'pbeWithSHAAnd3-KeyTripleDES-CBC'],
        ['a PBES1 scheme', alg('1.2.840.113549.1.5.10', sequence(octets(SALT.subarray(0, 8)), int(2048))), 'pbeWithSHA1AndDES-CBC'],
        ['a scheme nobody registered', alg('1.2.3.4'), 'an unrecognised scheme (1.2.3.4)'],
        ['PBES2 over scrypt', pbes2(alg('1.3.6.1.4.1.11591.4.11', sequence(octets(SALT), int(16384), int(8), int(1)))), 'PBES2 with a key derivation function other than PBKDF2 (1.3.6.1.4.1.11591.4.11)'],
        ['PBES2 with a salt from otherSource', pbes2(alg(PBKDF2, pbkdf2Params({ salt: alg('1.2.3.4') }))), 'PBES2 with PBKDF2 with a salt from otherSource, which RFC 8018 reserves for future use'],
        ['PBES2 over HMAC-SHA-224, which Web Crypto lacks', pbes2(alg(PBKDF2, pbkdf2Params({ prf: alg(HMAC['SHA-224']) }))), 'PBES2 with PBKDF2 with a PRF Web Crypto does not implement (1.2.840.113549.2.8)'],
        ['PBES2 over an HMAC with parameters', pbes2(alg(PBKDF2, pbkdf2Params({ prf: alg(HMAC['SHA-256'], int(1)) }))), 'PBES2 with PBKDF2 with a PRF Web Crypto does not implement (1.2.840.113549.2.9)'],
        ['PBES2 with 3DES', pbes2(undefined, alg('1.2.840.113549.3.7', octets(IV.subarray(0, 8)))), 'PBES2 with a cipher other than AES-CBC (1.2.840.113549.3.7)'],
    ])('should describe %s, with no PBES2 parameters', (_what, der, scheme) => {
        const { encryption } = read(der);
        expect(encryption.pbes2).toBeUndefined();
        expect(encryption.scheme).toBe(scheme);
    });

    it('should refuse to open a described scheme with a code that names it and the conversion', () => {
        const { encryption } = read(alg('1.2.840.113549.1.12.1.6', sequence(octets(SALT), int(2048))));
        const call = (): unknown => _requirePbes2(encryption, 'authSafe[0].encryptionAlgorithm', 12);
        expect(call).toThrow(PkiKeyError);
        expect(call).toThrow(expect.objectContaining({ code: 'PKI_KEY_ENCRYPTION_UNSUPPORTED', path: 'authSafe[0].encryptionAlgorithm', offset: 12 }));
        expect(call).toThrow(/pbeWithSHAAnd40BitRC2-CBC.*-pbmac1_pbkdf2/);
    });

    it('should hand back the parameters of a scheme it opens', () => {
        const { encryption } = read(pbes2());
        expect(_requirePbes2(encryption, 'x', 0)).toBe(encryption.pbes2);
    });
});

describe('_readPasswordEncryption — the bound, before the host runs anything', () => {
    it('should refuse an iteration count past maxKdfIterations, with the limit named', () => {
        const call = (): unknown => read(pbes2(alg(PBKDF2, pbkdf2Params({ iterations: 2_000_000 }))), { maxKdfIterations: 1_000_000 });
        expect(call).toThrow(PkiLimitError);
        expect(call).toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxKdfIterations', observed: 2_000_000 }));
    });

    it('should hold the default at ten million — a 2^31 count must not reach Web Crypto', () => {
        expect(() => read(pbes2(alg(PBKDF2, pbkdf2Params({ iterations: 0x7fffffff })))))
            .toThrow(expect.objectContaining({ limit: 'maxKdfIterations', configured: 10_000_000 }));
    });
});

describe('_readPasswordEncryption — structures that break the grammar', () => {
    it.each([
        ['an AlgorithmIdentifier that is not a SEQUENCE', int(1), 'encryptionAlgorithm'],
        ['an AlgorithmIdentifier with three values', sequence(oid(PBES2), sequence(), int(1)), 'encryptionAlgorithm'],
        ['an AlgorithmIdentifier with no OID', sequence(int(1)), 'encryptionAlgorithm.algorithm'],
        ['PBES2 without parameters', sequence(oid(PBES2)), 'encryptionAlgorithm.parameters'],
        ['PBES2 parameters with one half', alg(PBES2, sequence(alg(PBKDF2, pbkdf2Params()))), 'encryptionAlgorithm.parameters'],
        ['PBKDF2 parameters with a fifth value', pbes2(alg(PBKDF2, pbkdf2Params({ keyLength: 32, extra: [int(1)] }))), 'encryptionAlgorithm.parameters.keyDerivationFunc.parameters'],
        ['a salt that is not an OCTET STRING', pbes2(alg(PBKDF2, pbkdf2Params({ salt: int(1) }))), 'encryptionAlgorithm.parameters.keyDerivationFunc.parameters.salt'],
        ['an iteration count of zero', pbes2(alg(PBKDF2, pbkdf2Params({ iterations: 0 }))), 'encryptionAlgorithm.parameters.keyDerivationFunc.parameters.iterationCount'],
        ['a missing iteration count', pbes2(alg(PBKDF2, sequence(octets(SALT)))), 'encryptionAlgorithm.parameters.keyDerivationFunc.parameters.iterationCount'],
        ['a keyLength of zero', pbes2(alg(PBKDF2, pbkdf2Params({ keyLength: 0 }))), 'encryptionAlgorithm.parameters.keyDerivationFunc.parameters.keyLength'],
        ['a keyLength past 64 octets', pbes2(alg(PBKDF2, pbkdf2Params({ keyLength: 65 }))), 'encryptionAlgorithm.parameters.keyDerivationFunc.parameters.keyLength'],
        ['a keyLength the cipher contradicts', pbes2(alg(PBKDF2, pbkdf2Params({ keyLength: 16 }))), 'encryptionAlgorithm.parameters.keyDerivationFunc.parameters.keyLength'],
        ['a value after a PRF where a keyLength belongs', pbes2(alg(PBKDF2, pbkdf2Params({ extra: [int(1)] }))), 'encryptionAlgorithm.parameters.keyDerivationFunc.parameters'],
        ['AES without an initialisation vector', pbes2(undefined, sequence(oid(AES[256]))), 'encryptionAlgorithm.parameters.encryptionScheme.parameters'],
        ['an initialisation vector of 8 octets', pbes2(undefined, alg(AES[256], octets(IV.subarray(0, 8)))), 'encryptionAlgorithm.parameters.encryptionScheme.parameters'],
    ])('should refuse %s as PKI_KEY_STRUCTURE_INVALID, at the field', (_what, der, path) => {
        const error = refusal(der);
        expect(error).toBeInstanceOf(PkiKeyError);
        expect(error).toMatchObject({ code: 'PKI_KEY_STRUCTURE_INVALID', path });
        expect((error as PkiKeyError).message).toMatch(/^pkinative: /);
    });

    it('should let an ASN.1 value error surface as itself, not as a key error', () => {
        // An INTEGER with a redundant leading octet is an X.690 violation; it is
        // reported by the reader that found it, with its own code.
        const nonMinimal = universal(2, [0x00, 0x01]);
        expect(refusal(pbes2(alg(PBKDF2, sequence(octets(SALT), nonMinimal))))).toMatchObject({ code: 'PKI_ASN1_INTEGER_INVALID' });
    });
});

describe('_expectField', () => {
    it('should name what was missing, at the parent', () => {
        expect(() => _expectField(undefined, 4, 'x.salt', 7, 'an OCTET STRING salt'))
            .toThrow(expect.objectContaining({ code: 'PKI_KEY_STRUCTURE_INVALID', path: 'x.salt', offset: 7 }));
    });
});

describe('_passwordOctets', () => {
    it('should encode a string as UTF-8, not as the BMPString of RFC 7292 Appendix B, and wipe its own copy', () => {
        const { octets: bytes, wipe } = _passwordOctets('pässwörd');
        expect([...bytes]).toEqual([...new TextEncoder().encode('pässwörd')]);
        wipe();
        expect(bytes.every((b) => b === 0)).toBe(true);
    });

    it('should use a Uint8Array as given, and never touch the caller\'s buffer', () => {
        const given = Uint8Array.of(0xff, 0xfe, 0x00, 0x70);
        const { octets: bytes, wipe } = _passwordOctets(given);
        expect(bytes).toBe(given);
        wipe();
        expect([...given]).toEqual([0xff, 0xfe, 0x00, 0x70]);
    });

    it('should refuse a string with a lone surrogate, which has no UTF-8', () => {
        const call = (): unknown => _passwordOctets('\ud800');
        expect(call).toThrow(PkiError);
        expect(call).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });
});

describe('_derivePbes2Key', () => {
    it('should derive the key a PBES2 writer encrypted under', async () => {
        const subtle = globalThis.crypto.subtle;
        const params = read(pbes2()).encryption.pbes2;
        if (params === undefined) throw new Error('unreachable');
        const base = await subtle.importKey('raw', new TextEncoder().encode('hunter2'), 'PBKDF2', false, ['deriveKey']);
        const theirs = await subtle.deriveKey({ name: 'PBKDF2', salt: SALT, iterations: 2048, hash: 'SHA-256' }, base, { name: 'AES-CBC', length: 256 }, false, ['encrypt']);
        const plaintext = new TextEncoder().encode('certificates');
        const ciphertext = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: IV }, theirs, plaintext));
        const ours = await _derivePbes2Key('hunter2', params, PBES2);
        expect(await decryptContent(ours, IV, ciphertext, PBES2)).toEqual(plaintext);
    });
});
