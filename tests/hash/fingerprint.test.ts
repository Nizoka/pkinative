import { describe, it, expect, vi, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { computeFingerprint, computeFingerprintAsync, formatFingerprint } from '../../src/hash/fingerprint.js';
import type { FingerprintAlgorithm } from '../../src/types/hash-types.js';
import { PkiError } from '../../src/types/pki-errors.js';

const DER = Uint8Array.from({ length: 777 }, (_, i) => (i * 13) & 0xff);
const NODE_NAMES: Readonly<Record<FingerprintAlgorithm, string>> = { 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' };
const expected = (algorithm: FingerprintAlgorithm): string => createHash(NODE_NAMES[algorithm]).update(DER).digest('hex');
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

afterEach(() => {
    vi.unstubAllGlobals();
});

function codeOf(fn: () => unknown): string {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiError) return err.code;
        throw err;
    }
    return 'no error';
}

describe('computeFingerprint', () => {
    it.each(Object.keys(NODE_NAMES) as FingerprintAlgorithm[])('should compute %s like node:crypto', (algorithm) => {
        expect(hex(computeFingerprint(DER, algorithm))).toBe(expected(algorithm));
    });

    it('should refuse an unknown algorithm and a non-Uint8Array input', () => {
        expect(codeOf(() => computeFingerprint(DER, 'MD5' as FingerprintAlgorithm))).toBe('PKI_INVALID_OPTION');
        expect(codeOf(() => computeFingerprint('3082' as unknown as Uint8Array, 'SHA-256'))).toBe('PKI_INVALID_INPUT');
    });
});

describe('computeFingerprintAsync', () => {
    it.each(Object.keys(NODE_NAMES) as FingerprintAlgorithm[])('should compute %s through Web Crypto with the same bytes', async (algorithm) => {
        expect(hex(await computeFingerprintAsync(DER, algorithm))).toBe(expected(algorithm));
    });

    // The contract is "through Web Crypto when available": equal bytes alone
    // cannot tell the two paths apart, so the host's digest is observed.
    it.each(Object.keys(NODE_NAMES) as FingerprintAlgorithm[])('should hand %s to the host digest when Web Crypto offers one', async (algorithm) => {
        const subtle = globalThis.crypto.subtle;
        const digest = vi.fn((name: string, data: Uint8Array): Promise<ArrayBuffer> => subtle.digest(name, data));
        vi.stubGlobal('crypto', { subtle: { digest } });
        expect(hex(await computeFingerprintAsync(DER, algorithm))).toBe(expected(algorithm));
        expect(digest).toHaveBeenCalledTimes(1);
        expect(digest.mock.calls[0]?.[0]).toBe(algorithm);
        expect(hex(digest.mock.calls[0]?.[1] ?? new Uint8Array(0))).toBe(hex(DER));
    });

    it('should fall back to the pure path on a host without Web Crypto', async () => {
        vi.stubGlobal('crypto', undefined);
        expect(hex(await computeFingerprintAsync(DER, 'SHA-256'))).toBe(expected('SHA-256'));
    });

    it('should fall back to the pure path when Web Crypto refuses the digest', async () => {
        vi.stubGlobal('crypto', { subtle: { digest: () => Promise.reject(new Error('NotSupportedError')) } });
        expect(hex(await computeFingerprintAsync(DER, 'SHA-1'))).toBe(expected('SHA-1'));
    });

    it('should reject an unknown algorithm and a non-Uint8Array input', async () => {
        await expect(computeFingerprintAsync(DER, 'MD5' as FingerprintAlgorithm)).rejects.toMatchObject({ code: 'PKI_INVALID_OPTION' });
        await expect(computeFingerprintAsync(null as unknown as Uint8Array, 'SHA-256')).rejects.toMatchObject({ code: 'PKI_INVALID_INPUT' });
    });
});

describe('formatFingerprint', () => {
    const digest = Uint8Array.of(0xab, 0x01, 0xff);

    it('should render uppercase colon-separated octets by default', () => {
        expect(formatFingerprint(digest)).toBe('AB:01:FF');
    });

    it('should honour the separator and the letter case', () => {
        expect(formatFingerprint(digest, { separator: '', letterCase: 'lower' })).toBe('ab01ff');
        expect(formatFingerprint(digest, { separator: ' ' })).toBe('AB 01 FF');
    });

    it('should refuse a malformed option and a non-Uint8Array digest', () => {
        expect(codeOf(() => formatFingerprint(digest, { separator: 5 as unknown as string }))).toBe('PKI_INVALID_OPTION');
        expect(codeOf(() => formatFingerprint(digest, { letterCase: 'title' as 'upper' }))).toBe('PKI_INVALID_OPTION');
        expect(codeOf(() => formatFingerprint([0xab] as unknown as Uint8Array))).toBe('PKI_INVALID_INPUT');
    });
});
