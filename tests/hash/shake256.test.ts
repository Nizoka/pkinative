import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { shake256 } from '../../src/hash/shake256.js';
import { shake256 as fromIndex } from '../../src/index.js';
import { PkiError } from '../../src/types/pki-errors.js';

/**
 * SHAKE256, the digest of an Ed448 CMS signer (RFC 8419 §3.1). The known
 * answers are FIPS 202's; node:crypto is the independent oracle for every
 * padding boundary and every output length a squeeze can take.
 */

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const node = (input: Uint8Array, outputLength: number): string => createHash('shake256', { outputLength }).update(input).digest('hex');
/** Deterministic bytes that differ with the length, so two lengths never share a prefix pattern. */
const pattern = (length: number): Uint8Array => Uint8Array.from({ length }, (_, i) => (i * 31 + length) & 0xff);

describe('FIPS 202 known answers', () => {
    it('should produce the 512-bit output of the empty message — what an Ed448 signer digests nothing to', () => {
        expect(hex(shake256(new Uint8Array(0), 64))).toBe(
            '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be');
    });

    it('should produce the NIST SHAKE256_Msg1600 answer for 200 octets of 0xA3 (the first 64 of 512)', () => {
        // NIST CSRC example values, SHAKE256_Msg1600.pdf: the 1600-bit message
        // of 0xA3 octets. The first 512 bits of its output are below; the rest
        // of the published 4096 bits is held through node:crypto.
        const input = new Uint8Array(200).fill(0xa3);
        const out = shake256(input, 512);
        expect(hex(out.subarray(0, 64))).toBe(
            'cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b');
        expect(hex(out)).toBe(node(input, 512));
    });

    it('should be the same function from the package entry point', () => {
        expect(fromIndex).toBe(shake256);
    });
});

describe('agreement with node:crypto', () => {
    it.each([0, 1, 4, 7, 135, 136, 137, 271, 272, 273])('should agree on a %i-octet message at the 64-octet output of RFC 8419', (length) => {
        // 135: the separator and the final pad bit share the last octet of a
        // block (0x9F); 136 and 272: a full block, so the padding is a block of
        // its own; 137 and 273: one octet into a new block.
        expect(hex(shake256(pattern(length), 64))).toBe(node(pattern(length), 64));
    });

    it('should agree on every length from 0 to 300 octets', () => {
        for (let length = 0; length <= 300; length++) {
            expect(hex(shake256(pattern(length), 64)), `length ${String(length)}`).toBe(node(pattern(length), 64));
        }
    });

    it.each([0, 1, 3, 5, 32, 135, 136, 137, 200, 271, 272, 273, 1000])('should squeeze %i octets, across block boundaries and word tails', (outputLength) => {
        expect(hex(shake256(pattern(50), outputLength))).toBe(node(pattern(50), outputLength));
        expect(shake256(pattern(50), outputLength)).toHaveLength(outputLength);
    });

    it('should squeeze 200 octets as the first 200 of a longer output — the squeeze is a prefix function', () => {
        const long = shake256(pattern(99), 400);
        expect(hex(shake256(pattern(99), 200))).toBe(hex(long.subarray(0, 200)));
        expect(hex(long)).toBe(node(pattern(99), 400));
    });

    it('should agree on one megabyte', () => {
        const input = new Uint8Array(1_000_000).fill(0x61);
        expect(hex(shake256(input, 64))).toBe(node(input, 64));
    });

    it('should hash a view into a larger buffer by its own bytes only', () => {
        const buffer = Uint8Array.from({ length: 300 }, (_, i) => i & 0xff);
        const view = buffer.subarray(10, 160);
        expect(hex(shake256(view, 64))).toBe(node(view, 64));
    });

    it('should not depend on state from a previous call', () => {
        const first = hex(shake256(pattern(300), 64));
        shake256(pattern(17), 300);
        expect(hex(shake256(pattern(300), 64))).toBe(first);
    });
});

describe('arguments', () => {
    it('should refuse an input that is not a Uint8Array', () => {
        expect(() => shake256('abc' as unknown as Uint8Array, 64)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '64' as unknown as number])('should refuse an output length of %s', (outputLength) => {
        expect(() => shake256(new Uint8Array(0), outputLength)).toThrow(PkiError);
        expect(() => shake256(new Uint8Array(0), outputLength)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION', message: expect.stringContaining('outputLength') }));
    });

    it('should squeeze at most 1 048 576 octets — a digest, not a stream — and exactly that many at the bound', () => {
        expect(() => shake256(new Uint8Array(0), 1_048_577)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION', message: expect.stringContaining('1048576') }));
        expect(shake256(new Uint8Array(0), 1_048_576)).toHaveLength(1_048_576);
    });
});
