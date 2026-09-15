import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { sha1 } from '../../src/hash/sha1.js';
import { sha256 } from '../../src/hash/sha256.js';
import { sha384, sha512 } from '../../src/hash/sha512.js';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const ascii = (text: string): Uint8Array => new TextEncoder().encode(text);

const ALGORITHMS = [
    ['sha1', sha1],
    ['sha256', sha256],
    ['sha384', sha384],
    ['sha512', sha512],
] as const;

describe('FIPS 180-4 known answers', () => {
    it.each([
        ['SHA-1', sha1, '', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
        ['SHA-1', sha1, 'abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'],
        ['SHA-256', sha256, '', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
        ['SHA-256', sha256, 'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
        ['SHA-256', sha256, 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
        ['SHA-384', sha384, 'abc', 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'],
        ['SHA-512', sha512, 'abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'],
    ] as const)('should hash %s(%j)', (_name, fn, input, digest) => {
        expect(hex(fn(ascii(input)))).toBe(digest);
    });
});

describe('agreement with node:crypto', () => {
    it.each(ALGORITHMS)('%s should agree on every length from 0 to 300 octets, across every padding boundary', (name, fn) => {
        for (let length = 0; length <= 300; length++) {
            const input = Uint8Array.from({ length }, (_, i) => (i * 31 + length) & 0xff);
            expect(hex(fn(input)), `${name} length ${length}`).toBe(createHash(name).update(input).digest('hex'));
        }
    });

    it.each(ALGORITHMS)('%s should agree on one million "a"', (name, fn) => {
        const input = new Uint8Array(1_000_000).fill(0x61);
        expect(hex(fn(input))).toBe(createHash(name).update(input).digest('hex'));
    });

    it('should hash a view into a larger buffer by its own bytes only', () => {
        const buffer = Uint8Array.from({ length: 100 }, (_, i) => i);
        const view = buffer.subarray(10, 60);
        for (const [name, fn] of ALGORITHMS) expect(hex(fn(view)), name).toBe(createHash(name).update(view).digest('hex'));
    });
});
