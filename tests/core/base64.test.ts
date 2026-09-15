import { describe, it, expect } from 'vitest';
import { decodeBase64, encodeBase64 } from '../../src/core/base64.js';

const ascii = (text: string): Uint8Array => Uint8Array.from([...text].map((c) => c.charCodeAt(0)));

describe('encodeBase64 and decodeBase64', () => {
    // RFC 4648 §10 test vectors.
    it.each([
        ['', ''],
        ['f', 'Zg=='],
        ['fo', 'Zm8='],
        ['foo', 'Zm9v'],
        ['foob', 'Zm9vYg=='],
        ['fooba', 'Zm9vYmE='],
        ['foobar', 'Zm9vYmFy'],
    ])('should map %j to %j both ways (RFC 4648 §10)', (plain, encoded) => {
        expect(encodeBase64(ascii(plain))).toBe(encoded);
        expect([...(decodeBase64(encoded) ?? [])]).toEqual([...ascii(plain)]);
    });

    it('should round-trip every octet value, and agree with Node Buffer', () => {
        const all = Uint8Array.from({ length: 256 }, (_, i) => i);
        const encoded = encodeBase64(all);
        expect(encoded).toBe(Buffer.from(all).toString('base64'));
        expect([...(decodeBase64(encoded) ?? [])]).toEqual([...all]);
    });
});

describe('decodeBase64 strictness', () => {
    it.each([
        ['a length that is not a multiple of four', 'Zg='],
        ['no padding', 'Zg'],
        ['three padding characters', 'Z==='],
        ['padding in the middle', 'Zg==Zm9v'],
        ['padding at the start', '=Zg='],
        ['padding followed by a character', 'Zg=a'],
        ['non-zero padding bits after one byte', 'Zh=='],
        ['non-zero padding bits after two bytes', 'Zm9='],
        ['a character outside the alphabet', 'Zm9*'],
        ['the URL-safe alphabet', 'Zm-_'],
        ['whitespace', 'Zm9v Zg=='],
        ['a non-ASCII character', 'Zm9é'],
    ])('should refuse %s', (_label, text) => {
        expect(decodeBase64(text)).toBeNull();
    });
});
