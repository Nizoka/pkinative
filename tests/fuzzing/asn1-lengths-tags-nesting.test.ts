import { describe, it, expect } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { createPrng } from '../helpers/prng.js';
import { berNest, concat, derNest, identifierOctets, lengthOctets } from '../helpers/raw-der-builder.js';
import { outcome } from './_harness.js';

describe('fuzzing — length encoding', () => {
    it('should turn every long-form length pattern into a value or a typed error, never a negative length', () => {
        const seed = 0x5eed_0002;
        const rng = createPrng(seed);
        for (let iteration = 0; iteration < 5000; iteration++) {
            const count = 1 + rng.int(9);
            const lengthBody = Array.from(rng.bytes(count));
            if (rng.int(4) === 0) lengthBody[0] = 0x80 | rng.int(128); // the high bit that broke pdfnative
            const tail = rng.bytes(rng.int(40));
            const input = concat([0x04, 0x80 | count], lengthBody, tail);
            for (const encodingRules of ['der', 'ber'] as const) {
                const result = outcome(`seed ${seed} iteration ${iteration}`, input, () => decodeAsn1(input, { encodingRules, allowTrailingData: true, onDiagnostic: () => undefined }));
                if (result === 'ok') {
                    const node = decodeAsn1(input, { encodingRules, allowTrailingData: true, onDiagnostic: () => undefined });
                    expect(node.contentLength).toBeGreaterThanOrEqual(0);
                    expect(node.contentLength).toBeLessThanOrEqual(tail.length);
                }
            }
        }
    });

    it.each([
        ['84 80 00 00 01', [0x04, 0x84, 0x80, 0x00, 0x00, 0x01]],
        ['84 FF FF FF FF', [0x04, 0x84, 0xff, 0xff, 0xff, 0xff]],
        ['a 126-octet length', [0x04, 0xfe, ...new Array<number>(126).fill(0xff)]],
    ])('should refuse the hostile length %s as truncated', (_label, octets) => {
        expect(outcome('hostile length', Uint8Array.from(octets), () => decodeAsn1(Uint8Array.from(octets)))).toBe('PKI_ASN1_TRUNCATED');
    });
});

describe('fuzzing — high tag numbers', () => {
    it('should decode every valid high tag number exactly and refuse every malformed one with a typed error', () => {
        const seed = 0x5eed_0003;
        const rng = createPrng(seed);
        for (let iteration = 0; iteration < 3000; iteration++) {
            const tagNumber = 31 + rng.int(0x7fffffff - 31);
            const cls = rng.int(4) as 0 | 1 | 2 | 3;
            const valid = Uint8Array.from([...identifierOctets(cls, false, tagNumber), 0x00]);
            expect(decodeAsn1(valid).tagNumber).toBe(tagNumber);
            const random = concat([0x1f | (cls << 6)], rng.bytes(1 + rng.int(7)), [0x00]);
            outcome(`seed ${seed} iteration ${iteration}`, random, () => decodeAsn1(random, { allowTrailingData: true }));
        }
    });
});

describe('fuzzing — nesting', () => {
    it('should stop hostile DER and BER nesting at maxDepth with PKI_LIMIT_EXCEEDED, never a RangeError', () => {
        expect(outcome('der nest', derNest(200), () => decodeAsn1(derNest(200)))).toBe('PKI_LIMIT_EXCEEDED');
        const deep = berNest(200_000);
        expect(outcome('ber nest', deep, () => decodeAsn1(deep, { encodingRules: 'ber', onDiagnostic: () => undefined }))).toBe('PKI_LIMIT_EXCEEDED');
    });

    it('should stop a flat flood of values at maxNodes', () => {
        const nulls = new Uint8Array(2 * 200_001);
        for (let i = 0; i < 200_001; i++) nulls[i * 2] = 0x05;
        const flood = concat([0x30], lengthOctets(nulls.length), nulls);
        expect(outcome('flood', flood, () => decodeAsn1(flood))).toBe('PKI_LIMIT_EXCEEDED');
    });
});
