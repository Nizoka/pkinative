import { describe, it, expect } from 'vitest';
import { padMessage, writeBitLength } from '../../src/hash/hash-shared.js';

describe('padMessage', () => {
    it.each([
        [0, 64, 8, 64],
        [55, 64, 8, 64],
        [56, 64, 8, 128],
        [63, 64, 8, 128],
        [64, 64, 8, 128],
        [111, 128, 16, 128],
        [112, 128, 16, 256],
        [128, 128, 16, 256],
    ] as const)('should pad %i octets into blocks of %i with a %i-octet length to %i octets', (length, block, lengthOctets, total) => {
        const input = new Uint8Array(length).fill(0x61);
        const padded = padMessage(input, block, lengthOctets);
        expect(padded.length).toBe(total);
        expect([...padded.subarray(0, length)]).toEqual([...input]);
        expect(padded[length]).toBe(0x80);
        expect(padded.subarray(length + 1, total - 8).every((b) => b === 0)).toBe(true);
        const view = new DataView(padded.buffer);
        expect(view.getUint32(total - 8) * 2 ** 32 + view.getUint32(total - 4)).toBe(length * 8);
    });
});

describe('writeBitLength', () => {
    const lastEight = (byteLength: number): number[] => {
        const target = new Uint8Array(16);
        writeBitLength(target, 16, byteLength);
        return [...target.subarray(8)];
    };

    it('should write small lengths in the low word', () => {
        expect(lastEight(3)).toEqual([0, 0, 0, 0, 0, 0, 0, 0x18]);
    });

    it('should write the high word from 2^29 octets on — the SHA-256 bug pdfnative carried', () => {
        expect(lastEight(2 ** 29 - 1)).toEqual([0, 0, 0, 0, 0xff, 0xff, 0xff, 0xf8]);
        expect(lastEight(2 ** 29)).toEqual([0, 0, 0, 1, 0, 0, 0, 0]);
        expect(lastEight(2 ** 29 + 1)).toEqual([0, 0, 0, 1, 0, 0, 0, 0x08]);
        expect(lastEight(2 ** 32)).toEqual([0, 0, 0, 8, 0, 0, 0, 0]);
        expect(lastEight(Number.MAX_SAFE_INTEGER)).toEqual([0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8]);
    });

    it('should write into a view that does not start at offset 0 of its buffer', () => {
        const buffer = new Uint8Array(24);
        writeBitLength(buffer.subarray(8), 16, 1);
        expect([...buffer.subarray(16)]).toEqual([0, 0, 0, 0, 0, 0, 0, 8]);
        expect(buffer.subarray(0, 16).every((b) => b === 0)).toBe(true);
    });
});
