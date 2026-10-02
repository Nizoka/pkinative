import { describe, it, expect } from 'vitest';
import { runInNewContext } from 'node:vm';
import { assertBytes, bytesEqual, concatBytes, isBytes, toHex } from '../../src/core/bytes.js';
import { PkiError } from '../../src/types/pki-errors.js';

describe('isBytes', () => {
    it('should accept a Uint8Array from this realm, a Buffer, and a Uint8Array another realm created', () => {
        expect(isBytes(Uint8Array.of(1))).toBe(true);
        expect(isBytes(Buffer.from([1]))).toBe(true);
        // `instanceof Uint8Array` is false for this one: the vm context has its
        // own constructor. The bytes are bytes all the same.
        const foreign = runInNewContext('new Uint8Array([1, 2, 3])') as unknown;
        expect(foreign instanceof Uint8Array).toBe(false);
        expect(isBytes(foreign)).toBe(true);
    });

    it('should refuse every other view, buffer or array', () => {
        for (const value of [new Uint16Array(1), new Int8Array(1), new DataView(new ArrayBuffer(1)), new ArrayBuffer(1), [1], 'AQ==', null, undefined, 1]) {
            expect(isBytes(value)).toBe(false);
        }
    });
});

describe('assertBytes', () => {
    it('should return a Uint8Array and a Node Buffer unchanged', () => {
        const bytes = new Uint8Array([1, 2]);
        expect(assertBytes(bytes, 'der')).toBe(bytes);
        const buffer = Buffer.from([3]);
        expect(assertBytes(buffer, 'der')).toBe(buffer);
    });

    it.each([
        ['an ArrayBuffer', new ArrayBuffer(4), 'object'],
        ['a Uint16Array', new Uint16Array(2), 'object'],
        ['a number array', [1, 2], 'object'],
        ['a string', '3082', 'string'],
        ['null', null, 'null'],
        ['undefined', undefined, 'undefined'],
    ])('should refuse %s with PKI_INVALID_INPUT', (_label, input, kind) => {
        let caught: unknown;
        try {
            assertBytes(input, 'der');
        } catch (err) {
            caught = err;
        }
        expect(caught).toBeInstanceOf(PkiError);
        expect(caught).toMatchObject({ code: 'PKI_INVALID_INPUT' });
        expect((caught as Error).message).toBe(`pkinative: der must be a Uint8Array, got ${kind} — decode PEM text with decodePem() first`);
    });
});

describe('toHex', () => {
    it('should render lowercase hex with an optional separator', () => {
        const bytes = new Uint8Array([0x00, 0x0f, 0xa5, 0xff]);
        expect(toHex(bytes)).toBe('000fa5ff');
        expect(toHex(bytes, ':')).toBe('00:0f:a5:ff');
        expect(toHex(new Uint8Array(0))).toBe('');
    });
});

describe('bytesEqual', () => {
    it('should compare length and every octet', () => {
        expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
        expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
        expect(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
        expect(bytesEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    });
});

describe('concatBytes', () => {
    it('should copy every part in order into one new array', () => {
        const a = new Uint8Array([1, 2]);
        const out = concatBytes([a, new Uint8Array(0), new Uint8Array([3])]);
        expect([...out]).toEqual([1, 2, 3]);
        out[0] = 9;
        expect(a[0]).toBe(1);
        expect(concatBytes([]).length).toBe(0);
    });
});
