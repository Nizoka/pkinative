import { describe, expect, it } from 'vitest';
import { ecdsaDerToRaw, ecdsaRawToDer } from '../../src/crypto/crypto-signature.js';
import { concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * The DER ↔ P1363 converter, which is the one piece of signature handling
 * pkinative implements itself rather than handing to Web Crypto.
 *
 * Every refusal below is a real Wycheproof class: a converter that accepts
 * any of them lets one signature be presented in several encodings, which
 * is how a strict verifier and a lenient one come to disagree about the
 * same bytes (CWE-436).
 */

const bytes = (hex: string): Uint8Array => Uint8Array.from((hex.match(/../g) ?? []).map((h) => parseInt(h, 16)));
const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * `SEQUENCE { INTEGER r, INTEGER s }` from two content hexes, with the
 * minimal length form — a P-521 pair is 138 content bytes and needs the
 * one-octet long form, which is exactly the case a short-form-only helper
 * would have quietly stopped testing.
 */
function sig(r: string, s: string): Uint8Array {
    const body = `02${(r.length / 2).toString(16).padStart(2, '0')}${r}02${(s.length / 2).toString(16).padStart(2, '0')}${s}`;
    const length = body.length / 2;
    const header = length < 0x80 ? length.toString(16).padStart(2, '0') : `81${length.toString(16).padStart(2, '0')}`;
    return bytes(`30${header}${body}`);
}

const r32 = '7b'.repeat(32);
const s32 = '4c'.repeat(32);

describe('ecdsaDerToRaw', () => {
    it('should place r and s at the coordinate size, left-padded with zeroes', () => {
        const raw = ecdsaDerToRaw(sig(r32, s32), 32);
        expect(raw).not.toBeNull();
        expect(hex(raw ?? new Uint8Array())).toBe(r32 + s32);
    });

    it('should left-pad a short value rather than shifting the other half', () => {
        // r is one octet; s is full width. Getting this wrong produces a
        // signature that verifies against nothing, silently.
        const raw = ecdsaDerToRaw(sig('09', s32), 32);
        expect(hex(raw ?? new Uint8Array())).toBe(`${'00'.repeat(31)}09${s32}`);
    });

    it('should strip the padding zero DER adds to clear a high bit', () => {
        const raw = ecdsaDerToRaw(sig(`00${'ff'.repeat(32)}`, s32), 32);
        expect(hex(raw ?? new Uint8Array())).toBe(`${'ff'.repeat(32)}${s32}`);
    });

    it.each([
        ['P-256', 32],
        ['P-384', 48],
        ['P-521', 66],
    ])('should size the output for %s', (_curve, size) => {
        const value = 'a1'.repeat(size);
        const raw = ecdsaDerToRaw(sig(`00${value}`, `00${value}`), size);
        expect(raw?.length).toBe(size * 2);
    });

    it('should accept the one-octet long form a P-521 signature needs', () => {
        const value = '7f'.repeat(66);
        const body = `0242${value}0242${value}`;
        const raw = ecdsaDerToRaw(bytes(`3081${(body.length / 2).toString(16)}${body}`), 66);
        expect(hex(raw ?? new Uint8Array())).toBe(value + value);
    });

    it.each([
        ['an input too short to be a signature at all', '30060201010201'],
        ['a value that is not a SEQUENCE', '31060201010201 01'.replace(' ', '')],
        ['a non-minimal one-octet long form', '308106020101020101'],
        ['a two-octet length, which no curve reaches', '30820006020101020101'],
        ['a length shorter than the content', '30050201010201 01'.replace(' ', '')],
    ])('should refuse %s', (_what, encoded) => {
        expect(ecdsaDerToRaw(bytes(encoded), 32)).toBeNull();
    });

    it('should refuse trailing bytes after the SEQUENCE', () => {
        const valid = sig(r32, s32);
        const withTrailer = new Uint8Array(valid.length + 1);
        withTrailer.set(valid);
        expect(ecdsaDerToRaw(withTrailer, 32)).toBeNull();
    });

    /**
     * A SEQUENCE whose outer length is always right for its body, so the
     * only defect under test is the one in the body. Without this, a
     * malformed fixture fails at the outer length check and the inner
     * branch it was written for is never reached.
     */
    const wrap = (body: string): Uint8Array => bytes(`30${(body.length / 2).toString(16).padStart(2, '0')}${body}`);

    it.each([
        ['r is an OCTET STRING, not an INTEGER', '0404010203040201ff'],
        ['r has a zero length', '02000201ff020101'],
        ['r declares a long-form length', '02810401020304020101'],
        ['r runs past the end of the SEQUENCE', '02200102030402010f'],
        ['s is missing entirely — r fills the SEQUENCE', '020401020304'],
        ['s has only a tag octet left', '02040102030402'],
    ])('should refuse a pair where %s', (_what, body) => {
        expect(ecdsaDerToRaw(wrap(body), 32)).toBeNull();
    });

    it('should refuse a negative r — a different signature wearing the same bytes', () => {
        expect(ecdsaDerToRaw(sig(`ff${'11'.repeat(31)}`, s32), 32)).toBeNull();
    });

    it('should refuse a non-minimal leading zero, where the next octet needs none', () => {
        expect(ecdsaDerToRaw(sig(`00${'11'.repeat(31)}`, s32), 32)).toBeNull();
    });

    it('should refuse a value wider than the curve', () => {
        expect(ecdsaDerToRaw(sig('7b'.repeat(33), s32), 32)).toBeNull();
    });

    it('should refuse a malformed s after a well-formed r', () => {
        expect(ecdsaDerToRaw(wrap(`0220${r32}02ff01`), 32)).toBeNull();
    });

    it('should refuse a third value hiding after a well-formed pair', () => {
        // r and s are both legal and the outer length is right, but a NULL
        // follows them inside the SEQUENCE. An Ecdsa-Sig-Value has two
        // fields, and a converter that stops after the second would let
        // that third one ride along unexamined.
        expect(ecdsaDerToRaw(wrap('020101020101 0500'.replace(' ', '')), 32)).toBeNull();
    });
});

/**
 * The boundaries of the grammar, each built with the engine-independent TLV
 * builder: the input-length floor, the 127 / 128 seam between the short and
 * the one-octet long length form (outer and inner), a BER indefinite length,
 * a zero-length or overrunning INTEGER, and the two-octet non-minimal
 * INTEGER. Each asserts the converted bytes or the `null`.
 */
describe('ecdsaDerToRaw — encoding boundaries', () => {
    /** `n` value octets, the first 0x01 so the INTEGER is minimal and positive, the rest `fill`. */
    const value = (n: number, fill: number): number[] => [0x01, ...new Array<number>(n - 1).fill(fill)];
    const integer = (n: number, fill: number): Uint8Array => universal(2, value(n, fill));
    /** The raw half: `n` value octets right-aligned in `size`. */
    const half = (n: number, fill: number, size: number): string => '00'.repeat(size - n) + hex(Uint8Array.from(value(n, fill)));

    it.each([
        ['an empty input', ''],
        ['a lone SEQUENCE identifier', '30'],
        ['a SEQUENCE identifier and a long-form marker with no length octet', '3081'],
    ])('should return null for %s, before reading past its end', (_what, encoded) => {
        expect(ecdsaDerToRaw(bytes(encoded), 32)).toBeNull();
    });

    it('should accept the largest short-form SEQUENCE, 127 content octets', () => {
        const der = sequence(integer(62, 0x11), integer(61, 0x22));
        expect(hex(der.subarray(0, 2))).toBe('307f');
        expect(hex(ecdsaDerToRaw(der, 66) ?? new Uint8Array())).toBe(half(62, 0x11, 66) + half(61, 0x22, 66));
    });

    it('should accept the smallest one-octet long form, 128 content octets', () => {
        const der = sequence(integer(62, 0x11), integer(62, 0x22));
        expect(hex(der.subarray(0, 3))).toBe('308180');
        expect(hex(ecdsaDerToRaw(der, 66) ?? new Uint8Array())).toBe(half(62, 0x11, 66) + half(62, 0x22, 66));
    });

    it('should refuse the one-octet long form for 127 content octets, which fit the short form (CWE-436)', () => {
        const der = tlv(0, true, 16, concat(integer(62, 0x11), integer(61, 0x22)), { lengthOctets: 1 });
        expect(hex(der.subarray(0, 3))).toBe('30817f');
        expect(ecdsaDerToRaw(der, 66)).toBeNull();
    });

    it('should refuse a BER indefinite-length SEQUENCE, whose 0x80 is not a length of 128', () => {
        // 30 80 | r (64 octets) | 02 3e + 60 octets | 00 00: read as a short
        // length, 0x80 would cover exactly the content plus the end-of-contents
        // marker, which would then be swallowed as the last two octets of s.
        const body = concat(integer(62, 0x11), [0x02, 0x3e], value(60, 0x22));
        const der = tlv(0, true, 16, body, { indefinite: true });
        expect(der.length).toBe(130);
        expect(ecdsaDerToRaw(der, 66)).toBeNull();
    });

    it('should refuse a zero-length r rather than reading s as its value', () => {
        expect(ecdsaDerToRaw(sequence(universal(2, []), universal(2, [0x01, 0x01])), 32)).toBeNull();
    });

    it('should refuse a zero-length s at the very end of the SEQUENCE', () => {
        expect(ecdsaDerToRaw(sequence(universal(2, [0x01, 0x01]), universal(2, [])), 32)).toBeNull();
    });

    it('should refuse an s whose header is the last two octets and whose length runs past them', () => {
        expect(ecdsaDerToRaw(sequence(universal(2, [0x01, 0x01]), [0x02, 0x05]), 32)).toBeNull();
    });

    it('should refuse a two-octet INTEGER with a needless leading zero (X.690 §8.3.2)', () => {
        expect(ecdsaDerToRaw(sequence(universal(2, [0x00, 0x01]), universal(2, [0x01])), 32)).toBeNull();
    });

    it('should accept an INTEGER of 127 octets, the largest short-form length, when the size admits it', () => {
        const der = sequence(integer(127, 0x11), integer(1, 0x00));
        expect(hex(der.subarray(0, 3))).toBe('308184');
        expect(hex(ecdsaDerToRaw(der, 127) ?? new Uint8Array())).toBe(half(127, 0x11, 127) + half(1, 0x00, 127));
    });

    it('should refuse an INTEGER length octet of 0x80 even when 128 octets follow and the size admits them', () => {
        const der = sequence(concat([0x02, 0x80], value(128, 0x11)), integer(1, 0x00));
        expect(ecdsaDerToRaw(der, 128)).toBeNull();
    });
});

describe('ecdsaRawToDer', () => {
    it('should produce an encoding ecdsaDerToRaw reads back unchanged', () => {
        for (const size of [32, 48, 66]) {
            for (const fill of [0x01, 0x7f, 0x80, 0xff]) {
                const raw = new Uint8Array(size * 2).fill(fill);
                const der = ecdsaRawToDer(raw, size);
                expect(hex(ecdsaDerToRaw(der, size) ?? new Uint8Array()), `size ${String(size)} fill ${String(fill)}`).toBe(hex(raw));
            }
        }
    });

    it('should pad a high-bit value so it is never read as negative', () => {
        // 0x80… would be a negative INTEGER, and a negative r is a different
        // signature wearing the same bytes; DER prepends one zero octet.
        const raw = new Uint8Array(64);
        raw[0] = 0x80;
        raw[32] = 0x01;
        const der = ecdsaRawToDer(raw, 32);
        // r: INTEGER, 33 content octets, the first of them the pad.
        expect([der[2], der[3], der[4], der[5]]).toEqual([0x02, 0x21, 0x00, 0x80]);
        // s needs no pad: 32 octets beginning with 0x01.
        expect([der[37], der[38], der[39]]).toEqual([0x02, 0x20, 0x01]);
        expect(hex(ecdsaDerToRaw(der, 32) ?? new Uint8Array())).toBe(hex(raw));
    });

    it('should strip leading zeroes, as DER minimality requires', () => {
        const raw = new Uint8Array(64);
        raw[31] = 0x09;
        raw[63] = 0x0a;
        // r and s are each one octet once the padding is gone.
        expect(hex(ecdsaRawToDer(raw, 32))).toBe('300602010902010a');
    });

    it('should keep one octet when the whole coordinate is zero', () => {
        expect(hex(ecdsaRawToDer(new Uint8Array(64), 32))).toBe('3006020100020100');
    });

    it('should use the one-octet long form when P-521 needs it', () => {
        const raw = new Uint8Array(132).fill(0x7f);
        const der = ecdsaRawToDer(raw, 66);
        expect(der[0]).toBe(0x30);
        expect(der[1]).toBe(0x81);
        expect(ecdsaDerToRaw(der, 66)).not.toBeNull();
    });

    it.each([
        ['127 octets, the largest short form', 61, '307f'],
        ['128 octets, the smallest one-octet long form', 62, '308180'],
    ])('should encode a body of %s with the minimal SEQUENCE length', (_what, sLength, header) => {
        // r: four leading zeroes stripped, 62 octets left; s: 66 − sLength stripped.
        const r = [0x01, ...new Array<number>(61).fill(0x11)];
        const s = [0x01, ...new Array<number>(sLength - 1).fill(0x22)];
        const raw = new Uint8Array(132);
        raw.set(r, 66 - r.length);
        raw.set(s, 132 - s.length);
        const der = ecdsaRawToDer(raw, 66);
        expect(hex(der.subarray(0, header.length / 2))).toBe(header);
        expect(hex(der)).toBe(hex(sequence(universal(2, r), universal(2, s))));
    });

    it('should refuse a signature whose length does not match the curve', () => {
        // A P-256 key with a P-384 curve named: the two disagree, and a
        // silently truncated signature would verify nowhere.
        expect(() => ecdsaRawToDer(new Uint8Array(64), 48))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('disagree') }));
    });
});
