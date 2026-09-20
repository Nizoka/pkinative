import { describe, expect, it } from 'vitest';
import { ecdsaDerToRaw } from '../../src/crypto/crypto-signature.js';

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
