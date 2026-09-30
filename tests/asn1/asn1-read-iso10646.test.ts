import { describe, expect, it } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { readString } from '../../src/asn1/asn1-read.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';

/**
 * What X.690 §8.23 forbids in the three ISO/IEC 10646 string types and a
 * decoder can still read: a byte-order signature leading a BMPString or a
 * UniversalString (§8.23.7, §8.23.8: "Signatures shall not be used"), and an
 * ISO/IEC 2022 code-extension control in any of the three (§8.23.9 b)–c),
 * §8.23.10: "Announcers and escape sequences shall not be used"). Each is
 * decoded and reported — never accepted silently, never refused unless the
 * caller asks for strict.
 */

const tlv = (tag: number, ...content: number[]): Uint8Array => Uint8Array.of(tag, content.length, ...content);
const UTF8 = 0x0c;
const BMP = 0x1e;
const UNIVERSAL = 0x1c;

function read(bytes: Uint8Array): { readonly value: string; readonly diagnostics: PkiDiagnostic[] } {
    const diagnostics: PkiDiagnostic[] = [];
    const value = readString(decodeAsn1(bytes), { onDiagnostic: (d) => { diagnostics.push(d); } }).value;
    return { value, diagnostics };
}

describe('readString — X.690 §8.23 in the ISO/IEC 10646 types', () => {
    it.each<[string, Uint8Array, string, string]>([
        ['a BMPString', tlv(BMP, 0xfe, 0xff, 0x00, 0x41), '\ufeffA', 'ITU-T X.690 §8.23.7, §8.23.8'],
        ['a UniversalString', tlv(UNIVERSAL, 0x00, 0x00, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x41), '\ufeffA', 'ITU-T X.690 §8.23.7, §8.23.8'],
    ])('should report the byte-order signature leading %s, and keep it in the value', (_what, bytes, value, standard) => {
        const read1 = read(bytes);
        expect(read1.value).toBe(value);
        expect(read1.diagnostics).toEqual([expect.objectContaining({ code: 'PKI_DIAG_STRING_SIGNATURE', standard })]);
    });

    it('should not take a U+FEFF after the first character for a signature', () => {
        expect(read(tlv(BMP, 0x00, 0x41, 0xfe, 0xff)).diagnostics).toEqual([]);
    });

    it('should not report a UTF8String that starts with U+FEFF as a signature — §8.23.10 names none', () => {
        expect(read(tlv(UTF8, 0xef, 0xbb, 0xbf, 0x41)).diagnostics).toEqual([]);
    });

    it.each<[string, Uint8Array, string, string]>([
        ['ESC ( B in a UTF8String', tlv(UTF8, 0x1b, 0x28, 0x42), 'ESC', 'ITU-T X.690 §8.23.9, §8.23.10'],
        ['ESC ( B in a BMPString', tlv(BMP, 0x00, 0x1b, 0x00, 0x28, 0x00, 0x42), 'ESC', 'ITU-T X.690 §8.23.9, §8.23.10'],
        ['SO in a UniversalString', tlv(UNIVERSAL, 0x00, 0x00, 0x00, 0x0e), 'SO', 'ITU-T X.690 §8.23.9, §8.23.10'],
        ['SI in a UTF8String', tlv(UTF8, 0x41, 0x0f), 'SI', 'ITU-T X.690 §8.23.9, §8.23.10'],
        ['SS2 in a UTF8String', tlv(UTF8, 0xc2, 0x8e), 'SS2', 'ITU-T X.690 §8.23.9, §8.23.10'],
        ['SS3 in a BMPString', tlv(BMP, 0x00, 0x8f), 'SS3', 'ITU-T X.690 §8.23.9, §8.23.10'],
    ])('should report %s once, and decode it as ISO/IEC 10646', (_what, bytes, control, standard) => {
        const result = read(bytes);
        expect(result.diagnostics).toEqual([expect.objectContaining({ code: 'PKI_DIAG_STRING_ESCAPE_SEQUENCE', standard, message: expect.stringContaining(control) })]);
    });

    it('should report one escape diagnostic per string, however many controls it holds', () => {
        expect(read(tlv(UTF8, 0x1b, 0x28, 0x42, 0x1b, 0x24, 0x42)).diagnostics).toHaveLength(1);
    });

    it('should report both concerns of a signed BMPString that also escapes', () => {
        expect(read(tlv(BMP, 0xfe, 0xff, 0x00, 0x1b)).diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_STRING_SIGNATURE', 'PKI_DIAG_STRING_ESCAPE_SEQUENCE']);
    });

    it('should leave the control functions X.690 permits alone — LF, CR, TAB', () => {
        expect(read(tlv(UTF8, 0x41, 0x0a, 0x0d, 0x09)).diagnostics).toEqual([]);
        expect(read(tlv(BMP, 0x00, 0x0a)).diagnostics).toEqual([]);
    });

    it('should refuse under strict, as every diagnostic does', () => {
        let code = '';
        try {
            readString(decodeAsn1(tlv(UTF8, 0x1b, 0x28, 0x42)), { strict: true });
        } catch (error) {
            if (error instanceof PkiError) code = error.code;
        }
        expect(code).toBe('PKI_STRICT_DIAGNOSTIC');
    });
});
