import { describe, it, expect } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import {
    readBitString,
    readBoolean,
    readInteger,
    readNull,
    readOctetString,
    readSmallInteger,
    readString,
} from '../../src/asn1/asn1-read.js';
import type { Asn1Node } from '../../src/types/asn1-types.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic, PkiParseOptions } from '../../src/types/pki-types.js';
import { ascii, hex, tlv } from '../helpers/raw-der-builder.js';

const BER: PkiParseOptions = { encodingRules: 'ber', onDiagnostic: () => undefined };

const node = (text: string, options?: PkiParseOptions): Asn1Node => decodeAsn1(hex(text), options);

function codeOf(fn: () => unknown): string {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiError) return err.code;
        throw err;
    }
    return 'no error';
}

describe('reader arguments', () => {
    it.each([null, undefined, 5, {}, { content: new Uint8Array(0) },
        { content: 'x', children: [], tagNumber: 1 }, { content: new Uint8Array(0), children: null, tagNumber: 1 }, { content: new Uint8Array(0), children: [], tagNumber: '1' }])('should refuse %j as a node', (value) => {
        expect(codeOf(() => readBoolean(value as unknown as Asn1Node))).toBe('PKI_INVALID_INPUT');
    });
});

describe('readBoolean', () => {
    it('should read canonical TRUE and FALSE, and an implicitly tagged BOOLEAN', () => {
        expect(readBoolean(node('01 01 FF'))).toBe(true);
        expect(readBoolean(node('01 01 00'))).toBe(false);
        expect(readBoolean(node('80 01 FF'))).toBe(true);
    });

    it('should refuse a non-canonical TRUE under DER and accept it under BER with a diagnostic', () => {
        expect(codeOf(() => readBoolean(node('01 01 01')))).toBe('PKI_ASN1_BOOLEAN_INVALID');
        const seen: PkiDiagnostic[] = [];
        expect(readBoolean(node('01 01 01'), { encodingRules: 'ber', onDiagnostic: (d) => seen.push(d) })).toBe(true);
        expect(seen[0]?.message).toContain('non-canonical BOOLEAN');
    });

    it.each([
        ['two content octets', '01 02 FF FF', 'PKI_ASN1_BOOLEAN_INVALID'],
        ['no content octet', '01 00', 'PKI_ASN1_BOOLEAN_INVALID'],
        ['another universal type', '02 01 01', 'PKI_ASN1_UNEXPECTED_TAG'],
        ['a constructed implicit tag', 'A0 00', 'PKI_ASN1_CONSTRUCTED_FORM_INVALID'],
    ])('should refuse %s', (_label, text, code) => {
        expect(codeOf(() => readBoolean(node(text)))).toBe(code);
    });
});

describe('readInteger', () => {
    it.each([
        ['02 01 00', 0n],
        ['02 01 7F', 127n],
        ['02 02 00 80', 128n],
        ['02 02 00 FF', 255n],
        ['02 02 01 00', 256n],
        ['02 01 FF', -1n],
        ['02 01 80', -128n],
        ['02 02 FF 7F', -129n],
        ['02 02 80 00', -32768n],
        ['02 09 01 00 00 00 00 00 00 00 00', 18446744073709551616n],
        ['81 01 05', 5n],
    ])('should read %s as %s', (text, value) => {
        expect(readInteger(node(text))).toBe(value);
    });

    it.each([
        ['an empty INTEGER', '02 00', 'PKI_ASN1_INTEGER_INVALID'],
        ['a redundant leading zero', '02 02 00 7F', 'PKI_ASN1_INTEGER_INVALID'],
        ['a redundant leading 0xFF', '02 02 FF 80', 'PKI_ASN1_INTEGER_INVALID'],
        ['an OCTET STRING', '04 01 00', 'PKI_ASN1_UNEXPECTED_TAG'],
        ['a constructed implicit tag', 'A1 00', 'PKI_ASN1_CONSTRUCTED_FORM_INVALID'],
    ])('should refuse %s', (_label, text, code) => {
        expect(codeOf(() => readInteger(node(text)))).toBe(code);
    });

    it('should enforce maxIntegerBytes', () => {
        expect(codeOf(() => readInteger(node('02 03 01 00 00'), { limits: { maxIntegerBytes: 2 } }))).toBe('PKI_LIMIT_EXCEEDED');
    });
});

describe('readSmallInteger', () => {
    it('should read values within ±(2^53 − 1) and refuse the rest', () => {
        expect(readSmallInteger(node('02 07 1F FF FF FF FF FF FF'))).toBe(Number.MAX_SAFE_INTEGER);
        expect(readSmallInteger(node('02 07 E0 00 00 00 00 00 01'))).toBe(-Number.MAX_SAFE_INTEGER);
        expect(codeOf(() => readSmallInteger(node('02 07 20 00 00 00 00 00 00')))).toBe('PKI_ASN1_INTEGER_UNREPRESENTABLE');
        expect(codeOf(() => readSmallInteger(node('02 07 E0 00 00 00 00 00 00')))).toBe('PKI_ASN1_INTEGER_UNREPRESENTABLE');
    });
});

describe('readNull', () => {
    it('should read NULL and refuse content, another type and a constructed implicit tag', () => {
        expect(readNull(node('05 00'))).toBeNull();
        expect(codeOf(() => readNull(node('05 01 00')))).toBe('PKI_ASN1_NULL_INVALID');
        expect(codeOf(() => readNull(node('02 01 00')))).toBe('PKI_ASN1_UNEXPECTED_TAG');
        expect(codeOf(() => readNull(node('A5 00')))).toBe('PKI_ASN1_CONSTRUCTED_FORM_INVALID');
    });
});

describe('readBitString', () => {
    it('should read the octets as a zero-copy view and the unused-bits count', () => {
        const n = node('03 02 07 80');
        const bits = readBitString(n);
        expect([...bits.bytes]).toEqual([0x80]);
        expect(bits.unusedBits).toBe(7);
        expect(bits.bytes.buffer).toBe(n.bytes.buffer);
        expect(readBitString(node('03 01 00'))).toMatchObject({ unusedBits: 0 });
        expect(readBitString(node('03 01 00')).bytes.length).toBe(0);
    });

    it.each([
        ['no initial octet', '03 00'],
        ['eight unused bits', '03 02 08 00'],
        ['unused bits on an empty string', '03 01 03'],
        ['non-zero padding bits under DER', '03 02 01 01'],
    ])('should refuse %s', (_label, text) => {
        expect(codeOf(() => readBitString(node(text)))).toBe('PKI_ASN1_BIT_STRING_INVALID');
    });

    it('should refuse unused bits on an empty string under BER too, where padding alone would only be reported', () => {
        expect(() => readBitString(node('03 01 03'), { encodingRules: 'ber', onDiagnostic: () => undefined }))
            .toThrow(expect.objectContaining({ code: 'PKI_ASN1_BIT_STRING_INVALID', message: expect.stringContaining('empty BIT STRING') }));
    });

    it('should accept non-zero padding bits under BER with a diagnostic', () => {
        const seen: PkiDiagnostic[] = [];
        expect(readBitString(node('03 02 01 01'), { encodingRules: 'ber', onDiagnostic: (d) => seen.push(d) }).unusedBits).toBe(1);
        expect(seen[0]?.message).toContain('BIT STRING padding');
    });

    it('should join BER segments, nested ones included, and take the unused bits of the last', () => {
        const bits = readBitString(node('23 08 03 02 00 AA 03 02 04 B0', BER), BER);
        expect([...bits.bytes]).toEqual([0xaa, 0xb0]);
        expect(bits.unusedBits).toBe(4);
        expect([...readBitString(node('23 06 23 04 03 02 00 AA', BER), BER).bytes]).toEqual([0xaa]);
        expect(readBitString(node('23 00', BER), BER)).toMatchObject({ unusedBits: 0 });
    });

    it.each([
        ['a constructed implicit tag under DER', 'A1 04 03 02 00 AA', undefined, 'PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN'],
        ['a segment of another type', '23 04 04 02 00 AA', BER, 'PKI_ASN1_UNEXPECTED_TAG'],
        ['unused bits before the last segment', '23 08 03 02 04 A0 03 02 00 B0', BER, 'PKI_ASN1_BIT_STRING_INVALID'],
        ['another universal type', '04 01 00', undefined, 'PKI_ASN1_UNEXPECTED_TAG'],
    ])('should refuse %s', (_label, text, options, code) => {
        expect(codeOf(() => readBitString(node(text, options), options))).toBe(code);
    });

    it('should enforce maxBerSegments', () => {
        expect(codeOf(() => readBitString(node('23 08 03 02 00 AA 03 02 00 BB', BER), { ...BER, limits: { maxBerSegments: 1 } }))).toBe('PKI_LIMIT_EXCEEDED');
    });
});

describe('readOctetString', () => {
    it('should return a zero-copy view of a primitive OCTET STRING', () => {
        const n = node('04 02 41 42');
        const bytes = readOctetString(n);
        expect([...bytes]).toEqual([0x41, 0x42]);
        expect(bytes.buffer).toBe(n.bytes.buffer);
    });

    it('should join nested BER segments', () => {
        expect([...readOctetString(node('24 80 04 01 41 24 03 04 01 42 00 00', BER), BER)]).toEqual([0x41, 0x42]);
    });

    it('should refuse a constructed implicit tag under DER, a segment of another type and the segment limit', () => {
        expect(codeOf(() => readOctetString(node('A0 03 04 01 41')))).toBe('PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN');
        expect(codeOf(() => readOctetString(node('24 03 02 01 00', BER), BER))).toBe('PKI_ASN1_UNEXPECTED_TAG');
        expect(codeOf(() => readOctetString(node('24 06 04 01 41 04 01 42', BER), { ...BER, limits: { maxBerSegments: 1 } }))).toBe('PKI_LIMIT_EXCEEDED');
    });
});

describe('readString', () => {
    const str = (tag: number, content: ArrayLike<number>, options?: Parameters<typeof readString>[1]): ReturnType<typeof readString> => readString(decodeAsn1(tlv(0, false, tag, content)), options);

    it.each([
        ['utf8', 12, [0xc3, 0xa9], 'é'],
        ['numeric', 18, ascii('1 2'), '1 2'],
        ['printable', 19, ascii("AZ az 09 '()+,-./:=?"), "AZ az 09 '()+,-./:=?"],
        ['ia5', 22, [0x00, 0x7f, 0x40], ' @'],
        ['visible', 26, ascii('a~ '), 'a~ '],
        ['universal', 28, [0, 1, 0xf6, 0x00], '😀'],
        ['bmp', 30, [0x00, 0xe9, 0x20, 0xac], 'é€'],
    ])('should decode a %s string', (type, tag, content, value) => {
        const result = str(tag, content);
        expect(result.stringType).toBe(type);
        expect(result.value).toBe(value);
        expect([...result.raw]).toEqual([...content]);
        expect(Object.isFrozen(result)).toBe(true);
    });

    it('should decode a TeletexString as ISO 8859-1 and say so in a diagnostic', () => {
        const seen: PkiDiagnostic[] = [];
        expect(str(20, [0x4d, 0xfc], { onDiagnostic: (d) => seen.push(d) }).value).toBe('Mü');
        expect(seen).toEqual([expect.objectContaining({ code: 'PKI_DIAG_TELETEX_AS_LATIN1' })]);
    });

    it('should decode ASCII outside the PrintableString alphabet with a diagnostic naming the character', () => {
        const seen: PkiDiagnostic[] = [];
        expect(str(19, ascii('*.example.com'), { onDiagnostic: (d) => seen.push(d) }).value).toBe('*.example.com');
        expect(seen).toEqual([expect.objectContaining({ code: 'PKI_DIAG_PRINTABLE_STRING_CHARSET' })]);
        expect(seen[0]?.message).toContain('"*"');
    });

    it('should diagnose an octet outside the alphabet in the first position, NUL included', () => {
        const seen: PkiDiagnostic[] = [];
        str(19, [0x00, 0x61], { onDiagnostic: (d) => seen.push(d) });
        expect(seen).toEqual([expect.objectContaining({ code: 'PKI_DIAG_PRINTABLE_STRING_CHARSET' })]);
    });

    it.each([
        ['invalid UTF-8', 12, [0xff]],
        ['a non-ASCII PrintableString', 19, [0xe9]],
        ['a non-ASCII IA5String', 22, [0x80]],
        ['a control character in a VisibleString', 26, [0x1f]],
        ['a letter in a NumericString', 18, ascii('A')],
        ['an odd-length BMPString', 30, [0x00]],
        ['an out-of-range UniversalString', 28, [0, 0x11, 0, 0]],
    ])('should refuse %s', (_label, tag, content) => {
        expect(codeOf(() => str(tag, content))).toBe('PKI_ASN1_STRING_INVALID');
    });

    it('should refuse a universal type that is not a string', () => {
        expect(codeOf(() => readString(node('02 01 00')))).toBe('PKI_ASN1_UNEXPECTED_TAG');
    });

    it('should read an implicit tag only with stringType, and refuse an unknown stringType', () => {
        expect(codeOf(() => readString(node('82 03 61 62 63')))).toBe('PKI_API_MISUSE');
        expect(readString(node('82 03 61 62 63'), { stringType: 'ia5' }).value).toBe('abc');
        expect(codeOf(() => readString(node('82 03 61 62 63'), { stringType: 'ebcdic' as unknown as 'ia5' }))).toBe('PKI_INVALID_OPTION');
    });

    // P-11 (CWE-1321): an inherited key of a plain object is not a string type.
    it.each(['toString', 'constructor', '__proto__', 'hasOwnProperty'])('should refuse the inherited key %s as a stringType', (key) => {
        expect(codeOf(() => readString(node('82 03 61 62 63'), { stringType: key as unknown as 'ia5' }))).toBe('PKI_INVALID_OPTION');
    });

    it('should join a BER constructed string', () => {
        expect(readString(node('2C 06 04 01 C3 04 01 A9', BER), BER).value).toBe('é');
    });
});
