import { describe, it, expect } from 'vitest';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { encodeRelativeOid } from '../../src/asn1/asn1-encode.js';
import { decodeOid, encodeOid, isValidOid, readObjectIdentifier, readRelativeOid } from '../../src/asn1/asn1-oid.js';
import { PkiError } from '../../src/types/pki-errors.js';
import { hex } from '../helpers/raw-der-builder.js';

function codeOf(fn: () => unknown): string {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiError) return err.code;
        throw err;
    }
    return 'no error';
}

describe('encodeOid and decodeOid', () => {
    it.each([
        ['2.100.3', '81 34 03'], // X.690 §8.19.5
        ['1.2.840.113549', '2A 86 48 86 F7 0D'],
        ['1.2.840.113549.1.1.11', '2A 86 48 86 F7 0D 01 01 0B'],
        ['2.5.29.17', '55 1D 11'],
        ['0.0', '00'],
        ['1.39', '4F'],
        ['2.40', '78'],
        ['2.999', '88 37'],
    ])('should map %s to %s both ways', (oid, content) => {
        expect([...encodeOid(oid)]).toEqual([...hex(content)]);
        expect(decodeOid(hex(content))).toBe(oid);
    });

    it('should keep arcs beyond 2^53 exact, in the first subidentifier and after it', () => {
        const uuid = '2.25.329800735698586629295641978511506172918';
        expect(decodeOid(encodeOid(uuid))).toBe(uuid);
        const bigFirst = '2.18446744073709551616';
        expect(decodeOid(encodeOid(bigFirst))).toBe(bigFirst);
        const bigLater = '1.2.18446744073709551615.7';
        expect(decodeOid(encodeOid(bigLater))).toBe(bigLater);
    });

    it.each([
        ['empty content', ''],
        ['a subidentifier starting with 0x80', '80 01'],
        ['content that ends inside a subidentifier', '2A 86'],
    ])('should refuse %s', (_label, content) => {
        expect(codeOf(() => decodeOid(hex(content)))).toBe('PKI_OID_INVALID');
    });

    it('should enforce maxOidBytes and refuse a non-Uint8Array', () => {
        expect(codeOf(() => decodeOid(hex('2A 86 48'), { limits: { maxOidBytes: 2 } }))).toBe('PKI_LIMIT_EXCEEDED');
        expect(codeOf(() => decodeOid('2a' as unknown as Uint8Array))).toBe('PKI_INVALID_INPUT');
    });
});

describe('isValidOid', () => {
    it.each(['0.0', '1.39', '2.40', '2.25.123', '1.2.840.113549.1.1.11'])('should accept %s', (oid) => {
        expect(isValidOid(oid)).toBe(true);
    });

    it.each(['', '1', '3.1', '1.40', '0.01', '01.2', '1..2', '1.2.', 'a.b', ' 1.2', '1.2 '])('should refuse %j', (oid) => {
        expect(isValidOid(oid)).toBe(false);
    });

    it('should refuse a non-string', () => {
        expect(isValidOid(12 as unknown as string)).toBe(false);
    });
});

describe('encodeOid arguments', () => {
    it('should refuse an invalid dotted string, truncating a long one in the message', () => {
        expect(codeOf(() => encodeOid('1.40'))).toBe('PKI_OID_INVALID');
        let message = '';
        try {
            encodeOid(`9.${'1'.repeat(100)}`);
        } catch (err) {
            message = (err as Error).message;
        }
        expect(message).toContain('…');
        expect(codeOf(() => encodeOid(5 as unknown as string))).toBe('PKI_INVALID_INPUT');
    });
});

describe('readObjectIdentifier', () => {
    it('should read an OBJECT IDENTIFIER and an implicitly tagged one', () => {
        expect(readObjectIdentifier(decodeAsn1(hex('06 03 55 1D 11')))).toBe('2.5.29.17');
        expect(readObjectIdentifier(decodeAsn1(hex('80 01 00')))).toBe('0.0');
    });

    it('should refuse another type and a constructed implicit tag', () => {
        expect(codeOf(() => readObjectIdentifier(decodeAsn1(hex('04 01 00'))))).toBe('PKI_ASN1_UNEXPECTED_TAG');
        expect(codeOf(() => readObjectIdentifier(decodeAsn1(hex('A0 00'))))).toBe('PKI_ASN1_CONSTRUCTED_FORM_INVALID');
    });
});

describe('readRelativeOid and encodeRelativeOid', () => {
    it.each([
        ['8571.3.2', '0D 04 C2 7B 03 02'], // X.690 §8.20.2
        ['0', '0D 01 00'],
        ['127', '0D 01 7F'],
        ['128', '0D 02 81 00'],
        ['1.2.3', '0D 03 01 02 03'],
        ['16384.1', '0D 04 81 80 00 01'],
        ['18446744073709551616', '0D 0A 82 80 80 80 80 80 80 80 80 00'],
    ])('should map %s to %s both ways', (oid, encoding) => {
        expect([...encodeRelativeOid(oid)]).toEqual([...hex(encoding)]);
        expect(readRelativeOid(decodeAsn1(hex(encoding)))).toBe(oid);
    });

    it('should not pack the first two arcs the way an OBJECT IDENTIFIER does', () => {
        // Under §8.19.4 the content octet 0x2A is 1.2; under §8.20.2 it is the one arc 42.
        expect(readRelativeOid(decodeAsn1(hex('0D 01 2A')))).toBe('42');
        expect(readObjectIdentifier(decodeAsn1(hex('06 01 2A')))).toBe('1.2');
        expect(readRelativeOid(decodeAsn1(hex('0D 01 50')))).toBe('80');
        expect(readRelativeOid(decodeAsn1(hex('0D 02 01 02')))).toBe('1.2');
    });

    it('should read an implicitly tagged RELATIVE-OID and keep an arc beyond 2^53 exact', () => {
        expect(readRelativeOid(decodeAsn1(hex('80 01 2A')))).toBe('42');
        const huge = '329800735698586629295641978511506172918.7';
        expect(readRelativeOid(decodeAsn1(encodeRelativeOid(huge)))).toBe(huge);
    });

    it.each([
        ['empty content (X.690 §8.20.2)', '0D 00'],
        ['a subidentifier starting with 0x80', '0D 02 80 01'],
        ['content that ends inside a subidentifier', '0D 01 C2'],
    ])('should refuse %s with PKI_OID_INVALID, naming the type', (_label, encoding) => {
        expect(codeOf(() => readRelativeOid(decodeAsn1(hex(encoding))))).toBe('PKI_OID_INVALID');
        expect(() => readRelativeOid(decodeAsn1(hex(encoding)))).toThrow(/RELATIVE-OID/);
    });

    it('should refuse another universal type and a constructed implicit tag', () => {
        expect(codeOf(() => readRelativeOid(decodeAsn1(hex('06 03 55 1D 11'))))).toBe('PKI_ASN1_UNEXPECTED_TAG');
        expect(codeOf(() => readRelativeOid(decodeAsn1(hex('A0 00'))))).toBe('PKI_ASN1_CONSTRUCTED_FORM_INVALID');
        expect(() => readRelativeOid(decodeAsn1(hex('A0 00')))).toThrow(/the RELATIVE-OID at offset 0 is constructed/);
        expect(codeOf(() => readRelativeOid('0d' as unknown as never))).toBe('PKI_INVALID_INPUT');
    });

    it('should enforce maxOidBytes on the content', () => {
        expect(codeOf(() => readRelativeOid(decodeAsn1(hex('0D 04 C2 7B 03 02')), { limits: { maxOidBytes: 3 } }))).toBe('PKI_LIMIT_EXCEEDED');
        expect(() => readRelativeOid(decodeAsn1(hex('0D 04 C2 7B 03 02')), { limits: { maxOidBytes: 3 } })).toThrow(/the RELATIVE-OID content length/);
        expect(readRelativeOid(decodeAsn1(hex('0D 04 C2 7B 03 02')), { limits: { maxOidBytes: 4 } })).toBe('8571.3.2');
    });

    it.each(['', '.', '1.', '.1', '1..2', '01', '1.02', 'a', '1.2 ', ' 1', '-1', '1.2.3.'])('should refuse %j when encoding', (oid) => {
        expect(codeOf(() => encodeRelativeOid(oid))).toBe('PKI_OID_INVALID');
    });

    it('should refuse a non-string when encoding, and cut a long string in the message', () => {
        expect(codeOf(() => encodeRelativeOid(7 as unknown as string))).toBe('PKI_INVALID_INPUT');
        expect(() => encodeRelativeOid(`.${'1'.repeat(100)}`)).toThrow(/…/);
        expect(() => encodeRelativeOid('1.x')).toThrow(/"1.x" is not a dotted-decimal RELATIVE-OID/);
    });
});
