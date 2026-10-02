import { describe, it, expect } from 'vitest';
import {
    STRING_TAGS,
    TAG_BIT_STRING,
    TAG_BMP_STRING,
    TAG_BOOLEAN,
    TAG_ENUMERATED,
    TAG_EOC,
    TAG_GENERALIZED_TIME,
    TAG_IA5_STRING,
    TAG_INTEGER,
    TAG_NULL,
    TAG_NUMERIC_STRING,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_PRINTABLE_STRING,
    TAG_SEQUENCE,
    TAG_SET,
    TAG_TELETEX_STRING,
    TAG_UNIVERSAL_STRING,
    TAG_UTC_TIME,
    TAG_UTF8_STRING,
    TAG_VISIBLE_STRING,
    isConstructedOnly,
    isPrimitiveOnly,
    isStringTag,
    stringTypeOfTag,
    tagLabel,
} from '../../src/asn1/asn1-tags.js';

describe('universal tag numbers', () => {
    // ITU-T X.680 §8.4 Table 1; the end-of-contents octets are universal 0 (X.690 §8.1.5).
    it.each([
        ['end-of-contents', TAG_EOC, 0],
        ['BOOLEAN', TAG_BOOLEAN, 1],
        ['INTEGER', TAG_INTEGER, 2],
        ['BIT STRING', TAG_BIT_STRING, 3],
        ['OCTET STRING', TAG_OCTET_STRING, 4],
        ['NULL', TAG_NULL, 5],
        ['OBJECT IDENTIFIER', TAG_OID, 6],
        ['ENUMERATED', TAG_ENUMERATED, 10],
        ['UTF8String', TAG_UTF8_STRING, 12],
        ['SEQUENCE', TAG_SEQUENCE, 16],
        ['SET', TAG_SET, 17],
        ['NumericString', TAG_NUMERIC_STRING, 18],
        ['PrintableString', TAG_PRINTABLE_STRING, 19],
        ['TeletexString', TAG_TELETEX_STRING, 20],
        ['IA5String', TAG_IA5_STRING, 22],
        ['UTCTime', TAG_UTC_TIME, 23],
        ['GeneralizedTime', TAG_GENERALIZED_TIME, 24],
        ['VisibleString', TAG_VISIBLE_STRING, 26],
        ['UniversalString', TAG_UNIVERSAL_STRING, 28],
        ['BMPString', TAG_BMP_STRING, 30],
    ])('should number %s as X.680 §8.4 does', (name, constant, number) => {
        expect(constant).toBe(number);
        expect(tagLabel('universal', constant)).toBe(name);
    });
});

describe('tagLabel', () => {
    it('should name universal types, number unknown ones, and bracket the other classes', () => {
        expect(tagLabel('universal', 16)).toBe('SEQUENCE');
        expect(tagLabel('universal', 15)).toBe('[UNIVERSAL 15]');
        expect(tagLabel('context', 3)).toBe('[3]');
        expect(tagLabel('application', 7)).toBe('[APPLICATION 7]');
        expect(tagLabel('private', 1)).toBe('[PRIVATE 1]');
    });
});

describe('universal form predicates', () => {
    it('should classify the primitive-only, constructed-only and string types of X.690', () => {
        expect([1, 2, 5, 6, 9, 10, 13, 14].every(isPrimitiveOnly)).toBe(true);
        expect([3, 4, 16, 17, 12].some(isPrimitiveOnly)).toBe(false);
        expect([8, 11, 16, 17, 29].every(isConstructedOnly)).toBe(true);
        expect([2, 4, 30].some(isConstructedOnly)).toBe(false);
        expect([3, 4, 7, 12, 18, 22, 23, 24, 28, 30].every(isStringTag)).toBe(true);
        expect([2, 16, 29, 31].some(isStringTag)).toBe(false);
    });

    it('should map every decoded string type to its tag and back', () => {
        for (const [type, tag] of Object.entries(STRING_TAGS)) expect(stringTypeOfTag(tag)).toBe(type);
        expect(stringTypeOfTag(21)).toBeUndefined();
    });
});
