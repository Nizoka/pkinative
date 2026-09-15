import { describe, it, expect } from 'vitest';
import { STRING_TAGS, isConstructedOnly, isPrimitiveOnly, isStringTag, stringTypeOfTag, tagLabel } from '../../src/asn1/asn1-tags.js';

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
