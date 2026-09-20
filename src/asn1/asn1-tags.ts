/**
 * pkinative — ASN.1 universal tags
 * ================================
 * The universal tag numbers of ITU-T X.680 §8.4 and the encoding-form rules
 * X.690 attaches to them: which types are always primitive, which always
 * constructed, and which are strings that BER may split into segments.
 *
 * @module asn1/asn1-tags
 */

import type { Asn1StringType, TagClass } from '../types/asn1-types.js';

export const TAG_EOC = 0;
export const TAG_BOOLEAN = 1;
export const TAG_INTEGER = 2;
export const TAG_BIT_STRING = 3;
export const TAG_OCTET_STRING = 4;
export const TAG_NULL = 5;
export const TAG_OID = 6;
export const TAG_ENUMERATED = 10;
export const TAG_UTF8_STRING = 12;
export const TAG_SEQUENCE = 16;
export const TAG_SET = 17;
export const TAG_NUMERIC_STRING = 18;
export const TAG_PRINTABLE_STRING = 19;
export const TAG_TELETEX_STRING = 20;
export const TAG_IA5_STRING = 22;
export const TAG_UTC_TIME = 23;
export const TAG_GENERALIZED_TIME = 24;
export const TAG_VISIBLE_STRING = 26;
export const TAG_UNIVERSAL_STRING = 28;
export const TAG_BMP_STRING = 30;

/** Index = the two class bits of the identifier octet. */
export const TAG_CLASSES: readonly TagClass[] = ['universal', 'application', 'context', 'private'];

/**
 * The class the two leading bits of an identifier octet name (X.690 §8.1.2.2).
 *
 * Written out rather than indexed into `TAG_CLASSES`: a computed index is
 * `TagClass | undefined` under `noUncheckedIndexedAccess`, and the fallback
 * that narrowed it back was a branch no octet could reach.
 */
export function tagClassOf(identifier: number): TagClass {
    const bits = identifier & 0xc0;
    if (bits === 0x00) return 'universal';
    if (bits === 0x40) return 'application';
    if (bits === 0x80) return 'context';
    return 'private';
}

/** The universal tag of each decoded character string type. */
export const STRING_TAGS: Readonly<Record<Asn1StringType, number>> = {
    utf8: TAG_UTF8_STRING,
    numeric: TAG_NUMERIC_STRING,
    printable: TAG_PRINTABLE_STRING,
    teletex: TAG_TELETEX_STRING,
    ia5: TAG_IA5_STRING,
    visible: TAG_VISIBLE_STRING,
    universal: TAG_UNIVERSAL_STRING,
    bmp: TAG_BMP_STRING,
};

const NAMES: Readonly<Record<number, string>> = {
    0: 'end-of-contents', 1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL',
    6: 'OBJECT IDENTIFIER', 7: 'ObjectDescriptor', 8: 'EXTERNAL', 9: 'REAL', 10: 'ENUMERATED',
    11: 'EMBEDDED PDV', 12: 'UTF8String', 13: 'RELATIVE-OID', 14: 'TIME', 16: 'SEQUENCE', 17: 'SET',
    18: 'NumericString', 19: 'PrintableString', 20: 'TeletexString', 21: 'VideotexString',
    22: 'IA5String', 23: 'UTCTime', 24: 'GeneralizedTime', 25: 'GraphicString', 26: 'VisibleString',
    27: 'GeneralString', 28: 'UniversalString', 29: 'CHARACTER STRING', 30: 'BMPString',
};

/** Universal types X.690 always encodes in primitive form. */
export function isPrimitiveOnly(tagNumber: number): boolean {
    return tagNumber === 1 || tagNumber === 2 || tagNumber === 5 || tagNumber === 6 || tagNumber === 9
        || tagNumber === 10 || tagNumber === 13 || tagNumber === 14;
}

/** Universal types X.690 always encodes in constructed form. */
export function isConstructedOnly(tagNumber: number): boolean {
    return tagNumber === 8 || tagNumber === 11 || tagNumber === 16 || tagNumber === 17 || tagNumber === 29;
}

/** Universal string types BER may encode in constructed (segmented) form and DER never does (X.690 §10.2). */
export function isStringTag(tagNumber: number): boolean {
    return tagNumber === 3 || tagNumber === 4 || tagNumber === 7 || tagNumber === 12
        || (tagNumber >= 18 && tagNumber <= 28) || tagNumber === 30;
}

/** The decoded string type of a universal tag, or undefined when it is not one. */
export function stringTypeOfTag(tagNumber: number): Asn1StringType | undefined {
    for (const type of Object.keys(STRING_TAGS) as Asn1StringType[]) {
        if (STRING_TAGS[type] === tagNumber) return type;
    }
    return undefined;
}

/** A human label for messages: `SEQUENCE`, `[UNIVERSAL 15]`, `[0]`, `[APPLICATION 3]`. */
export function tagLabel(tagClass: TagClass, tagNumber: number): string {
    if (tagClass === 'universal') return NAMES[tagNumber] ?? `[UNIVERSAL ${tagNumber}]`;
    if (tagClass === 'context') return `[${tagNumber}]`;
    return `[${tagClass.toUpperCase()} ${tagNumber}]`;
}
