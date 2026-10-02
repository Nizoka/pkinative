import { describe, it, expect } from 'vitest';
import { decodeAsn1, decodeAsn1Sequence } from '../../src/asn1/asn1-decode.js';
import { PkiEncodingError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';
import { berNest, concat, derNest, hex, tlv } from '../helpers/raw-der-builder.js';

function failure(fn: () => unknown): PkiError {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiError) return err;
        throw err;
    }
    throw new Error('expected a PkiError');
}

describe('decodeAsn1 — well-formed DER', () => {
    it('should decode a SEQUENCE holding an INTEGER with exact positions and zero-copy views', () => {
        const input = hex('30 03 02 01 05');
        const node = decodeAsn1(input);
        expect(node).toMatchObject({ tagClass: 'universal', tagNumber: 16, constructed: true, offset: 0, headerLength: 2, contentLength: 3, indefinite: false });
        expect(node.bytes.buffer).toBe(input.buffer);
        expect([...node.content]).toEqual([0x02, 0x01, 0x05]);
        const child = node.children[0];
        expect(child).toMatchObject({ tagNumber: 2, constructed: false, offset: 2, headerLength: 2, contentLength: 1 });
        expect([...(child?.content ?? [])]).toEqual([5]);
        expect(child?.children).toEqual([]);
        expect(Object.isFrozen(node) && Object.isFrozen(node.children)).toBe(true);
    });

    it('should decode every class and high tag numbers', () => {
        expect(decodeAsn1(hex('41 00'))).toMatchObject({ tagClass: 'application', tagNumber: 1, constructed: false });
        expect(decodeAsn1(hex('C2 00'))).toMatchObject({ tagClass: 'private', tagNumber: 2 });
        expect(decodeAsn1(hex('9F 1F 00'))).toMatchObject({ tagClass: 'context', tagNumber: 31, constructed: false, headerLength: 3 });
        expect(decodeAsn1(hex('BF 81 00 00'))).toMatchObject({ tagClass: 'context', tagNumber: 128, constructed: true, headerLength: 4 });
        expect(decodeAsn1(hex('9F 87 FF FF FF 7F 00')).tagNumber).toBe(0x7fffffff);
    });

    it('should decode short, one-octet and multi-octet lengths', () => {
        const long = concat([0x04, 0x81, 0x80], new Uint8Array(128));
        expect(decodeAsn1(long)).toMatchObject({ headerLength: 3, contentLength: 128 });
        const longer = concat([0x04, 0x82, 0x01, 0x00], new Uint8Array(256));
        expect(decodeAsn1(longer)).toMatchObject({ headerLength: 4, contentLength: 256 });
    });

    it('should decode an empty constructed value', () => {
        expect(decodeAsn1(hex('30 00'))).toMatchObject({ constructed: true, contentLength: 0, children: [] });
    });
});

describe('decodeAsn1 — identifier errors', () => {
    it.each([
        ['a high tag number starting with 0x80', '9F 80 1F 00', 'PKI_ASN1_TAG_INVALID'],
        ['the long form for a tag number below 31', '9F 1E 00', 'PKI_ASN1_TAG_INVALID'],
        ['a tag number above 2^31 − 1', '9F 88 80 80 80 00 00', 'PKI_ASN1_TAG_INVALID'],
        ['a truncated high tag number', '9F 81', 'PKI_ASN1_TRUNCATED'],
        ['an empty input', '', 'PKI_ASN1_TRUNCATED'],
        ['an identifier without a length octet', '30', 'PKI_ASN1_TRUNCATED'],
    ])('should refuse %s', (_label, input, code) => {
        const err = failure(() => decodeAsn1(hex(input)));
        expect(err).toBeInstanceOf(PkiEncodingError);
        expect(err.code).toBe(code);
        expect(err.message).toMatch(/^pkinative: /);
    });
});

describe('decodeAsn1 — length errors', () => {
    it.each([
        ['the reserved length octet 0xFF', '04 FF', 'PKI_ASN1_LENGTH_INVALID'],
        ['truncated length octets', '04 83 01', 'PKI_ASN1_TRUNCATED'],
        ['content longer than the input', '30 05 02 01', 'PKI_ASN1_TRUNCATED'],
        ['the 0x80000001 length that pdfnative read as negative', '30 84 80 00 00 01', 'PKI_ASN1_TRUNCATED'],
        ['the same length inside an enclosing value', '30 06 04 84 80 00 00 01', 'PKI_ASN1_LENGTH_OVERFLOW'],
        ['a child that overruns its parent', '30 03 04 05 00', 'PKI_ASN1_LENGTH_OVERFLOW'],
    ])('should refuse %s', (_label, input, code) => {
        expect(failure(() => decodeAsn1(hex(input))).code).toBe(code);
    });

    it('should refuse non-minimal lengths under DER and accept them under BER with one diagnostic', () => {
        const oneOctet = concat([0x04, 0x81, 0x05], new Uint8Array(5));
        const leadingZero = concat([0x04, 0x82, 0x00, 0x80], new Uint8Array(128));
        expect(failure(() => decodeAsn1(oneOctet)).code).toBe('PKI_ASN1_LENGTH_NON_MINIMAL');
        expect(failure(() => decodeAsn1(leadingZero)).code).toBe('PKI_ASN1_LENGTH_NON_MINIMAL');
        const seen: PkiDiagnostic[] = [];
        expect(decodeAsn1(oneOctet, { encodingRules: 'ber', onDiagnostic: (d) => seen.push(d) }).contentLength).toBe(5);
        expect(seen).toEqual([expect.objectContaining({ code: 'PKI_DIAG_BER_CONSTRUCT_ACCEPTED', offset: 0 })]);
        expect(seen[0]?.message).toContain('non-minimal length');
    });

    it('should hold the one-octet long form to 128 and above: 127 is non-minimal, 128 is not (X.690 §10.1)', () => {
        expect(failure(() => decodeAsn1(concat([0x04, 0x81, 0x7f], new Uint8Array(127)))).code).toBe('PKI_ASN1_LENGTH_NON_MINIMAL');
        expect(decodeAsn1(concat([0x04, 0x81, 0x80], new Uint8Array(128))).contentLength).toBe(128);
    });
});

describe('decodeAsn1 — indefinite length and end-of-contents', () => {
    it('should refuse the indefinite form under DER', () => {
        expect(failure(() => decodeAsn1(hex('30 80 02 01 05 00 00'))).code).toBe('PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN');
    });

    it('should decode it under BER, excluding the marker from the content but not from the bytes', () => {
        const node = decodeAsn1(hex('30 80 02 01 05 00 00'), { encodingRules: 'ber', onDiagnostic: () => undefined });
        expect(node).toMatchObject({ indefinite: true, headerLength: 2, contentLength: 3 });
        expect(node.bytes.length).toBe(7);
        expect(node.children).toHaveLength(1);
        const nested = decodeAsn1(hex('30 80 30 80 05 00 00 00 00 00'), { encodingRules: 'ber', onDiagnostic: () => undefined });
        expect(nested.children[0]).toMatchObject({ indefinite: true, contentLength: 2 });
        expect(nested.children[0]?.bytes.length).toBe(6);
    });

    it('should report the indefinite form once per operation', () => {
        const seen: PkiDiagnostic[] = [];
        decodeAsn1(hex('30 80 30 80 00 00 30 80 00 00 00 00'), { encodingRules: 'ber', onDiagnostic: (d) => seen.push(d) });
        expect(seen).toHaveLength(1);
    });

    it.each([
        ['a missing end-of-contents marker', '30 80 02 01 05', 'PKI_ASN1_TRUNCATED'],
        ['a missing marker with one octet left', '30 80 02 01 05 00', 'PKI_ASN1_TRUNCATED'],
        ['an end-of-contents marker at the top level', '00 00', 'PKI_ASN1_EOC_UNEXPECTED'],
        ['an end-of-contents marker with a length', '30 80 00 01 00 00 00', 'PKI_ASN1_EOC_UNEXPECTED'],
        ['an end-of-contents marker inside a definite-length value', '30 02 00 00', 'PKI_ASN1_EOC_UNEXPECTED'],
        ['the indefinite form on a primitive value', '04 80 00 00', 'PKI_ASN1_CONSTRUCTED_FORM_INVALID'],
    ])('should refuse %s under BER', (_label, input, code) => {
        expect(failure(() => decodeAsn1(hex(input), { encodingRules: 'ber', onDiagnostic: () => undefined })).code).toBe(code);
    });

    it.each([
        ['the outer value', '30 80 02 01 05', 0],
        ['the innermost open value', '30 80 30 80 02 01 05', 2],
    ])('should point a missing end-of-contents marker at %s, not at the end of the input', (_label, input, offset) => {
        const error = failure(() => decodeAsn1(hex(input), { encodingRules: 'ber', onDiagnostic: () => undefined }));
        expect(error).toMatchObject({ code: 'PKI_ASN1_TRUNCATED', offset });
    });

    // P-03: an indefinite child is bounded by its definite parent, not by the input (X.690 §8.1.3.6).
    it.each([
        ['an end-of-contents marker that straddles the parent', '30 03 30 80 00 00', 2],
        ['no room left for the marker inside the parent', '30 02 30 80 00 00', 2],
        ['a child that fills the parent and leaves no marker', '30 04 30 80 05 00 00 00', 2],
        ['a nested indefinite value under an indefinite one', '30 04 30 80 30 80 00 00 00 00', 4],
    ])('should refuse %s with PKI_ASN1_LENGTH_OVERFLOW at the indefinite value', (_label, input, offset) => {
        const error = failure(() => decodeAsn1(hex(input), { encodingRules: 'ber', onDiagnostic: () => undefined, allowTrailingData: true }));
        expect(error).toBeInstanceOf(PkiEncodingError);
        expect(error).toMatchObject({ code: 'PKI_ASN1_LENGTH_OVERFLOW', offset });
    });

    it('should hold a child of an indefinite value to the definite parent around it', () => {
        const error = failure(() => decodeAsn1(hex('30 05 30 80 04 03 00 00 00'), { encodingRules: 'ber', onDiagnostic: () => undefined, allowTrailingData: true }));
        expect(error).toMatchObject({ code: 'PKI_ASN1_LENGTH_OVERFLOW', offset: 4 });
    });

    it('should still read a header that ends exactly at the definite parent', () => {
        const error = failure(() => decodeAsn1(hex('30 04 30 80 1f 05'), { encodingRules: 'ber', onDiagnostic: () => undefined }));
        expect(error).toMatchObject({ code: 'PKI_ASN1_TAG_INVALID', offset: 4 });
    });

    it('should close an indefinite value whose marker ends exactly at its definite parent', () => {
        const node = decodeAsn1(hex('30 06 30 80 05 00 00 00'), { encodingRules: 'ber', onDiagnostic: () => undefined });
        expect(node.children[0]).toMatchObject({ indefinite: true, offset: 2, contentLength: 2 });
        expect(node.children[0]?.bytes.length).toBe(6);
    });

    it('should explain which end-of-contents rule was broken', () => {
        expect(failure(() => decodeAsn1(hex('00 00'))).message).toContain('outside an indefinite-length value');
        expect(failure(() => decodeAsn1(hex('30 80 00 01 00 00 00'), { encodingRules: 'ber', onDiagnostic: () => undefined })).message).toContain('not the two octets');
    });
});

describe('decodeAsn1 — universal forms', () => {
    it.each([
        ['a primitive SEQUENCE', '10 00', 'PKI_ASN1_CONSTRUCTED_FORM_INVALID'],
        ['a primitive SET', '11 00', 'PKI_ASN1_CONSTRUCTED_FORM_INVALID'],
        ['a constructed INTEGER', '22 00', 'PKI_ASN1_CONSTRUCTED_FORM_INVALID'],
        ['a constructed OBJECT IDENTIFIER', '26 00', 'PKI_ASN1_CONSTRUCTED_FORM_INVALID'],
        ['a constructed OCTET STRING', '24 03 04 01 41', 'PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN'],
        ['a constructed UTF8String', '2C 03 04 01 41', 'PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN'],
    ])('should refuse %s under DER', (_label, input, code) => {
        expect(failure(() => decodeAsn1(hex(input))).code).toBe(code);
    });

    it('should accept a constructed string under BER with a diagnostic', () => {
        const seen: PkiDiagnostic[] = [];
        const node = decodeAsn1(hex('24 06 04 01 41 04 01 42'), { encodingRules: 'ber', onDiagnostic: (d) => seen.push(d) });
        expect(node.children).toHaveLength(2);
        expect(seen[0]?.message).toContain('constructed string');
    });

    it('should leave the form of non-universal tags to the schema', () => {
        expect(decodeAsn1(hex('A2 00')).constructed).toBe(true);
        expect(decodeAsn1(hex('80 01 FF')).constructed).toBe(false);
    });
});

describe('decodeAsn1 — trailing data', () => {
    it('should refuse bytes after the outermost value, naming how many and where', () => {
        const err = failure(() => decodeAsn1(hex('05 00 05 00')));
        expect(err).toMatchObject({ code: 'PKI_ASN1_TRAILING_DATA', offset: 2 });
        expect(err.message).toContain('2 byte(s)');
    });

    it('should accept them with allowTrailingData, and refuse a non-boolean option', () => {
        expect(decodeAsn1(hex('05 00 05 00'), { allowTrailingData: true }).bytes.length).toBe(2);
        expect(failure(() => decodeAsn1(hex('05 00'), { allowTrailingData: 'yes' as unknown as boolean })).code).toBe('PKI_INVALID_OPTION');
    });
});

describe('decodeAsn1Sequence', () => {
    it('should decode values placed back to back, with absolute offsets', () => {
        const nodes = decodeAsn1Sequence(hex('05 00 02 01 07'));
        expect(nodes.map((n) => [n.tagNumber, n.offset])).toEqual([[5, 0], [2, 2]]);
        expect(Object.isFrozen(nodes)).toBe(true);
        expect(decodeAsn1Sequence(new Uint8Array(0))).toEqual([]);
    });

    it('should propagate the first error and enforce the shared limits', () => {
        expect(failure(() => decodeAsn1Sequence(hex('05 00 05'))).code).toBe('PKI_ASN1_TRUNCATED');
        expect(failure(() => decodeAsn1Sequence(hex('05 00 05 00 05 00'), { limits: { maxNodes: 2 } })).code).toBe('PKI_LIMIT_EXCEEDED');
        expect(failure(() => decodeAsn1Sequence(hex('05 00'), { limits: { maxInputBytes: 1 } })).code).toBe('PKI_LIMIT_EXCEEDED');
        expect(failure(() => decodeAsn1Sequence('0500' as unknown as Uint8Array)).code).toBe('PKI_INVALID_INPUT');
    });
});

describe('decodeAsn1 — limits', () => {
    it('should enforce maxDepth on constructed nesting, definite or indefinite', () => {
        expect(() => decodeAsn1(derNest(64))).not.toThrow();
        const err = failure(() => decodeAsn1(derNest(65)));
        expect(err).toBeInstanceOf(PkiLimitError);
        expect(err).toMatchObject({ limit: 'maxDepth', configured: 64, observed: 65 });
        expect(failure(() => decodeAsn1(berNest(3), { encodingRules: 'ber', limits: { maxDepth: 2 }, onDiagnostic: () => undefined }))).toMatchObject({ limit: 'maxDepth', observed: 3 });
        expect(decodeAsn1(berNest(2), { encodingRules: 'ber', limits: { maxDepth: 2 }, onDiagnostic: () => undefined }).indefinite).toBe(true);
    });

    it('should enforce maxNodes and maxInputBytes', () => {
        expect(failure(() => decodeAsn1(hex('30 06 05 00 05 00 05 00'), { limits: { maxNodes: 3 } }))).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxNodes', observed: 4 });
        expect(failure(() => decodeAsn1(hex('30 00'), { limits: { maxInputBytes: 1 } }))).toMatchObject({ limit: 'maxInputBytes', observed: 2 });
    });

    it('should decode 100 000 levels of BER nesting iteratively when the caller lifts the limits', () => {
        const depth = 100_000;
        let node = decodeAsn1(berNest(depth), { encodingRules: 'ber', limits: { maxDepth: Infinity }, onDiagnostic: () => undefined });
        let levels = 0;
        while (node.constructed) {
            levels++;
            node = node.children[0] ?? node;
            if (!node.constructed) break;
        }
        expect(levels).toBe(depth);
    });
});

describe('decodeAsn1 — arguments', () => {
    it.each([
        ['a string input', () => decodeAsn1('3000' as unknown as Uint8Array), 'PKI_INVALID_INPUT'],
        ['null options', () => decodeAsn1(hex('05 00'), null as unknown as undefined), 'PKI_INVALID_OPTION'],
        ['an unknown encoding rule', () => decodeAsn1(hex('05 00'), { encodingRules: 'xer' as unknown as 'der' }), 'PKI_INVALID_OPTION'],
        ['a non-boolean strict', () => decodeAsn1(hex('05 00'), { strict: 1 as unknown as boolean }), 'PKI_INVALID_OPTION'],
        ['a non-function onDiagnostic', () => decodeAsn1(hex('05 00'), { onDiagnostic: 5 as unknown as () => void }), 'PKI_INVALID_OPTION'],
        ['an invalid limit', () => decodeAsn1(hex('05 00'), { limits: { maxDepth: 0 } }), 'PKI_LIMIT_INVALID'],
    ])('should refuse %s', (_label, fn, code) => {
        expect(failure(fn).code).toBe(code);
    });

    it('should escalate an accepted BER construct under strict', () => {
        expect(failure(() => decodeAsn1(hex('30 80 00 00'), { encodingRules: 'ber', strict: true })).code).toBe('PKI_STRICT_DIAGNOSTIC');
    });

    it('should decode a value built with an explicit long length only under BER', () => {
        const forced = tlv(0, false, 4, [0x41], { lengthOctets: 2 });
        expect(failure(() => decodeAsn1(forced)).code).toBe('PKI_ASN1_LENGTH_NON_MINIMAL');
        expect(decodeAsn1(forced, { encodingRules: 'ber', onDiagnostic: () => undefined }).contentLength).toBe(1);
    });
});
