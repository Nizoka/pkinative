import { describe, expect, it } from 'vitest';
import {
    decodeAsn1,
    encodeBoolean,
    encodeEnumerated,
    encodeExplicit,
    encodeImplicit,
    encodeInteger,
    encodeNamedBits,
    encodeOctetString,
    encodeSequence,
    encodeString,
    readBitString,
} from '../../src/index.js';

/**
 * The four encoders 0.3 added: the two tagging forms, ENUMERATED, and the
 * named-bits BIT STRING. Every expectation below is an octet string read
 * from X.690 or RFC 5280, not from this library's own output.
 */

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

describe('encodeEnumerated', () => {
    it('should use tag 10, not INTEGER', () => {
        // CRLReason keyCompromise (RFC 5280 §5.3.1) is ENUMERATED 1. A
        // reader that expects tag 10 rejects tag 2, so the two are not
        // interchangeable however similar their content.
        expect(hex(encodeEnumerated(1))).toBe('0a0101');
        expect(hex(encodeInteger(1))).toBe('020101');
    });

    it('should carry the minimal two’s-complement content of an INTEGER', () => {
        expect(hex(encodeEnumerated(0))).toBe('0a0100');
        expect(hex(encodeEnumerated(128))).toBe('0a020080');
        expect(hex(encodeEnumerated(-1))).toBe('0a01ff');
        expect(hex(encodeEnumerated(6n))).toBe('0a0106');
    });

    it('should refuse a value an INTEGER cannot represent', () => {
        expect(() => encodeEnumerated(1.5)).toThrow(expect.objectContaining({ code: 'PKI_ASN1_VALUE_OUT_OF_RANGE' }));
    });
});

describe('encodeExplicit', () => {
    it('should wrap the inner encoding, keeping its own header', () => {
        // [0] EXPLICIT Version, the first field of a v3 tbsCertificate.
        expect(hex(encodeExplicit(0, encodeInteger(2)))).toBe('a003020102');
    });

    it('should let another tag class be named', () => {
        expect(hex(encodeExplicit(1, encodeInteger(0), { tagClass: 'application' }))).toBe('6103020100');
    });

    it('should refuse an inner value that is not bytes', () => {
        expect(() => encodeExplicit(0, 'not bytes' as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should refuse a tag number outside the range', () => {
        expect(() => encodeExplicit(-1, encodeInteger(0))).toThrow(expect.objectContaining({ code: 'PKI_ASN1_VALUE_OUT_OF_RANGE' }));
    });
});

describe('encodeImplicit', () => {
    it('should keep a primitive type primitive', () => {
        // GeneralName dNSName is [2] IMPLICIT IA5String: primitive, 0x82.
        const tagged = encodeImplicit(2, encodeString('ia5', 'a.example'));
        expect(hex(tagged)).toBe(`82096${'12e6578616d706c65'}`);
        expect(decodeAsn1(tagged).constructed).toBe(false);
    });

    it('should keep a constructed type constructed', () => {
        // The bit belongs to the type being re-tagged, not to the tag: an
        // implicitly tagged SEQUENCE stays constructed, and getting this
        // wrong is the classic implicit-tagging defect.
        const tagged = encodeImplicit(4, encodeSequence([encodeInteger(1)]));
        expect(hex(tagged)).toBe('a403020101');
        expect(decodeAsn1(tagged).constructed).toBe(true);
    });

    it('should replace the identifier rather than wrap it', () => {
        const inner = encodeOctetString(Uint8Array.of(0xab, 0xcd));
        expect(hex(inner)).toBe('0402abcd');
        expect(hex(encodeImplicit(0, inner))).toBe('8002abcd');
    });

    it('should preserve a long-form length', () => {
        const long = encodeOctetString(new Uint8Array(200).fill(0x41));
        const tagged = encodeImplicit(3, long);
        expect(hex(tagged.subarray(0, 3))).toBe('8381c8');
        expect(tagged.length).toBe(long.length);
    });

    it('should let another tag class be named', () => {
        expect(hex(encodeImplicit(5, encodeOctetString(Uint8Array.of(1)), { tagClass: 'private' }))).toBe('c50101');
    });

    it.each([
        ['an empty input', new Uint8Array(0)],
        ['a single octet', Uint8Array.of(0x04)],
    ])('should refuse %s, which is not a complete encoding', (_what, bytes) => {
        expect(() => encodeImplicit(0, bytes)).toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE' }));
    });

    it('should refuse an indefinite-length value, which DER has no form for', () => {
        expect(() => encodeImplicit(0, Uint8Array.of(0x30, 0x80, 0x00, 0x00)))
            .toThrow(expect.objectContaining({ code: 'PKI_API_MISUSE', message: expect.stringContaining('indefinite') }));
    });

    it('should refuse an input that is not bytes', () => {
        expect(() => encodeImplicit(0, null as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should keep a primitive type with an odd tag number primitive', () => {
        // IssuingDistributionPoint onlyContainsUserCerts is [1] IMPLICIT BOOLEAN (RFC 5280 §5.2.5):
        // the identifier 01 has its low bit set, which is not the constructed bit 0x20.
        const tagged = encodeImplicit(1, encodeBoolean(true));
        expect(hex(tagged)).toBe('8101ff');
        expect(decodeAsn1(tagged).constructed).toBe(false);
    });
});

describe('encodeNamedBits', () => {
    it('should drop every trailing zero bit (X.690 §11.2.2)', () => {
        // keyCertSign + cRLSign is the KeyUsage of every CA certificate:
        // bits 5 and 6, which DER writes as one octet with one unused bit.
        expect(hex(encodeNamedBits([5, 6]))).toBe('03020106');
        // digitalSignature alone is bit 0: seven unused bits.
        expect(hex(encodeNamedBits([0]))).toBe('03020780');
    });

    it('should encode no bit as the empty BIT STRING, not as a zero octet', () => {
        // Every bit of a single zero octet is trailing, so DER leaves none.
        expect(hex(encodeNamedBits([]))).toBe('030100');
    });

    it('should cross into a second octet only when a bit needs one', () => {
        expect(hex(encodeNamedBits([7]))).toBe('03020001');
        expect(hex(encodeNamedBits([8]))).toBe('0303070080');
    });

    it('should ignore the order and the repetition of positions', () => {
        expect(hex(encodeNamedBits([6, 5, 5]))).toBe(hex(encodeNamedBits([5, 6])));
    });

    it('should round-trip through readBitString', () => {
        const read = readBitString(decodeAsn1(encodeNamedBits([0, 5])));
        expect(read.unusedBits).toBe(2);
        expect(hex(read.bytes)).toBe('84');
    });

    it('should accept position 65535, the ceiling, in the last bit of an 8192-octet string', () => {
        const read = readBitString(decodeAsn1(encodeNamedBits([65535])));
        expect(read.unusedBits).toBe(0);
        expect(read.bytes.length).toBe(8192);
        expect(read.bytes[8191]).toBe(0x01);
        expect(read.bytes.subarray(0, 8191).every((b) => b === 0)).toBe(true);
    });

    it.each([
        ['a fraction', 1.5],
        ['a negative position', -1],
        ['the first position past the ceiling', 65536],
        ['a position past the ceiling', 70000],
    ])('should refuse %s', (_what, bit) => {
        expect(() => encodeNamedBits([bit])).toThrow(expect.objectContaining({ code: 'PKI_ASN1_VALUE_OUT_OF_RANGE' }));
    });
});
