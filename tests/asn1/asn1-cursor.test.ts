import { describe, expect, it } from 'vitest';
import { readTlvHeader, walkChildren } from '../../src/asn1/asn1-cursor.js';

/**
 * The lazy TLV cursor, and every way it refuses.
 *
 * The cursor exists so a million-entry CRL can be walked without being
 * decoded, which means it is a **second reading path** over attacker-controlled
 * bytes. A cursor that accepted what the decoder refuses would be a weaker
 * parser for the same input — exactly the ambiguity DER exists to remove, and
 * exactly the shape of CVE-2020-0601-style trouble. So every rule the decoder
 * enforces is tested here too, on the cursor.
 */

const bytes = (...values: readonly number[]): Uint8Array => Uint8Array.from(values);

describe('readTlvHeader', () => {
    it('should read a short-form header', () => {
        const header = readTlvHeader(bytes(0x02, 0x01, 0x05), 0, 'value');
        expect(header).toMatchObject({ tagClass: 'universal', tagNumber: 2, constructed: false, contentStart: 2, length: 1, end: 3 });
    });

    it('should read a constructed context tag', () => {
        const header = readTlvHeader(bytes(0xa3, 0x02, 0x30, 0x00), 0, 'value');
        expect(header).toMatchObject({ tagClass: 'context', tagNumber: 3, constructed: true });
    });

    it.each([
        { name: 'application', first: 0x41, expected: 'application' },
        { name: 'private', first: 0xc1, expected: 'private' },
    ])('should read a $name class tag', ({ first, expected }) => {
        expect(readTlvHeader(bytes(first, 0x00), 0, 'value').tagClass).toBe(expected);
    });

    it('should read a long-form length', () => {
        const data = new Uint8Array(3 + 200);
        data.set([0x04, 0x81, 0xc8], 0);
        expect(readTlvHeader(data, 0, 'value')).toMatchObject({ length: 200, contentStart: 3, end: 203 });
    });

    it('should read a high tag number', () => {
        // [APPLICATION 31] in the two-octet high-tag form.
        expect(readTlvHeader(bytes(0x5f, 0x1f, 0x00), 0, 'value')).toMatchObject({ tagNumber: 31, contentStart: 3 });
        // A two-continuation form: 0x81 0x00 → 128.
        expect(readTlvHeader(bytes(0x5f, 0x81, 0x00, 0x00), 0, 'value')).toMatchObject({ tagNumber: 128 });
    });

    it.each([
        { name: 'nothing at the offset', data: bytes(), code: 'PKI_ASN1_TRUNCATED' },
        { name: 'no length octet', data: bytes(0x02), code: 'PKI_ASN1_TRUNCATED' },
        { name: 'a high tag number running past the input', data: bytes(0x5f, 0x81), code: 'PKI_ASN1_TRUNCATED' },
        { name: 'a high tag number starting with 0x80', data: bytes(0x5f, 0x80, 0x01, 0x00), code: 'PKI_ASN1_TAG_INVALID' },
        { name: 'a tag number wider than four octets', data: bytes(0x5f, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00), code: 'PKI_ASN1_TAG_INVALID' },
        { name: 'an indefinite length', data: bytes(0x30, 0x80, 0x00, 0x00), code: 'PKI_ASN1_LENGTH_INVALID' },
        { name: 'a length in seven octets', data: bytes(0x04, 0x87, 1, 1, 1, 1, 1, 1, 1), code: 'PKI_ASN1_LENGTH_INVALID' },
        { name: 'a length running past the input', data: bytes(0x04, 0x82, 0x01), code: 'PKI_ASN1_TRUNCATED' },
        { name: 'a long-form length with a leading zero', data: bytes(0x04, 0x82, 0x00, 0x81), code: 'PKI_ASN1_LENGTH_INVALID' },
        { name: 'a long form used below 128', data: bytes(0x04, 0x81, 0x05, 1, 2, 3, 4, 5), code: 'PKI_ASN1_LENGTH_INVALID' },
        { name: 'content running past the input', data: bytes(0x04, 0x05, 1, 2), code: 'PKI_ASN1_TRUNCATED' },
    ])('should refuse $name', ({ data, code }) => {
        expect(() => readTlvHeader(data, 0, 'value')).toThrow(expect.objectContaining({ code }));
    });

    it('should read at a non-zero offset, and report that offset in the error', () => {
        const data = bytes(0xff, 0xff, 0x02, 0x01, 0x07);
        expect(readTlvHeader(data, 2, 'value').contentStart).toBe(4);
        try {
            readTlvHeader(bytes(0x00, 0x04, 0x09), 1, 'value');
            expect.unreachable('should have thrown');
        } catch (error) {
            expect((error as { offset: number }).offset).toBe(1);
        }
    });

    it('should accept a zero-length value', () => {
        expect(readTlvHeader(bytes(0x05, 0x00), 0, 'value')).toMatchObject({ length: 0, contentStart: 2, end: 2 });
    });
});

describe('walkChildren', () => {
    it('should yield each child in encoded order', () => {
        const parent = readTlvHeader(bytes(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02), 0, 'seq');
        const children = [...walkChildren(bytes(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02), parent, 'seq')];
        expect(children.map((c) => c.contentStart)).toEqual([4, 7]);
    });

    it('should yield nothing for an empty parent', () => {
        const data = bytes(0x30, 0x00);
        expect([...walkChildren(data, readTlvHeader(data, 0, 'seq'), 'seq')]).toEqual([]);
    });

    it('should refuse a child that overruns its parent', () => {
        // The two lengths disagree, and a value that overruns its container is
        // how one parser reads what another does not.
        const data = bytes(0x30, 0x03, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05);
        const parent = readTlvHeader(data, 0, 'seq');
        expect(() => [...walkChildren(data, parent, 'seq')]).toThrow(expect.objectContaining({ code: 'PKI_ASN1_TRUNCATED' }));
    });

    it('should hold only one header at a time', () => {
        // The property the whole design rests on: a caller can step through a
        // million values in constant memory. Taking one child from a large
        // parent must not walk the rest.
        const count = 50_000;
        const content = new Uint8Array(count * 3);
        for (let i = 0; i < count; i += 1) content.set([0x02, 0x01, i & 0x7f], i * 3);
        const data = new Uint8Array(4 + content.length);
        data.set([0x30, 0x83, (content.length >> 16) & 0xff, (content.length >> 8) & 0xff], 0);
        // A three-octet length needs four header octets; rebuild it correctly.
        const header = Uint8Array.of(0x30, 0x83, (content.length >> 16) & 0xff, (content.length >> 8) & 0xff, content.length & 0xff);
        const whole = new Uint8Array(header.length + content.length);
        whole.set(header, 0);
        whole.set(content, header.length);

        const parent = readTlvHeader(whole, 0, 'seq');
        const iterator = walkChildren(whole, parent, 'seq');
        expect(iterator.next().value).toMatchObject({ tagNumber: 2, contentStart: header.length + 2 });

        let walked = 0;
        for (const _ of walkChildren(whole, parent, 'seq')) walked += 1;
        expect(walked).toBe(count);
    });
});
