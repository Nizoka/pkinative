import { describe, it, expect } from 'vitest';
import { createAsn1Context } from '../../src/asn1/asn1-context.js';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { _readGeneralName, _readGeneralNames } from '../../src/x509/x509-general-name.js';
import { PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiParseOptions } from '../../src/types/pki-types.js';
import type { GeneralName } from '../../src/types/x509-types.js';
import { context, explicit, integer, name, octetString, oid, utf8 } from '../helpers/cert-builder.js';
import { ascii, concat, sequence, tlv } from '../helpers/raw-der-builder.js';

const QUIET: PkiParseOptions = { onDiagnostic: () => undefined };

const readGeneralName = (bytes: Uint8Array, inNameConstraints = false, options: PkiParseOptions = QUIET): GeneralName =>
    _readGeneralName(decodeAsn1(bytes, options), createAsn1Context(options), 'name', inNameConstraints);

function codeOf(fn: () => unknown): string {
    try {
        fn();
    } catch (error) {
        if (error instanceof PkiError) return error.code;
        throw error;
    }
    return 'no error';
}

const ipv6 = (...groups: number[]): number[] => groups.flatMap((g) => [g >> 8, g & 0xff]);

describe('_readGeneralName', () => {
    describe('text names', () => {
        it.each<[number, string, string]>([
            [1, 'rfc822Name', 'user@example.com'],
            [2, 'dNSName', 'example.com'],
            [6, 'uniformResourceIdentifier', 'http://crl.example.com/root.crl'],
        ])('should read [%i] as %s', (tag, kind, value) => {
            const bytes = context(tag, false, ascii(value));
            const parsed = readGeneralName(bytes);
            expect(parsed).toMatchObject({ kind, value });
            expect([...parsed.der]).toEqual([...bytes]);
            expect(Object.isFrozen(parsed)).toBe(true);
        });

        it('should refuse non-ASCII octets in an IA5String name', () => {
            expect(codeOf(() => readGeneralName(context(2, false, [0x63, 0xc3, 0xa9])))).toBe('PKI_X509_GENERAL_NAME_INVALID');
        });

        it('should join a constructed name under BER and refuse it under DER', () => {
            const bytes = context(2, true, concat(octetString(ascii('a.')), octetString(ascii('com'))));
            expect(readGeneralName(bytes, false, { encodingRules: 'ber', onDiagnostic: () => undefined })).toMatchObject({ value: 'a.com' });
            expect(codeOf(() => readGeneralName(bytes))).toBe('PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN');
        });
    });

    describe('iPAddress', () => {
        it('should read an IPv4 address', () => {
            expect(readGeneralName(context(7, false, [192, 0, 2, 1]))).toMatchObject({ kind: 'iPAddress', version: 4, address: '192.0.2.1', mask: undefined });
        });

        it.each<[string, number[]]>([
            ['2001:db8::1', ipv6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
            ['::', ipv6(0, 0, 0, 0, 0, 0, 0, 0)],
            ['::1', ipv6(0, 0, 0, 0, 0, 0, 0, 1)],
            ['1::', ipv6(1, 0, 0, 0, 0, 0, 0, 0)],
            ['1:2:3:4:5:6:7:8', ipv6(1, 2, 3, 4, 5, 6, 7, 8)],
            ['2001:db8:0:1:1:1:1:1', ipv6(0x2001, 0xdb8, 0, 1, 1, 1, 1, 1)],
            ['2001::1:0:0:1:1', ipv6(0x2001, 0, 0, 1, 0, 0, 1, 1)],
        ])('should write the IPv6 address %s in RFC 5952 form', (text, bytes) => {
            expect(readGeneralName(context(7, false, bytes))).toMatchObject({ version: 6, address: text });
        });

        it('should read an IPv4 address and mask in name constraints', () => {
            expect(readGeneralName(context(7, false, [192, 0, 2, 0, 255, 255, 255, 0]), true))
                .toMatchObject({ version: 4, address: '192.0.2.0', mask: '255.255.255.0' });
        });

        it('should read an IPv6 address and mask in name constraints', () => {
            const bytes = [...ipv6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), ...ipv6(0xffff, 0xffff, 0, 0, 0, 0, 0, 0)];
            expect(readGeneralName(context(7, false, bytes), true)).toMatchObject({ version: 6, address: '2001:db8::', mask: 'ffff:ffff::' });
        });

        it.each<[string, number, boolean]>([
            ['5 octets', 5, false],
            ['8 octets outside name constraints', 8, false],
            ['4 octets in name constraints', 4, true],
            ['9 octets in name constraints', 9, true],
        ])('should refuse %s', (_, length, inNameConstraints) => {
            expect(codeOf(() => readGeneralName(context(7, false, new Array<number>(length).fill(1)), inNameConstraints))).toBe('PKI_X509_GENERAL_NAME_INVALID');
        });
    });

    describe('structured names', () => {
        it('should read an otherName', () => {
            const parsed = readGeneralName(context(0, true, concat(oid('1.3.6.1.4.1.311.20.2.3'), explicit(0, utf8('user@example.com')))));
            expect(parsed).toMatchObject({ kind: 'otherName', typeId: '1.3.6.1.4.1.311.20.2.3' });
            expect(parsed.kind === 'otherName' ? parsed.value.tagNumber : -1).toBe(12);
        });

        it('should read a directoryName', () => {
            const parsed = readGeneralName(explicit(4, name([['2.5.4.3', utf8('dir')]])));
            expect(parsed.kind === 'directoryName' ? parsed.name.rdns[0]?.[0]?.value?.value : undefined).toBe('dir');
        });

        it('should keep x400Address and ediPartyName as their tagged node', () => {
            expect(readGeneralName(context(3, true, sequence()))).toMatchObject({ kind: 'x400Address', value: { tagNumber: 3 } });
            expect(readGeneralName(context(5, true, context(1, false, ascii('p'))))).toMatchObject({ kind: 'ediPartyName', value: { tagNumber: 5 } });
        });

        it('should read a registeredID', () => {
            expect(readGeneralName(context(8, false, oid('1.2.3.4').subarray(2)))).toMatchObject({ kind: 'registeredID', oid: '1.2.3.4' });
        });

        it.each<[string, Uint8Array]>([
            ['a primitive otherName', context(0, false, [0x01])],
            ['an otherName of one value', context(0, true, oid('1.2.3'))],
            ['an otherName whose type is not an OID', context(0, true, concat(integer([1]), explicit(0, utf8('x'))))],
            ['an otherName value under another tag', context(0, true, concat(oid('1.2.3'), explicit(1, utf8('x'))))],
            ['an otherName of two values under [0]', context(0, true, concat(oid('1.2.3'), explicit(0, utf8('x'), utf8('y'))))],
            ['a primitive x400Address', context(3, false, [0x01])],
            ['an empty directoryName', context(4, true, [])],
            ['a constructed registeredID', context(8, true, oid('1.2.3'))],
            ['a universal value', utf8('x')],
            ['an application-class value', tlv(1, false, 2, ascii('a'))],
            ['the tag [9]', context(9, false, [0x01])],
        ])('should refuse %s', (_, bytes) => {
            expect(codeOf(() => readGeneralName(bytes))).toBe('PKI_X509_GENERAL_NAME_INVALID');
        });

        it('should refuse a directoryName that is not a Name as a name error', () => {
            expect(codeOf(() => readGeneralName(explicit(4, integer([1]))))).toBe('PKI_X509_NAME_INVALID');
        });
    });
});

describe('_readGeneralNames', () => {
    const readNames = (bytes: Uint8Array, options: PkiParseOptions = QUIET): readonly GeneralName[] =>
        _readGeneralNames(decodeAsn1(bytes), createAsn1Context(options), 'names', false);

    it('should read every name in order', () => {
        const names = readNames(sequence(context(2, false, ascii('a.example')), context(7, false, [192, 0, 2, 1])));
        expect(names.map((n) => n.kind)).toEqual(['dNSName', 'iPAddress']);
        expect(Object.isFrozen(names)).toBe(true);
    });

    it('should return an empty sequence as empty', () => {
        expect(readNames(sequence())).toEqual([]);
    });

    it('should enforce maxGeneralNames', () => {
        let error: unknown;
        try {
            readNames(sequence(context(2, false, ascii('a')), context(2, false, ascii('b'))), { limits: { maxGeneralNames: 1 } });
        } catch (caught) {
            error = caught;
        }
        expect(error).toBeInstanceOf(PkiLimitError);
        expect(error).toMatchObject({ limit: 'maxGeneralNames' });
    });

    it('should refuse a value that is not a SEQUENCE', () => {
        expect(codeOf(() => readNames(integer([1])))).toBe('PKI_X509_GENERAL_NAME_INVALID');
    });
});
