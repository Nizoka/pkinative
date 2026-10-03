import { describe, it, expect } from 'vitest';
import { createAsn1Context } from '../../src/asn1/asn1-context.js';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import { _readName } from '../../src/x509/x509-name.js';
import { formatDistinguishedName } from '../../src/x509/x509-name-format.js';
import { PkiCertificateError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic, PkiParseOptions } from '../../src/types/pki-types.js';
import type { DistinguishedName } from '../../src/types/x509-types.js';
import { bitString, ia5, integer, name, oid, printable, set, utf8 } from '../helpers/cert-builder.js';
import { sequence } from '../helpers/raw-der-builder.js';

const QUIET: PkiParseOptions = { onDiagnostic: () => undefined };

const readName = (bytes: Uint8Array, options: PkiParseOptions = QUIET): DistinguishedName =>
    _readName(decodeAsn1(bytes), createAsn1Context(options), 'name', 0);

function thrown(fn: () => unknown): unknown {
    try {
        fn();
    } catch (error) {
        return error;
    }
    throw new Error('expected a throw');
}

function codeOf(fn: () => unknown): string {
    const error = thrown(fn);
    if (error instanceof PkiError) return error.code;
    throw error;
}

function diagnosticsOf(bytes: Uint8Array): PkiDiagnostic[] {
    const seen: PkiDiagnostic[] = [];
    readName(bytes, { onDiagnostic: (d) => { seen.push(d); } });
    return seen;
}

const cn = (value: string): Uint8Array => sequence(oid('2.5.4.3'), utf8(value));

describe('_readName', () => {
    it('should read every RDN and attribute in encoded order', () => {
        const parsed = readName(name([['2.5.4.6', printable('US')]], [['2.5.4.11', utf8('A')], ['2.5.4.3', utf8('B')]]));
        expect(parsed.rdns.map((rdn) => rdn.map((a) => [a.type, a.value?.stringType, a.value?.value])))
            .toEqual([[['2.5.4.6', 'printable', 'US']], [['2.5.4.11', 'utf8', 'A'], ['2.5.4.3', 'utf8', 'B']]]);
        expect(Object.isFrozen(parsed.rdns)).toBe(true);
    });

    it('should keep a value that is not a character string as its encoding', () => {
        const [attribute] = readName(name([['2.5.4.45', bitString([0xaa])]])).rdns[0] ?? [];
        expect(attribute?.value).toBeUndefined();
        expect([...(attribute?.valueDer ?? [])]).toEqual([0x03, 0x02, 0x00, 0xaa]);
    });

    it('should read an empty name', () => {
        expect(readName(name()).rdns).toEqual([]);
    });

    it('should report a multi-valued RDN out of DER SET OF order', () => {
        expect(diagnosticsOf(sequence(set(cn('b'), cn('a'))))).toEqual([expect.objectContaining({ code: 'PKI_DIAG_RDN_SET_NOT_SORTED', path: 'name.rdns[0]' })]);
    });

    it.each<[string, Uint8Array]>([
        ['in order', set(cn('a'), cn('b'))],
        ['in order by length', set(cn('a'), cn('ab'))],
        ['with equal elements', set(cn('a'), cn('a'))],
    ])('should accept a multi-valued RDN %s', (_, rdn) => {
        expect(diagnosticsOf(sequence(rdn))).toEqual([]);
    });

    it('should report a PrintableString character outside its alphabet with the attribute path', () => {
        expect(diagnosticsOf(name([['2.5.4.3', printable('a*b')]])))
            .toEqual([expect.objectContaining({ code: 'PKI_DIAG_PRINTABLE_STRING_CHARSET', path: 'name.rdns[0][0].value' })]);
    });

    it.each<[string, Uint8Array]>([
        ['a name that is not a SEQUENCE', integer([1])],
        ['an RDN that is not a SET', sequence(sequence(cn('a')))],
        ['an empty RDN', sequence(set())],
        ['an attribute that is not a SEQUENCE', sequence(set(integer([1])))],
        ['an attribute of three values', sequence(set(sequence(oid('2.5.4.3'), utf8('a'), utf8('b'))))],
        ['an attribute type that is not an OID', sequence(set(sequence(integer([3]), utf8('a'))))],
    ])('should refuse %s', (_, bytes) => {
        expect(codeOf(() => readName(bytes))).toBe('PKI_X509_NAME_INVALID');
    });

    it('should refuse a missing name at the offset of its parent', () => {
        const error = thrown(() => _readName(undefined, createAsn1Context(undefined), 'name', 7));
        expect(error).toBeInstanceOf(PkiCertificateError);
        expect(error).toMatchObject({ code: 'PKI_X509_NAME_INVALID', offset: 7, path: 'name' });
    });

    it('should enforce maxNameAttributes across RDNs', () => {
        const error = thrown(() => readName(name([['2.5.4.3', utf8('a')]], [['2.5.4.3', utf8('b')]], [['2.5.4.3', utf8('c')]]), { limits: { maxNameAttributes: 2 } }));
        expect(error).toBeInstanceOf(PkiLimitError);
        expect(error).toMatchObject({ limit: 'maxNameAttributes' });
    });

    it('should refuse a character string that is not valid for its type', () => {
        expect(codeOf(() => readName(sequence(set(sequence(oid('2.5.4.3'), Uint8Array.of(0x0c, 0x01, 0xff))))))).toBe('PKI_ASN1_STRING_INVALID');
    });

    describe('the syntax RFC 5280 Appendix A.1 gives each attribute', () => {
        it.each<[string, string, Uint8Array, string]>([
            ['a UTF8String countryName', '2.5.4.6', utf8('US'), 'UTF8String'],
            ['a UTF8String serialNumber', '2.5.4.5', utf8('42'), 'UTF8String'],
            ['a UTF8String dnQualifier', '2.5.4.46', utf8('q'), 'UTF8String'],
            ['a UTF8String domainComponent', '0.9.2342.19200300.100.1.25', utf8('com'), 'UTF8String'],
            ['a PrintableString emailAddress', '1.2.840.113549.1.9.1', printable('a'), 'PrintableString'],
            ['an IA5String commonName', '2.5.4.3', ia5('a'), 'IA5String'],
            ['an INTEGER organizationName', '2.5.4.10', integer([1]), 'INTEGER'],
        ])('should report %s, and still read it', (_what, type, value, found) => {
            const seen = diagnosticsOf(name([[type, value]]));
            expect(seen).toEqual([expect.objectContaining({ code: 'PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE', path: 'name.rdns[0][0].value', standard: 'RFC 5280 Appendix A.1' })]);
            expect(seen[0]?.message).toContain(found);
            expect(readName(name([[type, value]])).rdns[0]?.[0]?.valueDer).toEqual(value);
        });

        it.each<[string, string, Uint8Array]>([
            ['a PrintableString countryName of two letters', '2.5.4.6', printable('US')],
            ['an IA5String emailAddress', '1.2.840.113549.1.9.1', ia5('a@b')],
            ['an IA5String domainComponent', '0.9.2342.19200300.100.1.25', ia5('com')],
            ['a PrintableString commonName', '2.5.4.3', printable('a')],
            ['a UTF8String commonName', '2.5.4.3', utf8('a')],
            ['a BMPString commonName', '2.5.4.3', Uint8Array.of(0x1e, 0x02, 0x00, 0x61)],
            ['a UniversalString commonName', '2.5.4.3', Uint8Array.of(0x1c, 0x04, 0x00, 0x00, 0x00, 0x61)],
            ['an IA5String under an attribute Appendix A does not define', '2.5.4.9', ia5('street')],
        ])('should accept %s silently', (_what, type, value) => {
            expect(diagnosticsOf(name([[type, value]]))).toEqual([]);
        });

        it.each<[string, Uint8Array, number]>([
            ['three letters', printable('USA'), 3],
            ['none', printable(''), 0],
        ])('should report a countryName of %s', (_what, value, characters) => {
            expect(diagnosticsOf(name([['2.5.4.6', value]])))
                .toEqual([expect.objectContaining({ code: 'PKI_DIAG_COUNTRY_NAME_SIZE', message: expect.stringContaining(`is ${String(characters)} characters long`) })]);
        });

        it('should report both concerns of a UTF8String countryName of three letters', () => {
            expect(diagnosticsOf(name([['2.5.4.6', utf8('USA')]])).map((d) => d.code))
                .toEqual(['PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE', 'PKI_DIAG_COUNTRY_NAME_SIZE']);
        });

        it('should not measure a countryName that is not a character string', () => {
            expect(diagnosticsOf(name([['2.5.4.6', integer([1])]])).map((d) => d.code)).toEqual(['PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE']);
        });

        it('should refuse under strict, as every diagnostic does', () => {
            expect(codeOf(() => readName(name([['2.5.4.6', utf8('US')]]), { strict: true }))).toBe('PKI_STRICT_DIAGNOSTIC');
        });
    });

    describe('the upper bounds RFC 5280 Appendix A.1 gives each attribute (X.520 ub-*)', () => {
        it.each<[string, string, Uint8Array, number, number]>([
            ['commonName', '2.5.4.3', utf8('a'.repeat(65)), 65, 64],
            ['organizationName', '2.5.4.10', utf8('o'.repeat(65)), 65, 64],
            ['organizationalUnitName', '2.5.4.11', printable('u'.repeat(100)), 100, 64],
            ['title', '2.5.4.12', utf8('t'.repeat(65)), 65, 64],
            ['serialNumber', '2.5.4.5', printable('1'.repeat(65)), 65, 64],
            ['localityName', '2.5.4.7', utf8('l'.repeat(129)), 129, 128],
            ['stateOrProvinceName', '2.5.4.8', utf8('s'.repeat(129)), 129, 128],
            ['pseudonym', '2.5.4.65', utf8('p'.repeat(129)), 129, 128],
            ['emailAddress', '1.2.840.113549.1.9.1', ia5(`${'e'.repeat(250)}@x.example`), 260, 255],
            ['givenName', '2.5.4.42', utf8('g'.repeat(32769)), 32769, 32768],
        ])('should report a %s past its bound as information, naming the length and the bound', (attribute, type, value, characters, bound) => {
            const seen = diagnosticsOf(name([[type, value]]));
            expect(seen).toEqual([expect.objectContaining({
                code: 'PKI_DIAG_NAME_ATTRIBUTE_TOO_LONG', severity: 'info', path: 'name.rdns[0][0].value', standard: 'ITU-T X.520 / RFC 5280 Appendix A.1', offset: expect.any(Number),
            })]);
            expect(seen[0]?.message).toContain(`the ${attribute} is ${String(characters)} characters long`);
            expect(seen[0]?.message).toContain(`bounds it at ${String(bound)}`);
        });

        it.each<[string, string, Uint8Array]>([
            ['a commonName of exactly 64 characters', '2.5.4.3', utf8('a'.repeat(64))],
            ['a commonName of 64 two-octet characters, counted in characters', '2.5.4.3', utf8('é'.repeat(64))],
            ['an emailAddress of 255 characters', '1.2.840.113549.1.9.1', ia5(`${'e'.repeat(245)}@x.example`)],
            ['a dnQualifier of 300 characters, which Appendix A.1 leaves unbounded', '2.5.4.46', printable('q'.repeat(300))],
            ['a domainComponent of 300 characters, which Appendix A.1 leaves unbounded', '0.9.2342.19200300.100.1.25', ia5('d'.repeat(300))],
            ['a 300-character value of an attribute Appendix A.1 does not define', '2.5.4.9', utf8('s'.repeat(300))],
        ])('should accept %s silently', (_what, type, value) => {
            expect(diagnosticsOf(name([[type, value]]))).toEqual([]);
        });

        it('should report a commonName of 65 characters once, beside its string-type concern when both hold', () => {
            expect(diagnosticsOf(name([['2.5.4.3', ia5('a'.repeat(65))]])).map((d) => d.code))
                .toEqual(['PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE', 'PKI_DIAG_NAME_ATTRIBUTE_TOO_LONG']);
        });

        it('should not throw under strict, since the bound is information, and still report it', () => {
            const seen: string[] = [];
            const read = readName(name([['2.5.4.3', utf8('a'.repeat(65))]]), { strict: true, onDiagnostic: (d) => { seen.push(d.code); } });
            expect(read.rdns[0]?.[0]?.value?.value).toBe('a'.repeat(65));
            expect(seen).toEqual(['PKI_DIAG_NAME_ATTRIBUTE_TOO_LONG']);
        });
    });

    describe('countryName against ISO 3166-1', () => {
        it.each(['US', 'FR', 'GB', 'DE', 'TW', 'XK', 'AA', 'QM', 'QZ', 'XA', 'XZ', 'ZZ'])('should accept %s silently', (code) => {
            expect(diagnosticsOf(name([['2.5.4.6', printable(code)]]))).toEqual([]);
        });

        it.each([
            ['UK', 'exceptionally reserved, the assigned code being GB'],
            ['EU', 'exceptionally reserved'],
            ['AN', 'transitionally reserved, formerly assigned'],
            ['QL', 'just outside the user-assigned range'],
            ['ZY', 'just outside the user-assigned range'],
            ['fr', 'lower case'],
            ['Fr', 'mixed case'],
            ['12', 'digits'],
        ])('should report %s (%s) as information, quoting it', (code) => {
            const seen = diagnosticsOf(name([['2.5.4.6', printable(code)]]));
            expect(seen).toEqual([expect.objectContaining({
                code: 'PKI_DIAG_NAME_COUNTRY_UNKNOWN', severity: 'info', path: 'name.rdns[0][0].value', standard: 'ISO 3166-1:2020', offset: expect.any(Number),
            })]);
            expect(seen[0]?.message).toContain(`the countryName "${code}" is not an assigned ISO 3166-1 alpha-2 code`);
        });

        it('should report the size of a three-letter code, and not look it up', () => {
            expect(diagnosticsOf(name([['2.5.4.6', printable('FRA')]])).map((d) => d.code)).toEqual(['PKI_DIAG_COUNTRY_NAME_SIZE']);
        });

        it('should report a UTF8String UK for both its type and its code', () => {
            expect(diagnosticsOf(name([['2.5.4.6', utf8('UK')]])).map((d) => d.code))
                .toEqual(['PKI_DIAG_NAME_ATTRIBUTE_STRING_TYPE', 'PKI_DIAG_NAME_COUNTRY_UNKNOWN']);
        });

        it('should not throw under strict, since the code is information, and still report it', () => {
            const seen: string[] = [];
            expect(readName(name([['2.5.4.6', printable('UK')]]), { strict: true, onDiagnostic: (d) => { seen.push(d.code); } }).rdns).toHaveLength(1);
            expect(seen).toEqual(['PKI_DIAG_NAME_COUNTRY_UNKNOWN']);
        });
    });
});

describe('formatDistinguishedName', () => {
    const format = (bytes: Uint8Array): string => formatDistinguishedName(readName(bytes));

    it('should write RDNs in reverse encoded order (RFC 4514 §2.1)', () => {
        expect(format(name([['2.5.4.6', printable('US')]], [['2.5.4.10', utf8('Example')]], [['2.5.4.3', utf8('example.com')]])))
            .toBe('CN=example.com,O=Example,C=US');
    });

    it('should join the attributes of a multi-valued RDN with +', () => {
        expect(format(name([['2.5.4.11', utf8('A')], ['2.5.4.3', utf8('B')]]))).toBe('OU=A+CN=B');
    });

    it('should use every RFC 4514 §3 short name', () => {
        expect(format(name(
            [['0.9.2342.19200300.100.1.25', ia5('com')]],
            [['0.9.2342.19200300.100.1.1', utf8('u')]],
            [['2.5.4.7', utf8('l')]],
            [['2.5.4.8', utf8('s')]],
            [['2.5.4.9', utf8('st')]],
        ))).toBe('STREET=st,ST=s,L=l,UID=u,DC=com');
    });

    it.each<[string, string, string]>([
        ['the special characters', 'a,b+c"d;e<f>g\\h', 'CN=a\\,b\\+c\\"d\\;e\\<f\\>g\\\\h'],
        ['a leading space', ' x', 'CN=\\ x'],
        ['a leading number sign', '#x', 'CN=\\#x'],
        ['a trailing space', 'x ', 'CN=x\\ '],
        ['a single space', ' ', 'CN=\\ '],
        ['control characters', 'a\u0000b\u001bc\u007f', 'CN=a\\00b\\1bc\\7f'],
        ['a C1 control, as its UTF-8 octets', 'a\u009bb', 'CN=a\\c2\\9bb'],
        ['a bidirectional override', 'abc\u202edef', 'CN=abc\\e2\\80\\aedef'],
    ])('should escape %s (RFC 4514 §2.4)', (_, value, expected) => {
        expect(format(name([['2.5.4.3', utf8(value)]]))).toBe(expected);
    });

    // Each escaped class at its first and last code point and one past it, and
    // each UTF-8 width of hexpairs at a code point whose low bits a wrong mask
    // or shift would change.
    it.each<[string, string, string]>([
        ['U+001F, the last C0 control', 'a\u001fb', 'CN=a\\1fb'],
        ['U+007E, the last printable ASCII character, literally', 'a~b', 'CN=a~b'],
        ['U+0080, the first C1 control, as two octets', 'a\u0080b', 'CN=a\\c2\\80b'],
        ['U+009F, the last C1 control', 'a\u009fb', 'CN=a\\c2\\9fb'],
        ['U+00A0, past the C1 controls, literally', 'a b', 'CN=a b'],
        ['U+061C, the arabic letter mark, as two octets', 'a؜b', 'CN=a\\d8\\9cb'],
        ['U+200F, the right-to-left mark, as three octets', 'a‏b', 'CN=a\\e2\\80\\8fb'],
        ['U+2066, the left-to-right isolate, as three octets', 'a⁦b', 'CN=a\\e2\\81\\a6b'],
    ])('should write %s (RFC 4514 §2.4 hexpairs of the UTF-8 octets)', (_, value, expected) => {
        expect(format(name([['2.5.4.3', utf8(value)]]))).toBe(expected);
    });

    it('should leave a number sign inside a value and non-ASCII text as they are', () => {
        expect(format(name([['2.5.4.3', utf8('a#b Zoë')]]))).toBe('CN=a#b Zoë');
    });

    it('should write a type without a short name as its OID and the value as hex (RFC 4514 §2.4)', () => {
        expect(format(name([['2.5.4.5', printable('123')]]))).toBe('2.5.4.5=#1303313233');
    });

    it('should write a value that is not a character string as hex', () => {
        expect(format(name([['2.5.4.3', integer([5])]]))).toBe('CN=#020105');
    });

    it('should write an empty name as the empty string', () => {
        expect(format(name())).toBe('');
    });

    it.each<[string, unknown]>([
        ['null', null],
        ['a string', 'CN=x'],
        ['an object without rdns', {}],
        // Previously printed ",," instead of saying what was wrong.
        ['an rdns entry that is not an array of attributes', { rdns: [null] }],
        ['a sparse rdns array', { rdns: new Array<unknown>(3) }],
    ])('should refuse %s', (_, value) => {
        expect(codeOf(() => formatDistinguishedName(value as DistinguishedName))).toBe('PKI_INVALID_INPUT');
    });
});
