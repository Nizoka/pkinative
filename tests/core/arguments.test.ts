import { describe, expect, it } from 'vitest';
import {
    A_CERTIFICATE, assertArray, assertCertificate, assertCertificates, assertFlag, assertFlags, assertInstant, assertIterable, assertObject, assertOptionFlags, assertOptions, assertParsed,
    assertParsedList, assertReiterable, assertString, describeValue, listOf,
} from '../../src/core/arguments.js';
import { PkiError } from '../../src/types/pki-errors.js';

const INVALID = expect.objectContaining({ code: 'PKI_INVALID_INPUT' }) as unknown;

/** Every kind of value an argument can wrongly be, bar the one the guard under test accepts. */
const VALUES: ReadonlyArray<readonly [string, unknown]> = [
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['a string', 'x'],
    ['a boolean', true],
    ['an object', {}],
    ['an array', []],
    ['a function', (): undefined => undefined],
    ['a symbol', Symbol('s')],
];
const except = (...labels: readonly string[]): ReadonlyArray<readonly [string, unknown]> => VALUES.filter(([label]) => !labels.includes(label));

describe('describeValue', () => {
    it('should give a primitive its own text', () => {
        expect(describeValue('SHA-1')).toBe('SHA-1');
        expect(describeValue(42)).toBe('42');
        expect(describeValue(7n)).toBe('7');
        expect(describeValue(true)).toBe('true');
        expect(describeValue(undefined)).toBe('undefined');
    });

    it('should name null, and not call it an object', () => {
        expect(describeValue(null)).toBe('null');
    });

    it('should name the kind of what has no text of its own', () => {
        expect(describeValue({})).toBe('an object');
        expect(describeValue([1, 2])).toBe('an array');
        expect(describeValue(new Uint8Array(2))).toBe('an object');
        expect(describeValue((): undefined => undefined)).toBe('a function');
        expect(describeValue(Symbol('s'))).toBe('a symbol');
    });

    it('should describe an object with no prototype, which String() throws on', () => {
        const bare: unknown = Object.create(null);
        expect(() => String(bare)).toThrow(TypeError);
        expect(describeValue(bare)).toBe('an object');
    });
});

describe('assertObject', () => {
    it('should accept an object, an array and bytes', () => {
        expect(() => { assertObject({}, 'input'); }).not.toThrow();
        expect(() => { assertObject([], 'input'); }).not.toThrow();
        expect(() => { assertObject(new Uint8Array(1), 'input'); }).not.toThrow();
        expect(() => { assertObject(Object.create(null), 'input'); }).not.toThrow();
    });

    it.each(except('an object', 'an array'))('should refuse %s', (_label, value) => {
        expect(() => { assertObject(value, 'input'); }).toThrow(PkiError);
        expect(() => { assertObject(value, 'input'); }).toThrow(INVALID);
    });
});

describe('assertArray', () => {
    it('should accept an array, empty or not', () => {
        expect(() => { assertArray([], 'names'); }).not.toThrow();
        expect(() => { assertArray([1], 'names'); }).not.toThrow();
    });

    it.each([...except('an array'), ['bytes', new Uint8Array(1)], ['a Set', new Set([1])]] as const)('should refuse %s', (_label, value) => {
        expect(() => { assertArray(value, 'names'); }).toThrow(PkiError);
        expect(() => { assertArray(value, 'names'); }).toThrow(INVALID);
    });
});

describe('assertIterable', () => {
    it('should accept an array, a Set, a string and a generator', () => {
        expect(() => { assertIterable([], 'bits'); }).not.toThrow();
        expect(() => { assertIterable(new Set([1]), 'bits'); }).not.toThrow();
        expect(() => { assertIterable('ab', 'bits'); }).not.toThrow();
        expect(() => { assertIterable((function* (): Generator<number> { yield 1; })(), 'bits'); }).not.toThrow();
    });

    it.each(except('a string', 'an array'))('should refuse %s', (_label, value) => {
        expect(() => { assertIterable(value, 'bits'); }).toThrow(PkiError);
        expect(() => { assertIterable(value, 'bits'); }).toThrow(INVALID);
    });

    it('should refuse an object whose Symbol.iterator is not a function', () => {
        expect(() => { assertIterable({ [Symbol.iterator]: 1 }, 'bits'); }).toThrow(INVALID);
    });
});

describe('assertString', () => {
    it('should accept a string, the empty one included', () => {
        expect(() => { assertString('', 'name'); }).not.toThrow();
        expect(() => { assertString('example.com', 'name'); }).not.toThrow();
    });

    it.each(except('a string'))('should refuse %s', (_label, value) => {
        expect(() => { assertString(value, 'name'); }).toThrow(PkiError);
        expect(() => { assertString(value, 'name'); }).toThrow(INVALID);
    });
});

describe('assertCertificate', () => {
    const der = Uint8Array.of(0x30, 0x00);
    const parsed = { der, subject: { der }, issuer: { der }, extensions: [] };

    it('should accept what carries the members every reader of a certificate goes to first', () => {
        expect(() => { assertCertificate(parsed, 'leaf'); }).not.toThrow();
    });

    it.each(VALUES)('should refuse %s', (_label, value) => {
        expect(() => { assertCertificate(value, 'leaf'); }).toThrow(PkiError);
        expect(() => { assertCertificate(value, 'leaf'); }).toThrow(INVALID);
    });

    it.each([
        ['its DER', { ...parsed, der: undefined }],
        ['a DER that is not bytes', { ...parsed, der: [0x30, 0x00] }],
        ['its subject', { ...parsed, subject: undefined }],
        ['a subject with no encoding', { ...parsed, subject: {} }],
        ['its issuer', { ...parsed, issuer: undefined }],
        ['an issuer with no encoding', { ...parsed, issuer: {} }],
        ['its extensions', { ...parsed, extensions: undefined }],
        ['extensions that are not a list', { ...parsed, extensions: {} }],
    ] as const)('should refuse a value without %s', (_label, value) => {
        expect(() => { assertCertificate(value, 'leaf'); }).toThrow(INVALID);
    });

    it('should refuse the DER of a certificate, which is what gets passed by mistake', () => {
        expect(() => { assertCertificate(der, 'leaf'); }).toThrow(INVALID);
    });
});

describe('assertCertificates', () => {
    const der = Uint8Array.of(0x30, 0x00);
    const parsed = { der, subject: { der }, issuer: { der }, extensions: [] };

    it('should accept a list of certificates, and the empty list', () => {
        expect(() => { assertCertificates([], 'trustAnchors'); }).not.toThrow();
        expect(() => { assertCertificates([parsed, parsed], 'trustAnchors'); }).not.toThrow();
    });

    it.each(except('an array'))('should refuse %s where the list is expected', (_label, value) => {
        expect(() => { assertCertificates(value, 'trustAnchors'); }).toThrow(INVALID);
    });

    it('should refuse a single certificate that is not in a list', () => {
        expect(() => { assertCertificates(parsed, 'trustAnchors'); }).toThrow(INVALID);
    });

    it('should name the entry that is not a certificate', () => {
        let caught: unknown;
        try { assertCertificates([parsed, parsed, der], 'trustAnchors'); } catch (error) { caught = error; }
        expect(caught).toBeInstanceOf(PkiError);
        expect(caught).toEqual(INVALID);
        // The index is the remedy: which of the caller's entries to look at.
        expect((caught as PkiError).message).toContain('trustAnchors[2]');
    });
});

describe('assertInstant', () => {
    const NOT_INSTANTS: ReadonlyArray<readonly [string, unknown]> = [...except('a number'), ['NaN', Number.NaN], ['Infinity', Infinity], ['a Date', new Date(0)], ['a bigint', 1n]];

    it.each(NOT_INSTANTS)('should refuse %s', (_label, value) => {
        expect(() => { assertInstant(value, 'at'); }).toThrow(INVALID);
    });

    it.each([0, -1, 1.5, Date.UTC(2026, 0, 1)])('should accept %d', (value) => {
        expect(() => { assertInstant(value, 'at'); }).not.toThrow();
    });
});

describe('listOf', () => {
    it('should give an empty list for what was left out', () => {
        expect(listOf(undefined, 'crls')).toEqual([]);
    });

    it('should give the array it was given', () => {
        const list = [1, 2];
        expect(listOf(list, 'crls')).toBe(list);
    });

    it.each(except('undefined', 'null', 'an array'))('should refuse %s', (_label, value) => {
        expect(() => listOf(value as never, 'crls')).toThrow(INVALID);
    });
});

describe('assertParsed', () => {
    const BYTES = Uint8Array.of(1);

    it.each(VALUES)('should refuse %s', (_label, value) => {
        expect(() => { assertParsed(value, 'leaf', A_CERTIFICATE, ['der']); }).toThrow(INVALID);
    });

    it('should accept a value whose named members are bytes, however deep', () => {
        expect(() => { assertParsed({ der: BYTES, subject: { der: BYTES }, key: { bits: { bytes: BYTES } } }, 'leaf', A_CERTIFICATE, ['der', 'subject.der', 'key.bits.bytes']); }).not.toThrow();
    });

    it('should ask for nothing it was not told to read', () => {
        expect(() => { assertParsed({ subject: { der: BYTES } }, 'leaf', A_CERTIFICATE, ['subject.der']); }).not.toThrow();
    });

    it.each([
        ['a member that is missing', { subject: { der: BYTES } }],
        ['a member that is not bytes', { der: 'x', subject: { der: BYTES } }],
        ['a path that stops at undefined', { der: BYTES }],
        ['a path that stops at null', { der: BYTES, subject: null }],
        ['a path that goes through a number', { der: BYTES, subject: 42 }],
        ['a last member that is not bytes', { der: BYTES, subject: { der: [1] } }],
    ])('should refuse %s', (_label, value) => {
        expect(() => { assertParsed(value, 'leaf', A_CERTIFICATE, ['der', 'subject.der']); }).toThrow(INVALID);
    });

    it('should name the argument and what it must be, never the value', () => {
        expect(() => { assertParsed(Object.create(null), 'leaf', A_CERTIFICATE, ['der']); }).toThrow(expect.objectContaining({ message: expect.stringContaining('leaf must be a certificate from parseCertificate') as unknown }));
    });
});

describe('assertParsedList', () => {
    const BYTES = Uint8Array.of(1);

    it.each(except('an array'))('should refuse %s where the list is expected', (_label, value) => {
        expect(() => { assertParsedList(value, 'path', A_CERTIFICATE, ['der']); }).toThrow(INVALID);
    });

    it('should accept an empty list, and a list of values that have the members', () => {
        expect(() => { assertParsedList([], 'path', A_CERTIFICATE, ['der']); }).not.toThrow();
        expect(() => { assertParsedList([{ der: BYTES }, { der: BYTES }], 'path', A_CERTIFICATE, ['der']); }).not.toThrow();
    });

    it('should refuse the first entry that lacks one, and say which', () => {
        expect(() => { assertParsedList([{ der: BYTES }, {}], 'path', A_CERTIFICATE, ['der']); }).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT', message: expect.stringContaining('path[1]') as unknown }));
    });
});

describe('assertReiterable', () => {
    it.each(except('a string', 'an array'))('should refuse %s, which cannot be iterated', (_label, value) => {
        expect(() => { assertReiterable(value, 'candidates'); }).toThrow(INVALID);
    });

    it('should accept what can be read twice: an array, a Set', () => {
        expect(() => { assertReiterable([1], 'candidates'); }).not.toThrow();
        expect(() => { assertReiterable(new Set([1]), 'candidates'); }).not.toThrow();
    });

    it('should refuse an iterator, which the first reading spends, and leave it unread', () => {
        const once = (function* (): Generator<number> { yield 1; })();
        expect(() => { assertReiterable(once, 'candidates'); }).toThrow(INVALID);
        expect([...once]).toEqual([1]);
    });
});

const OPTION = expect.objectContaining({ code: 'PKI_INVALID_OPTION' }) as unknown;

describe('assertOptions', () => {
    it.each(except('undefined', 'an object', 'an array'))('should refuse %s, whose options would all read as absent', (_label, value) => {
        expect(() => { assertOptions(value, 'options'); }).toThrow(OPTION);
        expect(() => { assertOptions(value, 'options'); }).toThrow(PkiError);
    });

    it('should name the argument and what it was given', () => {
        expect(() => { assertOptions(null, 'options'); }).toThrow(/options/);
    });

    it('should accept options left out, and an object', () => {
        expect(() => { assertOptions(undefined, 'options'); }).not.toThrow();
        expect(() => { assertOptions({}, 'options'); }).not.toThrow();
    });
});

describe('assertFlag', () => {
    it.each([['the text "true"', 'true'], ['the text "false"', 'false'], ['one', 1], ['zero', 0], ['null', null], ['an object', {}]] as const)('should refuse %s, which only reads as a boolean', (_label, value) => {
        expect(() => { assertFlag(value, 'requireRevocation'); }).toThrow(OPTION);
        expect(() => { assertFlag(value, 'requireRevocation'); }).toThrow(PkiError);
    });

    it('should accept true, false and a flag left out', () => {
        for (const value of [true, false, undefined]) expect(() => { assertFlag(value, 'requireRevocation'); }).not.toThrow();
    });

    it('should name the flag it refuses', () => {
        expect(() => { assertFlag('true', 'requireRevocation'); }).toThrow(/requireRevocation/);
    });
});

describe('assertFlags', () => {
    it('should accept an owner left out, without reading a flag from it', () => {
        expect(() => { assertFlags(undefined, 'options', ['allowSha1']); }).not.toThrow();
    });

    it.each(except('undefined', 'an object', 'an array'))('should refuse %s as the owner', (_label, value) => {
        expect(() => { assertFlags(value, 'options', ['allowSha1']); }).toThrow(INVALID);
    });

    it('should refuse the first named flag that is not a boolean, and only a named one', () => {
        expect(() => { assertFlags({ allowSha1: false, requireRevocation: 'true' }, 'input', ['allowSha1', 'requireRevocation']); }).toThrow(OPTION);
        expect(() => { assertFlags({ allowSha1: 'no' }, 'input', ['allowSha1', 'requireRevocation']); }).toThrow(/allowSha1/);
        expect(() => { assertFlags({ other: 'true' }, 'input', ['allowSha1']); }).not.toThrow();
    });

    it('should accept every named flag as a boolean or left out', () => {
        expect(() => { assertFlags({ allowSha1: true }, 'input', ['allowSha1', 'requireRevocation']); }).not.toThrow();
    });
});

describe('assertOptionFlags', () => {
    it.each(except('undefined', 'an object', 'an array'))('should refuse %s as the options, with the code of an option', (_label, value) => {
        expect(() => { assertOptionFlags(value, ['allowSha1']); }).toThrow(OPTION);
    });

    it('should refuse a named flag that is not a boolean', () => {
        expect(() => { assertOptionFlags({ allowSha1: 'true' }, ['allowSha1']); }).toThrow(OPTION);
        expect(() => { assertOptionFlags({ allowSha1: 'true' }, ['allowSha1']); }).toThrow(/allowSha1/);
    });

    it('should accept options left out, and flags that are booleans', () => {
        expect(() => { assertOptionFlags(undefined, ['allowSha1']); }).not.toThrow();
        expect(() => { assertOptionFlags({ allowSha1: true }, ['allowSha1']); }).not.toThrow();
    });
});
