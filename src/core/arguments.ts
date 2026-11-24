/**
 * pkinative — Argument guards
 * ===========================
 * What a function is given is refused here when it is not of the JavaScript
 * type its signature names, before the first property is read from it. The
 * type checker does this for a TypeScript caller and for nobody else: a
 * CommonJS script, or a satellite forwarding what a model wrote, passes
 * `undefined` where an input object is expected, and without these guards the
 * answer is a `TypeError` from a property read — no code, no remedy.
 *
 * Three levels, and no further: an argument, its members, and the members of
 * those — an option nested in an input, a field of `expected` — are each
 * refused when they are not of the type the signature names, at the point the
 * function first reads them. A value one of this library's readers made is
 * the exception: it is told by the bytes the function reads from it, never
 * walked, and a value built or edited by hand to pass for one is outside what
 * any guard here promises.
 *
 * `assertBytes` is the fourth guard, and lives with the bytes it describes
 * (`core/bytes`).
 *
 * @module core/arguments
 */

import { PkiError } from '../types/pki-errors.js';
import type { Certificate } from '../types/x509-types.js';
import { isBytes } from './bytes.js';

/**
 * How a value is named in a message, without ever throwing: `String(value)`
 * does, for an object with no prototype, and a message that cannot be built
 * hides the refusal it was meant to explain.
 *
 * @param value Anything a caller passed.
 * @returns The value's text for a primitive, its kind for anything else.
 */
export function describeValue(value: unknown): string {
    if (value === null) return 'null';
    if (typeof value === 'object') return Array.isArray(value) ? 'an array' : 'an object';
    if (typeof value === 'function' || typeof value === 'symbol') return `a ${typeof value}`;
    return String(value);
}

const refuse = (what: string, expected: string, value: unknown, remedy: string): PkiError =>
    new PkiError('PKI_INVALID_INPUT', `pkinative: ${what} must be ${expected}, got ${describeValue(value)} — ${remedy}`);

/**
 * Refuse what is not an object: `undefined`, `null`, a primitive, a function.
 *
 * @param value What the caller passed.
 * @param what  The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `value` is not an object.
 */
export function assertObject(value: unknown, what: string): asserts value is object {
    if (typeof value !== 'object' || value === null) {
        throw refuse(what, 'an object', value, 'pass the object the function documents, with its required members');
    }
}

/**
 * Refuse what is not an array.
 *
 * @param value What the caller passed.
 * @param what  The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `value` is not an array.
 */
export function assertArray(value: unknown, what: string): asserts value is readonly unknown[] {
    if (!Array.isArray(value)) {
        throw refuse(what, 'an array', value, 'pass an array, even for a single entry');
    }
}

/**
 * Refuse what cannot be iterated.
 *
 * @param value What the caller passed.
 * @param what  The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `value` has no iterator.
 */
export function assertIterable(value: unknown, what: string): asserts value is Iterable<unknown> {
    if (value === null || value === undefined || typeof (value as Partial<Iterable<unknown>>)[Symbol.iterator] !== 'function') {
        throw refuse(what, 'iterable', value, 'pass an array or a Set');
    }
}

/**
 * Refuse what cannot be iterated more than once: a list a function reads
 * twice. An iterator — a generator's — is spent by the first reading, and the
 * second would find an empty list where the caller passed a full one.
 *
 * @param value What the caller passed.
 * @param what  The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `value` has no iterator, or is one.
 */
export function assertReiterable(value: unknown, what: string): asserts value is Iterable<unknown> {
    assertIterable(value, what);
    if ((value[Symbol.iterator]() as unknown) === value) {
        throw refuse(what, 'an array or a Set', value, 'pass the list itself, not an iterator over it');
    }
}

/**
 * Refuse what is not a string.
 *
 * @param value What the caller passed.
 * @param what  The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `value` is not a string.
 */
export function assertString(value: unknown, what: string): asserts value is string {
    if (typeof value !== 'string') {
        throw refuse(what, 'a string', value, 'pass text, not bytes or an object');
    }
}

/**
 * Refuse what is not an instant: a finite number of milliseconds since the
 * epoch. A `Date` is refused with the rest — compared, it reads as its time;
 * added to a tolerance, as text, and the check it was passed for stops firing.
 *
 * @param value What the caller passed.
 * @param what  The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `value` is not a finite number.
 */
export function assertInstant(value: unknown, what: string): asserts value is number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw refuse(what, 'a finite number of milliseconds since the epoch', value, 'pass Date.now() or date.getTime(), not a Date or a string');
    }
}

/**
 * The list a caller may leave out: an empty one when it is, the array given
 * when it is one.
 *
 * @param value What the caller passed, or nothing.
 * @param what  The member's name, as the message gives it.
 * @returns The array, or an empty one.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `value` is given and is not an array.
 */
export function listOf<T>(value: readonly T[] | undefined, what: string): readonly T[] {
    const list: unknown = value ?? [];
    assertArray(list, what);
    return list as readonly T[];
}

/** How a message names what `parseCertificate` returns. */
export const A_CERTIFICATE = 'a certificate from parseCertificate';

/**
 * Refuse what is not a value one of this library's readers made, told by the
 * bytes the calling function reads from it — and by nothing it does not read,
 * so a value that served a function before its guard still does.
 *
 * @param value   What the caller passed.
 * @param what    The argument's name, as the message gives it.
 * @param made    What it must be, as the message gives it: `A_CERTIFICATE`.
 * @param bytesAt The members that must be bytes, each a dotted path from `value`.
 * @throws {PkiError} `PKI_INVALID_INPUT` when one of them is not.
 */
export function assertParsed(value: unknown, what: string, made: string, bytesAt: readonly string[]): void {
    for (const path of bytesAt) {
        let at = value;
        for (const name of path.split('.')) {
            at = typeof at === 'object' && at !== null ? (at as Readonly<Record<string, unknown>>)[name] : undefined;
        }
        if (!isBytes(at)) {
            throw new PkiError('PKI_INVALID_INPUT', `pkinative: ${what} must be ${made} — pass the parsed value, not its DER`);
        }
    }
}

/**
 * Refuse what is not an array of values a reader made, naming the first entry
 * that is not one.
 *
 * @param values  What the caller passed.
 * @param what    The argument's name, as the message gives it.
 * @param made    What each entry must be, as the message gives it.
 * @param bytesAt The members of each entry that must be bytes; see {@link assertParsed}.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `values` is not an array, or an entry is not such a value.
 */
export function assertParsedList(values: unknown, what: string, made: string, bytesAt: readonly string[]): asserts values is readonly unknown[] {
    assertArray(values, what);
    for (const [index, value] of values.entries()) assertParsed(value, `${what}[${String(index)}]`, made, bytesAt);
}

/**
 * Refuse what is not a certificate `parseCertificate` made, by the four
 * members the compositions of `verify/` have asked for since 1.0.0.
 *
 * @param value What the caller passed.
 * @param what  The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `value` is not a parsed certificate.
 */
export function assertCertificate(value: unknown, what: string): asserts value is Certificate {
    const candidate = value as Partial<Certificate> | null;
    if (typeof value !== 'object' || candidate === null
        || !isBytes(candidate.der)
        || !isBytes(candidate.subject?.der)
        || !isBytes(candidate.issuer?.der)
        || !Array.isArray(candidate.extensions)) {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: ${what} must be a certificate from parseCertificate — pass the parsed value, not its DER`);
    }
}

/**
 * Refuse what is not an array of certificates `parseCertificate` made, naming
 * the first entry that is not one.
 *
 * @param values What the caller passed.
 * @param what   The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `values` is not an array, or an entry is not a parsed certificate.
 */
export function assertCertificates(values: unknown, what: string): asserts values is readonly Certificate[] {
    assertArray(values, what);
    for (const [index, value] of values.entries()) assertCertificate(value, `${what}[${String(index)}]`);
}

/**
 * Refuse an options argument that is given and is not an object. A number or
 * a string has members too — every one of them `undefined` — so each option
 * read from it is absent, and the call goes on as if none had been passed.
 *
 * @param value What the caller passed, or nothing.
 * @param what  The argument's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_OPTION` when `value` is given and is not an object — the code the readers have given since 1.0.0.
 */
export function assertOptions(value: unknown, what: string): void {
    if (value !== undefined && (typeof value !== 'object' || value === null)) throw new PkiError('PKI_INVALID_OPTION', `pkinative: ${what} must be an object, got ${describeValue(value)} — pass an object of the options the function documents, or omit it`);
}

/**
 * Refuse a flag that is given and is not a boolean. Read as `=== true`, the
 * text `'true'` leaves a check off without a word; read as truthy, the text
 * `'false'` turns one on.
 *
 * @param value What the caller passed, or nothing.
 * @param what  The flag's name, as the message gives it.
 * @throws {PkiError} `PKI_INVALID_OPTION` when `value` is given and is not a boolean.
 */
export function assertFlag(value: unknown, what: string): void {
    if (value !== undefined && typeof value !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: ${what} must be a boolean, got ${typeof value} — pass true or false, not a value that reads as one`);
    }
}

/**
 * Refuse the object that carries a function's flags when it is given and is
 * not an object, then each of its flags that is not a boolean.
 *
 * @param owner What the caller passed for the options or the input, or nothing.
 * @param what  The argument's name, as the message gives it.
 * @param names The flags it may carry.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `owner` is given and is not an object;
 *   `PKI_INVALID_OPTION` when one of the flags is given and is not a boolean.
 */
export function assertFlags(owner: unknown, what: string, names: readonly string[]): void {
    if (owner === undefined) return;
    assertObject(owner, what);
    for (const name of names) assertFlag((owner as Readonly<Record<string, unknown>>)[name], name);
}

/**
 * Refuse an options argument that is given and is not an object, then each
 * of its flags that is not a boolean: `assertOptions`, then `assertFlags`.
 *
 * @param options What the caller passed for the options, or nothing.
 * @param names   The flags it may carry.
 * @throws {PkiError} `PKI_INVALID_OPTION` when `options` is given and is not an object, or when one of the flags is given and is not a boolean.
 */
export function assertOptionFlags(options: unknown, names: readonly string[]): void {
    assertOptions(options, 'options');
    assertFlags(options, 'options', names);
}
