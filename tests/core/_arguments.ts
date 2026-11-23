import { expect } from 'vitest';
import { PkiError } from '../../src/types/pki-errors.js';

/**
 * What the `arguments.test.ts` suites of every layer share: the values an
 * argument can wrongly be, and the assertion that the answer to one is a
 * `PkiError` with `PKI_INVALID_INPUT` — never the `TypeError` of a property
 * read, which is what each of these calls ended in before its guard.
 */

/** The wrong types a caller without the type checker passes most. */
export const WRONG: ReadonlyArray<readonly [string, unknown]> = [
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['a string', 'x'],
];

/** One value of every type an argument or a member could wrongly be. */
export const HOSTILE: ReadonlyArray<readonly [string, unknown]> = [
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['a string', 'x'],
    ['a boolean', true],
    ['an object', {}],
    // What `String(value)` and a template literal both throw on.
    ['an object with no prototype', Object.create(null)],
    ['an array', []],
    ['bytes', new Uint8Array(0)],
    ['a function', (): undefined => undefined],
    // What a template literal throws on, and `JSON.stringify` after it.
    ['a symbol', Symbol('hostile')],
    ['a bigint', 1n],
];

type Path = ReadonlyArray<string | number>;

/**
 * The members at most `depth` levels below `value`: the own names of an object,
 * the first entry of an array. Bytes are a leaf, and so is anything frozen: a
 * reader's result is replaced whole, never edited — a parsed value altered by
 * hand is outside what the guards promise.
 */
function membersOf(value: unknown, depth: number): Path[] {
    if (depth === 0 || typeof value !== 'object' || value === null || ArrayBuffer.isView(value) || Object.isFrozen(value)) return [];
    const keys: Path = Array.isArray(value) ? (value.length > 0 ? [0] : []) : Object.keys(value);
    return keys.flatMap((key) => [[key], ...membersOf((value as Record<string | number, unknown>)[key], depth - 1).map((rest) => [key, ...rest])]);
}

/** `value` with what `path` leads to replaced by `by`: every object on the way is copied, the rest is shared. */
function replaced(value: unknown, path: Path, by: unknown): unknown {
    const [key, ...rest] = path;
    if (key === undefined) return by;
    if (Array.isArray(value)) return value.map((entry: unknown, index) => (index === key ? replaced(entry, rest, by) : entry));
    const source = value as Record<string | number, unknown>;
    return { ...source, [key]: replaced(source[key], rest, by) };
}

/**
 * Every way a valid call can be wrong in **one** place: each argument, each of
 * its members and each member of those, replaced in turn by each hostile value
 * while everything else stays valid — which is how a guard further down a
 * function is reached at all.
 *
 * @returns One line per distinct exception that is not a `PkiError`, with the first replacement that reached it.
 */
export async function wrongInOnePlace(fn: (...args: never[]) => unknown, args: readonly unknown[]): Promise<string[]> {
    const escaped = new Map<string, string>();
    for (const [index, argument] of args.entries()) {
        for (const path of [[], ...membersOf(argument, 2)]) {
            for (const [label, value] of HOSTILE) {
                const call = args.map((a, i) => (i === index ? replaced(a, path, value) : a));
                try {
                    await fn(...(call as never[]));
                } catch (error) {
                    if (error instanceof PkiError) continue;
                    const cause = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
                    if (!escaped.has(cause)) escaped.set(cause, `argument ${String(index)}${path.map((key) => `.${String(key)}`).join('')} = ${label}`);
                }
            }
        }
    }
    return [...escaped].map(([cause, where]) => `${cause} — first by ${where}`);
}

/** What a caller without the type checker passes for `true` or `false`. */
export const NOT_FLAGS: ReadonlyArray<readonly [string, unknown]> = [
    ['the text "true"', 'true'],
    ['the text "false"', 'false'],
    ['one', 1],
    ['zero', 0],
    ['null', null],
    ['an object', {}],
];

/** What stands where an object, a list or bytes are expected only by mistake. */
export const NOT_OBJECTS: ReadonlyArray<readonly [string, unknown]> = [
    ['a number', 42],
    ['a string', 'x'],
    ['a boolean', true],
    ['a bigint', 1n],
    ['a symbol', Symbol('not an object')],
];

/**
 * The places of a valid call where a wrong value is **taken**: each argument
 * and member `concerns` selects is replaced in turn by each value of `by`, and
 * a call that then returns — or throws anything but a `PkiError` — is one line.
 *
 * `wrongInOnePlace` proves no `TypeError` escapes; this proves the refusal
 * happens at all, for the kinds of value nothing else could stand for — and,
 * when `code` is given, that it carries that code.
 *
 * @returns One line per place and replacement that was not refused, or was refused with another code.
 */
export async function takenInOnePlace(
    fn: (...args: never[]) => unknown,
    args: readonly unknown[],
    concerns: (value: unknown) => boolean,
    by: ReadonlyArray<readonly [string, unknown]>,
    code?: string,
): Promise<string[]> {
    const taken: string[] = [];
    for (const [index, argument] of args.entries()) {
        for (const path of [[], ...membersOf(argument, 2)]) {
            const valid = path.reduce<unknown>((at, key) => (at as Record<string | number, unknown>)[key], argument);
            if (!concerns(valid)) continue;
            for (const [label, value] of by) {
                const call = args.map((a, i) => (i === index ? replaced(a, path, value) : a));
                const error = await refusal(() => fn(...(call as never[])));
                const where = `argument ${String(index)}${path.map((key) => `.${String(key)}`).join('')} = ${label}`;
                if (!(error instanceof PkiError)) taken.push(where);
                else if (code !== undefined && error.code !== code) taken.push(`${where}: refused with ${error.code}, not ${code}`);
            }
        }
    }
    return taken;
}

/** What `call` throws or rejects with, or `undefined` when it does neither. */
export async function refusal(call: () => unknown): Promise<unknown> {
    try {
        await call();
    } catch (error) {
        return error;
    }
    return undefined;
}

/** Assert that `call` is refused with a `PkiError` of the given code. */
export async function expectCode(call: () => unknown, code: string): Promise<void> {
    const error = await refusal(call);
    expect(error).toBeInstanceOf(PkiError);
    expect(error).toEqual(expect.objectContaining({ code }));
}

/** Assert that `call` is refused with `PKI_INVALID_INPUT`. */
export async function expectInvalid(call: () => unknown): Promise<void> {
    await expectCode(call, 'PKI_INVALID_INPUT');
}
