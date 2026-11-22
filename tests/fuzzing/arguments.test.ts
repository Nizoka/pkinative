import { describe, expect, it } from 'vitest';
import * as api from '../../src/index.js';
import { PkiError } from '../../src/index.js';
import { HOSTILE } from '../core/_arguments.js';

/**
 * Arguments of the wrong type, on every export.
 *
 * The other fuzzing suites hand hostile **bytes** to the readers. This one
 * hands hostile **JavaScript values** to every function `src/index.ts`
 * exports, because a caller without the type checker — a CommonJS script, a
 * satellite forwarding what a model wrote — passes `undefined` where an input
 * object is expected, or an object whose members are not what the type says.
 * Each call must end the way every other one does: a returned value, or a
 * thrown `PkiError` whose code and message name the remedy. A `TypeError`
 * from a property read on `undefined` names neither.
 *
 * The list of functions is read from the entry point, so an export added
 * later is covered the day it is added. Three depths are tried: the argument
 * itself is of the wrong type; the argument is an object every member of
 * which is; and every member of every member is — an option nested in an
 * input, a field of a parsed value.
 */

type Callable = (...args: readonly unknown[]) => unknown;

const BYTES = new Uint8Array(0);

/** An object whose every named member is `value`; it is not iterable. */
const withEveryMember = (value: unknown): object => new Proxy({}, {
    get: (_target, key) => (typeof key === 'symbol' ? undefined : value),
});

/** The calls each function receives: a label for the failure message, and the arguments. */
const CALLS: ReadonlyArray<readonly [string, readonly unknown[]]> = [
    ['no argument', []],
    ...HOSTILE.flatMap(([label, value]): Array<readonly [string, readonly unknown[]]> => {
        const members = withEveryMember(value);
        const nested = withEveryMember(members);
        return [
            [`(${label})`, [value]],
            [`(${label}, ${label})`, [value, value]],
            [`(bytes, ${label})`, [BYTES, value]],
            [`({}, ${label})`, [{}, value]],
            [`(bytes, bytes, ${label})`, [BYTES, BYTES, value]],
            [`([${label}])`, [[value]]],
            [`({ every member: ${label} })`, [members]],
            [`({ every member: ${label} }) twice`, [members, members]],
            [`({ every member: ${label} }) three times`, [members, members, members]],
            [`(bytes, { every member: ${label} })`, [BYTES, members]],
            [`([{ every member: ${label} }])`, [[members]]],
            [`({ every member: { every member: ${label} } })`, [nested]],
            [`({ every member: { every member: ${label} } }) twice`, [nested, nested]],
            [`(bytes, { every member: { every member: ${label} } })`, [BYTES, nested]],
        ];
    }),
];

/** The `PkiError` family is the only thing the entry point exports that is called with `new`. */
const isErrorClass = (value: unknown): boolean => (value as { readonly prototype?: unknown }).prototype instanceof Error;

const FUNCTIONS: ReadonlyArray<readonly [string, Callable]> = Object.entries(api as Readonly<Record<string, unknown>>)
    .filter(([, value]) => typeof value === 'function' && !isErrorClass(value))
    .map(([name, value]): readonly [string, Callable] => [name, value as Callable])
    .sort(([a], [b]) => (a < b ? -1 : 1));

describe('arguments of the wrong type', () => {
    it('should find the functions of the entry point', () => {
        expect(FUNCTIONS.length).toBeGreaterThan(100);
    });

    it.each(FUNCTIONS)('%s should return, or throw a PkiError', async (_name, fn) => {
        // One line per distinct cause, with the first call that reached it:
        // the failure message is the worklist, and stays short.
        const escaped = new Map<string, string>();
        for (const [label, args] of CALLS) {
            try {
                await fn(...args);
            } catch (error) {
                if (error instanceof PkiError) continue;
                const cause = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
                if (!escaped.has(cause)) escaped.set(cause, label);
            }
        }
        const report = [...escaped].map(([cause, label]) => `${cause} — first by ${label}`);
        expect(report, report.join('\n')).toEqual([]);
    });
});
