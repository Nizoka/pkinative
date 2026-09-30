import { describe, expect, it } from 'vitest';
import * as pkinative from '../../src/index.js';

/**
 * Every constant the entry point exports is shared by every caller in the
 * process, so none may be changeable at runtime: one caller (or a compromised
 * dependency) must not be able to change what the library accepts for every
 * other. `readonly` in a type is a promise to the compiler only; this suite
 * holds the runtime to it, deeply.
 */

type Mutator = 'set' | 'delete' | 'clear' | 'add';

function assertDeeplyImmutable(value: unknown, path: string, seen: Set<unknown>): void {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return;
    if (seen.has(value)) return;
    seen.add(value);
    expect(Object.isFrozen(value), `${path} is not frozen`).toBe(true);
    if (value instanceof Map || value instanceof Set) {
        const collection = value as unknown as Record<Mutator, (...args: unknown[]) => unknown>;
        const mutators: readonly Mutator[] = value instanceof Map ? ['set', 'delete', 'clear'] : ['add', 'delete', 'clear'];
        for (const mutator of mutators) {
            expect(() => collection[mutator]('__probe__', 0), `${path}.${mutator} does not throw`).toThrow();
        }
        for (const [k, v] of value instanceof Map ? value : [...value].map((v) => [v, v] as const)) {
            assertDeeplyImmutable(k, `${path}[key]`, seen);
            assertDeeplyImmutable(v, `${path}[${String(k)}]`, seen);
        }
        return;
    }
    for (const key of Reflect.ownKeys(value)) {
        assertDeeplyImmutable((value as Record<PropertyKey, unknown>)[key], `${path}.${String(key)}`, seen);
    }
}

describe('exported constants', () => {
    const constants = Object.entries(pkinative).filter(([, value]) => typeof value !== 'function');

    it('should export at least the tables this suite was written for', () => {
        const names = constants.map(([name]) => name);
        expect(names).toEqual(expect.arrayContaining(['DEFAULT_PKI_LIMITS', 'KEY_PURPOSES', 'KEY_USAGE_BITS', 'OID_REGISTRY']));
    });

    it.each(constants)('should keep %s immutable at runtime, all the way down', (name, value) => {
        assertDeeplyImmutable(value, name, new Set());
    });
});
