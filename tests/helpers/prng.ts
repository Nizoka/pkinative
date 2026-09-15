/**
 * Seeded pseudo-random generator for the fuzzing and property suites
 * (mulberry32). Deterministic: a failure reproduces from its printed seed.
 * Never imports src/.
 */

export interface Prng {
    readonly seed: number;
    /** A float in [0, 1). */
    next(): number;
    /** An integer in [0, maxExclusive). */
    int(maxExclusive: number): number;
    /** `n` random octets. */
    bytes(n: number): Uint8Array;
    /** One element of a non-empty list. */
    pick<T>(items: readonly T[]): T;
}

export function createPrng(seed: number): Prng {
    let state = seed >>> 0;
    const next = (): number => {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const int = (maxExclusive: number): number => Math.floor(next() * maxExclusive);
    return {
        seed,
        next,
        int,
        bytes: (n) => Uint8Array.from({ length: n }, () => int(256)),
        pick: <T>(items: readonly T[]): T => {
            const item = items[int(items.length)];
            if (item === undefined) throw new Error('prng.pick: empty list');
            return item;
        },
    };
}
