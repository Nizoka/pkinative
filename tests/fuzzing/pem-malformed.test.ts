import { describe, it, expect } from 'vitest';
import { decodePem, encodePem } from '../../src/pem/pem.js';
import { createPrng } from '../helpers/prng.js';
import { outcome } from './_harness.js';

const SOURCE = encodePem('CERTIFICATE', Uint8Array.from({ length: 300 }, (_, i) => (i * 7) & 0xff))
    + encodePem('PRIVATE KEY', Uint8Array.of(1, 2, 3));
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=- :\r\n\té';

describe('fuzzing — malformed PEM', () => {
    it('should end 10 000 seeded mutations of a two-block text in blocks or a PkiError, in both modes', () => {
        const seed = 0x5eed_0008;
        const rng = createPrng(seed);
        const outcomes = new Map<string, number>();
        for (let iteration = 0; iteration < 10_000; iteration++) {
            const chars = [...SOURCE];
            for (let e = 0, edits = 1 + rng.int(4); e < edits; e++) {
                const at = rng.int(chars.length + 1);
                const kind = rng.int(3);
                if (kind === 0 && at < chars.length) chars[at] = rng.pick([...ALPHABET]);
                else if (kind === 1) chars.splice(at, 0, rng.pick([...ALPHABET]));
                else if (chars.length > 0) chars.splice(Math.min(at, chars.length - 1), 1);
            }
            const text = chars.join('');
            for (const mode of ['strict', 'lax'] as const) {
                const result = outcome(`seed ${seed} iteration ${iteration} ${mode}`, text, () => decodePem(text, { mode, onDiagnostic: () => undefined }));
                outcomes.set(result, (outcomes.get(result) ?? 0) + 1);
            }
        }
        expect(outcomes.get('ok') ?? 0).toBeGreaterThan(500);
        expect([...outcomes.keys()].filter((k) => k !== 'ok').length).toBeGreaterThan(3);
    }, 120_000);
});
