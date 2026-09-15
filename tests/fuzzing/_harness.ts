/**
 * Shared assertions of the fuzzing suites: every call ends in a value or in a
 * `PkiError` subclass. Anything else — a TypeError from an unchecked index, a
 * RangeError from the call stack — is a bug, and fails the suite with the seed
 * and the input that produced it.
 */

import { PkiError } from '../../src/types/pki-errors.js';

export function outcome(label: string, input: Uint8Array | string, fn: () => unknown): string {
    try {
        fn();
        return 'ok';
    } catch (err) {
        if (err instanceof PkiError) {
            if (!err.message.startsWith('pkinative: ')) throw new Error(`${label}: message without the pkinative prefix: ${err.message}`);
            return err.code;
        }
        const shown = typeof input === 'string' ? JSON.stringify(input.slice(0, 200)) : Buffer.from(input.subarray(0, 64)).toString('hex');
        throw new Error(`${label}: non-PkiError ${(err as Error).name}: ${(err as Error).message} — input ${shown}`, { cause: err });
    }
}
