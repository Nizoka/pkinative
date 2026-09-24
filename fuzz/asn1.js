/**
 * pkinative — fuzz target: the X.690 decoder
 * ==========================================
 * Coverage-guided fuzzing of `decodeAsn1`, in both strictness modes.
 *
 * The contract every target in this directory shares, and the only thing a
 * crash here ever means: **a `PkiError` subclass is a result, anything else
 * is a bug.** A `TypeError` from a field that was not there, a `RangeError`
 * from recursion, an out-of-memory from a declared length — each of those is
 * the parser failing to refuse rather than refusing, and each is what the
 * fuzzer is looking for. Swallowing them would make this file decorative.
 *
 * The specifier is the package's own name, not a relative path: Node
 * resolves it through the `exports` map by self-reference, so the container
 * fuzzes `dist/`, the bytes a consumer installs, while `tests/fuzzing/
 * targets.test.ts` runs the same file against `src/` through the vitest
 * alias. One target, two engines, no second copy to keep in step.
 *
 * @module fuzz/asn1
 */

import { decodeAsn1, PkiError } from 'pkinative';

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const bytes = new Uint8Array(data);
    // Both rule sets on the same input, in one iteration: BER reaches the
    // indefinite-length and constructed-string paths DER refuses outright, so
    // splitting them across executions would halve the coverage each input
    // buys. `strict` escalates every diagnostic to a throw, which is what
    // puts the diagnostic sites themselves on the fuzzer's map.
    for (const encodingRules of ['der', 'ber']) {
        try {
            decodeAsn1(bytes, { encodingRules, strict: true });
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }
}

export default fuzz;
