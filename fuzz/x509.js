/**
 * pkinative — fuzz target: the RFC 5280 certificate parser
 * ========================================================
 * The deepest reachable path in the library, and the one a caller points at
 * bytes that arrived over a socket. See `fuzz/asn1.js` for the contract:
 * a `PkiError` subclass is a result, anything else is a bug.
 *
 * Extension decoding is exercised in both settings. With
 * `decodeExtensions: false` the parser stops at the envelope, which is a
 * different and much shorter path than the twenty extension decoders — and
 * it is the setting a caller reaches for precisely when the input is
 * hostile, so it must be no less safe.
 *
 * @module fuzz/x509
 */

import { parseCertificate, PkiError } from 'pkinative';

/** Diagnostics are the point of the `strict` run below; collecting them
 *  costs one array and keeps `console.warn` out of a fuzzing loop. */
const drop = () => undefined;

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const der = new Uint8Array(data);
    for (const decodeExtensions of [true, false]) {
        try {
            parseCertificate(der, { decodeExtensions, strict: true, onDiagnostic: drop });
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }
}

export default fuzz;
