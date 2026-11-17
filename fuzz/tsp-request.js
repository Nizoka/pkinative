/**
 * pkinative — fuzz target: the RFC 3161 timestamp request
 * =======================================================
 * Coverage-guided fuzzing of `parseTimeStampRequest`: a version, an imprint
 * whose hash length is held to its algorithm, three optional fields that
 * come once each and in order, and an implicitly tagged list of extensions
 * handed to the certificate extension readers.
 *
 * The request is read as DER whatever the options say, so the two runs
 * differ by `strict` and not by encoding rules: the strict run stops at the
 * first warning, the lax one reads on through the extensions.
 *
 * See `fuzz/asn1.js` for the contract every target shares: a `PkiError`
 * subclass is a result, anything else is a bug.
 *
 * @module fuzz/tsp-request
 */

import { parseTimeStampRequest, PkiError } from 'pkinative';

const drop = () => undefined;

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const der = new Uint8Array(data);
    for (const options of [
        { strict: true, onDiagnostic: drop },
        { onDiagnostic: drop },
    ]) {
        try {
            parseTimeStampRequest(der, options);
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }
}

export default fuzz;
