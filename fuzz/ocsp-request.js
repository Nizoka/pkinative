/**
 * pkinative — fuzz target: the RFC 6960 OCSP request
 * ==================================================
 * Coverage-guided fuzzing of `parseOcspRequest`: an optional version and
 * requestor ahead of a list of `CertID`s, each with its own extensions, a
 * nonce two OCTET STRINGs deep, and an optional signature carrying
 * certificates — every field optional but one, which is where a reader
 * that counts positions instead of tags goes wrong.
 *
 * Strict DER first, then BER with diagnostics collected, so the lax run
 * reaches the extensions and the signature past any conformance concern.
 *
 * See `fuzz/asn1.js` for the contract every target shares: a `PkiError`
 * subclass is a result, anything else is a bug.
 *
 * @module fuzz/ocsp-request
 */

import { parseOcspRequest, PkiError } from 'pkinative';

const drop = () => undefined;

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const der = new Uint8Array(data);
    for (const options of [
        { encodingRules: 'der', strict: true, onDiagnostic: drop },
        { encodingRules: 'ber', onDiagnostic: drop },
    ]) {
        try {
            parseOcspRequest(der, options);
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }
}

export default fuzz;
