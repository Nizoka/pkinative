/**
 * pkinative — fuzz target: the RFC 6960 OCSP response
 * ===================================================
 * Coverage-guided fuzzing of `parseOcspResponse`: an ENUMERATED status, an
 * OID-typed body in an OCTET STRING, a responder identified by name or by
 * key hash, and a list of single answers each carrying a CHOICE of three
 * states — the states a parser differential must never confuse.
 *
 * Strict DER first, then BER with diagnostics collected, so the lax run
 * reaches the single-response extensions past any conformance concern.
 *
 * See `fuzz/asn1.js` for the contract every target shares: a `PkiError`
 * subclass is a result, anything else is a bug.
 *
 * @module fuzz/ocsp
 */

import { parseOcspResponse, PkiError } from 'pkinative';

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
            parseOcspResponse(der, options);
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }
}

export default fuzz;
