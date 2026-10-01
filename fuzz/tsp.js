/**
 * pkinative — fuzz target: RFC 3161 timestamps
 * ============================================
 * Coverage-guided fuzzing of the three timestamp readers on the same bytes:
 * `parseTimeStampResponse` (status, then a token), `parseTimeStampToken`
 * (a SignedData whose content must be a TSTInfo) and `parseTstInfo` (the
 * stamped imprint, the time, the accuracy). They nest, so one input that
 * the outer reader refuses early still reaches the inner one directly —
 * three entry points, one corpus.
 *
 * Strict DER, then BER with diagnostics collected, for each reader.
 *
 * See `fuzz/asn1.js` for the contract every target shares: a `PkiError`
 * subclass is a result, anything else is a bug.
 *
 * @module fuzz/tsp
 */

import { parseTimeStampResponse, parseTimeStampToken, parseTstInfo, PkiError } from 'pkinative';

const drop = () => undefined;

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const der = new Uint8Array(data);
    for (const parse of [parseTimeStampResponse, parseTimeStampToken, parseTstInfo]) {
        for (const options of [
            { encodingRules: 'der', strict: true, onDiagnostic: drop },
            { encodingRules: 'ber', onDiagnostic: drop },
        ]) {
            try {
                parse(der, options);
            } catch (error) {
                if (!(error instanceof PkiError)) throw error;
            }
        }
    }
}

export default fuzz;
