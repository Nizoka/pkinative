/**
 * pkinative — fuzz target: RFC 5652 SignedData
 * ============================================
 * Coverage-guided fuzzing of `parseSignedData`, the reader every CMS, PAdES
 * and timestamp verification starts from. CMS is the grammar where BER is
 * real — S/MIME and PDF signers write indefinite lengths — so the two runs
 * below split along that line: DER with every diagnostic escalated, and BER
 * with diagnostics collected, which is the path that goes deepest.
 *
 * `allowTrailingData` is the PDF `/Contents` setting: a zero-padded
 * placeholder after the DER. It changes where the parser stops reading, so
 * the BER run takes it, and the DER run keeps the default refusal.
 *
 * See `fuzz/asn1.js` for the contract every target shares: a `PkiError`
 * subclass is a result, anything else is a bug.
 *
 * @module fuzz/cms
 */

import { parseSignedData, PkiError } from 'pkinative';

const drop = () => undefined;

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const der = new Uint8Array(data);
    for (const options of [
        { encodingRules: 'der', strict: true, onDiagnostic: drop },
        { encodingRules: 'ber', allowTrailingData: true, onDiagnostic: drop },
    ]) {
        try {
            parseSignedData(der, options);
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }
}

export default fuzz;
