/**
 * pkinative — fuzz target: the RFC 5755 attribute certificate
 * ===========================================================
 * Coverage-guided fuzzing of `parseAttributeCertificate`: a holder of three
 * optional references, an issuer CHOICE of two forms, a validity period of
 * GeneralizedTime only, the attributes of RFC 5755 §4.4 with their nested
 * syntaxes, and the extensions — the certificate ones and the three only an
 * AC carries.
 *
 * Two runs differ by `strict` and by encoding rules: the strict DER run stops
 * at the first warning, the lax BER one reads on through every attribute.
 *
 * See `fuzz/asn1.js` for the contract every target shares: a `PkiError`
 * subclass is a result, anything else is a bug.
 *
 * @module fuzz/attribute-certificate
 */

import { parseAttributeCertificate, PkiError } from 'pkinative';

const drop = () => undefined;

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const der = new Uint8Array(data);
    for (const options of [
        { strict: true, onDiagnostic: drop },
        { encodingRules: 'ber', onDiagnostic: drop },
    ]) {
        try {
            parseAttributeCertificate(der, options);
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }
}

export default fuzz;
