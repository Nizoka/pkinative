/**
 * pkinative — fuzz target: the RFC 5280 §5 revocation list
 * ========================================================
 * Coverage-guided fuzzing of `parseCertificateList`. A CRL is the largest
 * structure a relying party downloads from a URL somebody else chose, and
 * its revoked-certificate list is walked lazily by the TLV cursor rather
 * than decoded into nodes — a second reading path over the same hostile
 * bytes, which is exactly what a fuzzer should be pointed at.
 *
 * Strict DER first, then BER with diagnostics collected: the lax run keeps
 * going past every conformance concern and reaches the entry extensions.
 *
 * See `fuzz/asn1.js` for the contract every target shares: a `PkiError`
 * subclass is a result, anything else is a bug.
 *
 * @module fuzz/crl
 */

import { parseCertificateList, PkiError } from 'pkinative';

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
            parseCertificateList(der, options);
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }
}

export default fuzz;
