/**
 * pkinative — fuzz target: PKCS#12 and PKCS#8 containers
 * ======================================================
 * Coverage-guided fuzzing of `parsePkcs12`, with the two PKCS#8 readers its
 * bags lead to. A `.p12` is the one input in this library that is routinely
 * opened from a file a stranger sent; everything here runs **before** any
 * password is involved — the structure, the declared KDF parameters, the
 * bag tree — so that is the surface the fuzzer can reach without one.
 *
 * Opening is asynchronous (Web Crypto derives and decrypts) and the target
 * runs with `--sync`, so it stops at the parse; the work a parsed file may
 * cost the host is bounded by the PBKDF2 limits, which are tested where they
 * are defined.
 *
 * Real PKCS#12 files are BER often enough (Java, older Windows) that the lax
 * run is the realistic one; the strict DER run escalates every diagnostic.
 *
 * See `fuzz/asn1.js` for the contract every target shares: a `PkiError`
 * subclass is a result, anything else is a bug.
 *
 * @module fuzz/pkcs12
 */

import { parseEncryptedPrivateKeyInfo, parsePkcs12, parsePrivateKeyInfo, PkiError } from 'pkinative';

const drop = () => undefined;

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const der = new Uint8Array(data);
    for (const parse of [parsePkcs12, parsePrivateKeyInfo, parseEncryptedPrivateKeyInfo]) {
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
