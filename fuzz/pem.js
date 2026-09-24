/**
 * pkinative — fuzz target: RFC 7468 PEM, and the OID codec
 * ========================================================
 * Two decoders that take their input from different alphabets, fuzzed
 * together because neither is deep enough to earn an execution of its own.
 *
 * PEM is the only entry point that takes **text**, so the bytes are decoded
 * as UTF-8 first — lone surrogates, overlong sequences and a BOM in the
 * middle of a header are all things a real file has had. The OID codec gets
 * the same bytes raw: arc encoding is where an attacker-supplied length
 * meets `bigint` arithmetic, and `encodeOid(decodeOid(x))` is the one place
 * a round trip can be asserted on an input nobody chose.
 *
 * See `fuzz/asn1.js` for the contract: a `PkiError` subclass is a result,
 * anything else is a bug.
 *
 * @module fuzz/pem
 */

import { decodeOid, decodePem, encodeOid, PkiError } from 'pkinative';

const decoder = new TextDecoder('utf-8', { fatal: false });
const drop = () => undefined;

/**
 * @param {Buffer} data Bytes chosen by the fuzzer.
 * @returns {void}
 */
export function fuzz(data) {
    const bytes = new Uint8Array(data);

    for (const mode of ['strict', 'lax']) {
        try {
            decodePem(decoder.decode(bytes), { mode, strict: true, onDiagnostic: drop });
        } catch (error) {
            if (!(error instanceof PkiError)) throw error;
        }
    }

    try {
        const oid = decodeOid(bytes);
        // Whatever the decoder accepted, the encoder must be able to write
        // again, byte for byte. A round trip that loses an arc is a parser
        // that read something the encoder cannot express — silent data loss,
        // not a refusal, and no error class would ever report it.
        const again = encodeOid(oid);
        if (again.length !== bytes.length || again.some((b, i) => b !== bytes[i])) {
            throw new Error(`pkinative fuzz: decodeOid/encodeOid round trip lost bytes for ${oid}`);
        }
    } catch (error) {
        if (!(error instanceof PkiError)) throw error;
    }
}

export default fuzz;
