/**
 * pkinative — PBES2, the one password scheme pkinative opens
 * ==========================================================
 * RFC 8018 §6.2 with PBKDF2 (§5.2) and AES-CBC (§B.2.5), read from an
 * AlgorithmIdentifier, and turned into a Web Crypto key through the door.
 *
 * Every other password scheme is **described and refused**, never guessed
 * at. RFC 7292's own PKCS#12 schemes derive their key with the Appendix B KDF
 * — iterated SHA-1 with byte arithmetic over the password — and protect it
 * with 3DES or 40-bit RC2; PBES1 is DES and RC2 under MD2, MD5 or SHA-1.
 * Implementing any of them would put secret-dependent arithmetic in
 * TypeScript, which is the one thing this library exists without. So a
 * refused scheme still parses, carries its name in `scheme`, and fails only
 * when something asks to decrypt it, with a code that names the conversion.
 *
 * The iteration count is the file's to declare and the host's to run, inside
 * Web Crypto where no JavaScript bound can reach it. `maxKdfIterations` is
 * therefore checked here, before the host is asked for anything.
 *
 * @internal
 * @module keys/key-pbes2
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readInteger, _readOctetString } from '../asn1/asn1-read.js';
import { TAG_INTEGER, TAG_NULL, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE } from '../asn1/asn1-tags.js';
import { AES_CBC_OIDS, HMAC_OIDS, OID_PBES2, OID_PBKDF2, REFUSED_PBE_SCHEMES } from '../core/key-oids.js';
import { defaultEncodedDiagnostic, keyKdfIterationsLowDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import { encodeUtf8 } from '../core/text.js';
import { derivePasswordKey } from '../crypto/webcrypto.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type { Pbes2Parameters, PasswordEncryption, Pbkdf2Prf } from '../types/key-types.js';
import { PkiError, PkiKeyError, type PkiKeyErrorCode } from '../types/pki-errors.js';
import type { CryptoKeyHandle, DerivedKeyParams } from '../types/webcrypto.js';
import type { AlgorithmIdentifier } from '../types/x509-types.js';
import { isBytes } from '../core/bytes.js';

// ── Errors and fields ──

/** What the caller can do about each code, appended to every message. */
const REMEDIES: Readonly<Record<PkiKeyErrorCode, string>> = /*#__PURE__*/ Object.freeze({
    PKI_KEY_STRUCTURE_INVALID: 'the input is not the RFC 5958 or RFC 7292 structure it was read as; check that it is DER and not its PEM or base64 text, and that the PEM label matched',
    PKI_KEY_VERSION_UNSUPPORTED: 'the syntax defines no such version, so what follows cannot be read; re-export the file from the tool that owns the key',
    PKI_KEY_ENCRYPTION_UNSUPPORTED: 'pkinative opens PBES2 with PBKDF2 and AES-CBC only, by policy; convert the file with OpenSSL 3.4 or later: openssl pkcs12 -in legacy.p12 -legacy -out bundle.pem, then openssl pkcs12 -export -in bundle.pem -pbmac1_pbkdf2 -out modern.p12 — or, for a key alone, openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256',
    PKI_KEY_MAC_UNSUPPORTED: 'pkinative verifies RFC 9579 PBMAC1 only; re-export with openssl pkcs12 -export -pbmac1_pbkdf2 (OpenSSL 3.4 or later)',
});

/**
 * The error of one field of a key structure.
 *
 * @internal
 */
export function _keyError(code: PkiKeyErrorCode, path: string, offset: number | undefined, why: string): PkiKeyError {
    const where = offset === undefined ? path : `${path} at offset ${String(offset)}`;
    return new PkiKeyError(code, `pkinative: ${where} ${why} — ${REMEDIES[code]}`, path, offset);
}

/**
 * A field that must be present and carry one universal tag.
 *
 * @internal
 */
export function _expectField(node: Asn1Node | undefined, tagNumber: number, path: string, parentOffset: number, what: string): Asn1Node {
    if (node === undefined) throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, parentOffset, `is missing; expected ${what}`);
    if (node.tagClass !== 'universal' || node.tagNumber !== tagNumber) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, node.offset, `is not ${what}`);
    }
    return node;
}

/**
 * An AlgorithmIdentifier: an OID and optional parameters, kept undecoded.
 *
 * The same shape `x509` reads; kept here because a key reader must not ship
 * the certificate parser, and the refusal must be a key error.
 *
 * @internal
 */
export function _readKeyAlgorithm(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): AlgorithmIdentifier {
    const seq = _expectField(node, TAG_SEQUENCE, path, parentOffset, 'an AlgorithmIdentifier SEQUENCE');
    if (seq.children.length > 2) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, seq.offset, `holds ${String(seq.children.length)} values; an AlgorithmIdentifier is an OID and optional parameters`);
    }
    const oidNode = _expectField(seq.children[0], TAG_OID, `${path}.algorithm`, seq.offset, 'an OBJECT IDENTIFIER');
    const oid = _readObjectIdentifier(oidNode, ctx);
    return Object.freeze({ oid, parameters: seq.children[1], der: seq.bytes });
}

/** Parameters that are absent or NULL — what an HMAC or a hash identifier may carry. */
function _absentOrNull(parameters: Asn1Node | undefined): boolean {
    return parameters === undefined || (parameters.tagClass === 'universal' && parameters.tagNumber === TAG_NULL && parameters.contentLength === 0);
}

// ── PBKDF2 (RFC 8018 §5.2, §A.2) ──

/** PBKDF2 parameters as read — or the reason pkinative will not run them. */
export type _Pbkdf2 =
    | { readonly ok: true; readonly salt: Uint8Array; readonly iterations: number; readonly keyLength: number | undefined; readonly prf: Pbkdf2Prf }
    | { readonly ok: false; readonly scheme: string };

/**
 * Read `PBKDF2-params` from a KDF AlgorithmIdentifier.
 *
 * A KDF other than PBKDF2, a salt from `otherSource`, or a PRF Web Crypto does
 * not implement is a refusal, not a malformation, and comes back as `ok:
 * false`; a structure that breaks the grammar throws.
 *
 * @internal
 */
export function _readPbkdf2(kdf: AlgorithmIdentifier, ctx: Asn1Context, path: string, offset: number): _Pbkdf2 {
    if (kdf.oid !== OID_PBKDF2) return { ok: false, scheme: `a key derivation function other than PBKDF2 (${kdf.oid})` };
    const params = _expectField(kdf.parameters, TAG_SEQUENCE, `${path}.parameters`, offset, 'PBKDF2-params');
    const [saltNode, countNode, third, fourth, ...extra] = params.children;
    if (extra.length > 0) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.parameters`, params.offset, 'holds more than salt, iterationCount, keyLength and prf');
    }
    if (saltNode !== undefined && saltNode.tagClass === 'universal' && saltNode.tagNumber === TAG_SEQUENCE) {
        return { ok: false, scheme: 'PBKDF2 with a salt from otherSource, which RFC 8018 reserves for future use' };
    }
    const saltField = _expectField(saltNode, TAG_OCTET_STRING, `${path}.parameters.salt`, params.offset, 'an OCTET STRING salt');
    const salt = _readOctetString(saltField, ctx);

    const countField = _expectField(countNode, TAG_INTEGER, `${path}.parameters.iterationCount`, params.offset, 'an INTEGER iteration count');
    const count = _readInteger(countField, ctx);
    if (count < 1n) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.parameters.iterationCount`, countField.offset, `is ${String(count)}; RFC 8018 requires at least 1`);
    }
    enforceLimit(ctx.limits, 'maxKdfIterations', Number(count), `${path}.parameters.iterationCount`);
    const iterations = Number(count);
    if (iterations < 1000) ctx.emitter.emit(keyKdfIterationsLowDiagnostic(`${path}.parameters.iterationCount`, iterations, countField.offset));

    // keyLength and prf are both optional, and told apart by tag.
    let keyLength: number | undefined;
    let prfNode: Asn1Node | undefined;
    if (third !== undefined && third.tagClass === 'universal' && third.tagNumber === TAG_INTEGER) {
        const length = _readInteger(third, ctx);
        if (length < 1n || length > 64n) {
            throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.parameters.keyLength`, third.offset, `is ${String(length)} octets; no key this scheme derives is shorter than 1 or longer than 64`);
        }
        keyLength = Number(length);
        prfNode = fourth;
    } else {
        if (fourth !== undefined) {
            throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.parameters`, params.offset, 'holds a fourth value after something that is not a keyLength');
        }
        prfNode = third;
    }

    let prf: Pbkdf2Prf = 'SHA-1';
    if (prfNode !== undefined) {
        const prfAlgorithm = _readKeyAlgorithm(prfNode, ctx, `${path}.parameters.prf`, params.offset);
        const named = HMAC_OIDS.get(prfAlgorithm.oid);
        if (named === undefined || !_absentOrNull(prfAlgorithm.parameters)) {
            return { ok: false, scheme: `PBKDF2 with a PRF Web Crypto does not implement (${prfAlgorithm.oid})` };
        }
        if (named === 'SHA-1') ctx.emitter.emit(defaultEncodedDiagnostic(`${path}.parameters.prf`, 'hmacWithSHA1', prfNode.offset));
        prf = named;
    }
    return { ok: true, salt, iterations, keyLength, prf };
}

// ── PBES2 (RFC 8018 §6.2, §A.4) ──

/**
 * Read a password-based encryption AlgorithmIdentifier.
 *
 * Never refuses a scheme: a refused one comes back with `pbes2` undefined and
 * its name in `scheme`, and {@link _requirePbes2} is where refusal happens.
 * Throws only for a PBES2 structure that breaks its grammar, and for an
 * iteration count past `maxKdfIterations`.
 *
 * @internal
 */
export function _readPasswordEncryption(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): PasswordEncryption {
    const seq = _expectField(node, TAG_SEQUENCE, path, parentOffset, 'an AlgorithmIdentifier SEQUENCE');
    const algorithm = _readKeyAlgorithm(seq, ctx, path, parentOffset);
    const refused = REFUSED_PBE_SCHEMES.get(algorithm.oid);
    if (refused !== undefined) return Object.freeze({ algorithm, pbes2: undefined, scheme: refused });
    if (algorithm.oid !== OID_PBES2) return Object.freeze({ algorithm, pbes2: undefined, scheme: `an unrecognised scheme (${algorithm.oid})` });

    const params = _expectField(algorithm.parameters, TAG_SEQUENCE, `${path}.parameters`, seq.offset, 'PBES2-params');
    if (params.children.length !== 2) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.parameters`, params.offset, `holds ${String(params.children.length)} values; PBES2-params is a keyDerivationFunc and an encryptionScheme`);
    }
    const kdf = _readKeyAlgorithm(params.children[0], ctx, `${path}.parameters.keyDerivationFunc`, params.offset);
    const cipher = _readKeyAlgorithm(params.children[1], ctx, `${path}.parameters.encryptionScheme`, params.offset);

    const derivation = _readPbkdf2(kdf, ctx, `${path}.parameters.keyDerivationFunc`, params.offset);
    if (!derivation.ok) return Object.freeze({ algorithm, pbes2: undefined, scheme: `PBES2 with ${derivation.scheme}` });

    const keyBits = AES_CBC_OIDS.get(cipher.oid);
    if (keyBits === undefined) return Object.freeze({ algorithm, pbes2: undefined, scheme: `PBES2 with a cipher other than AES-CBC (${cipher.oid})` });
    const ivField = _expectField(cipher.parameters, TAG_OCTET_STRING, `${path}.parameters.encryptionScheme.parameters`, params.offset, 'an OCTET STRING initialisation vector');
    const iv = _readOctetString(ivField, ctx);
    if (iv.length !== 16) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.parameters.encryptionScheme.parameters`, ivField.offset, `is ${String(iv.length)} octets; AES-CBC's initialisation vector is 16`);
    }
    if (derivation.keyLength !== undefined && derivation.keyLength * 8 !== keyBits) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.parameters.keyDerivationFunc.parameters.keyLength`, params.offset,
            `is ${String(derivation.keyLength)} octets, and the cipher needs ${String(keyBits / 8)}; the two halves of the scheme contradict each other`);
    }
    const pbes2: Pbes2Parameters = Object.freeze({
        salt: derivation.salt,
        iterations: derivation.iterations,
        prf: derivation.prf,
        keyBits,
        iv,
        cipherOid: cipher.oid,
    });
    return Object.freeze({ algorithm, pbes2, scheme: `PBES2 (PBKDF2 with HMAC-${derivation.prf}, AES-${String(keyBits)}-CBC)` });
}

/**
 * The PBES2 parameters of a scheme, or the refusal that names it.
 *
 * @internal
 */
export function _requirePbes2(encryption: PasswordEncryption, path: string, offset: number | undefined): Pbes2Parameters {
    if (encryption.pbes2 === undefined) {
        throw _keyError('PKI_KEY_ENCRYPTION_UNSUPPORTED', path, offset, `is encrypted with ${encryption.scheme}`);
    }
    return encryption.pbes2;
}

// ── The password ──

/**
 * The password as octets, and a way to wipe this function's copy.
 *
 * A string is encoded as UTF-8. That is an interoperability choice, not a
 * quotation: UTF-8 octets are what OpenSSL 3.4 and later write under PBES2
 * and PBMAC1, and what pkinative derives from and verifies — **not** the
 * NUL-terminated BMPString of RFC 7292 Appendix B, which belongs to the KDF
 * pkinative does not implement. A
 * `Uint8Array` is used as given, for a file written with another encoding,
 * and is never modified: it is the caller's to wipe.
 *
 * @internal
 */
export function _passwordOctets(password: Uint8Array | string): { readonly octets: Uint8Array; readonly wipe: () => void } {
    if (typeof password !== 'string') {
        if (!isBytes(password)) {
            throw new PkiError('PKI_INVALID_INPUT', `pkinative: the password must be a string or a Uint8Array, got ${password === null ? 'null' : typeof password}`);
        }
        return { octets: password, wipe: (): void => undefined };
    }
    const octets = encodeUtf8(password);
    if (octets === null) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: the password string contains a lone surrogate, so it has no UTF-8 encoding — pass the exact octets as a Uint8Array');
    }
    return { octets, wipe: (): void => { octets.fill(0); } };
}

/**
 * Derive the key a PBES2 scheme encrypts under.
 *
 * @internal
 */
export async function _derivePbes2Key(password: Uint8Array | string, pbes2: Pbes2Parameters, oid: string): Promise<CryptoKeyHandle> {
    const { octets, wipe } = _passwordOctets(password);
    const target: DerivedKeyParams = { name: 'AES-CBC', length: pbes2.keyBits };
    try {
        return await derivePasswordKey(octets, { name: 'PBKDF2', salt: pbes2.salt, iterations: pbes2.iterations, hash: { name: pbes2.prf } }, target, oid);
    } finally {
        wipe();
    }
}
