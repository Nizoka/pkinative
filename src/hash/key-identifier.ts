/**
 * pkinative — RFC 5280 §4.2.1.2 key identifiers
 * =============================================
 * The 20 bytes that let one certificate name the key of another.
 *
 * `subjectKeyIdentifier` says *"this is my key"*, `authorityKeyIdentifier` says
 * *"the key that signed me is that one"*, and together they are how a path
 * builder narrows hundreds of same-named candidates to the one worth trying.
 * Nothing here decides anything: the field is an opaque OCTET STRING and a
 * verifier that refused a chain over it would be refusing on a hint.
 *
 * ## One value, two places it is needed
 *
 * RFC 5280 §4.2.1.2 method 1 — *"the SHA-1 hash of the value of the BIT STRING
 * subjectPublicKey, excluding the tag, length, and number of unused bits"* — is
 * also, byte for byte, RFC 6960 §4.1.1's `issuerKeyHash`. Computing it once and
 * naming it once is why this lives here rather than being written twice.
 *
 * **The input is the key bits, not the SubjectPublicKeyInfo**, and that is the
 * mistake this module exists to make hard: hashing the SPKI produces an OCSP
 * request every responder answers `unknown` to, and a key identifier that
 * matches nothing. A parsed certificate hands you the right bytes directly as
 * `subjectPublicKeyInfo.publicKey.bytes`; from a freshly exported SPKI they are
 * one `decodeAsn1` away, which is a line the caller can see.
 *
 * @module hash/key-identifier
 */

import { assertBytes } from '../core/bytes.js';
import { sha1 } from './sha1.js';
import { sha256 } from './sha256.js';

/**
 * Compute a key identifier from a public key's BIT STRING content.
 *
 * ```ts
 * import { computeKeyIdentifier, decodeAsn1, encodeSubjectKeyIdentifier, readBitString } from 'pkinative';
 *
 * // From a key you just exported: SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
 * const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
 * const bits = readBitString(decodeAsn1(spki).children[1]!);
 * const extension = encodeSubjectKeyIdentifier(computeKeyIdentifier(bits.bytes));
 *
 * // From a certificate you parsed, the bytes are already there:
 * const theirs = computeKeyIdentifier(certificate.subjectPublicKeyInfo.publicKey.bytes);
 * ```
 *
 * SHA-1 by default, because that is what §4.2.1.2 method 1 specifies and what
 * every path builder in existence compares against. **This is a digest of a
 * public key, not a signature**: the collision resistance SHA-1 has lost is not
 * a property this value depends on, and a key identifier is a lookup hint that
 * no verdict rests on. `'SHA-256'` is offered for a caller who wants a wider
 * identifier — the field is an opaque OCTET STRING, so any width is legal — but
 * it will not match the `authorityKeyIdentifier` anybody else wrote.
 *
 * @param publicKeyBits The BIT STRING **content** of the public key: no tag, no
 *   length, no unused-bits octet. `subjectPublicKeyInfo.publicKey.bytes` on a
 *   parsed certificate is exactly this.
 * @param algorithm     The digest. `'SHA-1'` by default, per §4.2.1.2 method 1.
 * @returns The identifier: 20 bytes for SHA-1, 32 for SHA-256.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `publicKeyBits` is not a
 *   `Uint8Array`.
 */
export function computeKeyIdentifier(publicKeyBits: Uint8Array, algorithm: 'SHA-1' | 'SHA-256' = 'SHA-1'): Uint8Array {
    assertBytes(publicKeyBits, 'publicKeyBits');
    return algorithm === 'SHA-256' ? sha256(publicKeyBits) : sha1(publicKeyBits);
}
