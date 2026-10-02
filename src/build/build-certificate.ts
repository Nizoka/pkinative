/**
 * pkinative — certificate creation
 * ================================
 * An RFC 5280 certificate from a typed description, signed by a key the
 * caller holds.
 *
 * What this module deliberately does **not** do is own the key. It takes a
 * `CryptoKey` the caller imported or generated, hands it to
 * `crypto.subtle.sign` through the one boundary module, and never sees a
 * key bit. That is why `generateKey` and `exportKey` stay refused in `src/`
 * in every version, and why `subjectPublicKey` is a SubjectPublicKeyInfo in
 * DER rather than a `CryptoKey` this library would have to export. An
 * `ExternalSigner` goes one step further: the key lives in an HSM, a card or
 * a KMS, and pkinative sees only the signature it hands back.
 *
 * @module build/build-certificate
 */

import { encodeBitString, encodeExplicit, encodeInteger, encodeNull, encodeSequence, encodeTlv } from '../asn1/asn1-encode.js';
import { assertBytes } from '../core/bytes.js';
import { coordinateBytes, resolveSigner } from '../crypto/crypto-algorithms.js';
import { ecdsaRawToDer } from '../crypto/crypto-signature.js';
import { signData } from '../crypto/webcrypto.js';
import type { CertificateDescription, PkiBuildOptions } from '../types/build-types.js';
import type { Signer } from '../types/crypto-types.js';
import { PkiError } from '../types/pki-errors.js';
import {
    encodeAlgorithmIdentifier,
    encodeDistinguishedName,
    encodeExtensions,
    encodeValidity,
} from './build-structures.js';

/**
 * The `AlgorithmIdentifier` a signature algorithm writes into a structure,
 * parameters included — RSASSA-PSS carries its digest and salt length, and a
 * verifier reads them back out of exactly these bytes.
 *
 * Exposed because a caller building a structure pkinative does not model yet
 * needs the same bytes, and because a test can compare them to what a
 * certificate carries.
 *
 * @param signer A `SigningKey` or an `ExternalSigner`; only its algorithm is read.
 * @returns The `AlgorithmIdentifier` encoding.
 * @throws {PkiCryptoError} `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when the
 *   algorithm has no RFC 5280 OID, or its salt length is negative.
 */
export function encodeSignatureAlgorithm(signer: Signer): Uint8Array {
    const resolved = resolveSigner(signer.algorithm);
    if (resolved.pss === undefined) return encodeAlgorithmIdentifier(resolved.oid);
    // RFC 4055 §3.1. hashAlgorithm [0], maskGenAlgorithm [1] as MGF1 over
    // the same digest, saltLength [2]. trailerField [3] keeps its DEFAULT,
    // which DER requires to be absent.
    //
    // The digest AlgorithmIdentifier carries an explicit NULL. RFC 4055 §2.1
    // makes readers accept NULL and absent alike, but its own ASN.1 module
    // writes `sha256Identifier ::= { id-sha256, NULL }`, and CA/Browser Forum
    // BR §7.1.3.2.1 requires these bytes exactly: a verifier that enforces
    // that profile (pyca's WebPKI verifier, zlint, pkilint) refuses the
    // parameter-less form.
    const hash = encodeAlgorithmIdentifier(resolved.pss.hashOid, encodeNull());
    return encodeAlgorithmIdentifier(resolved.oid, encodeSequence([
        encodeExplicit(0, hash),
        encodeExplicit(1, encodeAlgorithmIdentifier('1.2.840.113549.1.1.8', hash)),
        encodeExplicit(2, encodeInteger(resolved.pss.saltLength)),
    ]));
}

/**
 * The first positive serial whose INTEGER needs 21 content octets: below it,
 * the magnitude fits in 159 bits and the sign octet makes 20 at most.
 */
const SERIAL_BOUND = 1n << 159n;

/** The serial as an INTEGER, from a bigint or from content octets. */
function encodeSerial(serial: bigint | Uint8Array): Uint8Array {
    if (typeof serial === 'bigint') {
        // RFC 5280 §4.1.2.2: positive, and at most 20 octets. A bigint is a
        // value the builder encodes, so it is held to the profile its own
        // parser diagnoses (PKI_DIAG_SERIAL_NOT_POSITIVE, PKI_DIAG_SERIAL_TOO_LONG).
        if (serial <= 0n) {
            throw new PkiError('PKI_API_MISUSE', 'pkinative: a certificate serial number must be positive (RFC 5280 §4.1.2.2) — zero and negative serials are refused by many relying parties');
        }
        if (serial >= SERIAL_BOUND) {
            throw new PkiError('PKI_API_MISUSE', 'pkinative: a certificate serial number must fit in 20 octets (RFC 5280 §4.1.2.2), so a positive bigint must be below 2^159 — CA/Browser Forum serials are 64 to 159 random bits');
        }
        return encodeInteger(serial);
    }
    // The byte form means "these exact content octets", so that a re-issued
    // or cross-signed certificate can carry a serial back byte for byte —
    // the same reason `issuerDer` takes DER. What it does NOT license is
    // bytes no INTEGER can hold: an empty value, or a non-minimal one, is
    // refused by this library's own decoder (X.690 §8.3.2), and a builder
    // that writes what its reader cannot read has written a broken file.
    // A negative serial is left alone on purpose: it is legal DER and a
    // conformance concern, and `parseCertificate` says so with
    // PKI_DIAG_SERIAL_NOT_POSITIVE rather than the builder refusing it.
    const bytes = assertBytes(serial, 'serialNumber');
    const first = bytes[0];
    if (first === undefined) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: a certificate serial number cannot be empty — an INTEGER has at least one content octet (X.690 §8.3.1); pass a bigint, or the octets of an existing serial');
    }
    const second = bytes[1];
    if (second !== undefined && ((first === 0x00 && second < 0x80) || (first === 0xff && second >= 0x80))) {
        throw new PkiError('PKI_API_MISUSE', `pkinative: the serial number's leading 0x${first.toString(16).padStart(2, '0')} octet is redundant, and DER requires the shortest form (X.690 §8.3.2) — drop it, or pass a bigint and let pkinative encode it`);
    }
    return encodeTlv('universal', 2, false, bytes);
}

/** Whether `value` is a `Uint8Array`, from this realm or another — the test `assertBytes` makes. */
function isByteArray(value: unknown): value is Uint8Array {
    return ArrayBuffer.isView(value) && Object.prototype.toString.call(value) === '[object Uint8Array]';
}

/** What an `ExternalSigner` returned, refused unless it has the shape `crypto.subtle.sign` produces. */
function checkExternalSignature(produced: unknown, curve: 'P-256' | 'P-384' | 'P-521' | undefined): Uint8Array {
    if (!isByteArray(produced) || produced.length === 0) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: an ExternalSigner\'s produceSignature must return a non-empty Uint8Array — the signature as crypto.subtle.sign would produce it; wrap an ArrayBuffer in new Uint8Array(…)');
    }
    if (curve !== undefined) {
        const expected = 2 * coordinateBytes(curve);
        if (produced.length !== expected) {
            // The usual cause is an HSM or KMS API that returns the DER
            // Ecdsa-Sig-Value. Guessing which form arrived is how a signature
            // gets encoded twice, so the form is fixed and a mismatch refused.
            throw new PkiError('PKI_API_MISUSE', `pkinative: an ExternalSigner for ECDSA on ${curve} must return the raw r ‖ s of exactly ${String(expected)} octets, as crypto.subtle.sign would, and returned ${String(produced.length)} — a DER Ecdsa-Sig-Value is the usual mistake; convert it to r ‖ s before returning it`);
        }
    }
    return produced;
}

/**
 * The signature over `data`, in the form a structure carries it — DER for
 * ECDSA, the plain octets for every other family.
 *
 * The one signing path of `build`, for both kinds of `Signer`. A
 * `SigningKey` goes through the Web Crypto boundary; an `ExternalSigner` is
 * handed the exact bytes and hands back what `crypto.subtle.sign` would
 * have, which is checked before it is trusted: a signature of the wrong
 * shape makes a structure that verifies nowhere, and the moment to say so
 * is now, not when a relying party refuses it.
 */
export async function computeSignatureValue(data: Uint8Array, signer: Signer): Promise<Uint8Array> {
    const resolved = resolveSigner(signer.algorithm);
    // A copy for the external signer, so that one which scribbles on its
    // argument cannot change the bytes embedded next to its signature.
    const raw = 'produceSignature' in signer
        ? checkExternalSignature(await signer.produceSignature(data.slice()), resolved.curve)
        : await signData(signer.key, resolved.signParams, data);
    // Web Crypto returns ECDSA as raw r‖s; X.509 and CMS carry DER. Every
    // other family is already in the form the structure wants.
    return resolved.curve === undefined ? raw : ecdsaRawToDer(raw, coordinateBytes(resolved.curve));
}

/**
 * Sign `tbs` and wrap it into the outer SEQUENCE the structure expects.
 *
 * Shared by certificates and requests, because the shape is the same:
 * the signed bytes, the algorithm that signed them, and the signature as a
 * BIT STRING of whole octets.
 */
export async function signAndWrap(tbs: Uint8Array, signer: Signer): Promise<Uint8Array> {
    const signature = await computeSignatureValue(tbs, signer);
    return encodeSequence([tbs, encodeSignatureAlgorithm(signer), encodeBitString(signature, 0)]);
}

/**
 * Build and sign an RFC 5280 certificate.
 *
 * ```ts
 * import { createCertificate } from 'pkinative';
 *
 * const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
 * const der = await createCertificate({
 *     serialNumber: 0x0123456789abcdefn,
 *     subject: [[{ type: '2.5.4.3', value: 'Example Root' }]],
 *     notBefore: Date.now(),
 *     notAfter: Date.now() + 365 * 86_400_000,
 *     subjectPublicKey: spki,
 * }, { key: privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
 * ```
 *
 * With no `issuerDer` and no `issuer`, the subject is used and the result is
 * self-signed. When the certificate belongs in a chain, pass the issuing
 * certificate's `subject.der` as `issuerDer`: a name re-encoded from its
 * decoded attributes will not always reproduce the issuer's own bytes, and a
 * chain whose names differ by one octet is a chain nothing will build.
 *
 * The result is **not verified** before it is returned. Verifying a
 * certificate you just signed with a key you hold tells you only that Web
 * Crypto works; `verifyCertificateSignature` is there for the cases where
 * the answer is not already known.
 *
 * @param description What the certificate says.
 * @param signer      The key that signs it, and the algorithm it signs with: a
 *   `SigningKey` for Web Crypto, or an `ExternalSigner` for a key held elsewhere.
 * @param options     See {@link PkiBuildOptions}.
 * @returns The complete certificate, in DER.
 * @throws {PkiError} `PKI_API_MISUSE` for a bigint serial outside 1 to 2^159 − 1, a malformed one, an
 *   inverted validity window, a duplicated extension, or an `ExternalSigner`
 *   that returns other than what `crypto.subtle.sign` would; `PKI_INVALID_INPUT` for a
 *   malformed name or a non-`Uint8Array` where DER is expected.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the runtime cannot
 *   sign; `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when the algorithm has no
 *   RFC 5280 OID; `PKI_CRYPTO_KEY_UNSUPPORTED` when the host refuses the key.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxNameAttributes` or `maxExtensions`.
 */
export async function createCertificate(description: CertificateDescription, signer: Signer, options?: PkiBuildOptions): Promise<Uint8Array> {
    const limits = options?.limits === undefined ? undefined : { limits: options.limits };
    const subject = description.subjectDer !== undefined
        ? assertBytes(description.subjectDer, 'subjectDer')
        : encodeDistinguishedName(description.subject, limits);
    const issuer = description.issuerDer !== undefined
        ? assertBytes(description.issuerDer, 'issuerDer')
        : description.issuer !== undefined
            ? encodeDistinguishedName(description.issuer, limits)
            : subject;

    const extensions = description.extensions ?? [];
    const fields: Uint8Array[] = [
        // v3 whenever there are extensions, v1 otherwise. RFC 5280 §4.1.2.1
        // makes the version DEFAULT v1, so a v1 certificate omits the field
        // entirely — writing [0] EXPLICIT INTEGER 0 is a DER violation.
        ...(extensions.length > 0 ? [encodeExplicit(0, encodeInteger(2))] : []),
        encodeSerial(description.serialNumber),
        // tbsCertificate.signature is the field the signature covers; the
        // outer one is not. They must be equal, and they are, because both
        // come from the same call.
        encodeSignatureAlgorithm(signer),
        issuer,
        encodeValidity(description.notBefore, description.notAfter),
        subject,
        assertBytes(description.subjectPublicKey, 'subjectPublicKey'),
    ];
    if (extensions.length > 0) fields.push(encodeExplicit(3, encodeExtensions(extensions, limits)));

    return signAndWrap(encodeSequence(fields), signer);
}
