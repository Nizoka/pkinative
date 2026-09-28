/**
 * pkinative — signing and verification types
 * ==========================================
 * How a caller names the algorithm a signature is made with, and hands over
 * the key that makes it.
 *
 * The key is a **`CryptoKey` the caller already holds**: pkinative never
 * generates one, never imports a private one and never exports any key
 * material — `generateKey`, `exportKey`, `deriveBits`, `encrypt` and
 * `wrapKey` are refused in `src/` in every version
 * (`KEY_OPERATION_POLICY`, SECURITY.md §Cryptographic Implementation Scope).
 * All pkinative does with it is pass it to `crypto.subtle.sign`.
 *
 * The algorithm is named, not inferred. A `CryptoKey`'s own `algorithm`
 * says RSASSA-PKCS1-v1_5 with SHA-256 but nothing about which RFC 5280 OID
 * the certificate must carry, and the two have to agree: naming it makes
 * the choice visible in the caller's code, where a review can see it.
 *
 * @module types/crypto-types
 */

import type { CryptoKeyHandle } from './webcrypto.js';

/** The digests RFC 5280 signature algorithms are built on. */
export type SignatureHash = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * A signature algorithm, in the shape that maps onto both an RFC 5280 OID
 * and a Web Crypto parameter object.
 *
 * SHA-1 is included because certificates signed with it exist and must be
 * readable; issuing one is a different matter, and `createCertificate`
 * emits a diagnostic rather than refusing, because the caller may be
 * reproducing a historical certificate on purpose.
 */
export type SignatureAlgorithm =
    | { readonly name: 'RSASSA-PKCS1-v1_5'; readonly hash: SignatureHash }
    | {
        readonly name: 'RSA-PSS';
        readonly hash: SignatureHash;
        /**
         * Salt length in bytes. Defaults to the digest's own output size,
         * which is what RFC 4055 §3.1 recommends and every modern issuer
         * uses — **not** the grammar's DEFAULT of 20, which is the SHA-1
         * size frozen into the ASN.1 and would be written into the
         * certificate's parameters as an explicit, unusual value.
         */
        readonly saltLength?: number | undefined;
    }
    | { readonly name: 'ECDSA'; readonly hash: SignatureHash; readonly namedCurve: 'P-256' | 'P-384' | 'P-521' }
    | { readonly name: 'Ed25519' }
    | { readonly name: 'Ed448' };

/** The key that signs, and what it signs with. */
export interface SigningKey {
    /**
     * A private `CryptoKey` with the `sign` usage, imported by the caller.
     * pkinative passes it to `crypto.subtle.sign` and does nothing else
     * with it; its bits never enter this library.
     */
    readonly key: CryptoKeyHandle;
    /** The algorithm, which decides both the OID written into the structure and the Web Crypto call. */
    readonly algorithm: SignatureAlgorithm;
}

/**
 * A signer whose key pkinative never sees at all — a hardware security module,
 * a smart card, a cloud KMS, a remote signing service.
 *
 * This is the stronger form of the promise `SigningKey` makes, not a weaker
 * one. A `SigningKey` hands pkinative an opaque handle it passes straight to
 * `crypto.subtle.sign`; an `ExternalSigner` hands it a function, so the key
 * does not even have to live in the same process. Document signing keys
 * usually live exactly there, and a library that could only sign with a
 * `CryptoKey` would be one those callers route around.
 *
 * The property is not called `sign`, and that is not an accident: the
 * `KEY_OPERATION_POLICY` of `scripts/lib/architecture.ts` reserves that name
 * to the Web Crypto boundary, so that every place a key operation happens can
 * be found by name. This is not a key operation pkinative performs; it is one
 * the caller performs and hands back.
 */
export interface ExternalSigner {
    /** The algorithm the signer uses, which decides the OID written into the structure. */
    readonly algorithm: SignatureAlgorithm;
    /**
     * Sign `data` — the exact bytes the signature covers, not a digest of them —
     * and return the signature **as `crypto.subtle.sign` would**: raw `r ‖ s`
     * for ECDSA, which pkinative converts to DER, and the plain octets for
     * every other family. A signer whose API returns DER for ECDSA must convert
     * it back; guessing which form arrived is how a signature gets encoded
     * twice.
     */
    readonly produceSignature: (data: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

/** Anything pkinative can sign with. */
export type Signer = SigningKey | ExternalSigner;
