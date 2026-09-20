/**
 * pkinative — the Web Crypto boundary
 * ===================================
 * The one door. This is the only module of `src/` allowed to name
 * `importKey` or `verify`, and — with `src/hash/fingerprint.ts` — one of two
 * allowed to reach `globalThis.crypto` at all
 * (`KEY_OPERATION_POLICY` and `WEBCRYPTO_HOST_MODULES` in
 * scripts/lib/architecture.ts, enforced by tests/tools/architecture.test.ts).
 *
 * Everything pkinative asks of a host is therefore readable in one file, in
 * about sixty lines. That is the whole point of the rule: not that the
 * library is careful with keys, but that a reviewer can confirm it in one
 * sitting.
 *
 * What it asks for is narrow by construction. Keys are imported from `spki`
 * — the public half, the bytes a certificate already publishes — with
 * `extractable: false` and the single usage `['verify']`. There is no path
 * from here to key material: `exportKey` is refused by the architecture
 * test, in this file as in every other.
 *
 * @module crypto/webcrypto
 */

import { PkiCryptoError } from '../types/pki-errors.js';
import type { CryptoKeyHandle, ImportParams, SubtlePublicKey, VerifyParams, WebCryptoHost } from '../types/webcrypto.js';

/** The host's `crypto.subtle`, or null when it cannot verify. */
function publicKeySubtle(): SubtlePublicKey | null {
    const subtle = (globalThis as WebCryptoHost).crypto?.subtle;
    if (subtle === undefined || typeof subtle.importKey !== 'function' || typeof subtle.verify !== 'function') return null;
    return subtle as SubtlePublicKey;
}

/**
 * Whether this runtime can verify a signature at all.
 *
 * Exposed so a caller can branch before building a report rather than
 * catching an exception inside one. Every modern runtime returns `true`;
 * a page served over plain HTTP has no `crypto.subtle` and returns
 * `false`, as does a sandbox that withholds it.
 *
 * @returns Whether `globalThis.crypto.subtle` offers both `importKey` and
 *   `verify`. It does not say which algorithms the host implements —
 *   Ed448 and Ed25519 are missing on several runtimes that answer `true`.
 * @throws Never — a missing host is the answer, not an error.
 */
export function canVerify(): boolean {
    return publicKeySubtle() !== null;
}

function requireSubtle(oid: string): SubtlePublicKey {
    const subtle = publicKeySubtle();
    if (subtle === null) {
        throw new PkiCryptoError('PKI_CRYPTO_UNAVAILABLE',
            'pkinative: this runtime exposes no crypto.subtle with importKey and verify, so no signature can be checked — call canVerify() first, or run where Web Crypto exists (Node 22+, any browser on a secure origin, Deno, Bun, Workers)', oid);
    }
    return subtle;
}

/**
 * Import a SubjectPublicKeyInfo as a non-extractable verification key.
 *
 * @param spkiDer The complete SubjectPublicKeyInfo encoding — the `der` of a
 *   parsed certificate's `subjectPublicKeyInfo`, not the key bits alone.
 * @param params What Web Crypto must be told the key is.
 * @param oid The signature algorithm OID, carried into any error.
 * @returns An opaque handle. pkinative never sees the key's bits.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the host cannot
 *   verify; `PKI_CRYPTO_KEY_UNSUPPORTED` when it refuses the key — an
 *   algorithm it does not implement (Ed448 and, on several runtimes still,
 *   Ed25519), or key bytes it will not accept.
 */
export async function importPublicKey(spkiDer: Uint8Array, params: ImportParams, oid: string): Promise<CryptoKeyHandle> {
    const subtle = requireSubtle(oid);
    try {
        return await subtle.importKey('spki', spkiDer, params, false, ['verify']);
    } catch (cause) {
        throw new PkiCryptoError('PKI_CRYPTO_KEY_UNSUPPORTED',
            `pkinative: this runtime refused to import the issuer's ${params.name} public key (${String(cause)}) — the algorithm may not be implemented here, or the key may be malformed; try another runtime before concluding the certificate is at fault`, oid);
    }
}

/**
 * Check one signature over one message.
 *
 * A host that throws is treated as a refusal, not as an incident: several
 * runtimes throw rather than return false for a signature of the wrong
 * length, and the two answers mean the same thing to a caller. Failing
 * closed here is what keeps a malformed signature from becoming an
 * exception someone catches into a success path.
 *
 * @param key A handle from {@link importPublicKey}.
 * @param params The algorithm, already resolved.
 * @param signature Raw signature octets — `r ‖ s` for ECDSA, never DER.
 * @param data The signed bytes, `tbsCertificate` for a certificate.
 * @returns Whether the signature checks out.
 */
export async function verifySignature(key: CryptoKeyHandle, params: VerifyParams, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
    const subtle = requireSubtle(params.name);
    try {
        return await subtle.verify(params, key, signature, data);
    } catch {
        return false;
    }
}
