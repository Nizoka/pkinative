/**
 * pkinative — signature algorithms, from OID to Web Crypto
 * ========================================================
 * RFC 5280 names a signature algorithm with an OID; Web Crypto names one
 * with an object. This module is the translation, and it is deliberately a
 * **closed table**: an algorithm absent from it is refused by name rather
 * than guessed at, because guessing here means verifying a signature under
 * an algorithm nobody chose.
 *
 * RSASSA-PSS is the one entry whose parameters are not implied by the OID
 * (RFC 4055 §3.1), so its hash and salt length are read out of the
 * certificate — the one place this layer touches ASN.1.
 *
 * @module crypto/crypto-algorithms
 */

import { readObjectIdentifier } from '../asn1/asn1-oid.js';
import { readSmallInteger } from '../asn1/asn1-read.js';
import { TAG_OID, TAG_SEQUENCE } from '../asn1/asn1-tags.js';
import type { Asn1Node } from '../types/asn1-types.js';
import { PkiCryptoError } from '../types/pki-errors.js';
import type { EcdsaVerifyParams, ImportParams, NamedVerifyParams, RsaPssVerifyParams, VerifyParams } from '../types/webcrypto.js';
import type { AlgorithmIdentifier, SubjectPublicKeyInfo } from '../types/x509-types.js';

// ── The digests ──────────────────────────────────────────────────────

/** NIST and OIW hash OIDs, to Web Crypto names. */
const HASH_BY_OID: ReadonlyMap<string, string> = /*#__PURE__*/ new Map([
    ['1.3.14.3.2.26', 'SHA-1'],
    ['2.16.840.1.101.3.4.2.1', 'SHA-256'],
    ['2.16.840.1.101.3.4.2.2', 'SHA-384'],
    ['2.16.840.1.101.3.4.2.3', 'SHA-512'],
]);

/**
 * RFC 4055 §3.1: `saltLength [2] INTEGER DEFAULT 20`. The default is 20
 * whatever the digest — it is the SHA-1 output size frozen into the
 * grammar, not a function of the hash, and reading it as one is a classic
 * way to verify PSS under the wrong parameters.
 */
const DEFAULT_PSS_SALT_LENGTH = 20;

// ── The signature algorithms ─────────────────────────────────────────

/**
 * What a signature OID says about the family and the digest.
 *
 * A union rather than one shape with an optional `hash`: the OID fixes the
 * digest for PKCS#1 v1.5 and ECDSA and does not for RSASSA-PSS or the
 * Edwards curves, and saying so in the type removes the `?? 'SHA-256'`
 * fallback that would otherwise sit, untestable, in both branches.
 */
type SignatureShape =
    | { readonly family: 'rsa-pkcs1' | 'ecdsa'; readonly hash: string }
    | { readonly family: 'rsa-pss' | 'ed25519' | 'ed448' };

/**
 * Every signature algorithm pkinative verifies, by OID.
 *
 * MD2 and MD5 signatures are deliberately absent. They appear in real
 * certificates, and Web Crypto implements neither — so the honest answer is
 * `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` naming the algorithm, not a
 * verification pkinative cannot perform.
 */
const SIGNATURE_BY_OID: ReadonlyMap<string, SignatureShape> = /*#__PURE__*/ new Map<string, SignatureShape>([
    ['1.2.840.113549.1.1.5', { family: 'rsa-pkcs1', hash: 'SHA-1' }],
    ['1.2.840.113549.1.1.11', { family: 'rsa-pkcs1', hash: 'SHA-256' }],
    ['1.2.840.113549.1.1.12', { family: 'rsa-pkcs1', hash: 'SHA-384' }],
    ['1.2.840.113549.1.1.13', { family: 'rsa-pkcs1', hash: 'SHA-512' }],
    ['1.2.840.113549.1.1.10', { family: 'rsa-pss' }],
    ['1.2.840.10045.4.1', { family: 'ecdsa', hash: 'SHA-1' }],
    ['1.2.840.10045.4.3.2', { family: 'ecdsa', hash: 'SHA-256' }],
    ['1.2.840.10045.4.3.3', { family: 'ecdsa', hash: 'SHA-384' }],
    ['1.2.840.10045.4.3.4', { family: 'ecdsa', hash: 'SHA-512' }],
    ['1.3.101.112', { family: 'ed25519' }],
    ['1.3.101.113', { family: 'ed448' }],
]);

/** Everything the boundary needs to import a key and check one signature. */
export interface ResolvedAlgorithm {
    readonly family: SignatureShape['family'];
    readonly importParams: ImportParams;
    readonly verifyParams: VerifyParams;
    /**
     * Set only for ECDSA, whose signature arrives as DER and must be
     * converted to `r ‖ s` at this curve's coordinate size. Carrying the
     * curve here rather than a boolean means the caller never re-derives it
     * and cannot re-derive it wrong.
     */
    readonly curve: 'P-256' | 'P-384' | 'P-521' | undefined;
}

function unsupported(message: string, oid: string): PkiCryptoError {
    return new PkiCryptoError('PKI_CRYPTO_ALGORITHM_UNSUPPORTED', `pkinative: ${message} — verify it with a library that implements it, or ask for it in an issue naming the certificate that needs it`, oid);
}

/**
 * RFC 4055 §3.1 RSASSA-PSS-params, as far as Web Crypto cares: the digest
 * and the salt length. Absent fields take their DEFAULT (SHA-1, 20).
 *
 * The mask generation function is checked but not returned: Web Crypto
 * implements MGF1 with the signature hash and offers no way to ask for
 * anything else, so a certificate specifying another MGF, or MGF1 over a
 * different digest, is refused rather than verified under parameters it did
 * not choose.
 */
function readPssParams(parameters: Asn1Node | undefined, oid: string): { hash: string; saltLength: number } {
    let hash = 'SHA-1';
    let saltLength: number | undefined;
    let mgfHash = 'SHA-1';

    if (parameters !== undefined) {
        if (parameters.tagClass !== 'universal' || parameters.tagNumber !== TAG_SEQUENCE) {
            throw unsupported('the RSASSA-PSS parameters are not a SEQUENCE', oid);
        }
        for (const field of parameters.children) {
            if (field.tagClass !== 'context') continue;
            const inner = field.children[0];
            if (inner === undefined) continue;
            if (field.tagNumber === 0) hash = hashNameOf(inner, oid);
            else if (field.tagNumber === 1) mgfHash = mgf1HashOf(inner, oid);
            else if (field.tagNumber === 2) saltLength = readSmallInteger(inner);
            else if (field.tagNumber === 3 && readSmallInteger(inner) !== 1) {
                throw unsupported('the RSASSA-PSS trailerField is not 1, the only value RFC 4055 defines', oid);
            }
        }
    }

    if (mgfHash !== hash) {
        throw unsupported(`the RSASSA-PSS mask generation uses ${mgfHash} while the signature uses ${hash}, and Web Crypto only offers MGF1 over the signature hash`, oid);
    }
    if (saltLength === undefined) saltLength = DEFAULT_PSS_SALT_LENGTH;
    if (saltLength < 0) throw unsupported('the RSASSA-PSS salt length is negative', oid);
    return { hash, saltLength };
}

/** The Web Crypto hash name of an AlgorithmIdentifier SEQUENCE. */
function hashNameOf(algorithm: Asn1Node, oid: string): string {
    const first = algorithm.tagClass === 'universal' && algorithm.tagNumber === TAG_SEQUENCE ? algorithm.children[0] : undefined;
    if (first === undefined || first.tagClass !== 'universal' || first.tagNumber !== TAG_OID) {
        throw unsupported('an RSASSA-PSS hash parameter is not an AlgorithmIdentifier', oid);
    }
    const hashOid = readObjectIdentifier(first);
    const name = HASH_BY_OID.get(hashOid);
    if (name === undefined) throw unsupported(`the RSASSA-PSS digest ${hashOid} is not one Web Crypto implements`, oid);
    return name;
}

/** MGF1's digest, from `id-mgf1` with an AlgorithmIdentifier parameter. */
function mgf1HashOf(algorithm: Asn1Node, oid: string): string {
    const first = algorithm.tagClass === 'universal' && algorithm.tagNumber === TAG_SEQUENCE ? algorithm.children[0] : undefined;
    if (first === undefined || first.tagClass !== 'universal' || first.tagNumber !== TAG_OID) {
        throw unsupported('the RSASSA-PSS maskGenAlgorithm is not an AlgorithmIdentifier', oid);
    }
    if (readObjectIdentifier(first) !== '1.2.840.113549.1.1.8') {
        throw unsupported('the RSASSA-PSS mask generation function is not MGF1, the only one Web Crypto implements', oid);
    }
    const inner = algorithm.children[1];
    return inner === undefined ? 'SHA-1' : hashNameOf(inner, oid);
}

/**
 * Whether an RSA signature may be checked against this key. Both OIDs are
 * accepted for both signature families: a key carrying `id-RSASSA-PSS`
 * still verifies a PKCS#1 v1.5 signature, and RFC 4055 §1.2 allows the
 * plain `rsaEncryption` OID under a PSS signature.
 */
const isRsaKey = (key: SubjectPublicKeyInfo): boolean => key.kind === 'rsa' || key.kind === 'rsa-pss';

/**
 * Resolve a signature algorithm and the key it will be checked against into
 * the two Web Crypto objects the boundary needs.
 *
 * Returns **`null`** when the key simply cannot have produced this kind of
 * signature — an RSA key under an ECDSA signature, an X25519 key under any
 * signature at all. That is a decided "no", not an inability to decide, and
 * a caller building a path must be able to try the next candidate issuer
 * without writing a `try`. Throwing is reserved for the questions that
 * genuinely cannot be put.
 *
 * @param algorithm The `signatureAlgorithm` of the certificate being checked.
 * @param key The issuer's `subjectPublicKeyInfo`.
 * @returns The import and verify parameters, or `null` when this key cannot
 *   have signed under this algorithm.
 * @throws {PkiCryptoError} `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when the OID is
 *   not in the table or its parameters name something Web Crypto cannot do;
 *   `PKI_CRYPTO_KEY_UNSUPPORTED` when the key is of the right family but on
 *   a curve Web Crypto does not verify.
 * @throws {PkiEncodingError} When the algorithm's parameters are malformed
 *   DER. `parseCertificate` leaves them undecoded, so this is the first
 *   reader to look inside them.
 */
export function resolveAlgorithm(algorithm: AlgorithmIdentifier, key: SubjectPublicKeyInfo): ResolvedAlgorithm | null {
    const shape = SIGNATURE_BY_OID.get(algorithm.oid);
    if (shape === undefined) throw unsupported(`the signature algorithm ${algorithm.oid} is not one pkinative verifies`, algorithm.oid);

    // Each branch checks the key kind itself rather than consulting a table
    // first. It costs a line and buys the narrowing: `key.curve` below is
    // reachable because TypeScript knows the key is an EC key, with no cast
    // and no defensive re-check that no test could ever reach.
    if (shape.family === 'rsa-pss') {
        if (!isRsaKey(key)) return null;
        const { hash, saltLength } = readPssParams(algorithm.parameters, algorithm.oid);
        const verifyParams: RsaPssVerifyParams = { name: 'RSA-PSS', saltLength };
        return { family: shape.family, importParams: { name: 'RSA-PSS', hash: { name: hash } }, verifyParams, curve: undefined };
    }

    if (shape.family === 'rsa-pkcs1') {
        if (!isRsaKey(key)) return null;
        const verifyParams: NamedVerifyParams = { name: 'RSASSA-PKCS1-v1_5' };
        return { family: shape.family, importParams: { name: 'RSASSA-PKCS1-v1_5', hash: { name: shape.hash } }, verifyParams, curve: undefined };
    }

    if (shape.family === 'ecdsa') {
        if (key.kind !== 'ec') return null;
        const curve = key.curve;
        if (curve !== 'P-256' && curve !== 'P-384' && curve !== 'P-521') {
            throw new PkiCryptoError('PKI_CRYPTO_KEY_UNSUPPORTED',
                `pkinative: the issuer's EC key is on ${curve ?? 'a curve pkinative does not name'}, and Web Crypto verifies ECDSA only on P-256, P-384 and P-521`, algorithm.oid);
        }
        const verifyParams: EcdsaVerifyParams = { name: 'ECDSA', hash: { name: shape.hash } };
        return { family: shape.family, importParams: { name: 'ECDSA', namedCurve: curve }, verifyParams, curve };
    }

    if (key.kind !== shape.family) return null;
    const name = shape.family === 'ed25519' ? 'Ed25519' : 'Ed448';
    return { family: shape.family, importParams: { name }, verifyParams: { name }, curve: undefined };
}

/** The curve of an ECDSA signature's r and s, in bytes — P-521 is 66, not 65. */
export function coordinateBytes(curve: 'P-256' | 'P-384' | 'P-521'): number {
    return curve === 'P-256' ? 32 : curve === 'P-384' ? 48 : 66;
}
