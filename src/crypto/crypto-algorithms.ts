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
 * certificate — the one place this layer touches ASN.1. An `id-RSASSA-PSS`
 * **key** is the other: the W3C Web Crypto specification imports an RSA
 * SubjectPublicKeyInfo only under `rsaEncryption`, so once RFC 4055 has been
 * held to, the same key bits are handed to the host under that identifier
 * ({@link _importableSpki}) — the one re-encoding this layer performs.
 *
 * CMS reads the same table with two differences (RFC 5652 §5.3): a signer
 * names its digest separately, and may name the bare key algorithm
 * `rsaEncryption` as its signature algorithm. The CMS entry points below add
 * exactly that, and the check that the two named hashes agree — including
 * the one digest Web Crypto does not compute, SHAKE256, which RFC 8419 §3.1
 * ties to Ed448 and `src/hash/shake256.ts` computes.
 *
 * @module crypto/crypto-algorithms
 */

import { encodeNull, encodeObjectIdentifier, encodeSequence, encodeTlv } from '../asn1/asn1-encode.js';
import { readObjectIdentifier } from '../asn1/asn1-oid.js';
import { readSmallInteger } from '../asn1/asn1-read.js';
import { TAG_BIT_STRING, TAG_INTEGER, TAG_NULL, TAG_OID, TAG_SEQUENCE } from '../asn1/asn1-tags.js';
import { concatBytes } from '../core/bytes.js';
import { _pkiError } from '../core/pki-error-guard.js';
import type { Asn1Node } from '../types/asn1-types.js';
import { PkiCryptoError, PkiError } from '../types/pki-errors.js';
import type { EcdsaVerifyParams, ImportParams, NamedVerifyParams, RsaPssVerifyParams, VerifyParams } from '../types/webcrypto.js';
import type { SignatureAlgorithm, SignatureHash } from '../types/crypto-types.js';
import type { AlgorithmIdentifier, RsaPublicKeyInfo, SubjectPublicKeyInfo } from '../types/x509-types.js';

// ── The digests ──────────────────────────────────────────────────────

/** NIST and OIW hash OIDs, to Web Crypto names. */
const HASH_BY_OID: ReadonlyMap<string, SignatureHash> = /*#__PURE__*/ new Map<string, SignatureHash>([
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
    /**
     * The digest this signature is over, as Web Crypto names it, or `undefined`
     * for Ed25519 and Ed448, whose digest is not a parameter.
     *
     * Carried so a **policy** decision can be made on it without re-reading the
     * OID or digging into `importParams`, where it lives in a different place
     * for each family. The one policy that needs it is the SHA-1 refusal in
     * `x509-verify.ts`: a caller deciding whether to believe a signature must be
     * able to see what it was computed over.
     */
    readonly hash: string | undefined;
}

/** A hash AlgorithmIdentifier's parameters are absent or NULL, and the two are the same algorithm (RFC 5754 §2, RFC 4055 §2.1). */
const hasNoHashParameters = (parameters: Asn1Node | undefined): boolean =>
    parameters === undefined || (parameters.tagClass === 'universal' && parameters.tagNumber === TAG_NULL && parameters.contentLength === 0);

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
 *
 * The grammar is held exactly — `[0]` to `[3]`, each at most once and in
 * that order, each one value under an explicit tag — because a reader that
 * skips a stray child or lets a repeated field win reads parameters another
 * verifier reads differently (CWE-436).
 */
function readPssParams(parameters: Asn1Node | undefined, oid: string): { hash: SignatureHash; saltLength: number } {
    let hash: SignatureHash = 'SHA-1';
    let saltLength: number | undefined;
    let mgfHash: SignatureHash = 'SHA-1';

    if (parameters !== undefined) {
        if (parameters.tagClass !== 'universal' || parameters.tagNumber !== TAG_SEQUENCE) {
            throw unsupported('the RSASSA-PSS parameters are not a SEQUENCE', oid);
        }
        let previous = -1;
        for (const field of parameters.children) {
            if (field.tagClass !== 'context' || field.tagNumber > 3 || field.tagNumber <= previous) {
                throw unsupported('the RSASSA-PSS parameters hold a field other than [0] to [3], each at most once and in order (RFC 4055 §3.1)', oid);
            }
            previous = field.tagNumber;
            // A primitive tag has no children, so this also refuses one.
            if (field.children.length !== 1) {
                throw unsupported(`the RSASSA-PSS field [${String(field.tagNumber)}] is not one value under an explicit tag (RFC 4055 §3.1)`, oid);
            }
            const inner = field.children[0] as Asn1Node;
            if (field.tagNumber === 0) hash = hashNameOf(inner, oid);
            else if (field.tagNumber === 1) mgfHash = mgf1HashOf(inner, oid);
            else if (field.tagNumber === 2) saltLength = pssInteger(inner, 'saltLength', oid);
            else if (pssInteger(inner, 'trailerField', oid) !== 1) {
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

/** The saltLength or trailerField INTEGER of RSASSA-PSS-params. */
function pssInteger(node: Asn1Node, what: string, oid: string): number {
    if (node.tagClass !== 'universal' || node.tagNumber !== TAG_INTEGER) {
        throw unsupported(`the RSASSA-PSS ${what} is not an INTEGER`, oid);
    }
    return readSmallInteger(node);
}

/**
 * The Web Crypto hash name of an AlgorithmIdentifier SEQUENCE, whose
 * parameters are absent or NULL (RFC 4055 §2.1) — never anything else.
 */
function hashNameOf(algorithm: Asn1Node, oid: string): SignatureHash {
    const first = algorithm.tagClass === 'universal' && algorithm.tagNumber === TAG_SEQUENCE ? algorithm.children[0] : undefined;
    if (first === undefined || first.tagClass !== 'universal' || first.tagNumber !== TAG_OID) {
        throw unsupported('an RSASSA-PSS hash parameter is not an AlgorithmIdentifier', oid);
    }
    if (algorithm.children.length > 2 || !hasNoHashParameters(algorithm.children[1])) {
        throw unsupported('an RSASSA-PSS hash AlgorithmIdentifier carries parameters other than absent or NULL (RFC 4055 §2.1)', oid);
    }
    const hashOid = readObjectIdentifier(first);
    const name = HASH_BY_OID.get(hashOid);
    if (name === undefined) throw unsupported(`the RSASSA-PSS digest ${hashOid} is not one Web Crypto implements`, oid);
    return name;
}

/** MGF1's digest, from `id-mgf1` with an AlgorithmIdentifier parameter. */
function mgf1HashOf(algorithm: Asn1Node, oid: string): SignatureHash {
    const first = algorithm.tagClass === 'universal' && algorithm.tagNumber === TAG_SEQUENCE ? algorithm.children[0] : undefined;
    if (first === undefined || first.tagClass !== 'universal' || first.tagNumber !== TAG_OID || algorithm.children.length > 2) {
        throw unsupported('the RSASSA-PSS maskGenAlgorithm is not an AlgorithmIdentifier', oid);
    }
    if (readObjectIdentifier(first) !== '1.2.840.113549.1.1.8') {
        throw unsupported('the RSASSA-PSS mask generation function is not MGF1, the only one Web Crypto implements', oid);
    }
    const inner = algorithm.children[1];
    return inner === undefined ? 'SHA-1' : hashNameOf(inner, oid);
}

/**
 * Whether an RSASSA-PSS signature may be checked against this key: an
 * `rsaEncryption` key places no restriction on how it is used (RFC 4055
 * §1.2), and an `id-RSASSA-PSS` key is certified for exactly this.
 */
const isRsaKey = (key: SubjectPublicKeyInfo): key is RsaPublicKeyInfo => key.kind === 'rsa' || key.kind === 'rsa-pss';

/**
 * Whether a PKCS#1 v1.5 signature may be checked against this key. Only an
 * `rsaEncryption` key: RFC 4055 §1.2 — "When a certificate conveys an RSA
 * public key with the id-RSASSA-PSS object identifier, the certificate user
 * MUST only use the certified RSA public key for RSASSA-PSS operations."
 */
const isPkcs1Key = (key: SubjectPublicKeyInfo): key is RsaPublicKeyInfo => key.kind === 'rsa';

/**
 * Refuse an RSA public exponent no signature scheme is defined for.
 *
 * RFC 8017 §3.1 makes the public exponent an odd integer between 3 and n − 1.
 * Web Crypto imports e = 1 regardless (Node.js 22 does), and under e = 1 the
 * "signature" of a message is the message's own PKCS#1 encoding: anyone writes
 * one with no private key at all. An even exponent is not a permutation of
 * the group, so no signature under it means anything either. Both are refused
 * before the key reaches the host — as `PKI_CRYPTO_KEY_UNSUPPORTED`, which the
 * reports carry as `SIGNATURE_NOT_CHECKED` and never as a verdict.
 *
 * @internal
 */
export function _refuseWeakRsaExponent(key: RsaPublicKeyInfo, oid: string): void {
    const e = key.publicExponent;
    if (e < 3n || (e & 1n) === 0n) {
        throw new PkiCryptoError('PKI_CRYPTO_KEY_UNSUPPORTED',
            `pkinative: the RSA public exponent is ${e.toString()}; RFC 8017 §3.1 requires an odd exponent of at least 3, and under this one a signature proves nothing — the certificate's key is not one any verifier should accept`, oid);
    }
}

/**
 * Whether the RSASSA-PSS parameters of a signature are ones this key admits.
 *
 * An `id-RSASSA-PSS` key whose AlgorithmIdentifier carries parameters
 * restricts the signatures it may verify, RFC 4055 §3.3: "All parameters in
 * the signature structure algorithm identifier MUST match the parameters in
 * the key structure algorithm identifier except the saltLength field. The
 * saltLength field in the signature parameters MUST be greater or equal to
 * that in the key parameters field." Absent key parameters restrict nothing
 * (§3.1). RFC 4056 §3 repeats the four comparisons for a CMS signer, and
 * `resolveCmsAlgorithm` reaches this function for every RSASSA-PSS signer.
 * Both sides are read to their DEFAULTs first — "default values are
 * considered to be the same as extant values" — so an explicit SHA-1
 * matches an omitted one; the MGF1 digest and the trailer field are held to
 * the hash and to 1 by {@link readPssParams} on both sides already, which
 * leaves the hash and the salt length to compare.
 */
function pssKeyAdmits(key: SubjectPublicKeyInfo, signature: { readonly hash: string; readonly saltLength: number }, oid: string): boolean {
    if (key.kind !== 'rsa-pss' || key.algorithm.parameters === undefined) return true;
    const restriction = readPssParams(key.algorithm.parameters, oid);
    return signature.hash === restriction.hash && signature.saltLength >= restriction.saltLength;
}

/**
 * Resolve a signature algorithm and the key it will be checked against into
 * the two Web Crypto objects the boundary needs.
 *
 * Returns **`null`** when the key simply cannot have produced this kind of
 * signature — an RSA key under an ECDSA signature, an X25519 key under any
 * signature at all, an `id-RSASSA-PSS` key under a PKCS#1 v1.5 signature
 * (RFC 4055 §1.2), or under RSASSA-PSS parameters its own parameters exclude
 * (RFC 4055 §3.3: another hash, or a shorter salt). That is a decided "no", not an inability to decide, and
 * a caller building a path must be able to try the next candidate issuer
 * without writing a `try`. Throwing is reserved for the questions that
 * genuinely cannot be put.
 *
 * @param algorithm The `signatureAlgorithm` of the certificate being checked.
 * @param key The issuer's `subjectPublicKeyInfo`.
 * @returns The import and verify parameters, or `null` when this key cannot
 *   have signed under this algorithm.
 * @throws {PkiCryptoError} `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when the OID is
 *   not in the table or its parameters — or those of an `id-RSASSA-PSS`
 *   key — name something Web Crypto cannot do; `PKI_CRYPTO_KEY_UNSUPPORTED`
 *   when the key is of the right family but on a curve Web Crypto does not
 *   verify.
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
        _refuseWeakRsaExponent(key, algorithm.oid);
        const { hash, saltLength } = readPssParams(algorithm.parameters, algorithm.oid);
        if (!pssKeyAdmits(key, { hash, saltLength }, algorithm.oid)) return null;
        const verifyParams: RsaPssVerifyParams = { name: 'RSA-PSS', saltLength };
        return { family: shape.family, importParams: { name: 'RSA-PSS', hash: { name: hash } }, verifyParams, curve: undefined, hash };
    }

    if (shape.family === 'rsa-pkcs1') {
        if (!isPkcs1Key(key)) return null;
        _refuseWeakRsaExponent(key, algorithm.oid);
        const verifyParams: NamedVerifyParams = { name: 'RSASSA-PKCS1-v1_5' };
        return { family: shape.family, importParams: { name: 'RSASSA-PKCS1-v1_5', hash: { name: shape.hash } }, verifyParams, curve: undefined, hash: shape.hash };
    }

    if (shape.family === 'ecdsa') {
        if (key.kind !== 'ec') return null;
        const curve = key.curve;
        if (curve !== 'P-256' && curve !== 'P-384' && curve !== 'P-521') {
            throw new PkiCryptoError('PKI_CRYPTO_KEY_UNSUPPORTED',
                `pkinative: the issuer's EC key is on ${curve ?? 'a curve pkinative does not name'}, and Web Crypto verifies ECDSA only on P-256, P-384 and P-521`, algorithm.oid);
        }
        const verifyParams: EcdsaVerifyParams = { name: 'ECDSA', hash: { name: shape.hash } };
        return { family: shape.family, importParams: { name: 'ECDSA', namedCurve: curve }, verifyParams, curve, hash: shape.hash };
    }

    if (key.kind !== shape.family) return null;
    const name = shape.family === 'ed25519' ? 'Ed25519' : 'Ed448';
    return { family: shape.family, importParams: { name }, verifyParams: { name }, curve: undefined, hash: undefined };
}

/** `rsaEncryption` with its NULL parameters — the one AlgorithmIdentifier Web Crypto imports an RSA key under. */
const RSA_ENCRYPTION_IDENTIFIER = /*#__PURE__*/ encodeSequence([encodeObjectIdentifier('1.2.840.113549.1.1.1'), encodeNull()]);

/**
 * The SubjectPublicKeyInfo to hand the host for this key.
 *
 * Every key goes as the certificate published it, with one exception. The
 * W3C Web Crypto specification imports an RSA SubjectPublicKeyInfo only when
 * its algorithm is `rsaEncryption`, and throws a DataError otherwise
 * (RSA-PSS "import key", format "spki"); an `id-RSASSA-PSS` key — what
 * `openssl genpkey -algorithm RSA-PSS`, GnuTLS `certtool --key-type=rsa-pss`
 * and `keytool -keyalg RSASSA-PSS` write — is therefore refused by every
 * conforming runtime, Node.js 22 included ("DataError: Invalid key type").
 * RFC 4055 §1.2 says what such a key is: the same RSA public key, restricted
 * by its identifier to RSASSA-PSS. So once {@link resolveAlgorithm} has held
 * the signature to that restriction — PSS only, and under the parameters the
 * key's own parameters admit (§3.3) — the restriction has done its work, and
 * the key bits are re-wrapped under `rsaEncryption`, unchanged, for the host
 * to import as RSA-PSS with the signature's hash. Nothing about the key is
 * guessed, and nothing is judged: the `subjectPublicKey` BIT STRING is copied
 * as it stands, unused-bits octet included, and the host judges the key as it
 * judges every other.
 *
 * @internal
 */
export function _importableSpki(key: SubjectPublicKeyInfo): Uint8Array {
    if (key.kind !== 'rsa-pss') return key.der;
    const bitString = encodeTlv('universal', TAG_BIT_STRING, false, concatBytes([Uint8Array.of(key.publicKey.unusedBits), key.publicKey.bytes]));
    return encodeSequence([RSA_ENCRYPTION_IDENTIFIER, bitString]);
}

/**
 * The digest an `id-RSASSA-PSS` key's own parameters bind it to, or
 * `undefined` for a key without parameters (which RFC 4055 §3.1 leaves to
 * sign over any digest) or a key of another kind.
 *
 * What a PKCS#12 reader needs: a private key under such a certificate signs
 * RSA-PSS, and over this digest when the certificate names one.
 *
 * @internal
 * @throws {PkiCryptoError} `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when the
 *   parameters name something Web Crypto cannot do, as {@link resolveAlgorithm}.
 */
export function _pssKeyHash(key: SubjectPublicKeyInfo): SignatureHash | undefined {
    if (key.kind !== 'rsa-pss' || key.algorithm.parameters === undefined) return undefined;
    return readPssParams(key.algorithm.parameters, key.algorithm.oid).hash;
}

// ── The same table, under CMS (0.7) ──────────────────────────────────

/**
 * `rsaEncryption`, the key OID. RFC 3370 §3.2 makes it a MUST as a CMS
 * *signature* algorithm, with the hash taken from `digestAlgorithm` — it is
 * what OpenSSL and most PDF signers write, so a verifier built on the X.509
 * table alone would refuse the commonest CMS signature there is.
 */
const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
const ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const ID_ED448 = '1.3.101.113';

/**
 * `id-shake256` (NIST CSOR): SHAKE256 with a 512-bit output when it stands
 * as a digest algorithm, parameters absent (RFC 8419 §2.1, RFC 8702 §3.1).
 * The one CMS digest Web Crypto does not compute and pkinative does, and the
 * only one RFC 8419 §3.1 allows an Ed448 signer. `id-shake256-len`
 * (…4.2.18), whose INTEGER parameter chooses the length, is not that
 * identifier and is held to be another algorithm.
 *
 * @internal
 */
export const ID_SHAKE256 = '2.16.840.1.101.3.4.2.12';

/** `md5WithRSAEncryption` and `id-md5`: refused as inconsistent, never reported as merely unsupported. */
const MD5_OIDS: ReadonlySet<string> = /*#__PURE__*/ new Set(['1.2.840.113549.1.1.4', '1.2.840.113549.2.5']);

/**
 * Whether a SignerInfo's two algorithms contradict each other — or name one
 * pkinative refuses outright — and if so, why.
 *
 * A CMS signer names up to three hashes (RFC 5652 §5.3): `digestAlgorithm`,
 * the one built into `signatureAlgorithm`, and the one inside RSASSA-PSS
 * parameters. Only `digestAlgorithm` is used for the content and the signed
 * attributes (RFC 8933 §3), so a signature algorithm that names another hash
 * describes a computation that did not happen; accepting it would let the
 * unsigned `digestAlgorithm` field be rewritten under a valid signature.
 *
 * `null` does not mean *supported*. DSA, SHA-224 and unknown OIDs are not
 * inconsistent, they are outside what Web Crypto runs, and
 * {@link resolveCmsAlgorithm} says so by throwing. Keeping the two answers
 * apart is what lets a report distinguish "this signer is wrong" from "this
 * signer could not be checked here".
 *
 * Ed448 is the one signer whose digest is not a Web Crypto hash: RFC 8419
 * §3.1 makes it `id-shake256` (512-bit output), which `src/hash/shake256.ts`
 * computes. It is judged first, because the table below only knows the FIPS
 * 180-4 digests and would otherwise leave an Ed448 signer over SHA-512 — a
 * computation RFC 8419 forbids — to a resolver that cannot tell.
 *
 * @internal
 * @param digestAlgorithm The SignerInfo's `digestAlgorithm`.
 * @param signatureAlgorithm The SignerInfo's `signatureAlgorithm`.
 * @returns One English clause naming the inconsistency, or `null`.
 * @throws Never — a PSS parameter set too malformed to read is left to the
 *   resolver, which reports it with a code.
 */
export function _cmsAlgorithmProblem(digestAlgorithm: AlgorithmIdentifier, signatureAlgorithm: AlgorithmIdentifier): string | null {
    if (MD5_OIDS.has(digestAlgorithm.oid) || MD5_OIDS.has(signatureAlgorithm.oid)) {
        return 'MD5 is refused: its collisions have been practical since 2004';
    }
    if (signatureAlgorithm.oid === ID_EC_PUBLIC_KEY) {
        return 'id-ecPublicKey is a key algorithm, not a signature algorithm, and no RFC lets it stand for ECDSA with the hash left to the unsigned digestAlgorithm';
    }
    if (signatureAlgorithm.oid === ID_ED448) {
        if (digestAlgorithm.oid !== ID_SHAKE256) {
            return `Ed448 requires the id-shake256 digestAlgorithm, SHAKE256 with a 512-bit output (RFC 8419 §3.1), not ${digestAlgorithm.oid}`;
        }
        return hasNoHashParameters(digestAlgorithm.parameters) ? null : 'the id-shake256 digestAlgorithm carries parameters, where RFC 8419 §2.1 allows none';
    }

    const digest = HASH_BY_OID.get(digestAlgorithm.oid);
    if (digest === undefined) return null;
    if (!hasNoHashParameters(digestAlgorithm.parameters)) {
        return `the ${digest} digestAlgorithm carries parameters, where RFC 5754 §2 allows only absent or NULL`;
    }
    if (signatureAlgorithm.oid === RSA_ENCRYPTION) return null;

    const shape = SIGNATURE_BY_OID.get(signatureAlgorithm.oid);
    if (shape === undefined) return null;

    if (shape.family === 'rsa-pkcs1' || shape.family === 'ecdsa') {
        return shape.hash === digest ? null : `${signatureAlgorithm.oid} signs over ${shape.hash}, but the digestAlgorithm is ${digest}`;
    }
    if (shape.family === 'rsa-pss') {
        // RFC 4056 §2.2: mandatory in CMS. An absent field is not "whatever
        // the key says" — reading it that way picks parameters nobody signed.
        if (signatureAlgorithm.parameters === undefined) return 'RSASSA-PSS without parameters, which RFC 4056 §2.2 makes mandatory in CMS';
        let pssHash: string;
        try {
            // An empty SEQUENCE is legal and means the RFC 4055 defaults —
            // SHA-1 — so it is consistent only with a SHA-1 digest.
            pssHash = readPssParams(signatureAlgorithm.parameters, signatureAlgorithm.oid).hash;
        } catch (error) {
            // Parameters that cannot be read are the resolver's to refuse,
            // with its own code; a non-PkiError is a bug and goes on as one.
            _pkiError(error);
            return null;
        }
        return pssHash === digest ? null : `RSASSA-PSS over ${pssHash}, but the digestAlgorithm is ${digest}`;
    }
    // Ed25519 is what remains: Ed448 was judged above, before the table.
    return digest === 'SHA-512' ? null : `Ed25519 requires a SHA-512 digestAlgorithm (RFC 8419 §3.1), not ${digest}`;
}

/**
 * Resolve a SignerInfo's algorithm pair and the signer's key into the Web
 * Crypto parameters, as {@link resolveAlgorithm} does for a certificate.
 *
 * It maps; it does not judge. Call {@link _cmsAlgorithmProblem} first — this
 * resolves `ecdsa-with-SHA384` whatever `digestAlgorithm` says.
 *
 * @param digestAlgorithm The SignerInfo's `digestAlgorithm`.
 * @param signatureAlgorithm The SignerInfo's `signatureAlgorithm`.
 * @param key The signer certificate's `subjectPublicKeyInfo`.
 * @returns The import and verify parameters, or `null` when this key cannot
 *   have signed under this algorithm.
 * An Ed448 signer resolves like an Ed448 certificate signature — `{ name:
 * 'Ed448' }` for the host, whose refusal on a runtime without Ed448 is the
 * same `PKI_CRYPTO_KEY_UNSUPPORTED` either way. Its SHAKE256 content digest
 * is not the host's concern: `verifySignedData` computes it.
 *
 * @param digestAlgorithm The SignerInfo's `digestAlgorithm`.
 * @param signatureAlgorithm The SignerInfo's `signatureAlgorithm`.
 * @param key The signer certificate's `subjectPublicKeyInfo`.
 * @returns The import and verify parameters, or `null` when this key cannot
 *   have signed under this algorithm.
 * @throws {PkiCryptoError} `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` for
 *   `rsaEncryption` over a digest Web Crypto does not compute, and wherever
 *   {@link resolveAlgorithm} throws it; `PKI_CRYPTO_KEY_UNSUPPORTED` as
 *   {@link resolveAlgorithm}.
 * @throws {PkiEncodingError} When the signature algorithm's parameters are
 *   malformed DER.
 */
export function resolveCmsAlgorithm(digestAlgorithm: AlgorithmIdentifier, signatureAlgorithm: AlgorithmIdentifier, key: SubjectPublicKeyInfo): ResolvedAlgorithm | null {
    if (signatureAlgorithm.oid !== RSA_ENCRYPTION) return resolveAlgorithm(signatureAlgorithm, key);

    const hash = HASH_BY_OID.get(digestAlgorithm.oid);
    if (hash === undefined) throw unsupported(`the digest algorithm ${digestAlgorithm.oid} is not one pkinative verifies`, RSA_ENCRYPTION);
    if (!isPkcs1Key(key)) return null;
    _refuseWeakRsaExponent(key, RSA_ENCRYPTION);
    return { family: 'rsa-pkcs1', importParams: { name: 'RSASSA-PKCS1-v1_5', hash: { name: hash } }, verifyParams: { name: 'RSASSA-PKCS1-v1_5' }, curve: undefined, hash };
}

/** The curve of an ECDSA signature's r and s, in bytes — P-521 is 66, not 65. */
export function coordinateBytes(curve: 'P-256' | 'P-384' | 'P-521'): number {
    return curve === 'P-256' ? 32 : curve === 'P-384' ? 48 : 66;
}

// ── The same table, read the other way (0.3 creation) ────────────────

/** Signature OID by family and digest — the inverse of `SIGNATURE_BY_OID`. */
const OID_BY_SIGNATURE: ReadonlyMap<string, string> = /*#__PURE__*/ new Map([
    ['RSASSA-PKCS1-v1_5/SHA-1', '1.2.840.113549.1.1.5'],
    ['RSASSA-PKCS1-v1_5/SHA-256', '1.2.840.113549.1.1.11'],
    ['RSASSA-PKCS1-v1_5/SHA-384', '1.2.840.113549.1.1.12'],
    ['RSASSA-PKCS1-v1_5/SHA-512', '1.2.840.113549.1.1.13'],
    ['ECDSA/SHA-1', '1.2.840.10045.4.1'],
    ['ECDSA/SHA-256', '1.2.840.10045.4.3.2'],
    ['ECDSA/SHA-384', '1.2.840.10045.4.3.3'],
    ['ECDSA/SHA-512', '1.2.840.10045.4.3.4'],
]);

/**
 * The Edwards curves, keyed by the literal union rather than by string, so
 * the lookup is total and needs no `?? ''` fallback no test could reach.
 */
const EDWARDS_OID: Readonly<Record<'Ed25519' | 'Ed448', string>> = /*#__PURE__*/ Object.freeze({
    Ed25519: '1.3.101.112',
    Ed448: '1.3.101.113',
});

/** The OID of a hash, for the RSASSA-PSS parameters. */
const OID_BY_HASH: ReadonlyMap<string, string> = /*#__PURE__*/ new Map([
    ['SHA-1', '1.3.14.3.2.26'],
    ['SHA-256', '2.16.840.1.101.3.4.2.1'],
    ['SHA-384', '2.16.840.1.101.3.4.2.2'],
    ['SHA-512', '2.16.840.1.101.3.4.2.3'],
]);

/** The digest's output size in bytes — the salt length a modern PSS issuer uses. */
const HASH_BYTES: ReadonlyMap<string, number> = /*#__PURE__*/ new Map([
    ['SHA-1', 20], ['SHA-256', 32], ['SHA-384', 48], ['SHA-512', 64],
]);

/** What a signer needs: the OID to write down, and the call to make. */
export interface ResolvedSigner {
    /** The RFC 5280 signature algorithm OID. */
    readonly oid: string;
    /** The Web Crypto `sign` parameters. */
    readonly signParams: VerifyParams;
    /**
     * The Web Crypto import parameters of a private key that signs this way —
     * what `keys` tells the host a PKCS#8 is before importing or unwrapping it.
     */
    readonly importParams: ImportParams;
    /** The curve, for ECDSA only — its raw signature must become DER. */
    readonly curve: 'P-256' | 'P-384' | 'P-521' | undefined;
    /** The digest OID and salt length of RSASSA-PSS, which the structure must carry. */
    readonly pss: { readonly hashOid: string; readonly saltLength: number } | undefined;
}

/**
 * Resolve a named signature algorithm into the OID a certificate carries and
 * the parameters Web Crypto takes.
 *
 * The inverse of {@link resolveAlgorithm}, and deliberately the same closed
 * table read backwards: an algorithm pkinative can write is an algorithm
 * pkinative can read, and the two can never drift apart into a certificate
 * this library produces and refuses.
 *
 * @param algorithm The algorithm the caller named.
 * @returns The OID, the Web Crypto sign and private-key import parameters,
 *   and the extra facts the structure needs for ECDSA and RSASSA-PSS.
 * @throws {PkiCryptoError} `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when the
 *   combination has no RFC 5280 OID — every ECDSA and PKCS#1 v1.5 digest
 *   pairing does, so this is reachable only through an unchecked cast.
 * @throws {PkiError} `PKI_INVALID_OPTION` for an ECDSA algorithm whose
 *   `namedCurve` is not P-256, P-384 or P-521 — a JavaScript caller can omit
 *   what the type requires, and the signature would then be written in a
 *   form no verifier accepts.
 */
export function resolveSigner(algorithm: SignatureAlgorithm): ResolvedSigner {
    if (algorithm.name === 'Ed25519' || algorithm.name === 'Ed448') {
        const name = algorithm.name;
        return { oid: EDWARDS_OID[name], signParams: { name }, importParams: { name }, curve: undefined, pss: undefined };
    }

    if (algorithm.name === 'RSA-PSS') {
        const hashOid = OID_BY_HASH.get(algorithm.hash);
        const size = HASH_BYTES.get(algorithm.hash);
        if (hashOid === undefined || size === undefined) throw unsupported(`RSASSA-PSS with ${algorithm.hash} is not a digest pkinative writes`, '1.2.840.113549.1.1.10');
        const saltLength = algorithm.saltLength ?? size;
        if (!Number.isInteger(saltLength) || saltLength < 0) {
            throw unsupported(`the RSASSA-PSS salt length must be a non-negative integer, got ${String(algorithm.saltLength)}`, '1.2.840.113549.1.1.10');
        }
        return {
            oid: '1.2.840.113549.1.1.10',
            signParams: { name: 'RSA-PSS', saltLength },
            importParams: { name: 'RSA-PSS', hash: { name: algorithm.hash } },
            curve: undefined,
            pss: { hashOid, saltLength },
        };
    }

    const oid = OID_BY_SIGNATURE.get(`${algorithm.name}/${algorithm.hash}`);
    if (oid === undefined) throw unsupported(`${algorithm.name} with ${algorithm.hash} has no RFC 5280 signature OID`, '');
    if (algorithm.name === 'ECDSA') {
        // The type requires the curve; a JavaScript caller or a cast can omit it. Without it the
        // r‖s the host returns would be written as it stands, a signature no verifier accepts —
        // an artefact that fails closed everywhere, which is still a lie in the writer's output.
        if (algorithm.namedCurve !== 'P-256' && algorithm.namedCurve !== 'P-384' && algorithm.namedCurve !== 'P-521') {
            throw new PkiError('PKI_INVALID_OPTION', `pkinative: an ECDSA signing key names its curve — algorithm.namedCurve must be 'P-256', 'P-384' or 'P-521', got ${String(algorithm.namedCurve)}`);
        }
        return {
            oid,
            signParams: { name: 'ECDSA', hash: { name: algorithm.hash } },
            importParams: { name: 'ECDSA', namedCurve: algorithm.namedCurve },
            curve: algorithm.namedCurve,
            pss: undefined,
        };
    }
    return {
        oid,
        signParams: { name: 'RSASSA-PKCS1-v1_5' },
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: { name: algorithm.hash } },
        curve: undefined,
        pss: undefined,
    };
}
