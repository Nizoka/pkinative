/**
 * pkinative — one CMS signer, judged the whole way
 * ================================================
 * Everything RFC 5652 §5.6 asks of a verifier for one SignerInfo, in the order
 * that keeps each answer honest, shared by the two compositions that need it:
 * a signed message has any number of signers, and a timestamp token has one.
 *
 * The order is not cosmetic. The algorithms are checked for consistency
 * **before** the signature, because an inconsistent pair is the shape of an
 * algorithm-substitution attack and the signature check would only add a
 * misleading `SIGNATURE_INVALID` on top. The digest of the content is computed
 * here, from the content, and never taken from the signer. And the signing
 * certificate is chosen by the signature **and** by the signer's own signed
 * statement of which certificate it used — several certificates may hold one
 * key, and the identifier that selects them is not signed.
 *
 * Nothing here judges trust. Whether the certificate chains to an anchor, is
 * current and is unrevoked belongs to `verifyCertificateChain`, which the
 * compositions call with the certificate this module found.
 *
 * @module verify/verify-signer
 */

import { _describeSid, _digestReason, _signerAttributeReasons, _signerCandidates, _signingCertificateReason } from '../cms/cms-check.js';
import { OID_ATTR_SIGNING_CERTIFICATE, OID_ATTR_SIGNING_CERTIFICATE_V2 } from '../core/cms-oids.js';
import {
    cmsAlgorithmMismatchReason,
    cmsAttributeInvalidReason,
    cmsContentMissingReason,
    cmsSignerNotFoundReason,
    signatureInvalidReason,
    signatureNotCheckedReason,
} from '../core/pki-reasons.js';
import { verifySignerInfoSignature } from '../crypto/cms-verify.js';
import { _cmsAlgorithmProblem } from '../crypto/crypto-algorithms.js';
import { computeFingerprintAsync } from '../hash/fingerprint.js';
import type { SignedData, SignerInfo } from '../types/cms-types.js';
import type { FingerprintAlgorithm } from '../types/hash-types.js';
import type { PkiError } from '../types/pki-errors.js';
import { _pkiError } from './verify-chain.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { Certificate } from '../types/x509-types.js';

/** The digests a content may be hashed with here, by OID. */
const DIGEST_NAMES: ReadonlyMap<string, FingerprintAlgorithm> = /*#__PURE__*/ new Map([
    ['1.3.14.3.2.26', 'SHA-1'],
    ['2.16.840.1.101.3.4.2.1', 'SHA-256'],
    ['2.16.840.1.101.3.4.2.2', 'SHA-384'],
    ['2.16.840.1.101.3.4.2.3', 'SHA-512'],
]);

/** The digest a parsed `AlgorithmIdentifier` names, as the hash layer names it; `undefined` for one it does not compute. @internal */
export function _digestName(oid: string): FingerprintAlgorithm | undefined {
    return DIGEST_NAMES.get(oid);
}

/** What one signer is judged against. */
export interface _SignerContext {
    readonly signedData: SignedData;
    /** Every parsed certificate the signer may be found among: the message's own bag, and the caller's. */
    readonly candidates: readonly Certificate[];
    /** How many of the message's certificates could not be read — said when the signer is not found. */
    readonly unreadable: number;
    /** The content, attached or supplied; `undefined` when neither. */
    readonly content: Uint8Array | undefined;
    /** A detached content's digest, supplied instead of the content. */
    readonly contentDigest: Uint8Array | undefined;
    readonly allowSha1: boolean;
    readonly requireSigningCertificate: boolean;
    readonly requireAlgorithmProtection: boolean;
}

/** What judging one signer established. */
export interface _SignerOutcome {
    /** Every reason, with paths under the prefix given. */
    readonly reasons: readonly PkiReason[];
    /** The certificate whose key verified the signature and which the signer committed to; `undefined` when none did. */
    readonly certificate: Certificate | undefined;
    /**
     * Whether every check that needs no trust store passed: the attributes say
     * what they must, the algorithms agree, the content hashes to the committed
     * digest, the signature verifies, and the key's certificate is the one the
     * signer named. Nothing about whether anybody trusts that certificate.
     */
    readonly intact: boolean;
    /** How many Web Crypto verifications this cost. */
    readonly signatureVerifications: number;
}

/**
 * Judge one signer: attributes, algorithms, digest, signature and
 * signing-certificate binding.
 *
 * @internal
 */
export async function _verifySigner(ctx: _SignerContext, signer: SignerInfo, path: string): Promise<_SignerOutcome> {
    const reasons: PkiReason[] = [..._signerAttributeReasons(ctx.signedData, signer, path, { requireAlgorithmProtection: ctx.requireAlgorithmProtection })];

    // RFC 5035 and RFC 3161 profiles make the binding mandatory. A raw
    // attribute present but unreadable as one value was already reported by the
    // attribute rules; this is only for one that is not there at all.
    if (ctx.requireSigningCertificate && !(signer.signedAttributes ?? []).some((attribute) =>
        attribute.oid === OID_ATTR_SIGNING_CERTIFICATE || attribute.oid === OID_ATTR_SIGNING_CERTIFICATE_V2)) {
        reasons.push(cmsAttributeInvalidReason(`${path}.signedAttrs.signingCertificate`,
            'the signer names no signing certificate (ESSCertID or ESSCertIDv2), and one was required — without it, the signature can be presented under any certificate for the same key'));
    }

    // Consistency first: an algorithm pair that contradicts itself is the
    // verdict, and checking a signature under it would only add a misleading
    // SIGNATURE_INVALID to it.
    const problem = _cmsAlgorithmProblem(signer.digestAlgorithm, signer.signatureAlgorithm);
    if (problem !== null) {
        reasons.push(cmsAlgorithmMismatchReason(`${path}.signatureAlgorithm`, problem));
        return { reasons, certificate: undefined, intact: false, signatureVerifications: 0 };
    }

    // ── The content ──
    const hasAttributes = signer.signedAttributes !== undefined;
    const digestName = _digestName(signer.digestAlgorithm.oid);
    let computed: Uint8Array | undefined;
    if (ctx.content !== undefined) {
        if (digestName === undefined) {
            reasons.push(signatureNotCheckedReason(`${path}.digestAlgorithm`, 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED',
                `the content digest ${signer.digestAlgorithm.oid} is one pkinative does not compute, so the content cannot be tied to this signature`));
        } else {
            computed = await computeFingerprintAsync(ctx.content, digestName);
        }
    } else if (ctx.contentDigest !== undefined && hasAttributes) {
        computed = ctx.contentDigest;
    } else if (ctx.contentDigest !== undefined) {
        // The signature covers the content octets themselves, so a digest of
        // them is not enough: Web Crypto hashes what it is handed.
        reasons.push(signatureNotCheckedReason(path, 'PKI_API_MISUSE',
            'this signer has no signed attributes, so its signature is over the content itself and cannot be checked from a digest — pass the content'));
        return { reasons, certificate: undefined, intact: false, signatureVerifications: 0 };
    } else {
        reasons.push(cmsContentMissingReason(`${path}`));
        // Without signed attributes there is nothing else the signature covers.
        if (!hasAttributes) return { reasons, certificate: undefined, intact: false, signatureVerifications: 0 };
    }
    const mismatch = _digestReason(signer, computed, path);
    if (mismatch !== null) reasons.push(mismatch);

    // ── The certificate, the signature, and the binding ──
    const candidates = _signerCandidates(signer.sid, ctx.candidates);
    if (candidates.length === 0) {
        const unread = ctx.unreadable === 0 ? '' : `; ${String(ctx.unreadable)} certificate(s) in the message could not be read`;
        reasons.push(cmsSignerNotFoundReason(`${path}.sid`, `${_describeSid(signer.sid)}${unread}`));
        return { reasons, certificate: undefined, intact: false, signatureVerifications: 0 };
    }

    let signatureVerifications = 0;
    let refusal: PkiError | undefined;
    const signedBy: Certificate[] = [];
    for (const candidate of candidates) {
        signatureVerifications += 1;
        try {
            const valid = await verifySignerInfoSignature(signer, candidate, {
                ...(hasAttributes || ctx.content === undefined ? {} : { content: ctx.content }),
                allowSha1: ctx.allowSha1,
            });
            if (valid) signedBy.push(candidate);
        } catch (error) {
            // A runtime that cannot decide, or a digest pkinative will not treat
            // as evidence, says nothing about the signature. Kept apart from a
            // `false` all the way into the report.
            refusal ??= _pkiError(error);
        }
    }
    if (signedBy.length === 0) {
        reasons.push(refusal === undefined
            ? signatureInvalidReason(`${path}.signature`)
            : signatureNotCheckedReason(`${path}.signature`, refusal.code, refusal.message));
        return { reasons, certificate: undefined, intact: false, signatureVerifications };
    }

    // RFC 5035 §2: when more than one certificate holds the key that verified,
    // the one the signer committed to is the one that counts. Only if none of
    // them matches is it a mismatch.
    const committed = signedBy.find((certificate) => _signingCertificateReason(signer, certificate, path) === null);
    if (committed === undefined) {
        reasons.push(_signingCertificateReason(signer, signedBy[0] as Certificate, path) as PkiReason);
        return { reasons, certificate: undefined, intact: false, signatureVerifications };
    }
    return { reasons, certificate: committed, intact: reasons.length === 0, signatureVerifications };
}

/**
 * A reason from a composition below, re-rooted under a path of this one.
 *
 * `verifyCertificateChain` reports `path[0]`, `crls[1]`; inside a signed
 * message the reader needs to know **whose** chain that was.
 *
 * @internal
 */
export function _under(prefix: string, reason: PkiReason): PkiReason {
    return Object.freeze({ ...reason, path: `${prefix}.${reason.path}` });
}
