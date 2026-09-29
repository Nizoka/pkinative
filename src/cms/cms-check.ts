/**
 * pkinative — what a signer's attributes must say
 * ===============================================
 * The structural half of verifying a CMS signer: every rule RFC 5652, RFC 5035
 * and RFC 6211 set on the signed attributes that can be decided without a key.
 *
 * This is the module that makes a verified signature **mean** something. A
 * signature over signed attributes proves that the key signed those attributes
 * — and nothing else. It is the `contentType` and `messageDigest` inside them
 * that tie the signature to a content, the signing-certificate attribute that
 * ties it to one certificate, and the algorithm protection that ties it to the
 * algorithms the verifier used. A verifier that checked the signature and
 * skipped these would accept a genuine signature over somebody else's
 * attributes: the whole class of CMS vulnerabilities that shipped in real
 * validators is some form of that.
 *
 * Synchronous, pure, and never throwing for a verdict, like the rest of the
 * decision layers. The digest of the content is computed by the caller — it may
 * be gigabytes, and hashing it is the one thing here that deserves the host's
 * implementation — and handed in.
 *
 * @module cms/cms-check
 */

import { bytesEqual, toHex } from '../core/bytes.js';
import {
    cmsAlgorithmMismatchReason,
    cmsAttributeInvalidReason,
    cmsDigestMismatchReason,
    cmsSigningCertificateMismatchReason,
} from '../core/pki-reasons.js';
import { sha1 } from '../hash/sha1.js';
import { sha256 } from '../hash/sha256.js';
import { sha384, sha512 } from '../hash/sha512.js';
import type { Attribute, SignedData, SignerIdentifier, SignerInfo } from '../types/cms-types.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { AlgorithmIdentifier, Certificate } from '../types/x509-types.js';
import { getExtension } from '../x509/x509-extensions.js';
import {
    OID_ATTR_ALGORITHM_PROTECTION,
    OID_ATTR_CONTENT_TYPE,
    OID_ATTR_COUNTERSIGNATURE,
    OID_ATTR_MESSAGE_DIGEST,
    OID_ATTR_SIGNING_CERTIFICATE,
    OID_ATTR_SIGNING_CERTIFICATE_V2,
    OID_ATTR_SIGNING_TIME,
    OID_DATA,
    SIGNED_ONLY_ATTRIBUTES,
} from '../core/cms-oids.js';

/** The digests a signing-certificate hash may use, by the name the parser gives them. */
const DIGESTS: ReadonlyMap<string, (input: Uint8Array) => Uint8Array> = /*#__PURE__*/ new Map([
    ['SHA-1', sha1],
    ['SHA-256', sha256],
    ['SHA-384', sha384],
    ['SHA-512', sha512],
]);

/** The attributes that must appear at most once with exactly one value, and the name each is reported under. */
const SINGLE_VALUED: ReadonlyMap<string, string> = /*#__PURE__*/ new Map([
    [OID_ATTR_CONTENT_TYPE, 'contentType'],
    [OID_ATTR_MESSAGE_DIGEST, 'messageDigest'],
    [OID_ATTR_SIGNING_TIME, 'signingTime'],
    [OID_ATTR_SIGNING_CERTIFICATE, 'signingCertificate'],
    [OID_ATTR_SIGNING_CERTIFICATE_V2, 'signingCertificateV2'],
    [OID_ATTR_ALGORITHM_PROTECTION, 'CMSAlgorithmProtection'],
]);

// ── Which certificate the signer names ──

/**
 * The certificates the signer identifier selects, in the order given.
 *
 * **Candidates, not the answer.** The identifier is not signed, so it only says
 * where to look; and a `subjectKeyIdentifier` names a key, which several
 * certificates may hold. The signature decides among them, and the
 * signing-certificate attribute — which *is* signed — decides which of those
 * the signer meant.
 *
 * Names are compared by their encoded bytes, as everywhere in this library: two
 * names that print the same and encode differently are two names.
 *
 * @internal
 */
export function _signerCandidates(sid: SignerIdentifier, certificates: readonly Certificate[]): Certificate[] {
    const out: Certificate[] = [];
    const seen = new Set<string>();
    for (const certificate of certificates) {
        const matches = sid.kind === 'issuerAndSerialNumber'
            ? bytesEqual(certificate.issuer.der, sid.issuer.der) && bytesEqual(certificate.serialNumber.bytes, sid.serialNumber.bytes)
            : _keyIdentifierMatches(certificate, sid.keyIdentifier);
        if (!matches) continue;
        const key = toHex(certificate.der);
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(certificate);
    }
    return out;
}

/**
 * RFC 5652 §5.3: the key identifier "matches the X.509 subjectKeyIdentifier
 * extension value". The **extension** — not a hash of the key computed here,
 * which would pick one of several methods RFC 5280 allows and silently disagree
 * with a CA that used another.
 */
function _keyIdentifierMatches(certificate: Certificate, keyIdentifier: Uint8Array): boolean {
    const extension = getExtension(certificate, 'subjectKeyIdentifier');
    return extension !== undefined && bytesEqual(extension.keyIdentifier, keyIdentifier);
}

/** A signer identifier, for a message a person reads. @internal */
export function _describeSid(sid: SignerIdentifier): string {
    return sid.kind === 'issuerAndSerialNumber'
        ? `issuer ${toHex(sid.issuer.der).slice(0, 32)}…, serial ${sid.serialNumber.hex}`
        : `subjectKeyIdentifier ${toHex(sid.keyIdentifier)}`;
}

// ── The attribute rules ──

/** What the attribute rules may be asked to enforce beyond RFC 5652. */
export interface _AttributeRuleOptions {
    /** Refuse a signer without `CMSAlgorithmProtection` (RFC 8933 §4 makes it a SHOULD for signers). */
    readonly requireAlgorithmProtection?: boolean | undefined;
}

/**
 * Every rule on a signer's attributes that needs neither a key nor the
 * content, as reasons.
 *
 * In order: whether signed attributes may be absent at all; each attribute that
 * must appear at most once with one value; `contentType` present and equal to
 * the content's type (§11.1, §5.6); `messageDigest` present (§11.2); nothing
 * that may only be signed found among the unsigned attributes; no
 * countersignature among the signed ones (§11.4); and the algorithm protection
 * agreeing with the algorithms the signer names (RFC 6211 §3).
 *
 * @internal
 */
export function _signerAttributeReasons(signedData: SignedData, signer: SignerInfo, path: string, options?: _AttributeRuleOptions): PkiReason[] {
    const out: PkiReason[] = [];
    const signed = signer.signedAttributes;

    if (signed === undefined) {
        // RFC 5652 §5.3: signed attributes MUST be present when the content is
        // not id-data. Without them the signature covers the content octets and
        // nothing says what type they were meant to be — the gap a content-type
        // confusion attack walks through.
        if (signedData.contentType !== OID_DATA) {
            out.push(cmsAttributeInvalidReason(`${path}.signedAttrs`,
                `the content type is ${signedData.contentType}, not id-data, and RFC 5652 §5.3 then requires signed attributes to say so`));
        }
        return [...out, ..._unsignedReasons(signer, path)];
    }

    for (const [oid, name] of SINGLE_VALUED) {
        const found = signed.filter((attribute) => attribute.oid === oid);
        if (found.length > 1) {
            out.push(cmsAttributeInvalidReason(`${path}.signedAttrs.${name}`, `the ${name} attribute appears ${String(found.length)} times, where it may appear once`));
        } else if (found.length === 1 && (found[0] as Attribute).values.length !== 1) {
            out.push(cmsAttributeInvalidReason(`${path}.signedAttrs.${name}`, `the ${name} attribute holds ${String((found[0] as Attribute).values.length)} values, where it must hold one`));
        }
    }

    if (!signed.some((attribute) => attribute.oid === OID_ATTR_CONTENT_TYPE)) {
        out.push(cmsAttributeInvalidReason(`${path}.signedAttrs.contentType`, 'there is no contentType attribute, which RFC 5652 §11.1 requires whenever there are signed attributes'));
    } else if (signer.contentType !== undefined && signer.contentType !== signedData.contentType) {
        out.push(cmsAttributeInvalidReason(`${path}.signedAttrs.contentType`,
            `the contentType attribute names ${signer.contentType} while the content is ${signedData.contentType}; RFC 5652 §5.6 requires them equal`));
    }
    if (!signed.some((attribute) => attribute.oid === OID_ATTR_MESSAGE_DIGEST)) {
        out.push(cmsAttributeInvalidReason(`${path}.signedAttrs.messageDigest`, 'there is no messageDigest attribute, which RFC 5652 §11.2 requires whenever there are signed attributes — without it the signature binds no content'));
    }
    if (signed.some((attribute) => attribute.oid === OID_ATTR_COUNTERSIGNATURE)) {
        out.push(cmsAttributeInvalidReason(`${path}.signedAttrs.countersignature`, 'a countersignature is among the signed attributes, and RFC 5652 §11.4 allows it only unsigned'));
    }

    out.push(..._unsignedReasons(signer, path));
    const protection = _algorithmProtectionReason(signer, signed, path, options?.requireAlgorithmProtection === true);
    if (protection !== null) out.push(protection);
    return out;
}

/** Attributes that may only be signed, found among the unsigned ones. */
function _unsignedReasons(signer: SignerInfo, path: string): PkiReason[] {
    const out: PkiReason[] = [];
    for (const attribute of signer.unsignedAttributes ?? []) {
        if (!SIGNED_ONLY_ATTRIBUTES.has(attribute.oid)) continue;
        out.push(cmsAttributeInvalidReason(`${path}.unsignedAttrs`,
            `the ${SINGLE_VALUED.get(attribute.oid) as string} attribute is unsigned, and it means something only when it is signed`));
    }
    return out;
}

// ── The digest ──

/**
 * The content's digest against the one the signer committed to.
 *
 * `computed` is the caller's own digest of the content under the signer's
 * `digestAlgorithm`. RFC 5652 §5.6: "The recipient MUST NOT rely on any message
 * digest values computed by the originator" — which is why this compares, and
 * never takes `messageDigest` as the digest of anything.
 *
 * `null` when there is nothing to compare: no messageDigest (already a reason
 * from the attribute rules) or no content (a reason the composition gives).
 *
 * @internal
 */
export function _digestReason(signer: SignerInfo, computed: Uint8Array | undefined, path: string): PkiReason | null {
    if (signer.messageDigest === undefined || computed === undefined) return null;
    return bytesEqual(signer.messageDigest, computed) ? null : cmsDigestMismatchReason(`${path}.signedAttrs.messageDigest`);
}

// ── The signing-certificate binding ──

/**
 * Whether the signing-certificate attribute names this certificate
 * (RFC 2634 §5.4, RFC 5035 §3).
 *
 * The first `ESSCertID` names the signing certificate; any others restrict the
 * path, which 0.7 does not enforce. When both the v1 and the v2 attribute are
 * present, the v2 one is checked: RFC 5035 asks for each to be evaluated
 * independently, and v2 binds with a stronger digest — a certificate
 * substituted under both would need a SHA-256 second preimage for v2 alone.
 *
 * A digest pkinative does not compute makes the binding **unestablished**, and
 * that is reported as a mismatch rather than passed: the attribute's purpose is
 * to say which certificate may be used, and a check that cannot run must not
 * default to "any".
 *
 * @internal
 */
export function _signingCertificateReason(signer: SignerInfo, certificate: Certificate, path: string): PkiReason | null {
    const attribute = signer.signingCertificate;
    if (attribute === undefined) return null;
    const where = `${path}.signedAttrs.${attribute.version === 2 ? 'signingCertificateV2' : 'signingCertificate'}`;
    const first = attribute.certIds[0];
    if (first === undefined) {
        return cmsSigningCertificateMismatchReason(where, 'the attribute lists no certificate at all');
    }
    const digest = DIGESTS.get(first.hashAlgorithm);
    if (digest === undefined) {
        return cmsSigningCertificateMismatchReason(where, `its certificate hash is computed with ${first.hashAlgorithm}, which pkinative does not compute, so the binding cannot be established`);
    }
    if (!bytesEqual(digest(certificate.der), first.certHash)) {
        return cmsSigningCertificateMismatchReason(where, 'its certificate hash is not the hash of the certificate whose key verified the signature');
    }
    const issuerSerial = first.issuerSerial;
    if (issuerSerial === undefined) return null;
    // RFC 2634 §5.4.1: for a public-key certificate, the issuer is exactly one
    // directoryName — the certificate's issuer Name.
    const [only, ...rest] = issuerSerial.issuer;
    if (rest.length > 0 || only?.kind !== 'directoryName' || !bytesEqual(only.name.der, certificate.issuer.der)) {
        return cmsSigningCertificateMismatchReason(where, 'its issuerSerial does not name the issuer of the certificate whose key verified the signature');
    }
    if (!bytesEqual(issuerSerial.serialNumber.bytes, certificate.serialNumber.bytes)) {
        return cmsSigningCertificateMismatchReason(where, 'its issuerSerial names another serial number');
    }
    return null;
}

// ── Algorithm protection (RFC 6211) ──

/**
 * The `CMSAlgorithmProtection` attribute against the algorithms the signer
 * names outside the signature.
 *
 * `digestAlgorithm` and `signatureAlgorithm` are not signed. This attribute is
 * the signer's **signed** statement of what they were, and RFC 6211 exists
 * because verifiers were being steered into checking a signature under a
 * weaker algorithm than the signer chose. Compared "modulo encoding" (RFC 6211
 * §3): the same OID with absent or NULL parameters is the same SHA-2 algorithm,
 * and anything else compares by its encoded parameters.
 *
 * The parser decoded it — a malformed one never reaches this function, because
 * a malformed recognised attribute is refused at parse. So this compares and
 * never has to turn a decoding failure into a verdict.
 */
function _algorithmProtectionReason(signer: SignerInfo, signed: readonly Attribute[], path: string, required: boolean): PkiReason | null {
    const where = `${path}.signedAttrs.CMSAlgorithmProtection`;
    if (!signed.some((attribute) => attribute.oid === OID_ATTR_ALGORITHM_PROTECTION)) {
        return required
            ? cmsAttributeInvalidReason(where, 'the signer did not protect its algorithms with a CMSAlgorithmProtection attribute, and one was required')
            : null;
    }
    // Present but not readable as one value: repeated or multi-valued, which
    // the multiplicity rule has already reported.
    const protectedAlgorithms = signer.algorithmProtection;
    if (protectedAlgorithms === undefined) return null;
    if (!_sameAlgorithm(protectedAlgorithms.digestAlgorithm, signer.digestAlgorithm)) {
        return cmsAlgorithmMismatchReason(where, `the signer protected ${protectedAlgorithms.digestAlgorithm.oid} as its digest and names ${signer.digestAlgorithm.oid} outside the signature`);
    }
    if (!_sameAlgorithm(protectedAlgorithms.signatureAlgorithm, signer.signatureAlgorithm)) {
        return cmsAlgorithmMismatchReason(where, `the signer protected ${protectedAlgorithms.signatureAlgorithm.oid} as its signature algorithm and names ${signer.signatureAlgorithm.oid} outside the signature`);
    }
    return null;
}

/** RFC 6211 §3 "modulo encoding": absent and NULL parameters are the same; anything else by its bytes. */
function _sameAlgorithm(a: AlgorithmIdentifier, b: AlgorithmIdentifier): boolean {
    if (a.oid !== b.oid) return false;
    const mine = _normalised(a.parameters?.bytes);
    const theirs = _normalised(b.parameters?.bytes);
    return mine === undefined || theirs === undefined ? mine === theirs : bytesEqual(mine, theirs);
}

const NULL = /*#__PURE__*/ Uint8Array.of(0x05, 0x00);

function _normalised(parameters: Uint8Array | undefined): Uint8Array | undefined {
    return parameters === undefined || bytesEqual(parameters, NULL) ? undefined : parameters;
}
