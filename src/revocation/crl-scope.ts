/**
 * pkinative — what a revocation list is about
 * ===========================================
 * `issuingDistributionPoint` (RFC 5280 §5.2.5), decoded, and the question it
 * exists to answer: **is this list entitled to speak about this certificate?**
 *
 * Getting that wrong has one direction and it is the dangerous one. A list is
 * evidence of absence — "your serial is not on it" — and evidence of absence is
 * only worth what the list's scope says it is worth. A CA that publishes one
 * list for its end-entity certificates and another for its sub-CAs marks both
 * with an IDP; a verifier that ignores the mark reads a sub-CA's absence from
 * the end-entity list as a clean bill of health, and accepts every certificate
 * under a CA its own issuer has revoked. RFC 5280 requires the extension to be
 * critical for that reason alone.
 *
 * So the rule here is the conservative one in every undecidable case: a list
 * whose scope cannot be established **does not cover** the certificate. That
 * answer costs a caller one more fetch. The other answer costs them the
 * revocation check.
 *
 * ## What is decided here, and what is not
 *
 * Decided: the §5.2.5 scope fields, the §6.3.3 (b) agreement between a
 * certificate's `cRLDistributionPoints` and the list's own IDP — including the
 * indirect case, where the list is issued by somebody other than the CA whose
 * certificates it revokes — and the two §6.3.3 rules that make a list unusable
 * whatever it covers: an unprocessed critical extension, and a delta CRL read
 * without its base.
 *
 * Not decided: whether the list is current, whether its signature verifies, and
 * whether the serial is on it. Those are `crl-check.ts`, and keeping them apart
 * is what lets a report say "the right list, but stale" rather than collapsing
 * four different failures into one.
 *
 * ## The order of the questions, which is not arbitrary
 *
 * Everything about *this certificate* is asked first, and everything about the
 * list alone last. Asking the cheap list-only questions first would report every
 * unreadable list a caller happens to be holding, about any CA, against every
 * certificate on the path: **a list that is not about this certificate raises no
 * question about this certificate.**
 *
 * @module revocation/crl-scope
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { decodeValueAt } from '../asn1/asn1-decode.js';
import { _readBitString, _readBoolean } from '../asn1/asn1-read.js';
import { bytesEqual } from '../core/bytes.js';
import type { CertificateList, IssuingDistributionPoint } from '../types/crl-types.js';
import type {
    AttributeTypeAndValue,
    Certificate,
    DistinguishedName,
    DistributionPoint,
    Extension,
    GeneralName,
    ReasonFlag,
    RelativeDistinguishedName,
} from '../types/x509-types.js';
import { _REASON_FLAGS, _readDistributionPointName } from '../x509/x509-ext-distribution.js';
import { contextFields, expectSequence, readNamedBits } from '../x509/x509-ext-shared.js';
import { getExtension } from '../x509/x509-extensions.js';
import { _readGeneralNameList } from '../x509/x509-general-name.js';

/** `issuingDistributionPoint`. */
export const OID_ISSUING_DISTRIBUTION_POINT = '2.5.29.28';

/** `certificateIssuer`, the CRL **entry** extension of §5.3.3. */
export const OID_CERTIFICATE_ISSUER = '2.5.29.29';

/**
 * Decode an `issuingDistributionPoint` extension value.
 *
 * Unlike `cRLNumber`, a malformed IDP is **not** shrugged off. The whole point
 * of the extension is to narrow what the list may be believed about, and a
 * value that cannot be read leaves that narrowing unknown — so it throws, and
 * the list is refused as input rather than silently treated as unrestricted.
 *
 * @param extension The extension, as `readExtensions` returned it.
 * @param ctx       The decoding context; the limits apply to the names.
 * @returns The decoded scope.
 * @throws {PkiCertificateError} `PKI_X509_EXTENSION_MALFORMED` when the value is not an IssuingDistributionPoint.
 * @throws {PkiEncodingError} For any DER violation inside the value.
 * @internal
 */
export function _readIssuingDistributionPoint(extension: Extension, ctx: Asn1Context): IssuingDistributionPoint {
    const path = 'tbsCertList.crlExtensions.issuingDistributionPoint';
    // The SEQUENCE is checked before its fields are: a primitive value has no
    // children, so reading its fields would find none and produce an
    // IssuingDistributionPoint with every restriction false — an unreadable
    // value silently widened into an unrestricted list, which is the one
    // outcome this extension exists to prevent.
    const node = expectSequence(decodeValueAt(extension.valueDer, 0, ctx), path, 0);
    // `contextFields` carries the DER ordering rule with it: [0] to [5], each at
    // most once and in increasing order. An IDP that repeats a field is refused
    // here rather than resolved by a last-wins rule nobody wrote down.
    const [nameNode, userNode, caNode, reasonsNode, indirectNode, attributeNode] = contextFields(node.children, 5, path);
    const name = nameNode === undefined
        ? { fullName: undefined, nameRelativeToCRLIssuer: undefined }
        : _readDistributionPointName(nameNode, ctx, `${path}.distributionPoint`);
    let onlySomeReasons: readonly ReasonFlag[] | undefined;
    if (reasonsNode !== undefined) {
        onlySomeReasons = Object.freeze(readNamedBits(_readBitString(reasonsNode, ctx), _REASON_FLAGS, ctx, `${path}.onlySomeReasons`, reasonsNode.offset));
    }
    const point: IssuingDistributionPoint = {
        fullName: name.fullName,
        nameRelativeToCRLIssuer: name.nameRelativeToCRLIssuer,
        onlyContainsUserCerts: userNode !== undefined && _readBoolean(userNode, ctx),
        onlyContainsCACerts: caNode !== undefined && _readBoolean(caNode, ctx),
        onlySomeReasons,
        indirectCRL: indirectNode !== undefined && _readBoolean(indirectNode, ctx),
        onlyContainsAttributeCerts: attributeNode !== undefined && _readBoolean(attributeNode, ctx),
    };
    return Object.freeze(point);
}

/** What to ask about. */
export interface CrlScopeInput {
    /** The certificate whose status is in question. */
    readonly certificate: Certificate;
    /** The parsed list. */
    readonly crl: CertificateList;
    /**
     * Ask whether the list covers the certificate **as a delta**, alongside a
     * complete list that covers it too.
     *
     * Without it a delta is refused whatever it covers, because on its own it
     * answers nothing: it lists what changed since a base, so a certificate
     * absent from it is not a certificate that is unrevoked. With it the same
     * question is asked about scope alone, which is what `_deltaApplies` needs
     * before it will pair the two.
     */
    readonly asDelta?: boolean | undefined;
}

/**
 * Why a list cannot answer about a certificate — two failures, not one.
 *
 * `wrong-issuer` means no CA connects the list to the certificate at all: a
 * caller holding the wrong file. `out-of-scope` means the right CA, publishing
 * several lists, and this is not the one. They read the same in a boolean and
 * send a caller to two different places, which is why they are two.
 */
export type CrlScopeProblem =
    | { readonly kind: 'wrong-issuer' }
    | { readonly kind: 'out-of-scope'; readonly why: string }
    | { readonly kind: 'unusable'; readonly oid: string };

/**
 * The CRL extensions this library processes.
 *
 * RFC 5280 §6.3.3: *"If the CRL contains a critical extension that the
 * application cannot process, the CRL MUST NOT be used."* It is the same rule
 * §6.1.3 (f) sets for certificates, and it exists for the same reason — a
 * critical marking is the issuer saying *"if you do not understand this, you do
 * not understand what this list means"*. Ignoring one is how a list scoped by
 * an extension nobody here has heard of gets read as covering everything.
 *
 * `deltaCRLIndicator` is here because its `BaseCRLNumber` is read and acted on
 * (§5.2.4). That is not the same as a delta being *usable*: one handed over on
 * its own still answers nothing, and `_usability` says so in its own words
 * rather than through the generic rule.
 */
const PROCESSED_CRL_EXTENSIONS: ReadonlySet<string> = new Set([
    '2.5.29.18', // issuerAltName
    '2.5.29.20', // cRLNumber
    '2.5.29.27', // deltaCRLIndicator
    '2.5.29.28', // issuingDistributionPoint
    '2.5.29.35', // authorityKeyIdentifier
    '2.5.29.46', // freshestCRL
    '1.3.6.1.5.5.7.1.1', // authorityInfoAccess
]);

/**
 * Whether this list is entitled to answer about this certificate.
 *
 * @param input See {@link CrlScopeInput}.
 * @returns The problem, or `null` when the list does cover the certificate.
 * @internal
 */
export function _crlScopeProblem(input: CrlScopeInput): CrlScopeProblem | null {
    const { certificate, crl } = input;
    const idp = crl.issuingDistributionPoint;

    // ── §5.2.5: the kind of certificate the list is about ──
    //
    // These three are decided before anything about names, because they are
    // decided about the certificate alone: a list that only covers CAs covers
    // no end-entity certificate no matter which point published it.
    if (idp?.onlyContainsAttributeCerts === true) {
        return _outOfScope('it declares onlyContainsAttributeCerts, so it covers X.509 attribute certificates and never a public-key certificate');
    }
    const isCa = getExtension(certificate, 'basicConstraints')?.cA === true;
    if (idp?.onlyContainsUserCerts === true && isCa) {
        return _outOfScope('it declares onlyContainsUserCerts, and this certificate asserts cA in basicConstraints; a CA\'s absence from an end-entity list is not evidence that the CA is unrevoked');
    }
    if (idp?.onlyContainsCACerts === true && !isCa) {
        return _outOfScope('it declares onlyContainsCACerts, and this certificate does not assert cA in basicConstraints');
    }

    // ── §6.3.3 (b): the list, the certificate's distribution points, or neither ──
    const points = getExtension(certificate, 'crlDistributionPoints')?.points ?? [];
    const fromIssuer = bytesEqual(crl.issuer.der, certificate.issuer.der);
    if (points.length === 0) {
        // No cRLDistributionPoints at all — the ordinary case, and the one
        // RFC 5280 §6.3.3 handles by falling back to the certificate's issuer.
        // A list that names a distribution point is then unmatchable: nothing
        // in the certificate says it belongs to that point, and assuming it
        // does is exactly the assumption the extension exists to forbid.
        if (!fromIssuer) return { kind: 'wrong-issuer' };
        if (idp !== undefined && (idp.fullName !== undefined || idp.nameRelativeToCRLIssuer !== undefined)) {
            return _outOfScope('it is scoped to a distribution point, and the certificate carries no cRLDistributionPoints naming it; nothing establishes that this point covers this certificate');
        }
        return _usability(input);
    }

    const problems: string[] = [];
    let delegated = false;
    for (const point of points) {
        if (point.cRLIssuer !== undefined && _namesInclude(point.cRLIssuer, crl.issuer.der)) delegated = true;
        const problem = _pointProblem(point, input, idp);
        if (problem === null) return _usability(input);
        problems.push(problem);
    }
    // Nothing in the certificate connects this CA to it — neither as its own
    // issuer nor as a cRLIssuer it delegates to. That is a different mistake
    // from a scope that does not line up, and it gets the more specific code.
    if (!fromIssuer && !delegated) return { kind: 'wrong-issuer' };
    // The first explanation is the useful one: the points are examined in
    // encoded order, and a CA lists the one it expects first.
    return _outOfScope(`no cRLDistributionPoints entry in the certificate is answered by it — ${problems[0] as string}`);
}

/**
 * §6.3.3 (d): the reasons a list that covers this certificate answers for it
 * — its `interim_reasons_mask`.
 *
 * Two parties restrict it, and the RFC takes the intersection: the list, by
 * its `issuingDistributionPoint` `onlySomeReasons`, and the certificate, by
 * the `reasons` of the distribution point the list answers. A certificate
 * that sends keyCompromise to one point and everything else to another has
 * said a list answering at the first point covers keyCompromise and nothing
 * more, even when the list itself claims every reason. Several points the
 * list answers add up (their union); a point with no `reasons`, or a
 * certificate with no distribution point at all, restricts nothing.
 *
 * Asked only of a list `_crlScopeProblem` found covering the certificate.
 *
 * @param input See {@link CrlScopeInput}.
 * @returns The reasons covered, or `undefined` for every reason.
 * @internal
 */
export function _interimReasons(input: CrlScopeInput): readonly ReasonFlag[] | undefined {
    const idp = input.crl.issuingDistributionPoint;
    const only = idp?.onlySomeReasons;
    // Bounded by the certificate's distribution points, which the extension
    // reader bounded by `maxGeneralNames`.
    const points = getExtension(input.certificate, 'crlDistributionPoints')?.points ?? [];
    const answered = points.filter((point) => _pointProblem(point, input, idp) === null);
    if (answered.length === 0 || answered.some((point) => point.reasons === undefined)) return only;
    const named = new Set(answered.flatMap((point) => point.reasons as readonly ReasonFlag[]));
    return (only ?? _REASON_FLAGS).filter((reason) => named.has(reason));
}

function _outOfScope(why: string): CrlScopeProblem {
    return { kind: 'out-of-scope', why };
}

/**
 * The last two questions, asked only of a list that **would** cover this
 * certificate: is it complete, and is all of it understood?
 *
 * Deliberately last. Both are facts about the list alone, so asking them first
 * would be cheaper — and would report every unreadable list a caller happens to
 * be holding, about any CA, against every certificate on the path. A list that
 * is not about this certificate raises no question about this certificate.
 */
function _usability(input: CrlScopeInput): CrlScopeProblem | null {
    const { crl } = input;
    // A delta answers *what changed since a base list*, and nothing else. Read
    // as a complete list it reports every certificate absent from it — which is
    // almost all of them — as unrevoked, so it is the one misreading that turns
    // a revocation list into a blanket clearance. `asDelta` is the caller
    // saying they hold the base too, which is the only way the question becomes
    // answerable; `_deltaApplies` then decides whether that base is the right
    // one.
    if (crl.isDelta && input.asDelta !== true) {
        return _outOfScope('it is a delta CRL: it lists what changed since a base list, so a certificate absent from it is not a certificate that is unrevoked — supply the complete list it applies over');
    }
    for (const extension of crl.extensions) {
        if (extension.critical && !PROCESSED_CRL_EXTENSIONS.has(extension.oid)) return { kind: 'unusable', oid: extension.oid };
    }
    return null;
}

/**
 * Whether a delta CRL describes the changes since **this** complete list
 * (RFC 5280 §5.2.4, §6.3.3).
 *
 * Three conditions, and each one is a way of pairing the wrong two lists:
 *
 * - the base's `cRLNumber` is **at least** the delta's `BaseCRLNumber`, or the
 *   two do not meet and everything revoked in between is invisible to both;
 * - the base's `cRLNumber` is **below** the delta's, or the "delta" is the
 *   older document and applying it would undo revocations the base already
 *   records;
 * - both name the same issuer, because a delta is a diff against one CA's
 *   list and nothing else.
 *
 * Both numbers must be present. RFC 5280 §5.2.3 requires `cRLNumber` on every
 * list a delta could apply to, and a base without one leaves the first two
 * conditions undecidable — so the pair is refused rather than guessed, which
 * loses a revocation at worst and never invents one.
 *
 * Scope equality is not compared field by field. The caller has already
 * established that both lists cover the certificate in question, which is the
 * only sense in which "the same scope" changes this answer.
 *
 * @param base  A complete list that covers the certificate.
 * @param delta A delta list that covers it too.
 * @returns Whether the two may be read together.
 * @internal
 */
export function _deltaApplies(base: CertificateList, delta: CertificateList): boolean {
    if (!delta.isDelta || base.isDelta) return false;
    if (!bytesEqual(base.issuer.der, delta.issuer.der)) return false;
    const { baseCrlNumber } = delta;
    if (baseCrlNumber === undefined || base.crlNumber === undefined || delta.crlNumber === undefined) return false;
    return base.crlNumber >= baseCrlNumber && base.crlNumber < delta.crlNumber;
}

/** Whether one of the certificate's distribution points is served by this list. */
function _pointProblem(point: DistributionPoint, input: CrlScopeInput, idp: IssuingDistributionPoint | undefined): string | null {
    const { certificate, crl } = input;

    // §6.3.3 (b)(1): who is allowed to have issued the list for this point.
    //
    // A cRLIssuer is the certificate's own statement that somebody else
    // publishes its revocations — and the only thing that makes that safe is
    // the list agreeing, by asserting indirectCRL. Accepting a list from a
    // third party that does *not* claim to be an indirect CRL would let any CA
    // named in any cRLIssuer field answer for certificates it never issued.
    if (point.cRLIssuer !== undefined) {
        if (!_namesInclude(point.cRLIssuer, crl.issuer.der)) {
            return 'the distribution point names a cRLIssuer other than the issuer of this list';
        }
        if (idp?.indirectCRL !== true) {
            return 'the distribution point delegates to a cRLIssuer, and the list does not assert indirectCRL; a list that does not claim to answer for another CA must not be read as if it did';
        }
    } else if (!bytesEqual(crl.issuer.der, certificate.issuer.der)) {
        return 'the distribution point delegates to nobody, so only the certificate\'s own issuer may publish its list';
    }

    // §6.3.3 (b)(2): the point named by the list must be one the certificate
    // names. When the list names no point it covers all of them, which is the
    // common case and needs no comparison.
    if (idp === undefined || (idp.fullName === undefined && idp.nameRelativeToCRLIssuer === undefined)) return null;

    // "…verify that one of the names in the IDP matches one of the names in the
    // DP. If the distribution point name is omitted from the DP, then verify
    // that one of the names in the IDP matches one of the names in the
    // cRLIssuer field of the DP." — RFC 5280 §6.3.3 (b)(2), read literally: the
    // cRLIssuer stands in only when the entry names no point of its own.
    const mine = point.fullName ?? (point.nameRelativeToCRLIssuer === undefined ? point.cRLIssuer : undefined);
    if (mine === undefined && point.nameRelativeToCRLIssuer === undefined) {
        return 'the list is scoped to a distribution point, and this entry names neither a fullName nor a cRLIssuer to compare it against';
    }

    // Either side may name its point **relative to the CRL issuer** (§4.2.1.13),
    // and a first version of this refused that form rather than composing it.
    // NIST built four tests on it, so refusing turned four valid paths into
    // unproven ones — the safe direction, and still the wrong answer.
    //
    // The composition is exact and needs no re-encoding: appending an RDN to a
    // name is appending an element to `rdns`, so the comparison runs RDN by RDN
    // on the attribute types and the **encoded** values. Re-rendering the name
    // and comparing bytes is the version of this that turns a TeletexString into
    // a UTF8String and stops matching.
    //
    // Each side is a relative RDN or a list of names, never both and never
    // neither: the early return above rules out a list that names nothing, and
    // the `mine === undefined` return rules out an entry that does. Resolving
    // the two into locals **here** is what keeps the four combinations below
    // free of fallbacks no control path can reach.
    const listNames = idp.fullName ?? [];
    const entryNames = mine ?? [];
    if (point.nameRelativeToCRLIssuer !== undefined && idp.nameRelativeToCRLIssuer !== undefined) {
        // Both relative, and both to the same name — the one checked above.
        if (_rdnEquals(point.nameRelativeToCRLIssuer, idp.nameRelativeToCRLIssuer)) return null;
    } else if (point.nameRelativeToCRLIssuer !== undefined) {
        if (_composedMatches(point.nameRelativeToCRLIssuer, listNames, crl.issuer)) return null;
    } else if (idp.nameRelativeToCRLIssuer !== undefined) {
        if (_composedMatches(idp.nameRelativeToCRLIssuer, entryNames, crl.issuer)) return null;
    } else {
        for (const theirs of listNames) {
            if (_namesInclude(entryNames, theirs.der)) return null;
        }
    }
    return 'the list is scoped to a distribution point this entry does not name';
}

/** Two RDNs are the same when they hold the same attributes, in encoded order, with the same encoded values. */
function _rdnEquals(a: RelativeDistinguishedName, b: RelativeDistinguishedName): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) {
        const left = a[i] as AttributeTypeAndValue;
        const right = b[i] as AttributeTypeAndValue;
        if (left.type !== right.type || !bytesEqual(left.valueDer, right.valueDer)) return false;
    }
    return true;
}

/**
 * Whether appending `relative` to `base` gives one of the directory names in
 * `names` — the composition RFC 5280 §4.2.1.13 defines, done structurally.
 */
function _composedMatches(relative: RelativeDistinguishedName, names: readonly GeneralName[], base: DistinguishedName): boolean {
    for (const name of names) {
        if (name.kind !== 'directoryName') continue;
        const rdns = name.name.rdns;
        // One RDN longer than the issuer's, sharing every one of its RDNs, and
        // ending in this one. Anything else is a different name.
        if (rdns.length !== base.rdns.length + 1) continue;
        if (!_rdnEquals(rdns[base.rdns.length] as RelativeDistinguishedName, relative)) continue;
        let same = true;
        for (let i = 0; i < base.rdns.length; i += 1) {
            if (!_rdnEquals(rdns[i] as RelativeDistinguishedName, base.rdns[i] as RelativeDistinguishedName)) { same = false; break; }
        }
        if (same) return true;
    }
    return false;
}

/** Whether a GeneralNames holds this exact encoding. Bytes, as everywhere: two names that print the same and encode differently are two names. */
function _namesInclude(names: readonly GeneralName[], der: Uint8Array): boolean {
    for (const name of names) {
        if (bytesEqual(name.der, der)) return true;
        // A cRLIssuer is a GeneralNames, and the alternative a CA uses for it is
        // always `directoryName [4]`. Its `der` carries the context tag, while
        // the list's own `issuer` is a bare Name — so the two are compared on
        // the Name inside, which is the thing both of them mean.
        if (name.kind === 'directoryName' && bytesEqual(name.name.der, der)) return true;
    }
    return false;
}

/**
 * Decode the `issuingDistributionPoint` of a parsed list, if it carries one.
 *
 * Separate from `parseCertificateList` only in the file it lives in: the parser
 * calls it, and it is here so that everything deciding what a list is about is
 * in one module.
 *
 * @internal
 */
export function _findIssuingDistributionPoint(extensions: readonly Extension[], ctx: Asn1Context): IssuingDistributionPoint | undefined {
    const extension = extensions.find((e) => e.oid === OID_ISSUING_DISTRIBUTION_POINT);
    return extension === undefined ? undefined : _readIssuingDistributionPoint(extension, ctx);
}

/**
 * The `certificateIssuer` (RFC 5280 §5.3.3) an entry names, as encoded Name
 * bytes, or `undefined` when the entry does not name one.
 *
 * The extension is a `GeneralNames`, and the only alternative that means
 * anything here is `directoryName`: an entry attributing itself to a CA by URI
 * names nothing this library can compare a certificate's issuer against.
 *
 * @internal
 */
export function _entryCertificateIssuer(extensions: readonly Extension[], ctx: Asn1Context, path: string): Uint8Array | undefined {
    const extension = extensions.find((e) => e.oid === OID_CERTIFICATE_ISSUER);
    if (extension === undefined) return undefined;
    // A GeneralNames is a GeneralNames wherever it appears, so it is read by
    // the x509 reader rather than by a second implementation that would drift.
    const names = _readGeneralNameList(decodeValueAt(extension.valueDer, 0, ctx), ctx, path, false);
    for (const name of names) {
        if (name.kind === 'directoryName') return name.name.der;
    }
    return undefined;
}
