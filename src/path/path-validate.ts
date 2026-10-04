/**
 * pkinative — RFC 5280 §6 certification path validation
 * =====================================================
 * A mutable state record plus pure step functions — exactly the shape
 * `Asn1Context` already uses, and for the same reason: a closure factory
 * would hide the state from the tests and let the steps be exercised only
 * end to end. Here each step is exported and tested against its clause, so a
 * PKITS case becomes a three-line test against a synthetic `PathState`
 * instead of a whole certificate chain.
 *
 * **This function is synchronous and throws nothing for a validation issue.**
 * Anything structurally wrong was already thrown at parse time; §6 only
 * judges. Every negative answer is a `PkiReason` in the returned report, and
 * several are returned together whenever several apply.
 *
 * ## Fail closed, which is what makes this safe to finish in stages
 *
 * RFC 5280 §6.1.3 (f) says a verifier must **refuse** a certificate carrying
 * a critical extension it does not process. `PROCESSED_CRITICAL_EXTENSIONS`
 * below is the set this validator handles, and everything else critical is
 * `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION`.
 *
 * That is not a placeholder, it is the correct behaviour: a critical
 * extension outside the set is **refused rather than silently accepted**. A
 * validator that ignored an extension it had not implemented would answer
 * "valid" for a chain the issuing CA forbade, which is the shape of a real
 * CVE rather than a missing feature. `nameConstraints`, `policyConstraints`,
 * `policyMappings` and `inhibitAnyPolicy` each joined the set in their own
 * commit, with their own tests, once §6 processed them — and only then.
 *
 * @module path/path-validate
 */

import {
    expiredReason,
    issuerNotFoundReason,
    limitExceededReason,
    nameExcludedReason,
    nameNotPermittedReason,
    noTrustAnchorReason,
    notACaReason,
    noValidPolicyReason,
    policyMappingInvalidReason,
    notYetValidReason,
    pathLoopsReason,
    pathTooLongReason,
    signatureInvalidReason,
    signatureNotCheckedReason,
    unknownCriticalExtensionReason,
} from '../core/pki-reasons.js';
import {
    accumulateNameConstraints,
    checkName,
    initialNameConstraints,
    type NameConstraintState,
} from './path-name-constraints.js';
import {
    advancePolicyCounters,
    ANY_POLICY,
    applyPolicyMappings,
    growPolicyTree,
    initialPolicyState,
    killPolicyTree,
    wrapUpPolicies,
    type PolicyState,
} from './path-policies.js';
import { resolveLimits } from '../core/pki-limits.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { ValidateCertificatePathInput, ValidateCertificatePathReport, SignatureVerdict, SignatureResult } from '../types/path-types.js';
import type { Certificate, DistinguishedName, GeneralName } from '../types/x509-types.js';
import { getExtension } from '../x509/x509-extensions.js';
import { formatDistinguishedName } from '../x509/x509-name-format.js';

/** PKCS #9 emailAddress, the subject attribute §4.2.1.10 puts under rfc822Name constraints. */
const EMAIL_ADDRESS = '1.2.840.113549.1.9.1';

/**
 * The critical extensions this validator processes. RFC 5280 §6.1.3 (f)
 * requires refusing any other critical extension, so this set is the exact
 * boundary of what a chain may rely on. Every entry is processed by a §6
 * step below; an extension joins the set only with the step that honours it.
 */
export const PROCESSED_CRITICAL_EXTENSIONS: ReadonlySet<string> = new Set([
    '2.5.29.19', // basicConstraints — §6.1.4 (k), (l)
    '2.5.29.15', // keyUsage — §6.1.4 (n)
    '2.5.29.17', // subjectAltName — §6.1.3 (b), (c), against the name constraints
    '2.5.29.30', // nameConstraints — §6.1.4 (g)
    '2.5.29.32', // certificatePolicies — §6.1.3 (d)
    '2.5.29.33', // policyMappings — §6.1.4 (a), (b)
    '2.5.29.36', // policyConstraints — §6.1.4 (i)
    '2.5.29.54', // inhibitAnyPolicy — §6.1.4 (j)
    '2.5.29.37', // extKeyUsage: not a §6 input; carried so a leaf that marks it critical still validates
]);

/**
 * The walk's mutable bookkeeping. **Internal and never exported as a type a
 * caller can hold** — it exists so the step functions can be tested in
 * isolation, not so anyone can build one.
 */
export interface PathState {
    /** Remaining certificates that may still be intermediates, §6.1.4 (l). */
    maxPathLength: number;
    /**
     * The issuer name the previous certificate named. Carried as the whole
     * `DistinguishedName` rather than only its bytes, so a mismatch can be
     * *reported* with the name that was looked for — the comparison is still
     * on `der`, because two names that print the same and encode differently
     * are two names.
     */
    expectedIssuer: DistinguishedName | null;
    /** Every `der` already walked, so a loop is caught rather than followed. */
    readonly seen: Set<string>;
    readonly reasons: PkiReason[];
}

/** One entry of the verdict map; `'ambiguous'` is the fail-closed marker. */
export type SignatureEntry =
    | { readonly verdict: SignatureVerdict; readonly errorCode?: string | undefined; readonly detail?: string | undefined }
    | 'ambiguous';

/** Everything the walk reads and never changes. */
export interface PathContext {
    readonly at: number;
    /**
     * Verdicts by `hex(subject.der)`, and by `hex(subject.der)|hex(issuer.der)`
     * when the caller named the issuer. The pair key is looked up first, which
     * is what makes a cross-signed bag decidable.
     */
    readonly signatures: ReadonlyMap<string, SignatureEntry>;
    /** The anchors' subject names, for finding the anchor a certificate names as its issuer. */
    readonly trustAnchorSubjects: ReadonlySet<string>;
    /**
     * The anchors themselves, as `hex(subject.der)|hex(subjectPublicKeyInfo.der)`:
     * RFC 5280 §6.1.1 (d) makes a trust anchor a name **and a key**, so a
     * certificate in the path stands for an anchor only when it carries both.
     * Matching the name alone let a self-signed certificate that merely
     * copied an anchor's name end the walk unverified.
     */
    readonly trustAnchorKeys: ReadonlySet<string>;
    readonly maxPathLength: number;
    readonly maxCertificates: number;
}

const _hex = (bytes: Uint8Array): string => {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
};

/** A trust anchor as §6.1.1 (d) defines it — a name and a key — in one lookup key. */
const _anchorKey = (certificate: Certificate): string => `${_hex(certificate.subject.der)}|${_hex(certificate.subjectPublicKeyInfo.der)}`;

/**
 * §6.1.3 (a)(2) — the validity window.
 *
 * Reported rather than thrown, and reported for **both** ends: a caller
 * validating a signature made in the past needs to know which side of the
 * window they are on, and "invalid" would not tell them.
 *
 * @param certificate The certificate under test.
 * @param at          The validation instant, epoch milliseconds.
 * @param path        The report path prefix, e.g. `path[1]`.
 * @returns The reason, or null when the instant is inside the window.
 */
export function checkValidity(certificate: Certificate, at: number, path: string): PkiReason | null {
    const { notBefore, notAfter } = certificate.validity;
    if (at < notBefore.epochMilliseconds) return notYetValidReason(`${path}.validity`, notBefore.epochMilliseconds, at);
    if (at > notAfter.epochMilliseconds) return expiredReason(`${path}.validity`, notAfter.epochMilliseconds, at);
    return null;
}

/**
 * §6.1.3 (f) — a critical extension nobody here processes.
 *
 * @param certificate The certificate under test.
 * @param path        The report path prefix.
 * @returns One reason per unprocessed critical extension, in encoded order.
 */
export function checkCriticalExtensions(certificate: Certificate, path: string): PkiReason[] {
    const out: PkiReason[] = [];
    for (const extension of certificate.extensions) {
        if (extension.critical && !PROCESSED_CRITICAL_EXTENSIONS.has(extension.oid)) {
            out.push(unknownCriticalExtensionReason(`${path}.extensions`, extension.oid));
        }
    }
    return out;
}

/**
 * §6.1.3 (a)(1) — the signature, from a verdict computed beforehand.
 *
 * A certificate with no verdict is `PKI_REASON_SIGNATURE_NOT_CHECKED`, never
 * assumed valid. That default is the whole reason this takes a map rather
 * than a key: a missing entry has to be visible, and a validator that
 * treated silence as success would be a validator that passes when the
 * caller forgets to verify anything.
 *
 * When two certificates in the bag share a subject name — cross-signing, and
 * the case `buildCertificatePath` exists for — a verdict that does not name its
 * issuer is not an answer about *this* link. So the pair is looked up first, and
 * two issuer-less verdicts that disagree are `not-checked` rather than resolved
 * by insertion order: taking the last one is how a validator accepts the decoy
 * half of a cross-signed pair, which is what x509-limbo's bettertls path-building
 * cases are built to catch.
 *
 * @param certificate The certificate whose signature is at stake.
 * @param context     The walk's inputs.
 * @param path        The report path prefix.
 * @param issuer      The certificate that issued it, when the walk knows it.
 * @returns The reason, or null when the signature is known good.
 */
export function checkSignature(certificate: Certificate, context: PathContext, path: string, issuer?: Certificate | undefined): PkiReason | null {
    const subject = _hex(certificate.der);
    const result = (issuer === undefined ? undefined : context.signatures.get(`${subject}|${_hex(issuer.der)}`))
        ?? context.signatures.get(subject);
    if (result === undefined) {
        return signatureNotCheckedReason(path, 'PKI_CRYPTO_UNAVAILABLE', 'no signature verdict was supplied for this certificate');
    }
    if (result === 'ambiguous') {
        return signatureNotCheckedReason(path, 'PKI_API_MISUSE',
            'two verdicts disagree about this certificate and neither names its issuer — pass `issuer` in each SignatureResult when several candidates share a subject name');
    }
    if (result.verdict === 'valid') return null;
    if (result.verdict === 'invalid') return signatureInvalidReason(path);
    return signatureNotCheckedReason(path, result.errorCode ?? 'PKI_CRYPTO_KEY_UNSUPPORTED', result.detail ?? 'the signature could not be checked');
}

/**
 * §6.1.4 (k), (l), (n) — what an issuing certificate must assert, and how
 * much further the chain may go.
 *
 * Runs on a certificate **that has issued another one**, never on the leaf:
 * a leaf is not required to be a CA, and checking it as one is how a
 * validator ends up refusing every end-entity certificate in existence.
 *
 * A version 1 or 2 **intermediate** is refused whatever it carries, as
 * §6.1.4 (k) allows. A trust anchor is exempt from that one test — it is
 * trusted a priori, not by its encoding — but not from the others, so a v1
 * anchor, which cannot carry basicConstraints, is refused as an issuer all
 * the same.
 *
 * @param issuer The certificate that issued the previous one.
 * @param state  The walk's bookkeeping; `maxPathLength` is updated here.
 * @param path   The report path prefix.
 * @param anchor Whether `issuer` is the trust anchor, which the version test spares.
 * @returns Every reason this certificate may not have issued.
 */
export function checkIssuingCapability(issuer: Certificate, state: PathState, path: string, anchor = false): PkiReason[] {
    const out: PkiReason[] = [];
    const basicConstraints = getExtension(issuer, 'basicConstraints');
    const keyUsage = getExtension(issuer, 'keyUsage');

    // (k) *"conforming implementations may choose to reject all version 1 and
    // version 2 intermediate certificates"* — and this one does. The parser
    // only diagnoses a v1 certificate that carries extensions, so without
    // this test a v1 intermediate with a cA basicConstraints issued freely.
    if (!anchor && issuer.version < 3) out.push(notACaReason(path, 'version'));
    // (k) cA MUST be asserted. A v1 or v2 certificate has no basicConstraints
    // at all, and RFC 5280 §6.1.4 (k) gives it no licence to issue either.
    if (basicConstraints?.cA !== true) out.push(notACaReason(path, 'basicConstraints'));
    // (n) keyUsage, when present, MUST assert keyCertSign. Absent is allowed:
    // the extension is optional and its absence asserts nothing.
    if (keyUsage !== undefined && !keyUsage.usages.includes('keyCertSign')) out.push(notACaReason(path, 'keyUsage'));

    // (l) the remaining budget, then (m) this certificate's own constraint.
    //
    // §6.1.4 (l) spends budget only on a certificate that is **not**
    // self-issued: *"If the certificate was not self-issued, verify that
    // max_path_length is greater than zero and decrement max_path_length by
    // 1."* A CA re-keying itself adds a certificate to the path without adding
    // a link to the hierarchy, and charging it a step refuses a rollover that
    // fits the constraint its issuer wrote. (m) applies either way: a
    // `pathLenConstraint` on a self-issued certificate still binds what is
    // below it.
    const selfIssued = _hex(issuer.subject.der) === _hex(issuer.issuer.der);
    if (!selfIssued) {
        if (state.maxPathLength <= 0) out.push(pathTooLongReason(path, 0));
        state.maxPathLength -= 1;
    }
    const constraint = basicConstraints?.pathLenConstraint;
    if (constraint !== undefined && constraint < state.maxPathLength) state.maxPathLength = constraint;
    return out;
}

/**
 * §6.1.3 (b), (c) — every name a certificate asserts, against the
 * constraints accumulated above it.
 *
 * Both the `subject` distinguished name and every `subjectAltName` entry are
 * tested. Testing only the SAN is the mistake that lets a constrained CA
 * issue for a CN nobody checked, and testing only the subject misses every
 * modern certificate, where the identity lives in the SAN. A certificate with
 * no SAN also has each subject `emailAddress` tested as an rfc822Name.
 *
 * @param certificate The certificate under test.
 * @param names       The accumulated constraints.
 * @param path        The report path prefix.
 * @returns One reason per name outside the constraints.
 */
export function checkNamesAgainstConstraints(certificate: Certificate, names: NameConstraintState, path: string): PkiReason[] {
    const out: PkiReason[] = [];
    // An empty subject asserts nothing, and RFC 5280 §4.1.2.6 requires the
    // identity to live in a critical SAN in that case. Constraining an empty
    // name against a directoryName subtree would refuse it for having no name.
    if (certificate.subject.rdns.length > 0) {
        const asDirectory: GeneralName = { kind: 'directoryName', name: certificate.subject, der: certificate.subject.der };
        const verdict = checkName(names, asDirectory);
        if (verdict !== null) {
            out.push(verdict.why === 'excluded'
                ? nameExcludedReason(`${path}.subject`, 'subject', formatDistinguishedName(certificate.subject))
                : nameNotPermittedReason(`${path}.subject`, 'subject', formatDistinguishedName(certificate.subject)));
        }
    }
    const subjectAltName = getExtension(certificate, 'subjectAltName');
    // §4.2.1.10: "When constraints are imposed on the rfc822Name name form,
    // but the certificate does not include a subject alternative name, the
    // rfc822Name constraint MUST be applied to the attribute of type
    // emailAddress in the subject distinguished name." Skipping it lets a CA
    // constrained to one mail domain put any mailbox in the subject
    // (PKITS InvalidDNandRFC822nameConstraintsTest29). The attributes walked
    // came out of the name reader, bounded by `maxNameAttributes`.
    if (subjectAltName === undefined) {
        for (const attribute of certificate.subject.rdns.flat()) {
            if (attribute.type !== EMAIL_ADDRESS) continue;
            // A value that is not a character string is no mailbox: the empty
            // one is malformed, so a constrained form refuses it.
            const mailbox: GeneralName = { kind: 'rfc822Name', value: attribute.value?.value ?? '', der: attribute.valueDer };
            const verdict = checkName(names, mailbox);
            if (verdict === null) continue;
            out.push(verdict.why === 'excluded'
                ? nameExcludedReason(`${path}.subject`, verdict.form, verdict.text)
                : nameNotPermittedReason(`${path}.subject`, verdict.form, verdict.text));
        }
    }
    for (const entry of subjectAltName?.names ?? []) {
        const verdict = checkName(names, entry);
        if (verdict === null) continue;
        out.push(verdict.why === 'excluded'
            ? nameExcludedReason(`${path}.subjectAltName`, verdict.form, verdict.text)
            : nameNotPermittedReason(`${path}.subjectAltName`, verdict.form, verdict.text));
    }
    return out;
}

/**
 * §6.1.3 (d), (e) and §6.1.4 (a), (b), (h)–(j) for one certificate.
 *
 * The order inside is the rule, not a preference: the tree grows from this
 * certificate's own policies **before** the counters advance, because
 * `requireExplicitPolicy: 0` in a CA binds the certificate below it, and
 * advancing first would let that CA exempt its own child.
 *
 * @param certificate The certificate being stepped onto.
 * @param policies    The walk's policy state, updated in place.
 * @param maxNodes    The `maxPolicyNodes` bound.
 * @param path        The report path prefix.
 * @param final       Whether this is the final certificate, which §6.1.5 (a) decrements even when self-issued.
 * @returns Every reason policy processing produced for this step.
 */
export function advancePolicies(certificate: Certificate, policies: PolicyState, maxNodes: number, path: string, final: boolean): PkiReason[] {
    const out: PkiReason[] = [];
    const asserted = getExtension(certificate, 'certificatePolicies');
    if (asserted === undefined) {
        // §6.1.3 (e). A certificate that asserts no policy ends every branch.
        killPolicyTree(policies);
    } else if (growPolicyTree(policies, asserted.policies, maxNodes) === 'limit') {
        out.push(limitExceededReason(`${path}.certificatePolicies`, 'maxPolicyNodes', maxNodes));
    }

    const mappings = getExtension(certificate, 'policyMappings');
    if (mappings !== undefined) {
        for (const mapping of mappings.mappings) {
            if (mapping.issuerDomainPolicy === ANY_POLICY || mapping.subjectDomainPolicy === ANY_POLICY) {
                out.push(policyMappingInvalidReason(`${path}.policyMappings`, mapping.issuerDomainPolicy, mapping.subjectDomainPolicy));
            }
        }
        applyPolicyMappings(policies, mappings.mappings);
    }

    const constraints = getExtension(certificate, 'policyConstraints');
    const inhibitAny = getExtension(certificate, 'inhibitAnyPolicy');
    // A self-issued certificate does not advance the counters (§6.1.4 (h)):
    // a CA re-keying itself must not spend a step of anyone's budget. The
    // exemption stops at the final certificate, which §6.1.5 (a) decrements
    // unconditionally: *"If explicit_policy is not 0, decrement
    // explicit_policy by 1."* Exempting it let a self-issued leaf with no
    // policy pass a `requireExplicitPolicy: 1` its issuer wrote for it.
    const selfIssued = _hex(certificate.subject.der) === _hex(certificate.issuer.der);
    advancePolicyCounters(policies, selfIssued && !final, constraints?.requireExplicitPolicy, constraints?.inhibitPolicyMapping, inhibitAny?.skipCerts);
    return out;
}

/**
 * Validate a certification path (RFC 5280 §6).
 *
 * ```ts
 * import { validateCertificatePath, verifyCertificateSignature } from 'pkinative';
 *
 * // Every link gets a verdict, the last one against the anchor it names: a chain that stops at the
 * // intermediate — how most servers send it — is anchored by `roots`, not by its own last element.
 * const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((octet, j) => octet === b[j]);
 * const signatures = (await Promise.all(chain.map(async (cert, i) => {
 *     const issuer = chain[i + 1] ?? roots.find((root) => sameBytes(root.subject.der, cert.issuer.der));
 *     if (issuer === undefined) return [];   // nobody to check against: the validator reports NOT_CHECKED, never "valid"
 *     return [{ certificate: cert, verdict: await verifyCertificateSignature(cert, issuer) ? 'valid' as const : 'invalid' as const }];
 * }))).flat();
 * const report = validateCertificatePath({ path: chain, trustAnchors: roots, at: Date.now(), signatures });
 * if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
 * ```
 *
 * **It never throws for a validation issue**, and it never throws for a
 * missing input either: an empty chain, no trust anchor and no signature
 * verdicts are all answers, reported as reasons. The only thing that can
 * throw is misusing the API — an unknown key in `limits`.
 *
 * `nameConstraints`, `policyConstraints`, `policyMappings` and
 * `inhibitAnyPolicy` are processed (§6.1.3, §6.1.4); any **other** critical
 * extension is refused rather than ignored, as `PKI_REASON_UNKNOWN_CRITICAL_EXTENSION`.
 * See `PROCESSED_CRITICAL_EXTENSIONS`.
 *
 * A version 1 or 2 intermediate is `PKI_REASON_NOT_A_CA` (§6.1.4 (k)), and so
 * is a version 1 trust anchor that issued the next certificate: it cannot
 * carry the basicConstraints that would let it.
 *
 * @param input What to validate, and everything needed to judge it.
 * @returns The verdict and every reason behind it.
 * @throws {PkiError} `PKI_INVALID_OPTION` for an unknown key in `limits`.
 */
export function validateCertificatePath(input: ValidateCertificatePathInput): ValidateCertificatePathReport {
    return _validateIndexed(input, _signatureIndex(input.signatures ?? []));
}

/**
 * The verdict map `validateCertificatePath` looks signatures up in, keyed by
 * encoded certificate. Built once per verdict list: `buildCertificatePath`
 * validates up to `maxPathsExplored` candidate paths against one list, and
 * re-encoding every verdict's certificates for each of them made the search
 * cost paths × verdicts × certificate size — eighteen minutes for sixty-five
 * certificates sharing one name, before the index moved here.
 *
 * @internal
 */
export function _signatureIndex(results: readonly SignatureResult[]): ReadonlyMap<string, SignatureEntry> {
    const signatures = new Map<string, SignatureEntry>();
    // Bounded by the caller's verdict list, one entry each.
    for (const result of results) {
        const subject = _hex(result.certificate.der);
        const entry = { verdict: result.verdict, errorCode: result.errorCode, detail: result.detail };
        if (result.issuer !== undefined) {
            signatures.set(`${subject}|${_hex(result.issuer.der)}`, entry);
            continue;
        }
        // Two issuer-less verdicts for one certificate that disagree cannot both
        // be about the link being walked, and choosing by order would decide a
        // cross-signed path by accident. Agreeing duplicates are harmless: the
        // answer is the same whichever issuer was meant.
        const existing = signatures.get(subject);
        if (existing !== undefined && (existing === 'ambiguous' || existing.verdict !== result.verdict)) {
            signatures.set(subject, 'ambiguous');
            continue;
        }
        signatures.set(subject, entry);
    }
    return signatures;
}

/**
 * `validateCertificatePath` against a verdict map already built by
 * `_signatureIndex` from `input.signatures`, which this does not read.
 *
 * @internal
 */
export function _validateIndexed(input: ValidateCertificatePathInput, signatures: ReadonlyMap<string, SignatureEntry>): ValidateCertificatePathReport {
    const limits = resolveLimits(input.limits);
    const context: PathContext = {
        at: input.at,
        signatures,
        trustAnchorSubjects: new Set(input.trustAnchors.map((c) => _hex(c.subject.der))),
        trustAnchorKeys: new Set(input.trustAnchors.map(_anchorKey)),
        maxPathLength: limits.maxChainLength,
        maxCertificates: limits.maxChainLength,
    };
    const state: PathState = {
        maxPathLength: context.maxPathLength,
        expectedIssuer: null,
        seen: new Set<string>(),
        reasons: [],
    };

    const walked: Certificate[] = [];
    let anchored = false;
    // Set when the walk stopped at `maxChainLength`, so the anchor that does
    // not fit is not reported a second time below.
    let limited = false;

    for (const [index, certificate] of input.path.entries()) {
        const path = `path[${String(index)}]`;
        if (index >= context.maxCertificates) {
            state.reasons.push(limitExceededReason(path, 'maxChainLength', context.maxCertificates));
            limited = true;
            break;
        }
        const fingerprint = _hex(certificate.der);
        if (state.seen.has(fingerprint)) {
            state.reasons.push(pathLoopsReason(path));
            break;
        }
        state.seen.add(fingerprint);
        walked.push(certificate);

        // The link to the previous certificate: this one must be the issuer
        // the previous one named, byte for byte. Comparing encodings rather
        // than rendered names is the whole point — two names that print the
        // same and encode differently are two names.
        if (state.expectedIssuer !== null && _hex(certificate.subject.der) !== _hex(state.expectedIssuer.der)) {
            state.reasons.push(issuerNotFoundReason(path, formatDistinguishedName(state.expectedIssuer)));
            break;
        }

        const validity = checkValidity(certificate, context.at, path);
        if (validity !== null) state.reasons.push(validity);
        state.reasons.push(...checkCriticalExtensions(certificate, path));

        // A trust anchor is trusted a priori: its own signature is not
        // checked, and the walk stops there. Checking a root's self-signature
        // proves only that it is self-consistent, which is not what trust is.
        // It is the anchor only by name **and** key: a certificate that copies
        // an anchor's name under another key is a certificate like any other,
        // and its signature is checked against the anchor it names below.
        if (context.trustAnchorKeys.has(_anchorKey(certificate))) {
            anchored = true;
            break;
        }

        // The issuer this link will actually be walked to: the next certificate
        // in the chain, or, when the chain stops here, the anchor that names
        // itself as its issuer. Naming it is what lets a caller distinguish two
        // cross-signed issuers of the same name.
        const wanted = _hex(certificate.issuer.der);
        const issuer = input.path[index + 1] ?? input.trustAnchors.find((candidate) => _hex(candidate.subject.der) === wanted);
        const signature = checkSignature(certificate, context, path, issuer);
        if (signature !== null) state.reasons.push(signature);
        state.expectedIssuer = certificate.issuer;
    }

    // RFC 5280 §6.1.1 (a) takes the trust anchor as a **separate input**, not
    // as an element of the path. So a chain that stops one short of its root
    // is anchored when its last certificate names an anchor's subject — which
    // is how a server that sends only leaf and intermediate is meant to be
    // validated, and that is most of them.
    //
    // **The anchor then joins the walked path**, and it must: §6.1.2
    // initialises the state *from* the anchor, so its `nameConstraints`, its
    // `basicConstraints` and its `keyUsage` all bind what it issued. Leaving it
    // out — which this function did until x509-limbo scored it — means a
    // certificate issued by a name-constrained root, presented on its own,
    // validates with the constraint never applied. That is the shape of a real
    // CVE, and the reason the corpus is scored at all.
    if (!anchored && state.expectedIssuer !== null) {
        const wanted = _hex(state.expectedIssuer.der);
        const anchor = input.trustAnchors.find((candidate) => _hex(candidate.subject.der) === wanted);
        if (anchor !== undefined) {
            anchored = true;
            const path = `path[${String(walked.length)}]`;
            // Its **signature** is deliberately not checked: a trust anchor is
            // trusted a priori, and a root's self-signature proves only that it
            // is self-consistent.
            //
            // Its **validity window and its critical extensions are**, and the
            // same two checks run when the anchor arrives inside `path`
            // instead — a certificate that is judged differently depending on
            // which of two inputs the caller put it in is a certificate nobody
            // can reason about. Trusting a key is not the same as believing its
            // owner still holds it: an expired root is one whose owner retired
            // it, and an unknown critical extension on it is an instruction
            // this validator cannot follow. A relying party that means to trust
            // an expired anchor anyway can see the reason and decide; one that
            // never sees it cannot.
            //
            // It also **counts against `maxChainLength`**, for the same reason:
            // the bound is on the walked path, anchor included, and a chain
            // that is refused with its root inside `path` must not validate
            // with the same root supplied only in `trustAnchors`.
            if (walked.length >= context.maxCertificates) {
                if (!limited) state.reasons.push(limitExceededReason(path, 'maxChainLength', context.maxCertificates));
            } else {
                const validity = checkValidity(anchor, context.at, path);
                if (validity !== null) state.reasons.push(validity);
                state.reasons.push(...checkCriticalExtensions(anchor, path));
                walked.push(anchor);
            }
        }
    }
    if (!anchored) state.reasons.push(noTrustAnchorReason(`path[${String(Math.max(walked.length - 1, 0))}]`));

    // §6.1.4 (l) and (m) count **downwards from the anchor**, so this loop
    // runs from the anchor end towards the leaf. A `pathLenConstraint` bounds
    // what may appear BELOW the certificate carrying it, and walking the
    // other way makes a CA's own constraint apply to its issuer — which
    // refuses every chain under a `pathLenConstraint: 0` intermediate,
    // including the real Let's Encrypt one.
    // §6.1.4 (g) accumulates name constraints walking **down** from the
    // anchor, and §6.1.3 (b) and (c) test each certificate against what has
    // accumulated above it. Both happen in this one descending pass, in that
    // order: a CA's own constraints bind what it issues, never itself.
    const names = initialNameConstraints();
    // §6.1.2: the policy tree starts at the anchor, one node deep, and the
    // three counters start at n + 1 unless the caller asked otherwise.
    const policies = initialPolicyState(
        walked.length,
        input.requireExplicitPolicy === true,
        input.inhibitPolicyMapping === true,
        input.inhibitAnyPolicy === true,
    );
    for (let index = walked.length - 1; index >= 1; index -= 1) {
        const issuer = walked[index] as Certificate;
        const below = walked[index - 1] as Certificate;
        const belowPath = `path[${String(index - 1)}]`;
        state.reasons.push(...checkIssuingCapability(issuer, state, `path[${String(index)}]`, context.trustAnchorKeys.has(_anchorKey(issuer))));
        const constraints = getExtension(issuer, 'nameConstraints');
        if (constraints !== undefined) accumulateNameConstraints(names, constraints.permittedSubtrees, constraints.excludedSubtrees);
        // §6.1.3 (b), (c): *"Name constraints are not applied to self-issued
        // certificates (unless the certificate is the final certificate in the
        // path)"* — a CA re-keying itself keeps its own name, which its own
        // constraints need not permit, and refusing that would refuse every
        // key rollover. The exemption stops at the leaf: a self-issued final
        // certificate is the identity being judged, not a step in the chain.
        const selfIssued = _hex(below.subject.der) === _hex(below.issuer.der);
        if (!selfIssued || index - 1 === 0) state.reasons.push(...checkNamesAgainstConstraints(below, names, belowPath));
        state.reasons.push(...advancePolicies(below, policies, limits.maxPolicyNodes, belowPath, index - 1 === 0));
    }

    // §6.1.5 (g). Only a required explicit policy with nothing surviving
    // rejects a path; an empty tree nobody asked about is not a failure.
    if (wrapUpPolicies(policies, input.initialPolicySet ?? []) === null) {
        state.reasons.push(noValidPolicyReason('path'));
    }

    return { valid: state.reasons.length === 0, reasons: state.reasons, path: walked };
}
