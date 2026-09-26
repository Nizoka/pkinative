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
 * `PKI_REASON_UNRECOGNISED_CRITICAL_EXTENSION`.
 *
 * That is not a placeholder, it is the correct behaviour — and it means a
 * chain constrained by `nameConstraints` or `policyConstraints`, which this
 * version does not yet process, is **refused rather than silently accepted**.
 * A validator that ignored an extension it had not implemented would answer
 * "valid" for a chain the issuing CA forbade, which is the shape of a real
 * CVE rather than a missing feature. Name constraints and the policy tree
 * join the set in their own commits, each with its own tests; until then the
 * honest answer to a chain that uses them is no.
 *
 * @module path/path-validate
 */

import {
    expiredReason,
    issuerNotFoundReason,
    limitExceededReason,
    noTrustAnchorReason,
    notACaReason,
    notYetValidReason,
    pathLoopsReason,
    pathTooLongReason,
    signatureInvalidReason,
    signatureNotCheckedReason,
    unrecognisedCriticalExtensionReason,
} from '../core/pki-reasons.js';
import { resolveLimits } from '../core/pki-limits.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { PathValidationInput, PathValidationReport, SignatureVerdict } from '../types/path-types.js';
import type { Certificate, DistinguishedName } from '../types/x509-types.js';
import { getExtension } from '../x509/x509-extensions.js';
import { formatDistinguishedName } from '../x509/x509-name-format.js';

/**
 * The critical extensions this validator processes. RFC 5280 §6.1.3 (f)
 * requires refusing any other critical extension, so this set is the exact
 * boundary of what a chain may rely on.
 *
 * Absent on purpose, and each refuses a chain rather than being ignored:
 * `2.5.29.30` nameConstraints, `2.5.29.36` policyConstraints,
 * `2.5.29.54` inhibitAnyPolicy, `2.5.29.33` policyMappings.
 */
export const PROCESSED_CRITICAL_EXTENSIONS: ReadonlySet<string> = new Set([
    '2.5.29.19', // basicConstraints — §6.1.4 (k), (l)
    '2.5.29.15', // keyUsage — §6.1.4 (n)
    '2.5.29.17', // subjectAltName: read, and constrained only once nameConstraints lands
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

/** Everything the walk reads and never changes. */
export interface PathContext {
    readonly at: number;
    readonly signatures: ReadonlyMap<string, { readonly verdict: SignatureVerdict; readonly errorCode?: string | undefined; readonly detail?: string | undefined }>;
    readonly trustAnchorSubjects: ReadonlySet<string>;
    readonly maxPathLength: number;
    readonly maxCertificates: number;
}

const _hex = (bytes: Uint8Array): string => {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
};

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
            out.push(unrecognisedCriticalExtensionReason(`${path}.extensions`, extension.oid));
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
 * @param certificate The certificate whose signature is at stake.
 * @param context     The walk's inputs.
 * @param path        The report path prefix.
 * @returns The reason, or null when the signature is known good.
 */
export function checkSignature(certificate: Certificate, context: PathContext, path: string): PkiReason | null {
    const result = context.signatures.get(_hex(certificate.der));
    if (result === undefined) {
        return signatureNotCheckedReason(path, 'PKI_CRYPTO_UNAVAILABLE', 'no signature verdict was supplied for this certificate');
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
 * @param issuer The certificate that issued the previous one.
 * @param state  The walk's bookkeeping; `maxPathLength` is updated here.
 * @param path   The report path prefix.
 * @returns Every reason this certificate may not have issued.
 */
export function checkIssuingCapability(issuer: Certificate, state: PathState, path: string): PkiReason[] {
    const out: PkiReason[] = [];
    const basicConstraints = getExtension(issuer, 'basicConstraints');
    const keyUsage = getExtension(issuer, 'keyUsage');

    // (k) cA MUST be asserted. A v1 or v2 certificate has no basicConstraints
    // at all, and RFC 5280 §6.1.4 (k) gives it no licence to issue either.
    if (basicConstraints?.cA !== true) out.push(notACaReason(path, 'basicConstraints'));
    // (n) keyUsage, when present, MUST assert keyCertSign. Absent is allowed:
    // the extension is optional and its absence asserts nothing.
    if (keyUsage !== undefined && !keyUsage.usages.includes('keyCertSign')) out.push(notACaReason(path, 'keyUsage'));

    // (l) the remaining budget, then this certificate's own constraint.
    if (state.maxPathLength <= 0) out.push(pathTooLongReason(path, 0));
    state.maxPathLength -= 1;
    const constraint = basicConstraints?.pathLenConstraint;
    if (constraint !== undefined && constraint < state.maxPathLength) state.maxPathLength = constraint;
    return out;
}

/**
 * Validate a certification path (RFC 5280 §6).
 *
 * ```ts
 * import { validateCertificatePath, verifyCertificateSignature } from 'pkinative';
 *
 * const signatures = await Promise.all(chain.slice(0, -1).map(async (cert, i) => ({
 *     certificate: cert,
 *     verdict: await verifyCertificateSignature(cert, chain[i + 1]) ? 'valid' as const : 'invalid' as const,
 * })));
 * const report = validateCertificatePath({ certificates: chain, trustAnchors: roots, at: Date.now(), signatures });
 * if (!report.valid) for (const reason of report.reasons) console.log(reason.code, reason.path, reason.message);
 * ```
 *
 * **It never throws for a validation issue**, and it never throws for a
 * missing input either: an empty chain, no trust anchor and no signature
 * verdicts are all answers, reported as reasons. The only thing that can
 * throw is misusing the API — an unknown key in `limits`.
 *
 * What this version does **not** process, and therefore refuses rather than
 * ignores: `nameConstraints`, `policyConstraints`, `policyMappings` and
 * `inhibitAnyPolicy`. See `PROCESSED_CRITICAL_EXTENSIONS`.
 *
 * @param input What to validate, and everything needed to judge it.
 * @returns The verdict and every reason behind it.
 * @throws {PkiError} `PKI_INVALID_OPTION` for an unknown key in `limits`.
 */
export function validateCertificatePath(input: PathValidationInput): PathValidationReport {
    const limits = resolveLimits(input.limits);
    const signatures = new Map<string, { verdict: SignatureVerdict; errorCode?: string | undefined; detail?: string | undefined }>();
    for (const result of input.signatures ?? []) {
        signatures.set(_hex(result.certificate.der), { verdict: result.verdict, errorCode: result.errorCode, detail: result.detail });
    }
    const context: PathContext = {
        at: input.at,
        signatures,
        trustAnchorSubjects: new Set(input.trustAnchors.map((c) => _hex(c.subject.der))),
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

    for (const [index, certificate] of input.certificates.entries()) {
        const path = `path[${String(index)}]`;
        if (index >= context.maxCertificates) {
            state.reasons.push(limitExceededReason(path, 'maxChainLength', context.maxCertificates));
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
        if (context.trustAnchorSubjects.has(_hex(certificate.subject.der))) {
            anchored = true;
            break;
        }

        const signature = checkSignature(certificate, context, path);
        if (signature !== null) state.reasons.push(signature);
        state.expectedIssuer = certificate.issuer;
    }

    // RFC 5280 §6.1.1 (a) takes the trust anchor as a **separate input**, not
    // as an element of the path. So a chain that stops one short of its root
    // is anchored when its last certificate names an anchor's subject — which
    // is how a server that sends only leaf and intermediate is meant to be
    // validated, and that is most of them.
    if (!anchored && state.expectedIssuer !== null && context.trustAnchorSubjects.has(_hex(state.expectedIssuer.der))) {
        anchored = true;
    }
    if (!anchored) state.reasons.push(noTrustAnchorReason(`path[${String(Math.max(walked.length - 1, 0))}]`));

    // §6.1.4 (l) and (m) count **downwards from the anchor**, so this loop
    // runs from the anchor end towards the leaf. A `pathLenConstraint` bounds
    // what may appear BELOW the certificate carrying it, and walking the
    // other way makes a CA's own constraint apply to its issuer — which
    // refuses every chain under a `pathLenConstraint: 0` intermediate,
    // including the real Let's Encrypt one.
    for (let index = walked.length - 1; index >= 1; index -= 1) {
        state.reasons.push(...checkIssuingCapability(walked[index] as Certificate, state, `path[${String(index)}]`));
    }

    return { valid: state.reasons.length === 0, reasons: state.reasons, path: walked };
}
