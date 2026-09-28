/**
 * pkinative — certification path building
 * =======================================
 * Given a leaf, a bag of certificates and some trust anchors: find a path §6
 * accepts, or report why none exists.
 *
 * ## Why this is a search and not a walk
 *
 * `validateCertificatePath` takes an ordered chain. Real callers do not have
 * one — a TLS handshake hands over an unordered bag, a trust store holds
 * hundreds of anchors, and **cross-signing means one subject name can have
 * several plausible issuers**. Let's Encrypt's own hierarchy is the everyday
 * example: R3 was cross-signed, so a verifier choosing the first matching
 * issuer would fail on chains that validate perfectly through the other one.
 *
 * So the search is a depth-first walk over candidates with backtracking, and
 * the bound that matters is `maxPathsExplored` — **not** `maxChainLength`.
 * Path building is exponential in the candidate set and only linear in the
 * chain length, which is why the roadmap calls this *the* denial-of-service
 * vector of §6. A bag of 30 certificates that all name each other as issuer is
 * a few kilobytes of input and an unbounded amount of work.
 *
 * ## What it returns, and what it does not decide
 *
 * The first path §6 accepts, with §6's own report. When none is accepted, the
 * report of the **best attempt** — the one that got furthest before failing —
 * because "no path found" without saying why is a report nobody can act on,
 * and the reasons from the deepest attempt are almost always the ones a caller
 * needs to see.
 *
 * Choosing *which* anchors to trust is not this function's business, and
 * neither is fetching a certificate it has not been given. Both belong to the
 * caller, and a path builder that reached the network would be a path builder
 * an attacker can point at a host of their choosing.
 *
 * @module path/path-build
 */

import { bytesEqual } from '../core/bytes.js';
import { limitExceededReason } from '../core/pki-reasons.js';
import { resolveLimits } from '../core/pki-limits.js';
import type { PathValidationInput, PathValidationReport } from '../types/path-types.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { Certificate } from '../types/x509-types.js';
import { checkExtendedKeyUsage } from './path-purpose.js';
import { validateCertificatePath } from './path-validate.js';

/** What to build from, and everything needed to judge each candidate. */
export interface PathBuildInput extends Omit<PathValidationInput, 'certificates'> {
    /** The certificate a path is wanted for. */
    readonly leaf: Certificate;
    /**
     * Every certificate that may appear in the path, in any order, duplicates
     * and irrelevant entries included. A TLS handshake's `certificate_list` can
     * be handed over whole.
     */
    readonly candidates: readonly Certificate[];
    /**
     * KeyPurposeId OIDs every certificate on the path must permit, checked
     * **during** the search rather than after it.
     *
     * Pass them whenever you know what the chain is for. A builder that picks a
     * path without knowing its purpose will confidently return one that
     * `checkExtendedKeyUsage` then condemns **while an acceptable path existed**
     * — a real bag of cross-signed intermediates, some restricted to
     * `emailProtection` and some not, is exactly that shape, and x509-limbo has
     * the cases. Whatever can make a path unacceptable has to be inside the
     * search, for the same reason name constraints are inside §6 rather than
     * after it.
     *
     * `validateCertificatePath` is untouched by this: §6 has no notion of
     * purpose, and searching is not §6.
     */
    readonly requiredPurposes?: readonly string[] | undefined;
}

/** A path that was tried, and what §6 made of it. */
export interface PathBuildReport extends PathValidationReport {
    /**
     * How many candidate paths were explored before this answer. Worth
     * logging: a number near `maxPathsExplored` is a bag of certificates
     * designed to be expensive, not a hierarchy.
     */
    readonly explored: number;
}

const fingerprint = (certificate: Certificate): string => {
    let out = '';
    for (const b of certificate.der) out += b.toString(16).padStart(2, '0');
    return out;
};

/**
 * Build and validate a certification path.
 *
 * ```ts
 * import { buildCertificatePath } from 'pkinative';
 *
 * const report = buildCertificatePath({
 *     leaf, candidates: whateverTheServerSent, trustAnchors: yourRoots,
 *     at: Date.now(), signatures,
 * });
 * if (report.valid) console.log('path of', report.path.length);
 * else for (const reason of report.reasons) console.log(reason.code, reason.path);
 * ```
 *
 * **Signature verdicts still arrive precomputed**, which is the awkward part of
 * building rather than validating: a caller does not know in advance which
 * pairs will be tried. Verify every plausible pair up front — every candidate
 * against every candidate whose subject matches its issuer — and pass them all;
 * that is a bounded amount of work, done in parallel, and it keeps this
 * function synchronous and pure like the rest of `path`. A pair with no verdict
 * is reported as `PKI_REASON_SIGNATURE_NOT_CHECKED` and the path is not taken,
 * which fails closed.
 *
 * @param input See {@link PathBuildInput}.
 * @returns The first accepted path with §6's report, or the report of the
 *   attempt that got furthest; `explored` counts the candidates tried.
 * @throws {PkiError} `PKI_INVALID_OPTION` for an unknown key in `limits`.
 */
export function buildCertificatePath(input: PathBuildInput): PathBuildReport {
    const limits = resolveLimits(input.limits);
    const anchors = new Set(input.trustAnchors.map((c) => fingerprint(c)));
    const anchorSubjects = new Set(input.trustAnchors.map((c) => hexOf(c.subject.der)));

    // Index the bag by subject name so each step costs a lookup rather than a
    // scan. Encoded names, never rendered ones — two names that print the same
    // and encode differently are two names, and a builder that conflated them
    // would happily construct a path §6 then refuses.
    const bySubject = new Map<string, Certificate[]>();
    for (const candidate of input.candidates) {
        const key = hexOf(candidate.subject.der);
        bySubject.set(key, [...(bySubject.get(key) ?? []), candidate]);
    }
    for (const anchor of input.trustAnchors) {
        const key = hexOf(anchor.subject.der);
        const existing = bySubject.get(key) ?? [];
        // An anchor is a usable issuer too, and a caller who supplied it only
        // in `trustAnchors` still expects a path to be found through it.
        if (!existing.some((c) => bytesEqual(c.der, anchor.der))) bySubject.set(key, [...existing, anchor]);
    }

    // The leaf alone is always the first attempt, and always the fallback
    // report. Doing it here rather than inside the recursion is what makes
    // `best` non-nullable: `resolveLimits` refuses a `maxPathsExplored` below
    // 1, so there is always at least this one exploration, and an "if no
    // attempt was made" branch would be unreachable code carrying a `null`
    // nobody can produce.
    /**
     * §6's verdict, plus the purposes the caller needs, as one answer.
     *
     * The purposes are folded in here rather than checked by the caller
     * afterwards so that a path they forbid is **backtracked out of** instead of
     * returned. The reasons join the report, because a caller told only "no path
     * found" cannot see that the one path there was is restricted to signing
     * e-mail.
     */
    const judge = (certificates: readonly Certificate[]): PathValidationReport => {
        const report = validateCertificatePath({ ...input, certificates });
        if (!report.valid || input.requiredPurposes === undefined) return report;
        const refused = input.requiredPurposes.flatMap((purpose) => [...checkExtendedKeyUsage(report.path, purpose)]);
        return refused.length === 0 ? report : { valid: false, reasons: refused, path: report.path };
    };

    const first = judge([input.leaf]);
    let explored = 1;
    if (first.valid) return { ...first, explored };

    let best: PathValidationReport = first;
    let bestDepth = 0;
    let limitHit = false;

    /** Try every extension of `chain`, deepest-first, and stop at the first §6 accepts. */
    const extend = (chain: readonly Certificate[], seen: ReadonlySet<string>): PathBuildReport | null => {
        // Only extend while the chain could still reach an anchor. A chain
        // already at the length bound cannot, and trying anyway is the
        // exponential blow-up `maxPathsExplored` exists to stop.
        if (chain.length >= limits.maxChainLength) return null;

        const last = chain[chain.length - 1] as Certificate;
        if (anchors.has(fingerprint(last)) || anchorSubjects.has(hexOf(last.subject.der))) return null;

        for (const issuer of bySubject.get(hexOf(last.issuer.der)) ?? []) {
            const key = fingerprint(issuer);
            // A path that revisits a certificate is not a path, and following
            // one is how a cross-signed pair becomes an infinite loop.
            if (seen.has(key)) continue;
            if (explored >= limits.maxPathsExplored) { limitHit = true; return null; }
            explored += 1;

            const next = [...chain, issuer];
            const report = judge(next);
            if (report.valid) return { ...report, explored };
            if (next.length - 1 > bestDepth) { best = report; bestDepth = next.length - 1; }

            const found = extend(next, new Set([...seen, key]));
            if (found !== null) return found;
            if (limitHit) return null;
        }
        return null;
    };

    const found = extend([input.leaf], new Set([fingerprint(input.leaf)]));
    if (found !== null) return found;

    const reasons: PkiReason[] = [...best.reasons];
    if (limitHit) reasons.push(limitExceededReason('path', 'maxPathsExplored', limits.maxPathsExplored));
    // The deepest attempt's own path, so a caller sees how far it got.
    return { valid: false, reasons, path: best.path, explored };
}

function hexOf(bytes: Uint8Array): string {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
}
