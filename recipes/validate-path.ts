/**
 * Recipe: validate a certification path (RFC 5280 §6), and read the report.
 *
 * The shape to notice is that `validateCertificatePath` takes **signature
 * verdicts you computed beforehand**, never a key. Three things follow, and
 * all three are the point: §6 stays synchronous, it stays pure, and the
 * signatures can be checked in parallel — which is what a verifier should do
 * anyway.
 *
 * It also **never throws** for a validation issue. Every negative answer is a
 * `PkiReason` in the report, and several come back together when several
 * apply: a caller fixing one problem per round trip is a caller the report
 * failed.
 */
import {
    buildCertificatePath,
    parseCertificate,
    validateCertificatePath,
    verifyCertificateSignature,
    type Certificate,
    type BuildCertificatePathReport,
    type ValidateCertificatePathReport,
    type SignatureResult,
} from 'pkinative';
import { fixture } from './_fixtures.js';

const quiet = { onDiagnostic: (): undefined => undefined };
const load = (name: string): Certificate => parseCertificate(fixture(name), quiet);

/** Check every link in parallel, then hand the verdicts to §6. */
async function verdicts(chain: readonly Certificate[]): Promise<SignatureResult[]> {
    return Promise.all(chain.slice(0, -1).map(async (subject, index) => {
        const issuer = chain[index + 1] as Certificate;
        try {
            return { certificate: subject, verdict: await verifyCertificateSignature(subject, issuer) ? 'valid' as const : 'invalid' as const };
        } catch (error) {
            // A runtime that cannot check says nothing about the signature.
            // 'not-checked' keeps that distinction all the way into the report.
            const { code, message } = error as { code: string; message: string };
            return { certificate: subject, verdict: 'not-checked' as const, errorCode: code, detail: message };
        }
    }));
}

const summarise = (report: ValidateCertificatePathReport | BuildCertificatePathReport): string =>
    report.valid ? `valid, ${String(report.path.length)} certificates` : report.reasons.map((r) => r.code).join(',');

export default async function run(): Promise<Record<string, string>> {
    const root = load('isrg-root-x1');
    const intermediate = load('lets-encrypt-r12');
    // Inside R12's window (2024-03-13 … 2027-03-12) and the root's.
    const at = Date.UTC(2026, 9, 1);

    // The real hierarchy: R12 is issued by ISRG Root X1.
    const chain = [intermediate, root];
    const trusted = await verdicts(chain);

    const good = validateCertificatePath({ path: chain, trustAnchors: [root], at, signatures: trusted });

    // A chain that stops one short of its root is still anchored when its last
    // certificate names a trusted subject — most servers send it this way, and
    // §6.1.1 (a) takes the anchor as a separate input for exactly that reason.
    // The report's `path` nonetheless ends with the anchor: §6.1.2 initialises
    // the state FROM it, so its name constraints, its basicConstraints and its
    // keyUsage all bind what it issued, and a path that omitted it would be
    // claiming those were never applied.
    const short = validateCertificatePath({ path: [intermediate], trustAnchors: [root], at, signatures: trusted });

    // No anchor at all is an answer, not an exception.
    const untrusted = validateCertificatePath({ path: chain, trustAnchors: [], at, signatures: trusted });

    // Expired, and asked for a decade too late. Note that the report carries
    // both the time reason and the anchor reason, not just the first.
    const late = validateCertificatePath({ path: chain, trustAnchors: [root], at: Date.UTC(2040, 0, 1), signatures: trusted });

    // Forget to supply a verdict and you get NOT_CHECKED, never a pass. A
    // validator that read silence as success would pass whenever a caller
    // forgot to verify anything.
    const unverified = validateCertificatePath({ path: chain, trustAnchors: [root], at });

    // A leaf is not a CA, so it may not issue: this is the check whose absence
    // was the 2008 Basic Constraints attack.
    const leaf = load('letsencrypt-org-leaf');
    const forged = validateCertificatePath({ path: [root, leaf], trustAnchors: [leaf], at, signatures: [{ certificate: root, verdict: 'valid' }] });

    // A caller with an unordered bag rather than a chain uses the builder,
    // which searches with backtracking. Cross-signing means one subject name can
    // have several plausible issuers, so taking the first match is not enough —
    // and `maxPathsExplored` rather than `maxChainLength` is the bound, because
    // the search is exponential in the candidate set.
    const bag = [root, intermediate, leaf];
    const built = buildCertificatePath({ leaf: intermediate, candidates: bag, trustAnchors: [root], at, signatures: trusted });
    const unbuildable = buildCertificatePath({ leaf, candidates: bag, trustAnchors: [root], at, signatures: trusted });

    return {
        built: `${summarise(built)} explored=${String(built.explored)}`,
        // The committed leaf is issued by CN=YE2, which is not in the bag, so
        // no path reaches an anchor — and the report says how far it got.
        unbuildable: unbuildable.reasons.map((r) => r.code).sort().join(','),
        // `explored` is worth logging: a number near `maxPathsExplored` is a bag
        // of certificates designed to be expensive, not a hierarchy. Reaching
        // that bound needs a deeper hierarchy than these three fixtures make,
        // and tests/path/path-build.test.ts builds one.
        unbuildableExplored: String(unbuildable.explored),
        chain: summarise(good),
        anchorOutsideChain: summarise(short),
        noAnchor: summarise(untrusted),
        expired: summarise(late),
        unverified: summarise(unverified),
        leafCannotIssue: forged.reasons.some((r) => r.code === 'PKI_REASON_NOT_A_CA') ? 'refused' : 'ACCEPTED',
        neverThrows: 'true',
    };
}
