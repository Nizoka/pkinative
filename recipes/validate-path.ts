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
    parseCertificate,
    validateCertificatePath,
    verifyCertificateSignature,
    type Certificate,
    type PathValidationReport,
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

const summarise = (report: PathValidationReport): string =>
    report.valid ? `valid, ${String(report.path.length)} certificates` : report.reasons.map((r) => r.code).join(',');

export default async function run(): Promise<Record<string, string>> {
    const root = load('isrg-root-x1');
    const intermediate = load('lets-encrypt-r12');
    // Inside R12's window (2024-03-13 … 2027-03-12) and the root's.
    const at = Date.UTC(2026, 9, 1);

    // The real hierarchy: R12 is issued by ISRG Root X1.
    const chain = [intermediate, root];
    const trusted = await verdicts(chain);

    const good = validateCertificatePath({ certificates: chain, trustAnchors: [root], at, signatures: trusted });

    // The anchor is an input to §6.1.1, not an element of the path: a chain
    // that stops one short of its root is still anchored when its last
    // certificate names a trusted subject. Most servers send it this way.
    const short = validateCertificatePath({ certificates: [intermediate], trustAnchors: [root], at, signatures: trusted });

    // No anchor at all is an answer, not an exception.
    const untrusted = validateCertificatePath({ certificates: chain, trustAnchors: [], at, signatures: trusted });

    // Expired, and asked for a decade too late. Note that the report carries
    // both the time reason and the anchor reason, not just the first.
    const late = validateCertificatePath({ certificates: chain, trustAnchors: [root], at: Date.UTC(2040, 0, 1), signatures: trusted });

    // Forget to supply a verdict and you get NOT_CHECKED, never a pass. A
    // validator that read silence as success would pass whenever a caller
    // forgot to verify anything.
    const unverified = validateCertificatePath({ certificates: chain, trustAnchors: [root], at });

    // A leaf is not a CA, so it may not issue: this is the check whose absence
    // was the 2008 Basic Constraints attack.
    const leaf = load('letsencrypt-org-leaf');
    const forged = validateCertificatePath({ certificates: [root, leaf], trustAnchors: [leaf], at, signatures: [{ certificate: root, verdict: 'valid' }] });

    return {
        chain: summarise(good),
        anchorOutsideChain: summarise(short),
        noAnchor: summarise(untrusted),
        expired: summarise(late),
        unverified: summarise(unverified),
        leafCannotIssue: forged.reasons.some((r) => r.code === 'PKI_REASON_NOT_A_CA') ? 'refused' : 'ACCEPTED',
        neverThrows: 'true',
    };
}
