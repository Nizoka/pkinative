/**
 * pkinative — NIST PKITS, scored
 * ==============================
 * A **second** corpus for RFC 5280 §6, written by different people from a
 * different reading.
 *
 * x509-limbo comes from the Python cryptography project and is built around the
 * Web PKI; PKITS comes from NIST and is built around the US Federal PKI, with
 * certificate policies, policy mapping and indirect CRLs that the Web has never
 * used. L1–L4 prove agreement with other *implementations*; L6 proves agreement
 * with one corpus. Agreeing with two corpora written independently is a
 * different claim, and it is the only one that catches a shared misreading.
 *
 * ## Where the expectations come from
 *
 * **From the names, and nowhere else.** PKITS states its expected results in a
 * PDF, and the plan for this gate said plainly: transcribe them, never parse
 * the document. Parsing a PDF to decide what a conformance gate expects makes
 * the gate as stable as a text-extraction heuristic.
 *
 * What the archive does carry is the convention NIST itself uses: an
 * end-entity certificate called `Valid…Test1EE.crt` belongs to a test that must
 * succeed, `Invalid…Test1EE.crt` to one that must fail. 203 of the 223 tests
 * say so in their own file name, and those are scored. The other 20 are the
 * §4.8 certificate-policy tests, whose expected result depends on the
 * `user-initial-policy-set` the validator is given — PKITS gives several
 * answers per test, the archive states none of them, and this runner will not
 * guess. They are skipped with that reason until `scripts/data/pkits-score.json`
 * carries a reviewed transcription.
 *
 * ## The path is built, not transcribed
 *
 * PKITS describes each test's path in the same prose. Deriving it instead
 * removes 223 hand-copied lists — and replaces them with something better: the
 * whole bag of 404 certificates is handed to `buildCertificatePath` every time,
 * so each test also exercises path building on a candidate set with
 * cross-certificates in it. A test that only passes because somebody told the
 * validator which chain to walk is a test of the transcription.
 *
 * @module scripts/lib/pkits
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type * as Pki from '../../src/index.js';

/**
 * The instant every test is judged at.
 *
 * Fixed rather than `Date.now()`, and that is the point: the corpus lives
 * between 2010-01-01 and 2030-12-31, so a gate that asked about "now" would
 * answer the same thing every day until 2031 and then go red on a Tuesday for
 * reasons having nothing to do with this library. `assertCorpusIsLive` below
 * fails loudly when the pin falls outside the corpus's own window, which is the
 * message the maintainer actually needs at that point.
 */
export const PKITS_AT = Date.UTC(2020, 5, 15);

/** The certificate PKITS makes every path end at. */
const ANCHOR = 'TrustAnchorRootCertificate.crt';

/** What the archive holds, read once and reused by every test. */
export interface PkitsCorpus {
    readonly anchor: Pki.Certificate;
    /** Every CA certificate: the candidate bag handed to the path builder. */
    readonly candidates: readonly Pki.Certificate[];
    /** Every revocation list, as DER. */
    readonly crls: readonly Uint8Array[];
    /** One entry per end-entity certificate, by test name. */
    readonly tests: ReadonlyMap<string, Pki.Certificate>;
    /** Certificates the parser refused, by file name — none is expected. */
    readonly refused: ReadonlyMap<string, string>;
}

/**
 * Read the extracted archive.
 *
 * @param pki The built package.
 * @param dir The corpus directory, as `corpusDir` gives it.
 * @returns The anchor, the candidate bag, the lists and the tests.
 * @throws {Error} When the archive holds no trust anchor, which means the
 *   extraction produced something other than PKITS.
 */
export function readPkits(pki: typeof Pki, dir: string): PkitsCorpus {
    const quiet = { onDiagnostic: (): undefined => undefined };
    const candidates: Pki.Certificate[] = [];
    const tests = new Map<string, Pki.Certificate>();
    const refused = new Map<string, string>();
    let anchor: Pki.Certificate | undefined;

    for (const name of readdirSync(join(dir, 'certs')).sort()) {
        let certificate: Pki.Certificate;
        try {
            certificate = pki.parseCertificate(new Uint8Array(readFileSync(join(dir, 'certs', name))), quiet);
        } catch (error) {
            refused.set(name, (error as { code?: string }).code ?? 'PKI_X509_STRUCTURE_INVALID');
            continue;
        }
        if (name === ANCHOR) { anchor = certificate; continue; }
        // An end-entity certificate is a test; everything else is a candidate
        // issuer. Leaving the end entities out of the bag is not an
        // optimisation: a leaf is not an issuer, and a builder offered 223 of
        // them would explore paths no hierarchy contains.
        if (name.endsWith('EE.crt')) tests.set(name.replace(/EE\.crt$/, ''), certificate);
        else candidates.push(certificate);
    }
    if (anchor === undefined) throw new Error(`pkits: ${ANCHOR} is missing from ${dir} — the extraction is not PKITS`);

    const crls = readdirSync(join(dir, 'crls')).sort()
        .map((name) => new Uint8Array(readFileSync(join(dir, 'crls', name))));
    return { anchor, candidates, crls, tests, refused };
}

/**
 * What a test's own name says it expects, or `null` when it says nothing.
 *
 * NIST's convention, and the only machine-readable statement of intent the
 * archive carries. A name that begins with neither word is a §4.8 policy test
 * whose answer depends on the `user-initial-policy-set`, which the archive does
 * not state — so the answer here is *"it does not say"* rather than a guess.
 *
 * @param test The test name, without the `EE.crt` suffix.
 * @returns `true` for a path that must validate, `false` for one that must not,
 *   `null` when the name does not say.
 */
export function expectationOfName(test: string): boolean | null {
    if (test.startsWith('Valid')) return true;
    if (test.startsWith('Invalid')) return false;
    return null;
}

/**
 * Refuse to score a corpus whose own window has closed.
 *
 * The verdicts below are pinned at one instant, and they stay meaningful only
 * while that instant is inside the window NIST issued these certificates for.
 * Past it every test would fail for the same uninteresting reason, and a gate
 * that went red in 2031 saying `PKI_REASON_EXPIRED` two hundred times would tell
 * its maintainer nothing about what actually changed.
 *
 * @param anchor The trust anchor, whose window is the corpus's own.
 * @returns A message when the pinned instant is outside it, `null` otherwise.
 */
export function corpusWindowProblem(anchor: Pki.Certificate): string | null {
    const from = anchor.validity.notBefore.epochMilliseconds;
    const to = anchor.validity.notAfter.epochMilliseconds;
    if (PKITS_AT >= from && PKITS_AT <= to) return null;
    const day = (ms: number): string => new Date(ms).toISOString().slice(0, 10);
    return `PKITS_AT is ${day(PKITS_AT)} and the corpus trust anchor is valid ${day(from)} … ${day(to)}`
        + ' — move the instant, or re-pin a corpus NIST has since reissued';
}
