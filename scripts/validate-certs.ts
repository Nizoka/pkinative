/**
 * pkinative — conformance gate
 * ============================
 * The independent conformance barrier (zipnative's validate-zip, pdfnative's
 * veraPDF gate), run against the BUILT package in `dist/` — what users get —
 * over corpora pinned by commit and SHA-256 (scripts/lib/corpora.ts):
 *
 *   L0  the corpora match their pins, and their case counts match the
 *       canaries declared in docs/assets/ecosystem.json;
 *   L1  every unique certificate of x509-limbo parses, or is refused with a
 *       PkiError. A refusal must (a) touch only test cases that expect
 *       FAILURE and (b) match the reviewed baseline
 *       scripts/data/limbo-refusals.json, code included; a baseline entry
 *       that now parses is an UNEXPECTED-PASS. Any other exception fails;
 *   L2  every certificate re-encodes byte for byte from its decoded tree, and
 *       the TBS and signature boundaries agree with scripts/lib/raw-der.ts,
 *       a walker that never imports src/;
 *   L3  every parsed certificate agrees with node:crypto.X509Certificate
 *       (serial, validity, CA flag, SHA-256 fingerprint) and a sample agrees
 *       with the openssl CLI (serial, fingerprint); a missing openssl is a
 *       SKIP, which --require-all turns into a failure, while a non-reference
 *       implementation declining a certificate is reported as not applicable;
 *   L4  a sample is read again by implementations written by other people in
 *       other languages, and the readings must agree on SHA-256 of exact DER
 *       slices — never on anything either side renders. A positive canary
 *       unmasks a validator that rejects everything, negative canaries one
 *       that accepts anything, and a footer one that stopped halfway. A real
 *       difference is recorded in scripts/data/validator-disagreements.json
 *       with its reason. See scripts/lib/validators.ts;
 *   L6  every x509-limbo case is **scored**: pkinative builds a path, matches
 *       the host name and consults the CRL the way a caller would, and its
 *       verdict must match the one the corpus writes down. A disagreement is
 *       either a defect or a decision, and only a sentence in
 *       scripts/data/limbo-score.json tells them apart — so the tool records
 *       the id and a human records the reason, and an empty reason fails. A
 *       reviewed subset is pinned on its PkiReasonCode rather than on the
 *       boolean, because *rejected for the wrong reason* is a defect no
 *       pass/fail count can see, and two canaries — one case that must succeed,
 *       one that must fail — catch a harness that stopped deciding anything.
 *       See scripts/lib/limbo-score.ts;
 *   Wycheproof  ECDSA signatures decode as a strict Ecdsa-Sig-Value
 *       (SEQUENCE of two INTEGERs): every valid vector parses, every vector
 *       flagged as an encoding defect is refused.
 *
 * Usage:
 *   npx tsx scripts/validate-certs.ts [--level 0-6] [--require-all] [--update-baseline]
 *
 * Exit: 0 pass, 1 failure, 2 corpora or build missing.
 *
 * @module scripts/validate-certs
 */

import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type * as Pki from '../src/index.js';
import { CLAUSES } from './lib/clauses.js';
import { newScoreCache, scoreCase, type LimboScoreCase } from './lib/limbo-score.js';
import { CORPORA, checkCorpus, corpusDir, sha256Hex, type Corpus } from './lib/corpora.js';
import { certificateBounds } from './lib/raw-der.js';
import { evaluateClauses } from './validators/rfc5280-clauses.js';
import {
    VALIDATORS,
    compareRecord,
    negativeCanaries,
    parseStream,
    readOutput,
    writeBlob,
    type Expected,
} from './lib/validators.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE = join(ROOT, 'scripts', 'data', 'limbo-refusals.json');
const SCORE_BASELINE = join(ROOT, 'scripts', 'data', 'limbo-score.json');
const REPORT_DIR = join(ROOT, 'test-output', 'conformance');
const OPENSSL_SAMPLE = 200;
/** How many certificates each cross-implementation validator is given (L4). */
const VALIDATOR_SAMPLE = 200;
/** Wycheproof flags that mark a defect of the DER encoding itself. */
const ENCODING_FLAGS: ReadonlySet<string> = new Set(['BerEncodedSignature', 'InvalidEncoding', 'InvalidTypesInSignature']);

const args = process.argv.slice(2);
const levelAt = args.indexOf('--level');
const level = levelAt >= 0 ? Number(args[levelAt + 1]) : 6;
const requireAll = args.includes('--require-all');
const updateBaseline = args.includes('--update-baseline');

// ── Inputs ───────────────────────────────────────────────────────────

interface LimboCase {
    readonly id: string;
    readonly expected_result: 'SUCCESS' | 'FAILURE';
    readonly trusted_certs: readonly string[];
    readonly untrusted_intermediates: readonly string[];
    readonly peer_certificate: string;
}

interface WycheproofTest {
    readonly tcId: number;
    readonly flags: readonly string[];
    readonly sig: string;
    readonly result: 'valid' | 'invalid' | 'acceptable';
}

interface WycheproofFile {
    readonly numberOfTests: number;
    readonly testGroups: ReadonlyArray<{ readonly tests: readonly WycheproofTest[] }>;
}

interface Declared {
    readonly 'x509-limbo'?: { readonly commit?: string; readonly testcases?: number; readonly certificates?: number; readonly refused?: number; readonly agree?: number };
    readonly wycheproof?: { readonly commit?: string; readonly tests?: number };
}

interface Baseline {
    readonly $comment: string;
    readonly corpus: string;
    readonly commit: string;
    readonly refusals: Readonly<Record<string, string>>;
}

const corpus = (id: Corpus['id']): Corpus => CORPORA.find((c) => c.id === id) as Corpus;
const readCorpusJson = <T>(id: Corpus['id'], name: string): T => JSON.parse(readFileSync(join(corpusDir(ROOT, corpus(id)), name), 'utf8')) as T;

// ── Report ───────────────────────────────────────────────────────────

const failures: string[] = [];
const skips: string[] = [];
/**
 * Three states, not two. A tool that is absent is a SKIP, which
 * `--require-all` turns into a failure: on the reference platform every tool
 * must be there. A tool that is present but whose *acceptance policy* is not
 * ours — LibreSSL on the macOS runner refusing a certificate OpenSSL reads —
 * is neither. Recording that as a failure would make the gate red for
 * something that is not a defect here, and a gate that is red for the wrong
 * reason is a gate people learn to ignore.
 */
const notApplicable: string[] = [];
const lines: string[] = [];
const fail = (message: string): void => { failures.push(message); };
const record = (label: string, detail: string): void => { lines.push(`${label.padEnd(6)} ${detail}`); };

function openSslVersion(): string | null {
    const run = spawnSync('openssl', ['version'], { encoding: 'utf8', windowsHide: true });
    return run.status === 0 ? run.stdout.trim() : null;
}

/**
 * The certificate goes through a file, never stdin: Windows builds of the
 * openssl CLI read stdin in text mode and would rewrite DER octets.
 */
function openSslFacts(der: Uint8Array, scratch: string): { serial: string; fingerprint: string } | null {
    writeFileSync(scratch, der);
    const run = spawnSync('openssl', ['x509', '-inform', 'DER', '-in', scratch, '-noout', '-serial', '-fingerprint', '-sha256'], { encoding: 'utf8', windowsHide: true });
    if (run.status !== 0) return null;
    const serial = /serial=([0-9A-F-]+)/i.exec(run.stdout)?.[1];
    const fingerprint = /Fingerprint=([0-9A-F:]+)/i.exec(run.stdout)?.[1];
    return serial === undefined || fingerprint === undefined ? null : { serial, fingerprint };
}

function signedHex(text: string): bigint {
    return text.startsWith('-') ? -BigInt(`0x${text.slice(1)}`) : BigInt(`0x${text}`);
}

function colonHex(hex: string): string {
    return (hex.toUpperCase().match(/../g) ?? []).join(':');
}

// ── Levels ───────────────────────────────────────────────────────────

async function main(): Promise<number> {
    const dist = join(ROOT, 'dist', 'index.js');
    if (!existsSync(dist)) {
        console.error('validate-certs: dist/index.js is missing — run npm run build first (the gate checks the built package)');
        return 2;
    }
    const pki = await import(pathToFileURL(dist).href) as typeof Pki;

    // L0 — pins and canaries.
    for (const c of CORPORA) {
        const state = checkCorpus(ROOT, c);
        if (state.missing.length > 0 || state.mismatched.length > 0) {
            console.error(`validate-certs: ${c.id} is not fetched or does not match its pin (${[...state.missing, ...state.mismatched].join(', ')}) — run npx tsx scripts/fetch-corpora.ts`);
            return 2;
        }
    }
    const ecosystem = JSON.parse(readFileSync(join(ROOT, 'docs', 'assets', 'ecosystem.json'), 'utf8')) as { declared?: Declared };
    const declared = ecosystem.declared ?? {};
    const limbo = readCorpusJson<{ version: number; testcases: readonly LimboCase[] }>('x509-limbo', 'limbo.json');
    if (limbo.version !== 1) fail(`L0 limbo.json declares schema version ${limbo.version}; this gate reads version 1`);
    if (limbo.testcases.length !== declared['x509-limbo']?.testcases) {
        fail(`L0 limbo holds ${limbo.testcases.length} test cases; ecosystem.json declares ${String(declared['x509-limbo']?.testcases)} (canary)`);
    }

    const uses = new Map<string, Array<{ readonly id: string; readonly expected: string }>>();
    const certificates = new Map<string, Uint8Array>();
    for (const tc of limbo.testcases) {
        for (const pem of [...tc.trusted_certs, ...tc.untrusted_intermediates, tc.peer_certificate]) {
            for (const block of pki.decodePem(pem, { label: 'CERTIFICATE' })) {
                const hash = sha256Hex(block.bytes);
                certificates.set(hash, block.bytes);
                const list = uses.get(hash) ?? [];
                list.push({ id: tc.id, expected: tc.expected_result });
                uses.set(hash, list);
            }
        }
    }
    if (certificates.size !== declared['x509-limbo']?.certificates) {
        fail(`L0 limbo holds ${certificates.size} unique certificates; ecosystem.json declares ${String(declared['x509-limbo']?.certificates)} (canary)`);
    }
    record('L0', `x509-limbo@${corpus('x509-limbo').commit.slice(0, 12)}: ${limbo.testcases.length} cases, ${certificates.size} unique certificates`);
    if (level < 1) return report();

    // L1 — parse or refuse by the rules.
    const baseline = existsSync(BASELINE) ? JSON.parse(readFileSync(BASELINE, 'utf8')) as Baseline : null;
    const known = new Map(Object.entries(baseline?.refusals ?? {}));
    const refused = new Map<string, string>();
    const parsed = new Map<string, Pki.Certificate>();
    for (const [hash, der] of certificates) {
        try {
            parsed.set(hash, pki.parseCertificate(der, { onDiagnostic: () => undefined }));
        } catch (error) {
            if (!(error instanceof pki.PkiError)) {
                fail(`L1 ${hash}: threw ${String(error)} — only a PkiError may leave the parser`);
                continue;
            }
            refused.set(hash, error.code);
            const needed = (uses.get(hash) ?? []).filter((u) => u.expected !== 'FAILURE');
            if (needed.length > 0) fail(`L1 ${hash}: refused with ${error.code}, but ${needed[0]?.id ?? ''} expects SUCCESS with it`);
        }
    }
    if (updateBaseline) {
        const refusals = Object.fromEntries([...refused].sort(([a], [b]) => (a < b ? -1 : 1)));
        const next: Baseline = {
            $comment: 'Reviewed refusals of x509-limbo certificates: SHA-256 of the DER → the PkiError code pkinative raises. Every entry is used only by test cases that expect FAILURE (checked by scripts/validate-certs.ts). Regenerate with `npx tsx scripts/validate-certs.ts --update-baseline` after a reviewed parser change or a corpus re-pin; never hand-edit.',
            corpus: 'x509-limbo',
            commit: corpus('x509-limbo').commit,
            refusals,
        };
        mkdirSync(dirname(BASELINE), { recursive: true });
        writeFileSync(BASELINE, `${JSON.stringify(next, null, 2)}\n`);
        record('L1', `baseline rewritten: ${refused.size} refusals`);
    } else {
        if (baseline === null) fail(`L1 ${BASELINE} is missing — run with --update-baseline once and review it`);
        else if (baseline.commit !== corpus('x509-limbo').commit) fail(`L1 the baseline was made at x509-limbo ${baseline.commit}, the pin is ${corpus('x509-limbo').commit} — regenerate and review it`);
        for (const [hash, code] of refused) {
            const expected = known.get(hash);
            if (expected === undefined) fail(`L1 NEW-REFUSAL ${hash}: ${code} is not in the baseline`);
            else if (expected !== code) fail(`L1 ${hash}: refused with ${code}, the baseline says ${expected}`);
        }
        for (const hash of known.keys()) {
            if (parsed.has(hash)) fail(`L1 UNEXPECTED-PASS ${hash}: the baseline expects a refusal, the certificate now parses`);
            else if (!certificates.has(hash)) fail(`L1 stale baseline entry ${hash}: no such certificate in the corpus`);
        }
    }
    if (refused.size !== declared['x509-limbo']?.refused) {
        fail(`L1 ${refused.size} certificates refused; ecosystem.json declares ${String(declared['x509-limbo']?.refused)} (canary)`);
    }
    record('L1', `${parsed.size} parsed, ${refused.size} refused (all in FAILURE cases, all in the baseline)`);
    if (level < 2) return report();

    // L2 — re-encoding and independent boundaries.
    let reencoded = 0;
    for (const [hash, der] of certificates) {
        const again = pki.encodeAsn1Node(pki.decodeAsn1(der));
        if (Buffer.compare(Buffer.from(again), Buffer.from(der)) !== 0) fail(`L2 ${hash}: the decoded tree does not re-encode to the same bytes`);
        else reencoded++;
        const cert = parsed.get(hash);
        if (cert === undefined) continue;
        const bounds = certificateBounds(der);
        const tbsAt = cert.tbsDer.byteOffset - cert.der.byteOffset;
        const signatureAt = cert.signatureValue.bytes.byteOffset - cert.der.byteOffset;
        if (tbsAt !== bounds.tbs.offset || cert.tbsDer.length !== bounds.tbs.end - bounds.tbs.offset) fail(`L2 ${hash}: tbsCertificate boundaries differ from the raw walker`);
        if (signatureAt !== bounds.signatureValue.offset + bounds.signatureValue.headerLength + 1) fail(`L2 ${hash}: signatureValue boundaries differ from the raw walker`);
    }
    record('L2', `${reencoded} re-encoded byte for byte, ${parsed.size} boundary checks against the raw walker`);
    if (level < 3) return report();

    // L3 — node:crypto on every parsed certificate, openssl on a sample.
    let agreed = 0;
    for (const [hash, cert] of parsed) {
        const theirs = new X509Certificate(cert.der);
        const bc = pki.getExtension(cert, 'basicConstraints');
        const ku = pki.getExtension(cert, 'keyUsage');
        const ca = bc?.cA === true && (ku === undefined || ku.usages.includes('keyCertSign'));
        const problems = [
            cert.serialNumber.value !== signedHex(theirs.serialNumber) ? 'serial' : '',
            cert.validity.notBefore.epochMilliseconds !== Date.parse(theirs.validFrom) ? 'notBefore' : '',
            cert.validity.notAfter.epochMilliseconds !== Date.parse(theirs.validTo) ? 'notAfter' : '',
            ca !== theirs.ca ? 'CA flag' : '',
            colonHex(sha256Hex(cert.der)) !== theirs.fingerprint256 ? 'fingerprint' : '',
        ].filter((p) => p !== '');
        if (problems.length > 0) fail(`L3 ${hash}: node:crypto disagrees on ${problems.join(', ')}`);
        else agreed++;
    }
    record('L3', `node:crypto (OpenSSL ${process.versions.openssl}) agrees on ${agreed}/${parsed.size} certificates`);
    const openssl = openSslVersion();
    if (openssl === null) {
        skips.push('L3 openssl CLI not found');
    } else {
        // What is cross-checked is the VALUES the CLI reads, never its
        // acceptance policy: a disagreement on a serial or a fingerprint is
        // always a defect somewhere and always fails. A refusal to read is a
        // defect only for the reference implementation; another one refusing
        // is a difference between implementations, which is data.
        const reference = !/LibreSSL|BoringSSL/i.test(openssl);
        const step = Math.max(1, Math.floor(parsed.size / OPENSSL_SAMPLE));
        const scratch = join(REPORT_DIR, 'openssl-input.der');
        mkdirSync(REPORT_DIR, { recursive: true });
        let sampled = 0;
        let refused = 0;
        let index = 0;
        for (const [hash, cert] of parsed) {
            if (index++ % step !== 0) continue;
            sampled++;
            const facts = openSslFacts(cert.der, scratch);
            if (facts === null) {
                refused++;
                if (reference) fail(`L3 ${hash}: the openssl CLI cannot read a certificate pkinative parses`);
            } else if (signedHex(facts.serial) !== cert.serialNumber.value || facts.fingerprint !== colonHex(sha256Hex(cert.der))) {
                fail(`L3 ${hash}: ${openssl} disagrees on the serial or the fingerprint`);
            }
        }
        // Anti-vacuity: an implementation that reads almost nothing proves
        // nothing, and must not pass as a cross-check.
        if (sampled - refused < sampled / 2) {
            fail(`L3 ${openssl} read only ${sampled - refused} of ${sampled} sampled certificates — too few to be a cross-check`);
        }
        record('L3', `${openssl}: ${sampled - refused} of ${sampled} sampled certificates agree`);
        if (refused > 0 && !reference) {
            notApplicable.push(`L3 ${openssl} refused ${refused} of ${sampled} sampled certificates; its acceptance policy is not pkinative's contract, and every certificate it did read agrees`);
        }
    }

    if (level >= 4) runCrossValidators(pki, certificates, parsed);

    if (level >= 5) runClauseChecker(certificates, parsed);

    if (level >= 6) await runPathScorer(pki, limbo.testcases as unknown as readonly LimboScoreCase[], declared);

    // Wycheproof — strict Ecdsa-Sig-Value decoding.
    let vectors = 0;
    for (const file of corpus('wycheproof').files) {
        const data = readCorpusJson<WycheproofFile>('wycheproof', file.name);
        let counted = 0;
        for (const group of data.testGroups) {
            for (const test of group.tests) {
                counted++;
                let decoded = false;
                try {
                    const node = pki.decodeAsn1(Uint8Array.from(Buffer.from(test.sig, 'hex')));
                    const shape = node.tagClass === 'universal' && node.tagNumber === 16 && node.children.length === 2
                        && node.children.every((c) => c.tagClass === 'universal' && c.tagNumber === 2);
                    if (shape) {
                        for (const child of node.children) pki.readInteger(child);
                        decoded = true;
                    }
                } catch (error) {
                    if (!(error instanceof pki.PkiError)) fail(`Wycheproof ${file.name} #${test.tcId}: threw ${String(error)}`);
                }
                if (test.result !== 'invalid' && !decoded) fail(`Wycheproof ${file.name} #${test.tcId}: a ${test.result} signature was refused`);
                if (test.result === 'invalid' && test.flags.some((f) => ENCODING_FLAGS.has(f)) && decoded) {
                    fail(`Wycheproof ${file.name} #${test.tcId}: an encoding defect (${test.flags.join(', ')}) was accepted`);
                }
            }
        }
        if (counted !== data.numberOfTests) fail(`Wycheproof ${file.name}: ${counted} vectors read, the file declares ${data.numberOfTests}`);
        vectors += counted;
    }
    if (vectors !== declared.wycheproof?.tests) fail(`Wycheproof: ${vectors} vectors; ecosystem.json declares ${String(declared.wycheproof?.tests)} (canary)`);
    record('WP', `wycheproof@${corpus('wycheproof').commit.slice(0, 12)}: ${vectors} ECDSA vectors on P-256, P-384 and P-521`);
    return report();
}

// ── L5 — RFC 5280, clause by clause ─────────────────────────────────

/**
 * L1–L4 prove **agreement**. L5 proves **attribution**: which sentence of
 * RFC 5280 a certificate violates, and whether pkinative says so.
 *
 * The checker in `scripts/validators/rfc5280-clauses.ts` decides each clause
 * from the raw bytes, without importing `src/`. This function compares its
 * verdicts with pkinative's diagnostics and fails on three things:
 *
 *   - a clause that **no certificate in the corpus exercises** — a clause
 *     nothing triggers proves nothing, and a table full of them yields a
 *     number rather than evidence;
 *   - a clause that fails while pkinative emits no matching diagnostic —
 *     a violation the product is silent about;
 *   - for a clause marked `exhaustive`, a diagnostic with no clause failure
 *     behind it — the two readings disagree, and one of them is wrong.
 */
function runClauseChecker(certificates: ReadonlyMap<string, Uint8Array>, parsed: ReadonlyMap<string, Pki.Certificate>): void {
    const applicable = new Map<string, number>();
    const failed = new Map<string, number>();
    const silent = new Map<string, string>();
    const phantom = new Map<string, string>();
    for (const clause of CLAUSES) { applicable.set(clause.id, 0); failed.set(clause.id, 0); }

    for (const [hash, cert] of parsed) {
        const der = certificates.get(hash);
        if (der === undefined) continue;
        const verdicts = evaluateClauses(der);
        for (const clause of CLAUSES) {
            const verdict = verdicts.get(clause.id);
            if (verdict === undefined || verdict === 'not-applicable') continue;
            applicable.set(clause.id, (applicable.get(clause.id) ?? 0) + 1);
            if (clause.diagnostic === null) continue;

            const emitted = cert.diagnostics.some((d) => d.code === clause.diagnostic
                && (clause.paths === undefined || clause.paths.some((p) => d.path.includes(p))));
            if (verdict === 'fail') {
                failed.set(clause.id, (failed.get(clause.id) ?? 0) + 1);
                if (!emitted && !silent.has(clause.id)) silent.set(clause.id, hash);
            } else if (emitted && clause.exhaustive && !phantom.has(clause.id)) {
                phantom.set(clause.id, hash);
            }
        }
    }

    for (const clause of CLAUSES) {
        const seen = applicable.get(clause.id) ?? 0;
        if (seen === 0) {
            if (clause.unexercisedBy === undefined) {
                fail(`L5 ${clause.id}: no certificate in the corpus exercises it — a clause nothing triggers proves nothing about the parser. Either the corpus changed, or the clause needs a reviewed unexercisedBy naming the suite that does exercise it`);
            }
            continue;
        }
        // The converse, and it matters as much: a waiver that stops being
        // true is a waiver that hides a clause nobody checks any more.
        if (clause.unexercisedBy !== undefined) {
            fail(`L5 ${clause.id}: declares unexercisedBy ${clause.unexercisedBy.corpus}, yet ${String(seen)} certificate(s) exercise it — remove the waiver, the corpus now covers this clause`);
        }
        const hash = silent.get(clause.id);
        if (hash !== undefined) {
            fail(`L5 ${clause.id}: ${hash} violates ${clause.section} and pkinative emits no ${String(clause.diagnostic)} — "${clause.quote}"`);
        }
        const ghost = phantom.get(clause.id);
        if (ghost !== undefined) {
            fail(`L5 ${clause.id}: ${ghost} satisfies ${clause.section} by the independent reading, yet pkinative emits ${String(clause.diagnostic)} — the two readings disagree and one is wrong`);
        }
    }

    const violated = [...failed].filter(([, n]) => n > 0).length;
    const total = [...failed.values()].reduce((a, b) => a + b, 0);
    const waived = CLAUSES.filter((c) => c.unexercisedBy !== undefined).length;
    const corpusExercised = CLAUSES.length - waived;
    record('L5', `${CLAUSES.length} RFC 5280 clauses: ${corpusExercised} exercised by the corpus (${waived} waived to tests/conformance/clauses.test.ts), ${violated} violated by ${total} certificate readings, every violation attributed to its diagnostic`);
}

// ── L6 — path validation, scored against the corpus ─────────────────

/** The reviewed score baseline, `scripts/data/limbo-score.json`. */
interface ScoreBaseline {
    readonly $comment: string;
    readonly corpus: string;
    readonly commit: string;
    /** One case that must succeed and one that must fail — the anti-vacuity pair. */
    readonly canaries: { readonly mustSucceed: string; readonly mustFail: string };
    readonly totals: { readonly scored: number; readonly agree: number; readonly deviations: number; readonly unparsed: number; readonly skipped: number };
    /** Every accepted disagreement, each with the sentence that makes it one. */
    readonly deviations: Readonly<Record<string, { readonly expected: string; readonly why: string }>>;
    /** Cases pinned on their reason codes, not only on the boolean. */
    readonly reasons: Readonly<Record<string, string>>;
}

/**
 * L1–L5 judge certificates. **L6 judges chains**, which is the other half of
 * what this library is for and the only half a boolean can be wrong about
 * silently.
 *
 * It fails on five things, and the last two are the ones that make the number
 * evidence rather than a statistic:
 *
 *   - a **new disagreement** — a case whose verdict differs and which no
 *     reviewed deviation covers;
 *   - an **unexpected agreement** — a deviation that now agrees, so the reason
 *     written beside it has stopped being true and must be deleted;
 *   - a **changed reason code** on a pinned case: rejected for the wrong reason
 *     is a defect a pass/fail count cannot see;
 *   - a **canary** that stops behaving: a harness whose trust store silently
 *     stopped being passed through scores 99 % on a FAILURE-heavy corpus, and
 *     the positive canary is the only thing that notices;
 *   - a **deviation with no `why`**: a disagreement is either a defect or a
 *     decision, and the difference is a sentence someone wrote.
 */
async function runPathScorer(pki: typeof Pki, cases: readonly LimboScoreCase[], declared: Declared): Promise<void> {
    const baseline = existsSync(SCORE_BASELINE) ? JSON.parse(readFileSync(SCORE_BASELINE, 'utf8')) as ScoreBaseline : null;
    if (baseline !== null && baseline.commit !== corpus('x509-limbo').commit) {
        fail(`L6 the score baseline was made at x509-limbo ${baseline.commit}, the pin is ${corpus('x509-limbo').commit} — rescore and review it`);
    }

    const cache = newScoreCache();
    const started = Date.now();
    const disagreed = new Map<string, { expected: string; reasons: readonly string[] }>();
    const measured = new Map<string, string>();
    const skipped = new Map<string, string>();
    let agree = 0;
    let unparsed = 0;
    let scored = 0;
    for (const test of cases) {
        // `online::` cases fetch from the network, which this gate never does.
        if (test.id.startsWith('online::')) { skipped.set(test.id, 'the case requires network access'); continue; }
        const verdict = await scoreCase(pki, test, cache);
        if (verdict.kind === 'skipped') { skipped.set(test.id, verdict.why); continue; }
        if (verdict.kind === 'unparsed') { unparsed += 1; continue; }
        scored += 1;
        measured.set(test.id, verdict.reasons.join(','));
        if (verdict.valid === (test.expected_result === 'SUCCESS')) agree += 1;
        else disagreed.set(test.id, { expected: test.expected_result, reasons: verdict.reasons });
    }
    const seconds = Math.round((Date.now() - started) / 1000);

    if (updateBaseline) {
        // The ids and the measured reason codes are written; the `why` of each
        // deviation is carried over from the existing baseline and left EMPTY for
        // a new one, so a human has to fill it in and the gate stays red until
        // they do. A baseline a tool can complete unattended absorbs regressions.
        const deviations: Record<string, { expected: string; why: string }> = {};
        for (const [id, { expected }] of [...disagreed].sort(([a], [b]) => (a < b ? -1 : 1))) {
            deviations[id] = { expected, why: baseline?.deviations[id]?.why ?? '' };
        }
        // Which cases are pinned on their reason codes is a sampling decision the
        // tool may take; what the codes ARE is a measurement it must never
        // invent. So the first run seeds a deterministic spread — up to six
        // rejected cases per namespace, by id — and every later run only
        // re-measures the ids already pinned, so a reviewed pin never moves
        // because the sampler's idea of "representative" changed.
        const reasons: Record<string, string> = {};
        const pinned = Object.keys(baseline?.reasons ?? {});
        if (pinned.length === 0) {
            const perNamespace = new Map<string, number>();
            for (const [id, codes] of [...measured].sort(([a], [b]) => (a < b ? -1 : 1))) {
                if (codes === '' || disagreed.has(id)) continue;
                const namespace = id.slice(0, id.indexOf('::'));
                const taken = perNamespace.get(namespace) ?? 0;
                if (taken >= 6) continue;
                perNamespace.set(namespace, taken + 1);
                reasons[id] = codes;
            }
        } else {
            for (const id of pinned.sort()) reasons[id] = measured.get(id) ?? '(not scored)';
        }
        const next: ScoreBaseline = {
            $comment: 'Reviewed path-validation score of x509-limbo: every accepted disagreement with the sentence that makes it acceptable, and the cases pinned on their PkiReasonCode rather than on the boolean. Rescore with `npx tsx scripts/validate-certs.ts --update-baseline`, then WRITE the `why` of every new deviation by hand — the tool never fills one in, and an empty one fails the gate. Never hand-edit the ids.',
            corpus: 'x509-limbo',
            commit: corpus('x509-limbo').commit,
            canaries: baseline?.canaries ?? { mustSucceed: '', mustFail: '' },
            totals: { scored, agree, deviations: disagreed.size, unparsed, skipped: skipped.size },
            deviations,
            reasons,
        };
        mkdirSync(dirname(SCORE_BASELINE), { recursive: true });
        writeFileSync(SCORE_BASELINE, `${JSON.stringify(next, null, 2)}\n`);
        record('L6', `score baseline rewritten: ${agree} agree, ${String(disagreed.size)} deviations`);
        return;
    }

    if (baseline === null) {
        fail(`L6 ${SCORE_BASELINE} is missing — run with --update-baseline once, then write the reason for each deviation`);
        return;
    }

    // Anti-vacuity. A scorer that rejects everything is worthless against a
    // corpus that is mostly FAILURE, and this pair is what says so out loud.
    for (const [which, id] of [['mustSucceed', baseline.canaries.mustSucceed], ['mustFail', baseline.canaries.mustFail]] as const) {
        const reasons = measured.get(id);
        if (reasons === undefined) { fail(`L6 canary ${which} ${id} was not scored — the harness is not exercising the corpus`); continue; }
        const wants = which === 'mustSucceed';
        if ((reasons === '') !== wants) {
            fail(`L6 canary ${which} ${id} ${wants ? `must validate cleanly and reported ${reasons}` : 'must be refused and validated cleanly'} — the scorer is not deciding anything`);
        }
    }

    for (const [id, { expected, reasons }] of disagreed) {
        const reviewed = baseline.deviations[id];
        if (reviewed === undefined) {
            fail(`L6 NEW-DISAGREEMENT ${id}: the corpus expects ${expected} and pkinative says otherwise [${reasons.join(',') || 'accepted'}] — fix it, or add it to the baseline with the sentence that makes it acceptable`);
        } else if (reviewed.why.trim() === '') {
            fail(`L6 ${id}: the deviation has no reason written — a disagreement is either a defect or a decision, and only a sentence tells them apart`);
        }
    }
    for (const id of Object.keys(baseline.deviations)) {
        if (disagreed.has(id)) continue;
        if (!measured.has(id)) fail(`L6 stale deviation ${id}: no such case is scored in the corpus`);
        else fail(`L6 UNEXPECTED-AGREEMENT ${id}: the baseline expects a deviation and pkinative now agrees with the corpus — delete the entry, its reason has stopped being true`);
    }
    for (const [id, expected] of Object.entries(baseline.reasons)) {
        const actual = measured.get(id);
        if (actual === undefined) fail(`L6 pinned case ${id} was not scored — the pin is stale`);
        else if (actual !== expected) fail(`L6 ${id}: reasons are [${actual || 'none'}], the baseline pins [${expected || 'none'}] — rejected for a different reason is a change in behaviour, whatever the boolean says`);
    }

    if (scored !== baseline.totals.scored || unparsed !== baseline.totals.unparsed) {
        fail(`L6 ${String(scored)} cases scored and ${String(unparsed)} unparsed; the baseline says ${String(baseline.totals.scored)} and ${String(baseline.totals.unparsed)} (canary)`);
    }
    if (agree !== declared['x509-limbo']?.agree) {
        fail(`L6 ${String(agree)} cases agree; ecosystem.json declares ${String(declared['x509-limbo']?.agree)} (canary)`);
    }

    const rate = scored === 0 ? 0 : (agree / scored) * 100;
    record('L6', `${String(agree)}/${String(scored)} chains agree (${rate.toFixed(2)} %), ${String(disagreed.size)} reviewed deviations, ${String(Object.keys(baseline.reasons).length)} pinned on their reason codes, ${String(skipped.size)} skipped, ${String(unparsed)} refused at L1 — ${String(cache.verifications)} signature verifications in ${String(seconds)} s`);
}

// ── L4 — confrontation with other implementations ───────────────────

/** What pkinative says, in the vocabulary of `FIELDS`. */
function expectationOf(cert: Pki.Certificate): Expected {
    return {
        subjectFp256: sha256Hex(cert.subject.der),
        issuerFp256: sha256Hex(cert.issuer.der),
        spkiKeyFp256: sha256Hex(cert.subjectPublicKeyInfo.publicKey.bytes),
        tbsFp256: sha256Hex(cert.tbsDer),
        keyAlgOid: cert.subjectPublicKeyInfo.algorithm.oid,
        version: cert.version,
    };
}

interface Disagreements {
    readonly reviewed?: Readonly<Record<string, string>>;
}

/**
 * Confront a sample of the corpus with every implementation this platform
 * can reach. See scripts/lib/validators.ts for why the comparison is over
 * SHA-256 of DER slices and not over anything an implementation renders.
 */
function runCrossValidators(pki: typeof Pki, certificates: ReadonlyMap<string, Uint8Array>, parsed: ReadonlyMap<string, Pki.Certificate>): void {
    const reviewedFile = join(ROOT, 'scripts', 'data', 'validator-disagreements.json');
    const reviewed = existsSync(reviewedFile)
        ? (JSON.parse(readFileSync(reviewedFile, 'utf8')) as Disagreements).reviewed ?? {}
        : {};
    for (const [key, reason] of Object.entries(reviewed)) {
        if (/^TODO\b/.test(reason)) fail(`L4 the reviewed disagreement ${key} still says "${reason}" — every entry carries the reason it is accepted`);
    }

    // A sample, in corpus order, plus a known-good certificate as #0 and the
    // structurally broken canaries last.
    const step = Math.max(1, Math.floor(parsed.size / VALIDATOR_SAMPLE));
    const sample: Array<{ hash: string; der: Uint8Array; cert: Pki.Certificate }> = [];
    let index = 0;
    for (const [hash, cert] of parsed) {
        if (index++ % step !== 0) continue;
        const der = certificates.get(hash);
        if (der !== undefined) sample.push({ hash, der, cert });
    }
    const positivePath = join(ROOT, 'tests', 'fixtures', 'certs', 'isrg-root-x1.der');
    const positive = new Uint8Array(readFileSync(positivePath));
    const canaries = negativeCanaries(positive);
    const submitted = [positive, ...sample.map((s) => s.der), ...canaries.map((c) => c.bytes)];

    mkdirSync(REPORT_DIR, { recursive: true });
    const blobPath = join(REPORT_DIR, 'validator-input.blob');
    writeBlob(blobPath, submitted);
    const positiveExpected = expectationOf(pki.parseCertificate(positive, { onDiagnostic: () => undefined }));

    for (const spec of VALIDATORS) {
        if (!spec.platforms.includes(process.platform)) {
            notApplicable.push(`L4 ${spec.id} (${spec.lineage}) does not run on ${process.platform}`);
            continue;
        }
        const version = spec.probe();
        if (version === null) { skips.push(`L4 ${spec.id}: ${spec.lineage} is not installed on this ${process.platform} runner`); continue; }

        const outPath = join(REPORT_DIR, `validator-${spec.id}.ndjson`);
        const outcome = spec.emit(blobPath, outPath);
        const stream = parseStream(readOutput(outPath), submitted.length);
        if ('errors' in stream) {
            if (!outcome.ok) fail(`L4 ${spec.id}: the validator exited non-zero — ${outcome.stderr.slice(0, 200)}`);
            for (const message of stream.errors.slice(0, 5)) fail(`L4 ${spec.id}: ${message}`);
            continue;
        }

        // Anti-vacuity, before a single comparison is believed. Neither
        // verdict can be put on the reviewed list: a validator that rejects
        // everything or accepts everything is not disagreeing, it is broken,
        // and its agreement elsewhere would mean nothing.
        const first = stream.certs[0];
        if (first === undefined || !first.ok) {
            fail(`L4 ${spec.id}: VACUOUS — it rejects the positive canary, a certificate every implementation reads (${String(first?.error ?? 'no record')})`);
            continue;
        }
        const canaryDisagreement = compareRecord(positiveExpected, first, stream.header.fields);
        if (canaryDisagreement.length > 0) {
            fail(`L4 ${spec.id}: VACUOUS — it disagrees on the positive canary itself: ${canaryDisagreement.join('; ')}`);
            continue;
        }
        let xpass = 0;
        for (const [offset, canary] of canaries.entries()) {
            const record = stream.certs[1 + sample.length + offset];
            if (record?.ok === true) {
                xpass++;
                fail(`L4 ${spec.id}: XPASS — it accepts ${canary.why} as a certificate, so its agreement proves nothing`);
            }
        }
        if (xpass > 0) continue;

        let agreed = 0;
        let refusedBySample = 0;
        const unreviewed: string[] = [];
        for (const [offset, entry] of sample.entries()) {
            const record = stream.certs[1 + offset];
            if (record === undefined) continue;
            if (!record.ok) { refusedBySample++; continue; }
            const differences = compareRecord(expectationOf(entry.cert), record, stream.header.fields);
            if (differences.length === 0) { agreed++; continue; }
            for (const difference of differences) {
                const field = difference.split(':')[0] ?? '';
                const key = `${spec.id}:${entry.hash}:${field}@${process.platform}`;
                if (reviewed[key] === undefined) unreviewed.push(`L4 ${spec.id} ${entry.hash} ${difference} — record it in scripts/data/validator-disagreements.json under "${key}" with the reason, or fix the defect`);
            }
        }
        for (const message of unreviewed.slice(0, 20)) fail(message);
        if (unreviewed.length > 20) fail(`L4 ${spec.id}: … ${unreviewed.length - 20} more disagreements`);

        // A validator that read almost nothing agrees about almost nothing.
        if (agreed < sample.length / 2) {
            fail(`L4 ${spec.id}: it read only ${agreed} of ${sample.length} sampled certificates — too few to be a cross-check`);
        }
        record('L4', `${spec.id} (${spec.lineage}, ${version}): ${agreed}/${sample.length} agree on ${stream.header.fields.join(', ')}`);
        if (refusedBySample > 0) {
            notApplicable.push(`L4 ${spec.id} declined ${refusedBySample} of ${sample.length} sampled certificates; its acceptance policy is not pkinative's contract, and every one it read agrees`);
        }
    }
}

function report(): number {
    const failed = failures.length > 0 || (requireAll && skips.length > 0);
    const body = [
        ...lines,
        // n/a lines are printed, never counted as failures: they say what this
        // platform could not be asked, so a green run is not mistaken for a
        // run that asked everything.
        ...notApplicable.map((n) => `N/A    ${n}`),
        ...skips.map((s) => `SKIP   ${s}`),
        ...failures.slice(0, 50).map((f) => `FAIL   ${f}`),
        ...(failures.length > 50 ? [`FAIL   … ${failures.length - 50} more`] : []),
        `${failed ? 'FAILED' : 'PASSED'}: ${failures.length} failure(s), ${skips.length} skip(s), ${notApplicable.length} not applicable${requireAll ? ' (--require-all)' : ''}`,
    ];
    console.log(body.join('\n'));
    const summary = ['## pkinative conformance', '', '```', ...body, '```'];
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(join(REPORT_DIR, 'report.json'), `${JSON.stringify({ level, lines, notApplicable, skips, failures }, null, 2)}\n`);
    const stepSummary = process.env['GITHUB_STEP_SUMMARY'];
    if (stepSummary !== undefined && stepSummary !== '') appendFileSync(stepSummary, `${summary.join('\n')}\n`);
    return failed ? 1 : 0;
}

process.exitCode = await main();
