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
 *   L5  RFC 5280 clause by clause: an independent reading of every clause of
 *       scripts/lib/clauses.ts must agree with pkinative's diagnostics, and —
 *       against the pinned text of the RFC — every clause quote is found
 *       verbatim and every requirement sentence of §4.1 and §4.2 is accounted
 *       for in scripts/data/rfc5280-requirements.json. See
 *       scripts/lib/rfc-requirements.ts;
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
 *   L7  every NIST PKITS path is scored the same way against a second corpus,
 *       written independently for the US Federal PKI, with its own reviewed
 *       baseline scripts/data/pkits-score.json. See scripts/lib/pkits.ts;
 *   L8  every NIST PKITS S/MIME message is verified whole by
 *       verifySignedData — signature, signer and chain — and makes two claims:
 *       the CMS layer finds every message intact, and the verdict on each
 *       message is the L7 verdict on its signer's path, refused for a reason
 *       that path is refused for. Reviewed baseline:
 *       scripts/data/pkits-smime-score.json. See scripts/lib/pkits-smime.ts;
 *   Wycheproof  ECDSA signatures decode as a strict Ecdsa-Sig-Value
 *       (SEQUENCE of two INTEGERs): every valid vector parses, every vector
 *       flagged as an encoding defect is refused.
 *
 * Usage:
 *   npx tsx scripts/validate-certs.ts [--level 0-8] [--require-all] [--update-baseline]
 *
 * Exit: 0 pass, 1 failure, 2 corpora or build missing.
 *
 * @module scripts/validate-certs
 */

import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type * as Pki from '../src/index.js';
import { CLAUSES } from './lib/clauses.js';
import { checkInventoryAgainstRfc, checkInventoryShape, EXCLUSION_REASONS, type RequirementsInventory } from './lib/rfc-requirements.js';
import { newScoreCache, scoreCase, type LimboScoreCase } from './lib/limbo-score.js';
import { corpusWindowProblem, expectationOfName, PKITS_AT, readPkits } from './lib/pkits.js';
import { reasonLayer, reasonsBeyondPath, splitPkitsMessage, testsOfSigner, type PkitsSignedMessage } from './lib/pkits-smime.js';
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
const PKITS_BASELINE = join(ROOT, 'scripts', 'data', 'pkits-score.json');
const PKITS_SMIME_BASELINE = join(ROOT, 'scripts', 'data', 'pkits-smime-score.json');
const REQUIREMENTS = join(ROOT, 'scripts', 'data', 'rfc5280-requirements.json');
const REPORT_DIR = join(ROOT, 'test-output', 'conformance');
const OPENSSL_SAMPLE = 200;
/** How many certificates each cross-implementation validator is given (L4). */
const VALIDATOR_SAMPLE = 200;
/** Wycheproof flags that mark a defect of the DER encoding itself. */
const ENCODING_FLAGS: ReadonlySet<string> = new Set(['BerEncodedSignature', 'InvalidEncoding', 'InvalidTypesInSignature']);

const args = process.argv.slice(2);
const levelAt = args.indexOf('--level');
const level = levelAt >= 0 ? Number(args[levelAt + 1]) : 8;
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
    readonly rfc5280?: { readonly commit?: string; readonly requirements?: number; readonly clauses?: number; readonly excluded?: number };
    readonly pkits?: {
        readonly commit?: string;
        readonly certificates?: number;
        readonly tests?: number;
        readonly agree?: number;
        readonly messages?: number;
        readonly messagesIntact?: number;
        readonly messagesAgree?: number;
    };
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

    if (level >= 5) {
        runClauseChecker(certificates, parsed);
        runRequirementInventory(declared);
    }

    if (level >= 6) await runPathScorer(pki, limbo.testcases as unknown as readonly LimboScoreCase[], declared);

    if (level >= 7) {
        const paths = await runPkitsScorer(pki, declared);
        if (level >= 8) await runPkitsSmimeScorer(pki, declared, paths);
    }

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
    const ofRfc = CLAUSES.filter((c) => c.section.startsWith('RFC 5280 ')).length;
    record('L5', `${CLAUSES.length} clauses (${ofRfc} of RFC 5280, ${CLAUSES.length - ofRfc} of ITU-T X.690): ${corpusExercised} exercised by the corpus (${waived} waived to tests/conformance/clauses.test.ts), ${violated} violated by ${total} certificate readings, every violation attributed to its diagnostic`);
}

/**
 * The other half of L5: **completeness against the RFC itself.**
 *
 * `runClauseChecker` proves each clause is exercised and attributed; nothing
 * there can say the table is missing a sentence, or that a clause quotes one
 * the RFC does not contain. This reads the pinned text of RFC 5280, extracts
 * every requirement sentence of §4.1 and §4.2 (scripts/lib/rfc-requirements.ts)
 * and fails on:
 *
 *   - a clause citing RFC 5280 whose quote is not found verbatim, after
 *     whitespace normalisation, in the section it cites — an invented quote;
 *   - an extracted sentence the reviewed inventory
 *     `scripts/data/rfc5280-requirements.json` does not account for, and an
 *     inventory entry no extracted sentence matches any more (stale);
 *   - an entry of the wrong shape: a reason outside the vocabulary, an
 *     exclusion with no sentence, a `clause` entry whose clause quotes
 *     another sentence;
 *   - counts that drift from `declared.rfc5280` in ecosystem.json;
 *   - a `todo` entry under `--require-all`, which is what the conformance
 *     workflow and the release gate run — without it, a `todo` is a SKIP.
 */
function runRequirementInventory(declared: Declared): void {
    const rfc = corpus('rfc5280');
    const text = readFileSync(join(corpusDir(ROOT, rfc), 'rfc5280.txt'), 'utf8');
    const inventory = JSON.parse(readFileSync(REQUIREMENTS, 'utf8')) as RequirementsInventory;
    if (inventory.sha256 !== rfc.commit) {
        fail(`L5 scripts/data/rfc5280-requirements.json was reviewed against ${inventory.sha256.slice(0, 12)}; the pinned RFC is ${rfc.commit.slice(0, 12)} — review the inventory against the new text`);
    }
    for (const problem of checkInventoryShape(inventory, CLAUSES)) fail(`L5 inventory ${problem}`);
    const check = checkInventoryAgainstRfc(text, inventory, CLAUSES);
    for (const problem of check.problems) fail(`L5 RFC 5280 ${problem}`);
    for (const id of check.todo) {
        const message = `L5 RFC 5280 ${id}: still todo in scripts/data/rfc5280-requirements.json — every requirement is a clause or an exclusion with its reason before a release`;
        if (requireAll) fail(message);
        else skips.push(message);
    }

    const entries = Object.values(inventory.requirements);
    const clauses = entries.filter((e) => e.status === 'clause').length;
    const excluded = entries.filter((e) => e.status === 'excluded');
    const d = declared.rfc5280;
    if (check.extracted.length !== d?.requirements) fail(`L5 RFC 5280 §4.1–§4.2 hold ${String(check.extracted.length)} requirement sentences; ecosystem.json declares ${String(d?.requirements)} (canary)`);
    if (clauses !== d?.clauses) fail(`L5 the inventory maps ${String(clauses)} sentences to clauses; ecosystem.json declares ${String(d?.clauses)}`);
    if (excluded.length !== d?.excluded) fail(`L5 the inventory excludes ${String(excluded.length)} sentences; ecosystem.json declares ${String(d?.excluded)}`);

    const byReason = Object.keys(EXCLUSION_REASONS)
        .map((reason) => [reason, excluded.filter((e) => e.status === 'excluded' && e.reason === reason).length] as const)
        .filter(([, n]) => n > 0)
        .map(([reason, n]) => `${String(n)} ${reason}`)
        .join(', ');
    const quoted = CLAUSES.filter((c) => c.section.startsWith('RFC 5280 ')).length;
    record('L5', `rfc5280@${rfc.commit.slice(0, 12)}: ${String(check.extracted.length)} requirement sentences of §4.1–§4.2, ${String(clauses)} held by a clause, ${String(excluded.length)} excluded (${byReason}), ${String(check.todo.length)} todo; ${String(quoted)} RFC 5280 quotes found verbatim`);
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

// ── L7 — NIST PKITS, the second corpus ──────────────────────────────

/** The reviewed PKITS baseline, `scripts/data/pkits-score.json`. */
interface PkitsBaseline {
    readonly $comment: string;
    readonly corpus: string;
    readonly commit: string;
    readonly canaries: { readonly mustSucceed: string; readonly mustFail: string };
    readonly totals: { readonly scored: number; readonly agree: number; readonly deviations: number; readonly skipped: number };
    readonly deviations: Readonly<Record<string, { readonly expected: string; readonly why: string }>>;
    readonly reasons: Readonly<Record<string, string>>;
}

/**
 * L6 proves agreement with **one** corpus. L7 proves agreement with a second,
 * written by different people from a different reading — NIST's federal PKI
 * against the Python cryptography project's Web PKI — which is the only thing
 * that catches a misreading the first corpus shares.
 *
 * It fails on the same five things L6 does, for the same reasons, and the
 * baselines are separate because their canaries and their deviations are about
 * different standards. What it adds is one assertion the other cannot make:
 * every PKITS certificate and every PKITS list must **parse**, with no reviewed
 * refusal list at all. x509-limbo is adversarial and its 565 refusals are the
 * point; PKITS is a conformance suite issued by a standards body, and a
 * certificate in it that pkinative cannot read is a defect here.
 *
 * It returns the verdict it measured on every scored test, because L8 holds
 * each signed message to the verdict on its own signer's path; an empty map
 * when the corpus could not be scored at all.
 */
async function runPkitsScorer(pki: typeof Pki, declared: Declared): Promise<PkitsPathVerdicts> {
    const paths = new Map<string, PkitsPathVerdict>();
    const dir = corpusDir(ROOT, corpus('pkits'));
    const baseline = existsSync(PKITS_BASELINE) ? JSON.parse(readFileSync(PKITS_BASELINE, 'utf8')) as PkitsBaseline : null;
    if (baseline !== null && baseline.commit !== corpus('pkits').commit) {
        fail(`L7 the score baseline was made at pkits ${baseline.commit}, the pin is ${corpus('pkits').commit} — rescore and review it`);
    }

    const pkits = readPkits(pki, dir);
    for (const [name, code] of pkits.refused) {
        fail(`L7 ${name}: refused with ${code} — PKITS is a conformance suite, and a certificate in it this library cannot read is a defect here, not a reviewed refusal`);
    }
    const aged = corpusWindowProblem(pkits.anchor);
    if (aged !== null) { fail(`L7 ${aged}`); return paths; }

    const total = pkits.candidates.length + pkits.tests.size + 1;
    if (total !== declared.pkits?.certificates) {
        fail(`L7 pkits holds ${String(total)} certificates; ecosystem.json declares ${String(declared.pkits?.certificates)} (canary)`);
    }
    if (pkits.tests.size !== declared.pkits?.tests) {
        fail(`L7 pkits holds ${String(pkits.tests.size)} end-entity certificates; ecosystem.json declares ${String(declared.pkits?.tests)} (canary)`);
    }

    const started = Date.now();
    const measured = new Map<string, string>();
    const disagreed = new Map<string, { expected: string; reasons: readonly string[] }>();
    const skipped: string[] = [];
    let agree = 0;
    let verified = 0;
    for (const [name, leaf] of [...pkits.tests].sort(([a], [b]) => (a < b ? -1 : 1))) {
        const expected = expectationOfName(name);
        if (expected === null) { skipped.push(name); continue; }
        // Revocation is required, because PKITS is a suite for a validator that
        // checks it: `InvalidMissingCRLTest1` expects a refusal precisely when
        // no list covers the CA, and a runner that soft-failed would score that
        // test by not asking the question it is about.
        const report = await pki.verifyCertificateChain({
            leaf,
            candidates: pkits.candidates,
            trustAnchors: [pkits.anchor],
            at: PKITS_AT,
            crls: pkits.crls,
            requireRevocation: true,
            limits: { maxPathsExplored: 200 },
        });
        verified += report.verified;
        measured.set(name, report.reasons.map((reason) => reason.code).join(','));
        paths.set(name, { valid: report.valid, codes: report.reasons.map((reason) => reason.code) });
        if (report.valid === expected) agree += 1;
        else disagreed.set(name, { expected: expected ? 'SUCCESS' : 'FAILURE', reasons: report.reasons.map((r) => r.code) });
    }
    const seconds = Math.round((Date.now() - started) / 1000);

    if (updateBaseline) {
        const deviations: Record<string, { expected: string; why: string }> = {};
        for (const [name, { expected }] of [...disagreed].sort(([a], [b]) => (a < b ? -1 : 1))) {
            deviations[name] = { expected, why: baseline?.deviations[name]?.why ?? '' };
        }
        const reasons: Record<string, string> = {};
        const pinned = Object.keys(baseline?.reasons ?? {});
        if (pinned.length === 0) {
            // The same sampling discipline as L6: which cases are pinned is a
            // decision the tool may take, what their codes ARE is a measurement
            // it must never invent. Six per PKITS section, by name.
            const perSection = new Map<string, number>();
            for (const [name, codes] of [...measured].sort(([a], [b]) => (a < b ? -1 : 1))) {
                if (codes === '' || disagreed.has(name)) continue;
                const section = /^Invalid([A-Za-z]{1,12})/.exec(name)?.[1] ?? 'other';
                const taken = perSection.get(section) ?? 0;
                if (taken >= 2) continue;
                perSection.set(section, taken + 1);
                reasons[name] = codes;
            }
        } else {
            for (const name of pinned.sort()) reasons[name] = measured.get(name) ?? '(not scored)';
        }
        const next: PkitsBaseline = {
            $comment: 'Reviewed score of NIST PKITS: every accepted disagreement with the sentence that makes it acceptable, and the tests pinned on their PkiReasonCode rather than on the boolean. Expectations come from the file names, which is the only machine-readable statement of intent the archive carries — the PDF is transcribed, never parsed. Rescore with `npx tsx scripts/validate-certs.ts --update-baseline`, then WRITE the `why` of every new deviation by hand; the tool never fills one in, and an empty one fails the gate.',
            corpus: 'pkits',
            commit: corpus('pkits').commit,
            canaries: baseline?.canaries ?? { mustSucceed: '', mustFail: '' },
            totals: { scored: measured.size, agree, deviations: disagreed.size, skipped: skipped.length },
            deviations,
            reasons,
        };
        mkdirSync(dirname(PKITS_BASELINE), { recursive: true });
        writeFileSync(PKITS_BASELINE, `${JSON.stringify(next, null, 2)}\n`);
        record('L7', `pkits baseline rewritten: ${String(agree)} agree, ${String(disagreed.size)} deviations`);
        return paths;
    }

    if (baseline === null) {
        fail(`L7 ${PKITS_BASELINE} is missing — run with --update-baseline once, then write the reason for each deviation`);
        return paths;
    }
    for (const [which, name] of [['mustSucceed', baseline.canaries.mustSucceed], ['mustFail', baseline.canaries.mustFail]] as const) {
        const reasons = measured.get(name);
        if (reasons === undefined) { fail(`L7 canary ${which} ${name} was not scored — the harness is not exercising the corpus`); continue; }
        const wants = which === 'mustSucceed';
        if ((reasons === '') !== wants) {
            fail(`L7 canary ${which} ${name} ${wants ? `must validate cleanly and reported ${reasons}` : 'must be refused and validated cleanly'} — the scorer is not deciding anything`);
        }
    }
    for (const [name, { expected, reasons }] of disagreed) {
        const reviewed = baseline.deviations[name];
        if (reviewed === undefined) {
            fail(`L7 NEW-DISAGREEMENT ${name}: PKITS expects ${expected} and pkinative says otherwise [${reasons.join(',') || 'accepted'}] — fix it, or add it to the baseline with the sentence that makes it acceptable`);
        } else if (reviewed.why.trim() === '') {
            fail(`L7 ${name}: the deviation has no reason written — a disagreement is either a defect or a decision, and only a sentence tells them apart`);
        }
    }
    for (const name of Object.keys(baseline.deviations)) {
        if (disagreed.has(name)) continue;
        if (!measured.has(name)) fail(`L7 stale deviation ${name}: no such test is scored in the corpus`);
        else fail(`L7 UNEXPECTED-AGREEMENT ${name}: the baseline expects a deviation and pkinative now agrees with PKITS — delete the entry, its reason has stopped being true`);
    }
    for (const [name, expected] of Object.entries(baseline.reasons)) {
        const actual = measured.get(name);
        if (actual === undefined) fail(`L7 pinned test ${name} was not scored — the pin is stale`);
        else if (actual !== expected) fail(`L7 ${name}: reasons are [${actual || 'none'}], the baseline pins [${expected || 'none'}] — refused for a different reason is a change in behaviour, whatever the boolean says`);
    }
    if (measured.size !== baseline.totals.scored || skipped.length !== baseline.totals.skipped) {
        fail(`L7 ${String(measured.size)} tests scored and ${String(skipped.length)} skipped; the baseline says ${String(baseline.totals.scored)} and ${String(baseline.totals.skipped)} (canary)`);
    }
    if (agree !== declared.pkits?.agree) {
        fail(`L7 ${String(agree)} tests agree; ecosystem.json declares ${String(declared.pkits?.agree)} (canary)`);
    }

    const rate = measured.size === 0 ? 0 : (agree / measured.size) * 100;
    record('L7', `pkits@${corpus('pkits').commit.slice(0, 12)}: ${String(agree)}/${String(measured.size)} NIST paths agree (${rate.toFixed(2)} %), ${String(disagreed.size)} reviewed deviations, ${String(Object.keys(baseline.reasons).length)} pinned on their reason codes, ${String(skipped.length)} skipped, every one of ${String(total)} certificates and ${String(pkits.crls.length)} lists parsed — ${String(verified)} signature verifications in ${String(seconds)} s`);
    return paths;
}

// ── L8 — the PKITS signed messages, verified whole ─────────────────

/** What L7 measured on one test: the verdict, and the codes behind it. */
interface PkitsPathVerdict {
    readonly valid: boolean;
    readonly codes: readonly string[];
}

/** L7's verdicts, by test name. */
type PkitsPathVerdicts = ReadonlyMap<string, PkitsPathVerdict>;

/** The reviewed S/MIME baseline, `scripts/data/pkits-smime-score.json`. */
interface PkitsSmimeBaseline {
    readonly $comment: string;
    readonly corpus: string;
    readonly commit: string;
    /** Message names, as `splitPkitsMessage` gives them — not the test names of their signers. */
    readonly canaries: { readonly mustSucceed: string; readonly mustFail: string };
    readonly totals: {
        readonly messages: number;
        readonly intact: number;
        readonly scored: number;
        readonly agree: number;
        readonly deviations: number;
        readonly skipped: number;
    };
    /** Claim (a): every message whose signer the CMS layer does not find intact, with its CMS-layer codes. */
    readonly notIntact: Readonly<Record<string, { readonly reasons: string; readonly why: string }>>;
    /** Messages whose verdict is not the one NIST expects for their signer's test. */
    readonly deviations: Readonly<Record<string, { readonly test: string; readonly expected: string; readonly why: string }>>;
    /** Claim (b): messages whose verdict or chain reasons differ from L7's on the same test. */
    readonly pathDisagreements: Readonly<Record<string, { readonly test: string; readonly why: string }>>;
    /** Messages pinned on every reason code `verifySignedData` reports, in order. */
    readonly reasons: Readonly<Record<string, string>>;
}

/**
 * L7 judges a path to an end-entity certificate. **L8 judges what that
 * certificate signed**: each of the 224 PKITS messages is handed whole to
 * `verifySignedData` — the detached content, the SignedData, the anchor, the
 * same lists and the same instant as L7, and no certificate beyond those the
 * message carries — which is the call an S/MIME client makes.
 *
 * Two claims, kept apart because they fail for different reasons:
 *
 *   - **(a) the CMS layer.** NIST signed every message correctly, so every
 *     signer must be `intact`: attributes, algorithms, digest, signature and
 *     signer certificate all check out. A signer that is not is either a CMS
 *     defect or a signature this platform cannot check, and only a reviewed
 *     `notIntact` entry says which;
 *   - **(b) end to end.** The verdict on a message is the L7 verdict on its
 *     signer's path — L7's reviewed deviations included — and a refused message
 *     is refused for a reason that path is refused for. A message may not
 *     disagree with its own test without a reviewed `pathDisagreements` entry.
 *
 * On top of those, the L6 and L7 discipline: expectations from NIST's own
 * file names (through the signer's test, never a table of pairs), reviewed
 * deviations with a written reason, pinned reason codes, two canaries, and
 * counts held to `docs/assets/ecosystem.json`.
 */
async function runPkitsSmimeScorer(pki: typeof Pki, declared: Declared, paths: PkitsPathVerdicts): Promise<void> {
    const dir = corpusDir(ROOT, corpus('pkits'));
    const baseline = existsSync(PKITS_SMIME_BASELINE) ? JSON.parse(readFileSync(PKITS_SMIME_BASELINE, 'utf8')) as PkitsSmimeBaseline : null;
    if (baseline !== null && baseline.commit !== corpus('pkits').commit) {
        fail(`L8 the score baseline was made at pkits ${baseline.commit}, the pin is ${corpus('pkits').commit} — rescore and review it`);
    }
    if (paths.size === 0) {
        fail('L8 L7 scored no path, so no message has a path verdict to be held to');
        return;
    }

    const pkits = readPkits(pki, dir);
    const files = readdirSync(join(dir, 'smime')).filter((file) => file.endsWith('.eml')).sort();
    if (files.length !== declared.pkits?.messages) {
        fail(`L8 pkits holds ${String(files.length)} signed messages; ecosystem.json declares ${String(declared.pkits?.messages)} (canary)`);
    }

    const started = Date.now();
    const measured = new Map<string, string>();
    const links = new Map<string, string>();
    const notIntact = new Map<string, string>();
    const disagreed = new Map<string, { test: string; expected: string; reasons: string }>();
    const beyondPath = new Map<string, { test: string; detail: string }>();
    const skipped: string[] = [];
    let intact = 0;
    let agree = 0;
    let verified = 0;
    for (const file of files) {
        let message: PkitsSignedMessage;
        try {
            message = splitPkitsMessage(`smime/${file}`, new Uint8Array(readFileSync(join(dir, 'smime', file))));
        } catch (error) {
            fail(`L8 ${file}: ${String(error)}`);
            continue;
        }
        const name = message.test;

        let report: Pki.VerifySignedDataReport;
        try {
            // Nothing beyond the message's own certificates: an S/MIME client
            // has what the sender attached and its trust store. The lists are
            // L7's, added to those the message carries, and so are the anchor,
            // the instant, requireRevocation and the path-search budget.
            report = await pki.verifySignedData({
                signedData: message.signature,
                content: message.content,
                trustAnchors: [pkits.anchor],
                at: PKITS_AT,
                crls: pkits.crls,
                requireRevocation: true,
                limits: { maxPathsExplored: 200 },
            });
        } catch (error) {
            const crash = !(error instanceof pki.PkiError);
            fail(`L8 ${crash ? 'CRASH ' : ''}${name}: verifySignedData threw ${String(error)} — it throws only for API misuse${crash ? ', and only a PkiError may leave it' : ''}`);
            continue;
        }
        verified += report.verified;
        const signer = report.signers[0];
        const sid = report.signedData?.signerInfos[0]?.sid;
        if (report.signedData === undefined || sid === undefined || report.signers.length !== 1 || signer === undefined) {
            fail(`L8 ${name}: ${report.signedData === undefined ? 'the SignedData was not read' : `${String(report.signers.length)} signers`} [${report.reasons.map((r) => r.code).join(',')}] — every PKITS message is a readable SignedData with one signer`);
            continue;
        }
        const tests = testsOfSigner(pki, sid, pkits.tests);
        const test = tests[0];
        if (tests.length !== 1 || test === undefined) {
            fail(`L8 ${name}: its signer names ${tests.length === 0 ? 'no PKITS end-entity certificate' : `${String(tests.length)} of them (${tests.join(', ')})`} — the message cannot be held to a test`);
            continue;
        }

        links.set(name, test);
        const codes = report.reasons.map((reason) => reason.code);
        const cmsCodes = report.reasons.filter((reason) => reasonLayer(reason.path) === 'cms').map((reason) => reason.code);
        const chainCodes = report.reasons.filter((reason) => reasonLayer(reason.path) === 'chain').map((reason) => reason.code);
        measured.set(name, codes.join(','));
        if (signer.intact) intact += 1;
        else notIntact.set(name, cmsCodes.join(','));

        // The message's own name, where it says Valid or Invalid, must say what
        // its signer's test says — the check that the link above is right.
        const expected = expectationOfName(test);
        const named = expectationOfName(name);
        if (named !== null && named !== expected) {
            fail(`L8 ${name}: its file name expects ${named ? 'SUCCESS' : 'FAILURE'} and its signer's test ${test} does not — the link is wrong or the archive contradicts itself`);
        }
        const path = paths.get(test);
        if (expected === null || path === undefined) { skipped.push(name); continue; }

        if (report.valid === expected) agree += 1;
        else disagreed.set(name, { test, expected: expected ? 'SUCCESS' : 'FAILURE', reasons: codes.join(',') });
        const beyond = reasonsBeyondPath(chainCodes, path.codes);
        if (report.valid !== path.valid) {
            beyondPath.set(name, { test, detail: `the message is ${report.valid ? 'valid' : 'refused'} and L7 ${path.valid ? 'validates' : 'refuses'} the path of ${test}` });
        } else if (beyond.length > 0) {
            beyondPath.set(name, { test, detail: `the chain is refused for ${beyond.join(',')}, which L7 does not refuse the path of ${test} for [${path.codes.join(',')}]` });
        }
    }
    const seconds = Math.round((Date.now() - started) / 1000);
    const scored = measured.size - skipped.length;

    if (updateBaseline) {
        const byName = <T>(entries: Iterable<[string, T]>): Array<[string, T]> => [...entries].sort(([a], [b]) => (a < b ? -1 : 1));
        const deviations: Record<string, { test: string; expected: string; why: string }> = {};
        for (const [name, { test, expected }] of byName(disagreed)) deviations[name] = { test, expected, why: baseline?.deviations[name]?.why ?? '' };
        const reviewedNotIntact: Record<string, { reasons: string; why: string }> = {};
        for (const [name, reasons] of byName(notIntact)) reviewedNotIntact[name] = { reasons, why: baseline?.notIntact[name]?.why ?? '' };
        const pathDisagreements: Record<string, { test: string; why: string }> = {};
        for (const [name, { test }] of byName(beyondPath)) pathDisagreements[name] = { test, why: baseline?.pathDisagreements[name]?.why ?? '' };
        // Where L7 pins a test on its reason codes, L8 pins the messages its
        // signer signed — a sampling the tool may take. What the codes ARE is
        // measured, never invented, and a later run only re-measures the pins.
        const pinned = Object.keys(baseline?.reasons ?? {});
        const reasons: Record<string, string> = {};
        if (pinned.length === 0) {
            const l7 = existsSync(PKITS_BASELINE) ? (JSON.parse(readFileSync(PKITS_BASELINE, 'utf8')) as PkitsBaseline).reasons : {};
            for (const [name, codes] of byName(measured)) {
                if (codes === '' || disagreed.has(name) || !Object.hasOwn(l7, links.get(name) ?? '')) continue;
                reasons[name] = codes;
            }
        } else {
            for (const name of pinned.sort()) reasons[name] = measured.get(name) ?? '(not scored)';
        }
        const next: PkitsSmimeBaseline = {
            $comment: 'Reviewed score of the NIST PKITS S/MIME messages (conformance level L8): every message verified whole by verifySignedData against the L7 anchor, lists and instant. `notIntact` is claim (a) — a signer the CMS layer does not find intact; `pathDisagreements` is claim (b) — a message whose verdict, or whose chain reasons, differ from L7 on its signer\'s own test; `deviations` are messages whose verdict is not the one NIST expects. Keys are message names; `test` is the PKITS test the signer\'s certificate belongs to. Rescore with `npx tsx scripts/validate-certs.ts --update-baseline`, then WRITE every `why` by hand; the tool never fills one in, and an empty one fails the gate.',
            corpus: 'pkits',
            commit: corpus('pkits').commit,
            canaries: baseline?.canaries ?? { mustSucceed: '', mustFail: '' },
            totals: { messages: measured.size, intact, scored, agree, deviations: disagreed.size, skipped: skipped.length },
            notIntact: reviewedNotIntact,
            deviations,
            pathDisagreements,
            reasons,
        };
        mkdirSync(dirname(PKITS_SMIME_BASELINE), { recursive: true });
        writeFileSync(PKITS_SMIME_BASELINE, `${JSON.stringify(next, null, 2)}\n`);
        record('L8', `pkits S/MIME baseline rewritten: ${String(intact)} intact, ${String(agree)} agree, ${String(disagreed.size)} deviations, ${String(beyondPath.size)} path disagreements`);
        return;
    }

    if (baseline === null) {
        fail(`L8 ${PKITS_SMIME_BASELINE} is missing — run with --update-baseline once, then write the reason for each entry`);
        return;
    }
    const unexplained = (why: string): boolean => why.trim() === '';

    for (const [which, name] of [['mustSucceed', baseline.canaries.mustSucceed], ['mustFail', baseline.canaries.mustFail]] as const) {
        const reasons = measured.get(name);
        if (reasons === undefined) { fail(`L8 canary ${which} ${name} was not verified — the harness is not exercising the messages`); continue; }
        const wants = which === 'mustSucceed';
        if ((reasons === '') !== wants) {
            fail(`L8 canary ${which} ${name} ${wants ? `must verify cleanly and reported ${reasons}` : 'must be refused and verified cleanly'} — the scorer is not deciding anything`);
        }
    }

    // (a) the CMS layer.
    for (const [name, reasons] of notIntact) {
        const reviewed = baseline.notIntact[name];
        if (reviewed === undefined) fail(`L8 NOT-INTACT ${name}: the CMS layer refuses a message NIST signed correctly [${reasons || 'no CMS reason'}] — a CMS defect, or a signature this platform cannot check; fix it, or review it with the sentence that says which`);
        else if (reviewed.reasons !== reasons) fail(`L8 ${name}: the CMS layer reports [${reasons || 'none'}], the baseline reviewed [${reviewed.reasons || 'none'}] — not intact for a different reason is a change in behaviour`);
        else if (unexplained(reviewed.why)) fail(`L8 ${name}: the not-intact entry has no reason written`);
    }
    for (const name of Object.keys(baseline.notIntact)) {
        if (notIntact.has(name)) continue;
        if (!measured.has(name)) fail(`L8 stale not-intact entry ${name}: no such message was verified`);
        else fail(`L8 UNEXPECTED-INTACT ${name}: the baseline expects the CMS layer to refuse this signer and it is now intact — delete the entry, its reason has stopped being true`);
    }

    // The verdict against NIST's expectation.
    for (const [name, { test, expected, reasons }] of disagreed) {
        const reviewed = baseline.deviations[name];
        if (reviewed === undefined) {
            fail(`L8 NEW-DISAGREEMENT ${name}: PKITS expects ${expected} for ${test} and verifySignedData says otherwise [${reasons || 'accepted'}] — fix it, or add it to the baseline with the sentence that makes it acceptable`);
        } else if (reviewed.test !== test) {
            fail(`L8 ${name}: the baseline reviewed it as a message of ${reviewed.test}, its signer belongs to ${test}`);
        } else if (unexplained(reviewed.why)) {
            fail(`L8 ${name}: the deviation has no reason written — a disagreement is either a defect or a decision, and only a sentence tells them apart`);
        }
    }
    for (const name of Object.keys(baseline.deviations)) {
        if (disagreed.has(name)) continue;
        if (!measured.has(name)) fail(`L8 stale deviation ${name}: no such message is scored`);
        else fail(`L8 UNEXPECTED-AGREEMENT ${name}: the baseline expects a deviation and verifySignedData now agrees with PKITS — delete the entry, its reason has stopped being true`);
    }

    // (b) end to end: the message against its own path.
    for (const [name, { test, detail }] of beyondPath) {
        const reviewed = baseline.pathDisagreements[name];
        if (reviewed === undefined) fail(`L8 PATH-DISAGREEMENT ${name}: ${detail} — a message may not disagree with its own test's path verdict without a reviewed entry`);
        else if (reviewed.test !== test || unexplained(reviewed.why)) fail(`L8 ${name}: the path-disagreement entry names ${reviewed.test} or carries no reason; the signer belongs to ${test}`);
    }
    for (const name of Object.keys(baseline.pathDisagreements)) {
        if (!beyondPath.has(name)) fail(`L8 UNEXPECTED-PATH-AGREEMENT ${name}: the message now agrees with the path of its test — delete the entry, its reason has stopped being true`);
    }

    for (const [name, expected] of Object.entries(baseline.reasons)) {
        const actual = measured.get(name);
        if (actual === undefined) fail(`L8 pinned message ${name} was not verified — the pin is stale`);
        else if (actual !== expected) fail(`L8 ${name}: reasons are [${actual || 'none'}], the baseline pins [${expected || 'none'}] — refused for a different reason is a change in behaviour, whatever the boolean says`);
    }
    const totals = baseline.totals;
    if (measured.size !== totals.messages || scored !== totals.scored || skipped.length !== totals.skipped) {
        fail(`L8 ${String(measured.size)} messages verified, ${String(scored)} scored and ${String(skipped.length)} skipped; the baseline says ${String(totals.messages)}, ${String(totals.scored)} and ${String(totals.skipped)} (canary)`);
    }
    if (intact !== declared.pkits?.messagesIntact) {
        fail(`L8 ${String(intact)} messages intact at the CMS layer; ecosystem.json declares ${String(declared.pkits?.messagesIntact)} (canary)`);
    }
    if (agree !== declared.pkits?.messagesAgree) {
        fail(`L8 ${String(agree)} messages agree; ecosystem.json declares ${String(declared.pkits?.messagesAgree)} (canary)`);
    }

    const rate = scored === 0 ? 0 : (agree / scored) * 100;
    record('L8', `pkits@${corpus('pkits').commit.slice(0, 12)}: ${String(intact)}/${String(measured.size)} S/MIME messages intact at the CMS layer (${String(notIntact.size)} reviewed), ${String(agree)}/${String(scored)} verdicts agree with NIST (${rate.toFixed(2)} %), ${String(scored - beyondPath.size)}/${String(scored)} equal to the L7 verdict on their signer's path (${String(beyondPath.size)} reviewed), ${String(disagreed.size)} reviewed deviations, ${String(Object.keys(baseline.reasons).length)} pinned on their reason codes, ${String(skipped.length)} skipped — ${String(verified)} signature verifications in ${String(seconds)} s`);
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
