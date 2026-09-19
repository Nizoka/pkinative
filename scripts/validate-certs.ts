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
 *       SKIP, which --require-all turns into a failure;
 *   Wycheproof  ECDSA signatures decode as a strict Ecdsa-Sig-Value
 *       (SEQUENCE of two INTEGERs): every valid vector parses, every vector
 *       flagged as an encoding defect is refused.
 *
 * x509-limbo also scores path validation; pkinative 0.1 validates no path,
 * so no SUCCESS/FAILURE score is claimed before 0.5.
 *
 * Usage:
 *   npx tsx scripts/validate-certs.ts [--level 0-3] [--require-all] [--update-baseline]
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
import { CORPORA, checkCorpus, corpusDir, sha256Hex, type Corpus } from './lib/corpora.js';
import { certificateBounds } from './lib/raw-der.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE = join(ROOT, 'scripts', 'data', 'limbo-refusals.json');
const REPORT_DIR = join(ROOT, 'test-output', 'conformance');
const OPENSSL_SAMPLE = 200;
/** Wycheproof flags that mark a defect of the DER encoding itself. */
const ENCODING_FLAGS: ReadonlySet<string> = new Set(['BerEncodedSignature', 'InvalidEncoding', 'InvalidTypesInSignature']);

const args = process.argv.slice(2);
const levelAt = args.indexOf('--level');
const level = levelAt >= 0 ? Number(args[levelAt + 1]) : 3;
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
    readonly 'x509-limbo'?: { readonly commit?: string; readonly testcases?: number; readonly certificates?: number; readonly refused?: number };
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
        const step = Math.max(1, Math.floor(parsed.size / OPENSSL_SAMPLE));
        const scratch = join(REPORT_DIR, 'openssl-input.der');
        mkdirSync(REPORT_DIR, { recursive: true });
        let sampled = 0;
        let index = 0;
        for (const [hash, cert] of parsed) {
            if (index++ % step !== 0) continue;
            sampled++;
            const facts = openSslFacts(cert.der, scratch);
            if (facts === null) fail(`L3 ${hash}: the openssl CLI cannot read a certificate pkinative parses`);
            else if (signedHex(facts.serial) !== cert.serialNumber.value || facts.fingerprint !== colonHex(sha256Hex(cert.der))) fail(`L3 ${hash}: the openssl CLI disagrees on the serial or the fingerprint`);
        }
        record('L3', `${openssl}: ${sampled} sampled certificates agree`);
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

function report(): number {
    const failed = failures.length > 0 || (requireAll && skips.length > 0);
    const summary = [
        '## pkinative conformance',
        '',
        '```',
        ...lines,
        ...skips.map((s) => `SKIP   ${s}`),
        ...failures.slice(0, 50).map((f) => `FAIL   ${f}`),
        failures.length > 50 ? `FAIL   … ${failures.length - 50} more` : '',
        `${failed ? 'FAILED' : 'PASSED'}: ${failures.length} failure(s), ${skips.length} skip(s)${requireAll ? ' (--require-all)' : ''}`,
        '```',
    ].filter((l) => l !== '');
    console.log(summary.slice(3, -1).join('\n'));
    mkdirSync(REPORT_DIR, { recursive: true });
    writeFileSync(join(REPORT_DIR, 'report.json'), `${JSON.stringify({ level, lines, skips, failures }, null, 2)}\n`);
    const stepSummary = process.env['GITHUB_STEP_SUMMARY'];
    if (stepSummary !== undefined && stepSummary !== '') appendFileSync(stepSummary, `${summary.join('\n')}\n`);
    return failed ? 1 : 0;
}

process.exitCode = await main();
