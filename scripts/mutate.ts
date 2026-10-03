#!/usr/bin/env tsx
/**
 * pkinative — Mutation testing
 * ============================
 * A zero-dependency, deterministic mutation pass. Coverage is 100 % on every
 * axis, which proves that each line ran under some test; it does not prove
 * that any test would notice the line being wrong. This runner makes the
 * code wrong on purpose, one small change at a time, and asks the suites
 * whether they notice.
 *
 * For each target file it enumerates mutants on the TypeScript syntax tree
 * (`scripts/lib/mutation.ts`: relational, equality and logical operator
 * flips, `!` removal, conditional branch swap, `if` forced true or false, a
 * throw guard disabled, a limit or offset ± 1, a returned boolean negated),
 * type-checks each one against `tsconfig.json` (a mutant the compiler
 * refuses is `compile-error`, not counted), then applies it to a SANDBOX —
 * a copy of the tracked tree under `test-output/mutation/` — and runs
 * vitest there on the suites that import the file, with `--bail 1` and a
 * timeout. The working tree is never written.
 *
 * A mutant the direct suites miss is re-run against every suite whose
 * imports reach the file before it is called a survivor. A survivor is a
 * test gap, or an equivalent mutant recorded with its reason in
 * `scripts/data/mutation-equivalents.json` (format: `EquivalentEntry` in
 * `scripts/lib/mutation.ts`); an entry whose mutant no longer exists, or is
 * now killed, is reported as stale.
 *
 * Usage:
 *   npm run mutate                                        # every executable module of src/
 *   npx tsx scripts/mutate.ts --files src/keys/key-pbes2.ts
 *   npx tsx scripts/mutate.ts --files src/asn1/asn1-decode.ts=80 --seed 7
 *   npx tsx scripts/mutate.ts --files src/cms/cms-check.ts --list
 *
 * Flags:
 *   --files a,b=N       targets (repository-relative); `=N` samples N mutants of that file
 *   --sample N          sample size for every target without its own `=N`
 *   --seed S            sampling seed (default 1): the same seed, the same mutants
 *   --concurrency K     parallel sandboxes (default: half the CPUs)
 *   --tests a,b         run these suites instead of the direct selection
 *   --exclude-tests p   comma-separated path prefixes never selected (default tests/docs/,tests/tools/,tests/performance/ — the
 *                       time budgets measure the machine, not a mutant, and trip under the load of a mutation run)
 *   --no-escalate       do not re-run survivors against the reaching suites
 *   --no-typecheck      skip the compile check (a type-invalid mutant then runs)
 *   --list              print the mutants and the selected suites, run nothing
 *
 * Output: one character per mutant (. killed, T timeout, C compile error,
 * s survived the direct suites — then S when the reaching suites miss it
 * too), a summary table, and the full report in
 * `test-output/mutation/report.json`.
 *
 * Exit codes:
 *   0 — every mutant was killed, timed out, did not compile or is a reviewed equivalent
 *   1 — a mutant survived, or an equivalent entry is stale or refuted
 *   2 — bad usage, or a baseline run that is red before any mutation
 */

import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import {
    applyMutant, buildImportGraph, checkEquivalentsFile, enumerateMutants, matchEquivalents, sampleMutants, scoreOf, selectTests,
    type EquivalentEntry, type EquivalentsFile, type FileScore, type Mutant, type MutantStatus,
} from './lib/mutation.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_DIR = join(REPO_ROOT, 'test-output', 'mutation');
const REPORT = join(OUT_DIR, 'report.json');
export const EQUIVALENTS = 'scripts/data/mutation-equivalents.json';
const VITEST = join(REPO_ROOT, 'node_modules', 'vitest', 'vitest.mjs');

/**
 * The default targets: every module of `src/` that executes — the whole
 * perimeter, not the security-critical subset 0.x ran. Every mutant of every
 * file, no sampling: a sampled score cannot claim 100 %, and 100 % is the
 * claim. `tests/tools/mutation.test.ts` holds this table to the tree: a file
 * is here, or it matches an entry of `EXCLUDED_FROM_MUTATION` with its reason.
 */
export const DEFAULT_TARGETS: ReadonlyArray<{ readonly file: string; readonly sample?: number }> = [
    { file: 'src/asn1/asn1-context.ts' },
    { file: 'src/asn1/asn1-cursor.ts' },
    { file: 'src/asn1/asn1-decode.ts' },
    { file: 'src/asn1/asn1-encode.ts' },
    { file: 'src/asn1/asn1-oid.ts' },
    { file: 'src/asn1/asn1-read.ts' },
    { file: 'src/asn1/asn1-tags.ts' },
    { file: 'src/asn1/asn1-time.ts' },
    { file: 'src/build/build-certificate.ts' },
    { file: 'src/build/build-csr.ts' },
    { file: 'src/build/build-signed-data.ts' },
    { file: 'src/build/build-structures.ts' },
    { file: 'src/cms/cms-attributes.ts' },
    { file: 'src/cms/cms-check.ts' },
    { file: 'src/cms/cms-signed-data.ts' },
    { file: 'src/cms/tsp-request.ts' },
    { file: 'src/cms/tsp-response.ts' },
    { file: 'src/cms/tsp-tst-info.ts' },
    { file: 'src/core/base64.ts' },
    { file: 'src/core/bytes.ts' },
    { file: 'src/core/name-oids.ts' },
    { file: 'src/core/pki-diagnostics.ts' },
    { file: 'src/core/pki-error-guard.ts' },
    { file: 'src/core/pki-limits.ts' },
    { file: 'src/core/pki-reasons.ts' },
    { file: 'src/core/text.ts' },
    { file: 'src/core/uri.ts' },
    { file: 'src/crypto/cms-verify.ts' },
    { file: 'src/crypto/crypto-algorithms.ts' },
    { file: 'src/crypto/crypto-signature.ts' },
    { file: 'src/crypto/webcrypto.ts' },
    { file: 'src/crypto/x509-verify.ts' },
    { file: 'src/hash/fingerprint.ts' },
    { file: 'src/hash/hash-shared.ts' },
    { file: 'src/hash/key-identifier.ts' },
    { file: 'src/hash/sha1.ts' },
    { file: 'src/hash/sha256.ts' },
    { file: 'src/hash/sha512.ts' },
    { file: 'src/hash/shake256.ts' },
    { file: 'src/keys/key-import.ts' },
    { file: 'src/keys/key-pbes2.ts' },
    { file: 'src/keys/key-pkcs12.ts' },
    { file: 'src/keys/key-pkcs8.ts' },
    { file: 'src/oid/oid-names.ts' },
    { file: 'src/path/path-build.ts' },
    { file: 'src/path/path-name-constraints.ts' },
    { file: 'src/path/path-policies.ts' },
    { file: 'src/path/path-purpose.ts' },
    { file: 'src/path/path-server-name.ts' },
    { file: 'src/path/path-validate.ts' },
    { file: 'src/pem/pem.ts' },
    { file: 'src/revocation/crl-check.ts' },
    { file: 'src/revocation/crl-parse.ts' },
    { file: 'src/revocation/crl-scope.ts' },
    { file: 'src/revocation/ocsp-check.ts' },
    { file: 'src/revocation/ocsp-request.ts' },
    { file: 'src/revocation/ocsp-response.ts' },
    { file: 'src/types/pki-errors.ts' },
    { file: 'src/verify/verify-chain.ts' },
    { file: 'src/verify/verify-csr.ts' },
    { file: 'src/verify/verify-pkcs12.ts' },
    { file: 'src/verify/verify-signed-data.ts' },
    { file: 'src/verify/verify-signer.ts' },
    { file: 'src/verify/verify-timestamp.ts' },
    { file: 'src/x509/iso3166.ts' },
    { file: 'src/x509/x509-algorithm.ts' },
    { file: 'src/x509/x509-certificate.ts' },
    { file: 'src/x509/x509-csr.ts' },
    { file: 'src/x509/x509-ext-constraints.ts' },
    { file: 'src/x509/x509-ext-distribution.ts' },
    { file: 'src/x509/x509-ext-identifiers.ts' },
    { file: 'src/x509/x509-ext-policies.ts' },
    { file: 'src/x509/x509-ext-shared.ts' },
    { file: 'src/x509/x509-extensions.ts' },
    { file: 'src/x509/x509-fields.ts' },
    { file: 'src/x509/x509-general-name.ts' },
    { file: 'src/x509/x509-name-format.ts' },
    { file: 'src/x509/x509-name.ts' },
    { file: 'src/x509/x509-spki.ts' },
];

/**
 * What is not mutated, and why. A file that is neither a target nor matched
 * here fails `tests/tools/mutation.test.ts`, so a new module is a decision,
 * never an omission.
 */
export const EXCLUDED_FROM_MUTATION: ReadonlyArray<{ readonly pattern: RegExp; readonly reason: string }> = [
    { pattern: /^src\/index\.ts$/, reason: 're-exports only: no expression to mutate' },
    { pattern: /^src\/oid\/oid-registry\.ts$/, reason: 'data: the OID name table; the one function that reads it, oid-names.ts, is a target' },
    { pattern: /^src\/core\/(cms|key)-oids\.ts$/, reason: 'data: OID string constants only, where no operator applies (a full pass enumerated 0 mutants); name-oids.ts stays a target because it carries numeric bounds' },
    { pattern: /^src\/types\/(?!pki-errors\.ts$)[^/]+\.ts$/, reason: 'type declarations only; pki-errors.ts, which carries the brand and the class hierarchy, is a target' },
];

interface Options {
    targets: Array<{ file: string; sample?: number }>;
    sample: number | null;
    seed: number;
    concurrency: number;
    tests: string[] | null;
    exclude: string[];
    escalate: boolean;
    typecheck: boolean;
    list: boolean;
}

function usage(message: string): never {
    process.stderr.write(`mutate: ${message}\n`);
    process.exit(2);
}

function parseArgs(argv: readonly string[]): Options {
    const o: Options = {
        targets: [], sample: null, seed: 1, concurrency: Math.max(1, Math.floor(cpus().length / 2)),
        tests: null, exclude: ['tests/docs/', 'tests/tools/', 'tests/performance/'], escalate: true, typecheck: true, list: false,
    };
    const int = (flag: string, v: string | undefined): number => {
        const n = Number(v);
        if (v === undefined || !Number.isInteger(n) || n < 0) usage(`${flag} needs a non-negative integer`);
        return n;
    };
    const csv = (flag: string, v: string | undefined): string[] => {
        if (v === undefined || v === '') usage(`${flag} needs a value`);
        return v.split(',').map((s) => s.trim().replace(/\\/g, '/')).filter((s) => s !== '');
    };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        switch (a) {
            case '--files':
                for (const spec of csv(a, argv[++i])) {
                    const [file = '', n] = spec.split('=');
                    o.targets.push(n === undefined ? { file } : { file, sample: int('--files …=N', n) });
                }
                break;
            case '--sample': o.sample = int(a, argv[++i]); break;
            case '--seed': o.seed = int(a, argv[++i]); break;
            case '--concurrency': o.concurrency = Math.max(1, int(a, argv[++i])); break;
            case '--tests': o.tests = csv(a, argv[++i]); break;
            case '--exclude-tests': o.exclude = csv(a, argv[++i]); break;
            case '--no-escalate': o.escalate = false; break;
            case '--no-typecheck': o.typecheck = false; break;
            case '--list': o.list = true; break;
            default: usage(`unknown argument ${String(a)}`);
        }
    }
    if (o.targets.length === 0) o.targets = DEFAULT_TARGETS.map((t) => ({ ...t }));
    for (const t of o.targets) if (!existsSync(join(REPO_ROOT, t.file))) usage(`${t.file} does not exist`);
    return o;
}

// ── The tree ──

/** Tracked and untracked-but-not-ignored files: exactly what a fresh clone plus the work in progress holds. */
function repoFiles(): string[] {
    const r = spawnSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: REPO_ROOT, encoding: 'utf8' });
    if (r.status !== 0) usage(`git ls-files failed: ${r.stderr}`);
    return r.stdout.split('\0').filter((f) => f !== '' && existsSync(join(REPO_ROOT, f)));
}

function makeSandbox(index: number, files: readonly string[]): string {
    const dir = join(OUT_DIR, `sandbox-${index}`);
    rmSync(dir, { recursive: true, force: true });
    for (const f of files) {
        const to = join(dir, f);
        mkdirSync(dirname(to), { recursive: true });
        copyFileSync(join(REPO_ROOT, f), to);
    }
    return dir;
}

// ── The compile check ──

/** A language service over tsconfig.json whose one overridden file is the mutant. */
function createTypeChecker(): (file: string, text: string) => boolean {
    const configPath = join(REPO_ROOT, 'tsconfig.json');
    const parsed = ts.parseJsonConfigFileContent(ts.readConfigFile(configPath, ts.sys.readFile).config, ts.sys, REPO_ROOT);
    // A mutant that disables a guard often leaves a name unread or code
    // unreachable. Those are hygiene diagnostics, not type errors: the
    // mutant still runs, and a test must be the one to kill it. Only a
    // genuine type error (a possibly-undefined dereference the guard was
    // narrowing, a branch of the wrong type) counts as compile-error.
    parsed.options = { ...parsed.options, noUnusedLocals: false, noUnusedParameters: false, allowUnreachableCode: true, allowUnusedLabels: true };
    let override: { path: string; text: string; version: number } = { path: '', text: '', version: 0 };
    const norm = (p: string): string => resolve(p).toLowerCase();
    const host: ts.LanguageServiceHost = {
        getCompilationSettings: () => parsed.options,
        getScriptFileNames: () => parsed.fileNames,
        getScriptVersion: (p) => (norm(p) === override.path ? String(override.version) : '0'),
        getScriptSnapshot: (p) => {
            if (norm(p) === override.path) return ts.ScriptSnapshot.fromString(override.text);
            return existsSync(p) ? ts.ScriptSnapshot.fromString(readFileSync(p, 'utf8')) : undefined;
        },
        getCurrentDirectory: () => REPO_ROOT,
        getDefaultLibFileName: (o) => ts.getDefaultLibFilePath(o),
        fileExists: ts.sys.fileExists,
        readFile: ts.sys.readFile,
        readDirectory: ts.sys.readDirectory,
        directoryExists: ts.sys.directoryExists,
        getDirectories: ts.sys.getDirectories,
    };
    const service = ts.createLanguageService(host, ts.createDocumentRegistry());
    let version = 0;
    return (file, text) => {
        override = { path: norm(join(REPO_ROOT, file)), text, version: ++version };
        const abs = join(REPO_ROOT, file);
        return service.getSyntacticDiagnostics(abs).length === 0 && service.getSemanticDiagnostics(abs).length === 0;
    };
}

// ── Running vitest ──

interface RunResult { readonly outcome: 'pass' | 'fail' | 'timeout'; readonly ms: number; readonly tail: string }

function killTree(pid: number): void {
    if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' });
    else try { process.kill(-pid, 'SIGKILL'); } catch { /* already gone */ }
}

function runVitest(cwd: string, tests: readonly string[], timeoutMs: number, workers: number): Promise<RunResult> {
    const env: NodeJS.ProcessEnv = { ...process.env, FORCE_COLOR: '0', TZ: 'UTC' };
    delete env['GATE'];
    delete env['GITHUB_ACTIONS'];
    delete env['GATE_REQUIRE_ARTIFACTS'];
    const started = Date.now();
    return new Promise((done) => {
        const child = spawn(process.execPath, [VITEST, 'run', ...tests, '--bail', '1', '--reporter', 'dot', '--maxWorkers', String(workers)],
            { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
        let tail = '';
        const keep = (b: Buffer): void => { tail = (tail + b.toString()).slice(-4000); };
        child.stdout.on('data', keep);
        child.stderr.on('data', keep);
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; if (child.pid !== undefined) killTree(child.pid); }, timeoutMs);
        child.on('close', (code) => {
            clearTimeout(timer);
            done({ outcome: timedOut ? 'timeout' : code === 0 ? 'pass' : 'fail', ms: Date.now() - started, tail });
        });
    });
}

// ── The pass ──

interface MutantResult {
    readonly id: string;
    readonly operator: string;
    readonly line: number;
    readonly column: number;
    readonly original: string;
    readonly replacement: string;
    status: MutantStatus;
    /** Which suite set decided it: the direct suites, or the reaching ones on escalation. */
    decidedBy: 'typecheck' | 'direct' | 'reach';
    readonly equivalentReason?: string;
}

interface FileReport {
    readonly file: string;
    readonly enumerated: number;
    readonly sampled: number;
    readonly direct: string[];
    readonly reach: string[];
    readonly wallMs: number;
    readonly score: FileScore;
    readonly mutants: MutantResult[];
    readonly stale: EquivalentEntry[];
    readonly refuted: string[];
}

const SYMBOL: Record<MutantStatus, string> = { killed: '.', survived: 'S', timeout: 'T', 'compile-error': 'C', equivalent: 'E' };

async function main(): Promise<void> {
    const o = parseArgs(process.argv.slice(2));
    const files = repoFiles();
    const sources = new Map<string, string>();
    for (const f of files) if (f.endsWith('.ts') && /^(src|tests|recipes|scripts)\//.test(f)) sources.set(f, readFileSync(join(REPO_ROOT, f), 'utf8'));
    const graph = buildImportGraph(sources);

    const equivalentsRaw: unknown = JSON.parse(readFileSync(join(REPO_ROOT, EQUIVALENTS), 'utf8'));
    const shape = checkEquivalentsFile(equivalentsRaw);
    if (shape.length > 0) usage(`${EQUIVALENTS}: ${shape.join('; ')}`);
    const equivalents = (equivalentsRaw as EquivalentsFile).equivalents;

    const plans = o.targets.map((t) => {
        const source = sources.get(t.file) ?? readFileSync(join(REPO_ROOT, t.file), 'utf8');
        const all = enumerateMutants(t.file, source);
        const size = t.sample ?? o.sample ?? all.length;
        const selection = selectTests(graph, t.file, o.exclude);
        const direct = o.tests ?? selection.direct;
        return { file: t.file, source, all, chosen: sampleMutants(all, size, o.seed), direct, reach: selection.reach };
    });

    if (o.list) {
        for (const p of plans) {
            process.stdout.write(`${p.file}: ${p.chosen.length}/${p.all.length} mutants\n  direct: ${p.direct.join(' ')}\n  reach:  ${p.reach.length} suites\n`);
            for (const m of p.chosen) process.stdout.write(`  ${m.id}\n`);
        }
        return;
    }

    for (const p of plans) if (p.direct.length === 0) usage(`no test file imports ${p.file}; pass --tests`);
    mkdirSync(OUT_DIR, { recursive: true });
    const sandboxes = Array.from({ length: o.concurrency }, (_, i) => makeSandbox(i, files));
    const workers = Math.max(1, Math.floor(cpus().length / o.concurrency));
    const typecheck = o.typecheck ? createTypeChecker() : null;
    const reports: FileReport[] = [];

    for (const p of plans) {
        const started = Date.now();
        const { matched, stale } = matchEquivalents(equivalents, p.all);
        process.stdout.write(`${p.file} — ${p.chosen.length}/${p.all.length} mutants, ${p.direct.length} direct suites\n`);

        const baseline = async (tests: readonly string[], label: string): Promise<number> => {
            const r = await runVitest(sandboxes[0] as string, tests, 15 * 60_000, cpus().length);
            if (r.outcome !== 'pass') {
                process.stderr.write(`mutate: the ${label} suites of ${p.file} are red before any mutation:\n${r.tail}\n`);
                process.exit(2);
            }
            return r.ms;
        };
        const directMs = await baseline(p.direct, 'direct');

        const results: MutantResult[] = p.chosen.map((m) => {
            const eq = matched.get(m.id);
            return { id: m.id, operator: m.operator, line: m.line, column: m.column, original: m.original, replacement: m.replacement, status: 'survived', decidedBy: 'direct', ...(eq ? { equivalentReason: eq.reason } : {}) };
        });

        // One pool over the sandboxes: each worker owns one copy of the tree,
        // writes the mutant into it, runs, and puts the original back.
        const runPool = async (indices: readonly number[], tests: readonly string[], timeoutMs: number, phase: 'direct' | 'reach'): Promise<void> => {
            let next = 0;
            const target = (sandbox: string): string => join(sandbox, p.file);
            await Promise.all(sandboxes.map(async (sandbox) => {
                while (next < indices.length) {
                    const idx = indices[next++] as number;
                    const mutant = p.chosen[idx] as Mutant;
                    const result = results[idx] as MutantResult;
                    const mutated = applyMutant(p.source, mutant);
                    if (phase === 'direct' && typecheck !== null && !typecheck(p.file, mutated)) {
                        result.status = 'compile-error';
                        result.decidedBy = 'typecheck';
                    } else {
                        writeFileSync(target(sandbox), mutated);
                        try {
                            const r = await runVitest(sandbox, tests, timeoutMs, workers);
                            result.status = r.outcome === 'pass' ? 'survived' : r.outcome === 'fail' ? 'killed' : 'timeout';
                            result.decidedBy = phase;
                        } finally {
                            writeFileSync(target(sandbox), p.source);
                        }
                    }
                    process.stdout.write(phase === 'direct' && result.status === 'survived' ? 's' : SYMBOL[result.status]);
                }
            }));
        };

        const timeoutFor = (ms: number): number => Math.max(30_000, ms * 3 + 10_000);
        await runPool(results.map((_, i) => i), p.direct, timeoutFor(directMs), 'direct');
        const survivors = results.flatMap((r, i) => (r.status === 'survived' ? [i] : []));
        if (o.escalate && survivors.length > 0 && p.reach.length > p.direct.length) {
            process.stdout.write(` escalating ${survivors.length} to ${p.reach.length} suites `);
            const reachMs = await baseline(p.reach, 'reaching');
            await runPool(survivors, p.reach, timeoutFor(reachMs), 'reach');
        }
        process.stdout.write('\n');
        for (const r of results) if (r.status === 'survived' && r.equivalentReason !== undefined) r.status = 'equivalent';

        const refuted = results.filter((r) => r.equivalentReason !== undefined && r.status !== 'equivalent' && r.status !== 'compile-error').map((r) => r.id);
        reports.push({
            file: p.file, enumerated: p.all.length, sampled: p.chosen.length, direct: p.direct, reach: p.reach,
            wallMs: Date.now() - started, score: scoreOf(results.map((r) => r.status)), mutants: results, stale, refuted,
        });
        // Written after every file, so a long run can be read while it continues.
        writeFileSync(REPORT, `${JSON.stringify({ seed: o.seed, generatedAt: new Date().toISOString(), files: reports }, null, 2)}\n`);
    }

    const pad = (s: string | number, n: number): string => String(s).padStart(n);
    process.stdout.write(`\n${'file'.padEnd(34)} ${pad('mut', 5)} ${pad('kill', 5)} ${pad('surv', 5)} ${pad('tout', 5)} ${pad('comp', 5)} ${pad('equiv', 5)} ${pad('score', 7)} ${pad('wall', 7)}\n`);
    for (const r of reports) {
        const s = r.score;
        process.stdout.write(`${r.file.padEnd(34)} ${pad(`${s.total}${r.sampled < r.enumerated ? '*' : ''}`, 5)} ${pad(s.killed, 5)} ${pad(s.survived, 5)} ${pad(s.timeout, 5)} ${pad(s.compileError, 5)} ${pad(s.equivalent, 5)} ${pad(`${s.score.toFixed(1)}%`, 7)} ${pad(`${Math.round(r.wallMs / 1000)}s`, 7)}\n`);
    }
    process.stdout.write('(* sampled)\n');
    let failed = false;
    for (const r of reports) {
        const brief = (s: string): string => { const one = s.replace(/\s+/g, ' '); return one.length > 50 ? `${one.slice(0, 47)}...` : one; };
        for (const m of r.mutants.filter((x) => x.status === 'survived')) { failed = true; process.stdout.write(`SURVIVED  ${m.id}  ${brief(m.original)} => ${brief(m.replacement)}\n`); }
        for (const id of r.refuted) { failed = true; process.stdout.write(`REFUTED   ${id} — recorded as equivalent, and a test now kills it: remove the entry\n`); }
        for (const e of r.stale) { failed = true; process.stdout.write(`STALE     ${e.id} — no such mutant any more: re-review and update the entry\n`); }
    }
    process.stdout.write(`report: ${REPORT.slice(REPO_ROOT.length + 1).replace(/\\/g, '/')}\n`);
    process.exitCode = failed ? 1 : 0;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((e: unknown) => { process.stderr.write(`mutate: ${e instanceof Error ? e.stack ?? e.message : String(e)}\n`); process.exit(2); });
}
