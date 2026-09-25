#!/usr/bin/env tsx
/**
 * pkinative — Quality gate
 * ========================
 * The single definition of what "green" means. CI, the contributor docs and
 * the agent instructions all point here instead of each carrying its own
 * list of commands, so the list cannot drift between them. The engine is
 * pdfnative's (1.8.0); only the STEPS table is pkinative's own.
 *
 * Every step is an existing npm script (plus one inline check that dist/ is
 * complete). The gate runs them in order, captures each one's full output to
 * `test-output/.gate/<id>.log`, and prints ONE line per step — a passing run
 * is under twenty lines, which is what makes it usable from an agent loop
 * where every line of output costs tokens. On the first failure it prints
 * the tail of that step's log and stops.
 *
 * Usage:
 *   npm run gate                        # --ci: the CI profile
 *   npm run gate:fast                   # typecheck, lint, test, verify:docs
 *   npx tsx scripts/gate.ts --publish   # everything
 *   npx tsx scripts/gate.ts --only lint
 *   npx tsx scripts/gate.ts --from build
 *   npx tsx scripts/gate.ts --ci --json
 *   npx tsx scripts/gate.ts --publish --require-all   # what publish.yml runs
 *
 * (PowerShell swallows a bare `--`, so call the script directly when passing
 * flags rather than `npm run gate -- --fast`; `npm run gate:fast` exists for
 * the common case.)
 *
 * Profiles:
 *   --fast     typecheck:all, lint, test, verify:docs
 *   --ci       every step except the publish-only ones (default)
 *   --publish  every step, the conformance gate over the pinned corpora included
 *
 * Flags:
 *   --require-all  a step that would SKIP fails instead, with
 *                  `required by --require-all: <reason>`. CI and the release
 *                  workflow pass it: a runner without a required input must go
 *                  red, never quietly skip a check.
 *
 * Exit codes:
 *   0 — every selected step passed or was skipped with a reason
 *   1 — a step failed (its log tail is printed; the full log is on disk),
 *       or a step would have skipped under --require-all
 *   2 — bad usage
 */

import { spawnSync, type SpawnSyncOptions } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, rmSync, statSync, writeSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { probeBundle, probeDistFiles, type BundleBudget, type DistFile } from './lib/bundle-probe.js';
import { corporaReady } from './lib/corpora.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LOG_DIR = join(REPO_ROOT, 'test-output', '.gate');
const VITEST_JSON = join(LOG_DIR, 'vitest.json');
const COVERAGE_SUMMARY = join(REPO_ROOT, 'coverage', 'coverage-summary.json');

type Profile = 'fast' | 'ci' | 'publish';

export interface Step {
    readonly id: string;
    /** The npm script this step runs. Absent for the inline `dist-check`. */
    readonly npmScript?: string;
    readonly profiles: readonly Profile[];
    /** Returns a reason to skip the step, or null to run it. */
    readonly skipWhen?: () => string | null;
    /** Extra environment for the child process. */
    readonly env?: Readonly<Record<string, string>>;
    /** In-process check; returns the failure lines, empty when it passes. */
    readonly inline?: () => readonly string[];
    /** A short figure to show next to PASS, read after the step succeeds. */
    readonly note?: () => string | null;
}

// ── Notes (figures shown next to PASS) ──────────────────────────────

function testCount(): string | null {
    if (!existsSync(VITEST_JSON)) return null;
    // The whole suite, skipped tests included — the figure `declared.tests`
    // in docs/assets/ecosystem.json is held to.
    const report = JSON.parse(readFileSync(VITEST_JSON, 'utf8')) as { numTotalTests?: number; numPassedTests?: number; numPendingTests?: number };
    const total = report.numTotalTests ?? report.numPassedTests;
    if (typeof total !== 'number') return null;
    // A skipped suite is otherwise invisible in the one-line summary, which is
    // exactly how a suite that stopped running goes unnoticed for a release.
    const pending = report.numPendingTests ?? 0;
    return pending > 0 ? `${total} tests, ${pending} skipped` : `${total} tests`;
}

function coverageFigure(): string | null {
    if (!existsSync(COVERAGE_SUMMARY)) return null;
    const summary = JSON.parse(readFileSync(COVERAGE_SUMMARY, 'utf8')) as {
        total?: { statements?: { pct?: number } };
    };
    const pct = summary.total?.statements?.pct;
    return typeof pct === 'number' ? `${pct.toFixed(1)}% stmts` : null;
}

function joinNotes(...parts: Array<string | null>): string | null {
    const kept = parts.filter((p): p is string => p !== null);
    return kept.length > 0 ? kept.join(', ') : null;
}

// ── The gate ────────────────────────────────────────────────────────

/** Files `npm run build` must leave behind for the package to be complete. */
const DIST_FILES = [
    'dist/index.js',
    'dist/index.cjs',
    'dist/index.d.ts',
    'dist/index.d.cts',
] as const;

/**
 * The forensic probe of what `dist/` ships: portability, zero dependency, the
 * console rule, nothing foreign, declaration parity and the byte budgets.
 * Inline rather than an npm script — it is text over files that already exist,
 * it costs milliseconds, and the gate keeps one line per step.
 */
function bundleFindings(): readonly string[] {
    const files: DistFile[] = readdirSync(join(REPO_ROOT, 'dist')).map((name) => {
        const path = `dist/${name}`;
        const full = join(REPO_ROOT, path);
        return { path, text: readFileSync(full, 'utf8'), bytes: statSync(full).size };
    });
    const api = JSON.parse(readFileSync(join(REPO_ROOT, 'docs/assets/api.json'), 'utf8')) as { exports?: Array<{ name: string }> };
    const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'docs/assets/ecosystem.json'), 'utf8')) as {
        declared?: { bundle?: Record<string, BundleBudget | string> };
    };
    const budgets: Record<string, BundleBudget> = {};
    for (const [key, value] of Object.entries(manifest.declared?.bundle ?? {})) {
        if (typeof value === 'object') budgets[key] = value;
    }

    const findings = files
        .filter((f) => f.path.endsWith('.js') || f.path.endsWith('.cjs'))
        .flatMap((f) => probeBundle(f.path, f.text));
    return [...findings, ...probeDistFiles(files, (api.exports ?? []).map((e) => e.name), budgets)];
}

export const STEPS: readonly Step[] = [
    { id: 'typecheck:all', npmScript: 'typecheck:all', profiles: ['fast', 'ci', 'publish'] },
    { id: 'lint', npmScript: 'lint', profiles: ['fast', 'ci', 'publish'] },
    {
        id: 'test', npmScript: 'test', profiles: ['fast'],
        env: { GATE: '1' }, note: testCount,
    },
    // build comes before the suites so that tests/tools/bundle-probe.test.ts
    // has an artefact to read. GATE_REQUIRE_ARTIFACTS turns a missing dist/
    // into a failure there instead of a silent skip: inside the gate, the
    // build has already run, so absence can only mean something is wrong.
    { id: 'build', npmScript: 'build', profiles: ['ci', 'publish'] },
    {
        id: 'dist-check', profiles: ['ci', 'publish'],
        inline: () => DIST_FILES.filter(f => !existsSync(join(REPO_ROOT, f))).map(f => `missing: ${f}`),
    },
    { id: 'bundle-check', profiles: ['ci', 'publish'], inline: bundleFindings },
    {
        id: 'test:coverage', npmScript: 'test:coverage', profiles: ['ci', 'publish'],
        env: { GATE: '1', GATE_REQUIRE_ARTIFACTS: '1' }, note: () => joinNotes(testCount(), coverageFigure()),
    },
    { id: 'check:package', npmScript: 'check:package', profiles: ['ci', 'publish'] },
    { id: 'verify:bundle', npmScript: 'verify:bundle', profiles: ['ci', 'publish'] },
    // The other direction from the conformance gate: L0-L4 ask whether
    // pkinative reads bytes the way everyone else does, and say nothing about
    // the bytes it writes. An encoder can drift — a string type swapped, a
    // DEFAULT emitted, a SET reordered — with every structural assertion
    // still green, because the structure is still right. These are the bytes
    // a relying party hashes.
    { id: 'verify:samples', npmScript: 'verify:samples', profiles: ['fast', 'ci', 'publish'] },
    { id: 'smoke:install', npmScript: 'smoke:install', profiles: ['ci', 'publish'] },
    // The second layer of the playground's freshness guard. verify:docs
    // fingerprints the inputs hermetically; this re-derives the file from the
    // dist/ built above and compares byte for byte, which is what "the
    // playground runs the published build" actually claims.
    { id: 'docs:playground-fresh', npmScript: 'docs:playground-fresh', profiles: ['ci', 'publish'] },
    { id: 'verify:docs', npmScript: 'verify:docs', profiles: ['fast', 'ci', 'publish'] },
    {
        // Needs the network once (npm run conformance:fetch), so it stays out of
        // the hermetic CI profile; conformance.yml runs it on every change.
        id: 'conformance', npmScript: 'conformance', profiles: ['publish'],
        skipWhen: () => (corporaReady(REPO_ROOT) ? null : 'corpora not fetched or not matching their pins — run npm run conformance:fetch'),
    },
];

// ── Running a step ──────────────────────────────────────────────────

/**
 * Run an npm script with its stdout and stderr interleaved into one log
 * file. `npm_execpath` is set whenever this script itself was started by
 * npm, and running that CLI under the current node keeps the whole gate on
 * one toolchain; outside npm (a bare `tsx scripts/gate.ts`) fall back to
 * whatever `npm` is on PATH — through a shell, since on Windows that is an
 * `npm.cmd` shim which Node refuses to spawn directly.
 */
function runNpmScript(script: string, logPath: string, extraEnv: Readonly<Record<string, string>>): number {
    const env: NodeJS.ProcessEnv = { ...process.env, ...extraEnv, NO_COLOR: '1', FORCE_COLOR: '0' };
    const fd = openSync(logPath, 'w');
    try {
        const npmCli = process.env.npm_execpath;
        const common: SpawnSyncOptions = { cwd: REPO_ROOT, env, stdio: ['ignore', fd, fd], windowsHide: true };
        const result = npmCli && existsSync(npmCli) && /\.(c|m)?js$/.test(npmCli)
            ? spawnSync(process.execPath, [npmCli, 'run', script], common)
            : spawnSync('npm', ['run', script], { ...common, shell: true });
        if (result.error) throw result.error;
        return result.status ?? 1;
    } finally {
        closeSync(fd);
    }
}

function runInline(check: () => readonly string[], logPath: string): number {
    const failures = check();
    const fd = openSync(logPath, 'w');
    try {
        writeSync(fd, failures.length === 0 ? 'ok\n' : `${failures.join('\n')}\n`);
    } finally {
        closeSync(fd);
    }
    return failures.length === 0 ? 0 : 1;
}

function tail(file: string, lines: number): string[] {
    if (!existsSync(file)) return [];
    const all = readFileSync(file, 'utf8').replace(/\r\n/g, '\n').trimEnd().split('\n');
    return all.slice(-lines);
}

// ── CLI ─────────────────────────────────────────────────────────────

interface Options {
    readonly profile: Profile;
    readonly only: string | null;
    readonly from: string | null;
    readonly json: boolean;
    /** Turn every SKIP into a FAIL (CI and the release workflow). */
    readonly requireAll: boolean;
}

function usage(): string {
    return [
        'Usage: npx tsx scripts/gate.ts [--fast | --ci | --publish] [--only <id>] [--from <id>] [--require-all] [--json]',
        '',
        `Steps: ${STEPS.map(s => s.id).join(', ')}`,
    ].join('\n');
}

function parseArgs(argv: readonly string[]): Options | { error: string } {
    let profile: Profile | null = null;
    let only: string | null = null;
    let from: string | null = null;
    let json = false;
    let requireAll = false;
    const ids = new Set(STEPS.map(s => s.id));

    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--fast' || a === '--ci' || a === '--publish') {
            const p = a.slice(2) as Profile;
            if (profile !== null && profile !== p) return { error: `--${profile} and ${a} are mutually exclusive` };
            profile = p;
        } else if (a === '--only' || a === '--from') {
            const id = argv[i + 1];
            if (id === undefined || id.startsWith('--')) return { error: `${a} needs a step id` };
            if (!ids.has(id)) return { error: `unknown step "${id}"` };
            if (a === '--only') only = id; else from = id;
            i++;
        } else if (a === '--json') {
            json = true;
        } else if (a === '--require-all') {
            requireAll = true;
        } else {
            return { error: `unknown argument "${a}"` };
        }
    }
    return { profile: profile ?? 'ci', only, from, json, requireAll };
}

interface StepOutcome {
    readonly id: string;
    readonly status: 'pass' | 'fail' | 'skip';
    readonly seconds: number;
    readonly note: string | null;
}

function selectSteps(opts: Options): readonly Step[] {
    if (opts.only !== null) return STEPS.filter(s => s.id === opts.only);
    let selected = STEPS.filter(s => s.profiles.includes(opts.profile));
    if (opts.from !== null) {
        const at = selected.findIndex(s => s.id === opts.from);
        if (at < 0) {
            // The step exists but is not in this profile: run the profile
            // from the position it would occupy in the full table.
            const full = STEPS.findIndex(s => s.id === opts.from);
            selected = selected.filter(s => STEPS.indexOf(s) >= full);
        } else {
            selected = selected.slice(at);
        }
    }
    return selected;
}

function main(): number {
    const parsed = parseArgs(process.argv.slice(2));
    if ('error' in parsed) {
        process.stderr.write(`gate: ${parsed.error}\n${usage()}\n`);
        return 2;
    }
    const opts = parsed;
    const steps = selectSteps(opts);
    const width = Math.max(...STEPS.map(s => s.id.length));
    const say = (line: string): void => { if (!opts.json) process.stdout.write(`${line}\n`); };

    mkdirSync(LOG_DIR, { recursive: true });
    const outcomes: StepOutcome[] = [];
    const startedAt = Date.now();
    say(`gate --${opts.profile}: ${steps.length} step(s)`);

    let failedAt: string | null = null;
    for (const step of steps) {
        const reason = step.skipWhen?.() ?? null;
        if (reason !== null) {
            if (opts.requireAll) {
                const note = `required by --require-all: ${reason}`;
                outcomes.push({ id: step.id, status: 'fail', seconds: 0, note });
                say(`FAIL  ${step.id.padEnd(width)}          ${note}`);
                failedAt = step.id;
                break;
            }
            outcomes.push({ id: step.id, status: 'skip', seconds: 0, note: reason });
            say(`SKIP  ${step.id.padEnd(width)}          (${reason})`);
            continue;
        }

        const logPath = join(LOG_DIR, `${step.id.replace(/[^a-z0-9-]/gi, '-')}.log`);
        // A stale report from an earlier run must never be reported as this run's.
        if (step.env?.GATE === '1') rmSync(VITEST_JSON, { force: true });
        if (step.id === 'test:coverage') rmSync(COVERAGE_SUMMARY, { force: true });

        const t0 = Date.now();
        const status = step.inline
            ? runInline(step.inline, logPath)
            : runNpmScript(step.npmScript ?? step.id, logPath, step.env ?? {});
        const seconds = (Date.now() - t0) / 1000;
        const clock = `${seconds.toFixed(1)}s`.padStart(7);

        if (status === 0) {
            const note = step.note?.() ?? null;
            outcomes.push({ id: step.id, status: 'pass', seconds, note });
            say(`PASS  ${step.id.padEnd(width)}  ${clock}${note ? `  ${note}` : ''}`);
            continue;
        }

        const rel = relative(REPO_ROOT, logPath).replace(/\\/g, '/');
        outcomes.push({ id: step.id, status: 'fail', seconds, note: `exit ${status}; log: ${rel}` });
        say(`FAIL  ${step.id.padEnd(width)}  ${clock}  exit ${status}`);
        for (const line of tail(logPath, 12)) say(`      ${line}`);
        say(`      (full log: ${rel})`);
        failedAt = step.id;
        break;
    }

    const total = ((Date.now() - startedAt) / 1000).toFixed(1);
    if (opts.json) {
        process.stdout.write(`${JSON.stringify({ ok: failedAt === null, profile: opts.profile, steps: outcomes }, null, 2)}\n`);
    } else if (failedAt !== null) {
        process.stdout.write(`gate: failed at ${failedAt}\n`);
    } else {
        const passed = outcomes.filter(o => o.status === 'pass').length;
        const skipped = outcomes.filter(o => o.status === 'skip').length;
        process.stdout.write(`gate: ${passed} passed, ${skipped} skipped in ${total} s\n`);
    }
    return failedAt === null ? 0 : 1;
}

// Run only when invoked as the script. Without this guard, importing STEPS —
// which tests/tools/gate.test.ts does, to hold the step order to what the
// suites depend on — would run the whole gate recursively.
if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
    process.exit(main());
}
