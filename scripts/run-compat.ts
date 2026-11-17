#!/usr/bin/env tsx
/**
 * pkinative — compat-previous: the previous release's own test suite, run
 * against the current sources
 * ===================================================================
 * The 1.x promise (SECURITY.md §Compatibility promise) is held in two halves.
 * The three snapshots — `api.frozen.json`, `errors.frozen.json` and the
 * refusal baseline — hold what the surface *is*: every export, every code,
 * every refusal of the frozen corpora. THIS script holds what the release
 * *did*: it runs the test suite of the previous tag, exactly as it was
 * tagged, against today's `src/`. A test of 1.0.0 that fails on 1.1.0 is a
 * breaking change until `tests/compat/allow-<version>.json` names it with
 * its reason.
 *
 * What it does:
 *   1. `git archive <tag> tests recipes vitest.config.ts` into
 *      `test-output/.compat/<version>/` (git-ignored, a dot-directory, and
 *      removed again when the run ends unless `--keep`);
 *   2. copies the current `src/`, `scripts/`, `fuzz/`, `.clusterfuzzlite/`,
 *      `docs/data/` and `docs/guides/` next to it, with the single files
 *      they reach for, so the archived tests' relative imports
 *      (`../../src/…`, `../../scripts/…`) and the archived config's
 *      `pkinative` alias resolve to the sources under test, and the
 *      registries and counts the archived tests read are today's;
 *   3. runs vitest in that directory with the archived configuration,
 *      excluding the files the allow-list names.
 *
 * Exit code: vitest's (0 green, 1 red); 2 on a usage or git failure — among
 * them a tag that is not in this clone, named with the command that fetches
 * it, so that a skip is never mistaken for a pass.
 *
 * Usage:
 *   npx tsx scripts/run-compat.ts                 # tag from tests/compat/allow-*.json
 *   npx tsx scripts/run-compat.ts --tag v1.0.0
 *   npx tsx scripts/run-compat.ts --list          # print the exclusions and exit
 *   npx tsx scripts/run-compat.ts --print-tag     # print the tag the allow-list names (CI fetches it)
 *   npx tsx scripts/run-compat.ts --keep          # leave test-output/.compat/<version> behind
 */

import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');

/** What `git archive` takes from the previous tag: its suite, its recipes, its configuration. */
export const ARCHIVED_PATHS: readonly string[] = ['tests', 'recipes', 'vitest.config.ts'];
/** The current trees the archived suite imports or reads, besides its own files. */
export const CURRENT_TREES: readonly string[] = ['src', 'scripts', 'fuzz', '.clusterfuzzlite', 'docs/data', 'docs/guides'];
/**
 * Single files the suite or the copied trees reach for: `scripts/` reads the
 * package manifest and the TypeScript projects, the conformance tests read
 * the counts the ecosystem manifest declares.
 */
export const CURRENT_FILES: readonly string[] = ['package.json', 'tsconfig.json', 'tsconfig.scripts.json', 'tsconfig.test.json', 'docs/assets/ecosystem.json'];

export interface CompatExclusion {
    /** A vitest `--exclude` glob, relative to the archived tree (e.g. `tests/docs/**`). */
    readonly pattern: string;
    /** Why this file of the previous suite does not run against the current sources. */
    readonly reason: string;
    /** `tree` when the file tests the repository, not the engine; `behaviour` when the engine changed on purpose. */
    readonly kind: 'tree' | 'behaviour';
}

export interface CompatAllowList {
    readonly tag: string;
    readonly exclude: readonly CompatExclusion[];
}

/** The newest `tests/compat/allow-<version>.json` — the previous release's. */
export function findAllowList(root: string): string | null {
    const dir = join(root, 'tests', 'compat');
    if (!existsSync(dir)) return null;
    const files = readdirSync(dir)
        .filter((f) => /^allow-\d+\.\d+\.\d+\.json$/.test(f))
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    const last = files[files.length - 1];
    return last === undefined ? null : join(dir, last);
}

/**
 * Parse and validate an allow-list.
 *
 * @throws Error naming the entry, when the tag is not `vX.Y.Z`, an exclusion
 *   has no pattern, its reason is shorter than a sentence, or its kind is
 *   neither `tree` nor `behaviour`.
 */
export function parseAllowList(text: string): CompatAllowList {
    const parsed = JSON.parse(text) as { tag?: unknown; exclude?: unknown };
    if (typeof parsed.tag !== 'string' || !/^v\d+\.\d+\.\d+$/.test(parsed.tag)) throw new Error('allow-list: "tag" must be a vX.Y.Z string');
    if (!Array.isArray(parsed.exclude)) throw new Error('allow-list: "exclude" must be an array');
    const exclude: CompatExclusion[] = [];
    for (const entry of parsed.exclude as Array<Record<string, unknown>>) {
        const { pattern, reason, kind } = entry;
        if (typeof pattern !== 'string' || pattern === '') throw new Error('allow-list: every exclusion needs a "pattern"');
        if (typeof reason !== 'string' || reason.length < 40) throw new Error(`allow-list: ${pattern} needs a "reason" (a sentence, not a word)`);
        if (kind !== 'tree' && kind !== 'behaviour') throw new Error(`allow-list: ${pattern} needs "kind": "tree" (a test of the repository) or "behaviour" (the engine changed on purpose)`);
        exclude.push({ pattern, reason, kind });
    }
    return { tag: parsed.tag, exclude };
}

/** The vitest arguments of a run: the archived configuration, minus the allow-list. */
export function vitestArguments(allow: CompatAllowList): string[] {
    const args = ['run', '--config', 'vitest.config.ts'];
    for (const e of allow.exclude) args.push('--exclude', e.pattern);
    return args;
}

function git(args: string[], cwd: string = ROOT): { status: number | null; stdout: Buffer; stderr: string } {
    const r = spawnSync('git', args, { cwd, windowsHide: true, maxBuffer: 256 * 1024 * 1024 });
    return { status: r.status, stdout: r.stdout ?? Buffer.alloc(0), stderr: r.stderr?.toString('utf8') ?? '' };
}

/** Whether `tag` resolves to a commit in this clone. */
export function tagAvailable(root: string, tag: string): boolean {
    return git(['rev-parse', '--verify', '--quiet', `${tag}^{commit}`], root).status === 0;
}

function main(): number {
    const args = process.argv.slice(2);
    const tagArg = args.indexOf('--tag');

    const allowPath = findAllowList(ROOT);
    if (allowPath === null) {
        process.stderr.write('run-compat: no tests/compat/allow-<version>.json — nothing to check against\n');
        return 2;
    }
    let allow: CompatAllowList;
    try {
        allow = parseAllowList(readFileSync(allowPath, 'utf8'));
    } catch (err) {
        process.stderr.write(`run-compat: ${(err as Error).message}\n`);
        return 2;
    }
    const tag = tagArg >= 0 ? (args[tagArg + 1] ?? '') : allow.tag;
    if (!/^v\d+\.\d+\.\d+$/.test(tag)) {
        process.stderr.write(`run-compat: tag "${tag}" is not of the form vX.Y.Z\n`);
        return 2;
    }
    if (args.includes('--print-tag')) {
        process.stdout.write(`${tag}\n`);
        return 0;
    }
    if (args.includes('--list')) {
        process.stdout.write(`compat-previous: the ${tag} suite against the current sources; exclusions of ${allowPath}:\n`);
        for (const e of allow.exclude) process.stdout.write(`  ${e.pattern.padEnd(44)} [${e.kind}] ${e.reason}\n`);
        return 0;
    }
    if (!tagAvailable(ROOT, tag)) {
        process.stderr.write(`run-compat: tag ${tag} is not in this clone — fetch it first: git fetch --no-tags origin +refs/tags/${tag}:refs/tags/${tag}\n`);
        return 2;
    }

    const dir = join(ROOT, 'test-output', '.compat', tag.slice(1));
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });

    // 1. The archived tree. `git archive` writes a tar on stdout; it is
    //    extracted from inside the target directory, because Git for
    //    Windows' tar reads a `D:\…` argument to -C as a remote host.
    const archive = git(['archive', '--format=tar', tag, ...ARCHIVED_PATHS]);
    if (archive.status !== 0) {
        process.stderr.write(`run-compat: git archive ${tag} failed — ${archive.stderr.trim()}\n`);
        return 2;
    }
    const untar = spawnSync('tar', ['-x', '-f', '-'], { cwd: dir, input: archive.stdout, windowsHide: true });
    if (untar.status !== 0) {
        process.stderr.write(`run-compat: tar extraction failed — ${untar.stderr?.toString('utf8').trim() ?? ''}\n`);
        return 2;
    }

    // 2. The sources under test, where the archived tests expect them.
    for (const tree of CURRENT_TREES) cpSync(join(ROOT, tree), join(dir, tree), { recursive: true });
    for (const file of CURRENT_FILES) {
        mkdirSync(dirname(join(dir, file)), { recursive: true });
        cpSync(join(ROOT, file), join(dir, file));
    }

    // 3. The archived suite with the archived configuration, minus the allow-list.
    const vitest = join(ROOT, 'node_modules', 'vitest', 'vitest.mjs');
    if (!existsSync(vitest)) {
        process.stderr.write('run-compat: node_modules/vitest/vitest.mjs is missing — npm ci first\n');
        return 2;
    }
    process.stdout.write(`compat-previous: the ${tag} suite (${String(allow.exclude.length)} exclusion${allow.exclude.length === 1 ? '' : 's'}) against the current src/ in ${dir}\n`);
    const env: NodeJS.ProcessEnv = { ...process.env, TZ: 'UTC' };
    delete env['GATE']; // the archived configuration would otherwise write its JSON report over the gate's
    const r = spawnSync(process.execPath, [vitest, ...vitestArguments(allow)], { cwd: dir, stdio: 'inherit', env, windowsHide: true });
    // Left behind, the archived fixtures and the copied trees would be walked
    // by every walker that does not skip dot-directories.
    if (!args.includes('--keep')) rmSync(dir, { recursive: true, force: true });
    return r.status ?? 1;
}

if (import.meta.filename === resolve(process.argv[1] ?? '')) {
    process.exit(main());
}
