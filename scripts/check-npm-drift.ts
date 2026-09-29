#!/usr/bin/env tsx
/**
 * pkinative — the npm registry against the manifest
 * ==================================================
 * `docs/assets/ecosystem.json` says which version of pkinative exists; the
 * registry says which one a caller gets from `npm install pkinative`. This
 * script compares them. It is not a verify-docs rule on purpose: those are
 * offline and deterministic, and this answer changes without a commit.
 *
 * What the registry must hold, by the manifest's version:
 *
 *   - **Below 1.0.0** — the name reservation and nothing else: `latest` is
 *     the hand-published `0.0.1` placeholder that Trusted Publishing needs to
 *     exist before it can be configured (.github/workflows/publish.yml), and
 *     no other version at all. A real 0.x version on the registry means
 *     publish.yml's pre-1.0 refusal did not hold — which is exactly what this
 *     check exists to prove, week after week.
 *   - **From 1.0.0** — `latest` is the manifest's version. Behind it: the
 *     release is tagged but not published (in flight, or forgotten). Ahead of
 *     it: something was published that main does not describe.
 *   - **In every phase** — the name exists (an unreserved name can be taken),
 *     and no 0.x version other than the placeholder was ever published,
 *     under any dist-tag.
 *
 * Every version is read, not only `latest`: a pre-1.0 publish under
 * `--tag next` would leave `latest` untouched and still break the policy.
 *
 * Run by the scheduled `npm-drift` job of .github/workflows/docs.yml
 * (weekly and on demand, anonymous — `npm view` needs no token). Not a gate
 * step: the fast and CI profiles are hermetic, and in the publish profile
 * the registry is by definition one version behind the commit being
 * published.
 *
 * Usage:
 *   npm run check:npm-drift            # or: npx tsx scripts/check-npm-drift.ts [--json]
 *
 * Exit: 0 the registry matches, 1 drift, 2 the registry could not be read
 * (network, npm missing, unparseable answer) or the manifest is unreadable.
 *
 * @module scripts/check-npm-drift
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PACKAGE = 'pkinative';
/** The name reservation, published by hand before Trusted Publishing could be configured. */
export const PLACEHOLDER = '0.0.1';

/** What `npm view <name> dist-tags versions --json` said, reduced. */
export type RegistryState =
    | { readonly found: false }
    | { readonly found: true; readonly distTags: Readonly<Record<string, string>>; readonly versions: readonly string[] };

const parts = (v: string): number[] => v.split(/[.-]/).slice(0, 3).map(Number);
function compare(a: string, b: string): number {
    const [pa, pb] = [parts(a), parts(b)];
    for (let i = 0; i < 3; i++) {
        const d = (pa[i] ?? 0) - (pb[i] ?? 0);
        if (d !== 0) return d;
    }
    return 0;
}

/** Every problem with the registry state for a manifest at `manifestVersion`; empty when it matches. */
export function decideNpmDrift(manifestVersion: string, registry: RegistryState): string[] {
    if (!registry.found) {
        return [`${PACKAGE} is not on the registry at all — the name is unreserved and can be taken; publish the ${PLACEHOLDER} placeholder by hand (see the Trusted Publishing note in .github/workflows/publish.yml)`];
    }
    const out: string[] = [];
    const latest = registry.distTags['latest'] ?? null;
    const preOne = registry.versions.filter((v) => parts(v)[0] === 0 && v !== PLACEHOLDER);
    if (preOne.length > 0) {
        out.push(`pre-1.0 version(s) ${preOne.join(', ')} reached npm — publish.yml refuses every 0.x version, so its refusal did not hold; deprecate them (npm deprecate) and find how they were published`);
    }
    for (const [tag, v] of Object.entries(registry.distTags)) {
        if (!registry.versions.includes(v)) out.push(`dist-tag ${tag} points at ${v}, which the registry does not list`);
    }
    if (parts(manifestVersion)[0] === 0) {
        if (latest !== PLACEHOLDER) out.push(`the manifest is at ${manifestVersion} (pre-1.0, never on npm), so latest must be the ${PLACEHOLDER} placeholder; the registry says ${latest ?? 'nothing'}`);
        return out;
    }
    if (latest === null) out.push(`${PACKAGE} has no latest dist-tag; the manifest says ${manifestVersion}`);
    else if (compare(latest, manifestVersion) < 0) out.push(`latest is ${latest} and the manifest says ${manifestVersion} — ${manifestVersion} is not published yet (if its release is in flight, re-run once publish.yml has finished)`);
    else if (compare(latest, manifestVersion) > 0) out.push(`latest is ${latest}, ahead of the manifest's ${manifestVersion} — something was published that main does not describe`);
    else if (latest !== manifestVersion) out.push(`latest is ${latest}; the manifest says ${manifestVersion}`);
    return out;
}

/**
 * The state from the text `npm view --json` printed and its exit status.
 * Throws when the answer is neither a package nor a 404 — the caller turns
 * that into exit 2, never into a drift verdict.
 */
export function parseNpmView(stdout: string, stderr: string, status: number | null): RegistryState {
    if (status !== 0) {
        if (/\bE404\b/.test(stdout) || /\bE404\b/.test(stderr)) return { found: false };
        throw new Error(`npm view exited ${String(status)}: ${(stderr || stdout).trim().split('\n').slice(-3).join(' ')}`);
    }
    const value = JSON.parse(stdout) as { 'dist-tags'?: unknown; versions?: unknown };
    const tags = value['dist-tags'];
    if (typeof tags !== 'object' || tags === null) throw new Error('npm view returned no dist-tags');
    // npm prints a single version as a string, several as an array.
    const versions = typeof value.versions === 'string' ? [value.versions] : Array.isArray(value.versions) ? value.versions.filter((v): v is string => typeof v === 'string') : [];
    const distTags: Record<string, string> = {};
    for (const [k, v] of Object.entries(tags)) if (typeof v === 'string') distTags[k] = v;
    return { found: true, distTags, versions };
}

function queryRegistry(): RegistryState {
    const r = spawnSync('npm', ['view', PACKAGE, 'dist-tags', 'versions', '--json'], { encoding: 'utf8', shell: process.platform === 'win32', windowsHide: true, timeout: 60_000 });
    if (r.error) throw r.error;
    return parseNpmView(r.stdout, r.stderr, r.status);
}

function main(argv: readonly string[]): number {
    if (argv.some((a) => a !== '--json')) {
        console.error('usage: npx tsx scripts/check-npm-drift.ts [--json]');
        return 2;
    }
    const root = resolve(import.meta.dirname, '..');
    let manifestVersion: string;
    try {
        const manifest = JSON.parse(readFileSync(join(root, 'docs/assets/ecosystem.json'), 'utf8')) as { packages?: { pkinative?: { version?: unknown } } };
        const v = manifest.packages?.pkinative?.version;
        if (typeof v !== 'string') throw new Error('packages.pkinative.version is missing');
        manifestVersion = v;
    } catch (err) {
        console.error(`check-npm-drift: docs/assets/ecosystem.json — ${(err as Error).message}`);
        return 2;
    }
    let registry: RegistryState;
    try {
        registry = queryRegistry();
    } catch (err) {
        console.error(`check-npm-drift: the registry could not be read — ${(err as Error).message}`);
        return 2;
    }
    const problems = decideNpmDrift(manifestVersion, registry);
    if (argv.includes('--json')) {
        process.stdout.write(`${JSON.stringify({ ok: problems.length === 0, manifest: manifestVersion, registry, problems }, null, 2)}\n`);
    } else {
        for (const p of problems) console.log(`drift: ${p}`);
        const seen = registry.found ? `latest ${registry.distTags['latest'] ?? '—'}, ${String(registry.versions.length)} version(s)` : 'absent';
        console.log(`check-npm-drift: manifest ${manifestVersion}, registry ${seen} — ${problems.length === 0 ? 'in agreement' : `${String(problems.length)} problem(s)`}`);
    }
    return problems.length === 0 ? 0 : 1;
}

// Run only when invoked directly (keeps the module import-safe for tests).
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    process.exit(main(process.argv.slice(2)));
}
