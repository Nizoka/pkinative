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
 *   - **The satellites** — pkinative-cli and pkinative-mcp, which this site
 *     documents and counts: `latest` of each is the version its
 *     `packages.<name>` record holds, so a satellite release the site has not
 *     caught up with is found the week it ships (`decideSatelliteDrift`).
 *
 * Every version is read, not only `latest`: a pre-1.0 publish under
 * `--tag next` would leave `latest` untouched and still break the policy.
 *
 *   - **The GitHub release** — from 1.0.0, the release tagged with the
 *     manifest's version exists, is published, carries the five files
 *     publish.yml attests, and serves the tarball at the URL the
 *     documentation gives (`decideReleaseAssets`). The registry is satisfied
 *     by a release that carries nothing: the publish run of 1.0.0 was green
 *     and its release was empty.
 *
 * Run by the scheduled `npm-drift` job of .github/workflows/docs.yml
 * (weekly and on demand, anonymous — neither `npm view` nor the public
 * GitHub API needs a token). Not a gate
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
import { SATELLITES } from './lib/satellite-surface.js';

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

/** The satellites the site documents (scripts/lib/satellite-surface.ts): separate repositories, published from 1.0.0, never under the pre-1.0 policy. */
export { SATELLITES };

/**
 * Every problem with a satellite's registry state against its record in the
 * manifest: `latest` is the recorded version, so the site never documents a
 * release that is not out or misses one that is.
 */
export function decideSatelliteDrift(name: string, manifestVersion: string, registry: RegistryState): string[] {
    if (!registry.found) return [`${name} is not on the registry; the manifest records ${manifestVersion}`];
    const latest = registry.distTags['latest'] ?? null;
    if (latest === null) return [`${name} has no latest dist-tag; the manifest records ${manifestVersion}`];
    if (compare(latest, manifestVersion) < 0) return [`${name} latest is ${latest}; the manifest records ${manifestVersion}, which is not published`];
    if (compare(latest, manifestVersion) > 0) return [`${name} latest is ${latest}, ahead of the manifest's ${manifestVersion} — align the site on the release: npm run satellites:sync -- --expect ${name.replace('pkinative-', '')}=${latest} --capture --apply --worklist, then /satellite-align (CONTRIBUTING.md §Release)`];
    return latest === manifestVersion ? [] : [`${name} latest is ${latest}; the manifest records ${manifestVersion}`];
}

// ── The GitHub release of the manifest's version ─────────────────────

/** The repository whose releases carry the files (package.json `repository`). */
export const REPOSITORY = 'Nizoka/pkinative';

/** The five files publish.yml attests and attaches to a release, by suffix. */
export const RELEASE_ASSET_SUFFIXES: readonly string[] = ['.tgz', '.cdx.json', '.spdx.json', '.toolchain.cdx.json', '.sigstore.json'];

/** `pkinative-X.Y.Z.tgz` and its four companions. */
export function releaseAssetNames(version: string): string[] {
    return RELEASE_ASSET_SUFFIXES.map((suffix) => `${PACKAGE}-${version}${suffix}`);
}

/** The URL README.md and the quickstart give a reader to install the attested tarball. */
export function releaseTarballUrl(version: string): string {
    return `https://github.com/${REPOSITORY}/releases/download/v${version}/${PACKAGE}-${version}.tgz`;
}

/** What GitHub said about the release tagged `v<version>`, reduced. */
export type ReleaseState =
    | { readonly found: false }
    | { readonly found: true; readonly draft: boolean; readonly assets: readonly string[]; readonly tarballStatus: number };

/**
 * Every problem with the GitHub release of a manifest at `manifestVersion`;
 * empty when it carries its files.
 *
 * The publish run of 1.0.0 was green and its release carried no file: the
 * registry check above is satisfied by an empty release, and nothing else
 * looked. From 1.0.0 the release of the manifest's version exists, is
 * published, carries the five attested files, and serves the tarball at the
 * URL the documentation gives. Below 1.0.0 there is no release to hold.
 */
export function decideReleaseAssets(manifestVersion: string, release: ReleaseState): string[] {
    if (parts(manifestVersion)[0] === 0) return [];
    const tag = `v${manifestVersion}`;
    if (!release.found) {
        return [`the GitHub release ${tag} does not exist — the manifest says ${manifestVersion} (if its release is in flight, re-run once publish.yml has finished; otherwise the release was deleted or never published)`];
    }
    const out: string[] = [];
    if (release.draft) out.push(`the GitHub release ${tag} is still a draft — publish.yml runs when a release is published, so nothing was built from it`);
    const missing = releaseAssetNames(manifestVersion).filter((name) => !release.assets.includes(name));
    if (missing.length > 0) {
        out.push(`the GitHub release ${tag} does not carry ${missing.join(', ')} — the attest job of publish.yml attaches the five attested files; re-run it, or attach them by hand and say so in the release note`);
    }
    if (release.tarballStatus !== 200) {
        out.push(`${releaseTarballUrl(manifestVersion)} answers ${String(release.tarballStatus)} — README.md and the quickstart give that URL to install from`);
    }
    return out;
}

/**
 * The state from the GitHub API's answer for a release by tag, and the
 * status of the tarball URL. Throws when the API answered neither a release
 * nor a 404 — the caller turns that into exit 2, never into a verdict.
 */
export function parseRelease(apiStatus: number, apiBody: string, tarballStatus: number): ReleaseState {
    if (apiStatus === 404) return { found: false };
    if (apiStatus !== 200) throw new Error(`the GitHub API answered ${String(apiStatus)} for the release: ${apiBody.trim().split('\n')[0]?.slice(0, 200) ?? ''}`);
    const value = JSON.parse(apiBody) as { draft?: unknown; assets?: unknown };
    if (typeof value.draft !== 'boolean' || !Array.isArray(value.assets)) throw new Error('the GitHub API returned a release without `draft` or `assets`');
    const assets = (value.assets as Array<{ name?: unknown }>).map((a) => a.name).filter((n): n is string => typeof n === 'string');
    return { found: true, draft: value.draft, assets, tarballStatus };
}

/** Anonymous: the repository is public, and a token would only be one more thing to hold. */
async function queryRelease(version: string): Promise<ReleaseState> {
    const headers = { 'User-Agent': 'check-npm-drift', Accept: 'application/vnd.github+json' };
    const api = await fetch(`https://api.github.com/repos/${REPOSITORY}/releases/tags/v${version}`, { headers, signal: AbortSignal.timeout(60_000) });
    const body = await api.text();
    if (api.status === 404) return parseRelease(404, body, 0);
    const tarball = await fetch(releaseTarballUrl(version), { method: 'HEAD', headers: { 'User-Agent': 'check-npm-drift' }, redirect: 'follow', signal: AbortSignal.timeout(60_000) });
    return parseRelease(api.status, body, tarball.status);
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

function queryRegistry(name: string = PACKAGE): RegistryState {
    const r = spawnSync('npm', ['view', name, 'dist-tags', 'versions', '--json'], { encoding: 'utf8', shell: process.platform === 'win32', windowsHide: true, timeout: 60_000 });
    if (r.error) throw r.error;
    return parseNpmView(r.stdout, r.stderr, r.status);
}

async function main(argv: readonly string[]): Promise<number> {
    if (argv.some((a) => a !== '--json')) {
        console.error('usage: npx tsx scripts/check-npm-drift.ts [--json]');
        return 2;
    }
    const root = resolve(import.meta.dirname, '..');
    let manifestVersion: string;
    const satelliteVersions = new Map<string, string>();
    try {
        const manifest = JSON.parse(readFileSync(join(root, 'docs/assets/ecosystem.json'), 'utf8')) as { packages?: Record<string, { version?: unknown } | undefined> };
        const v = manifest.packages?.['pkinative']?.version;
        if (typeof v !== 'string') throw new Error('packages.pkinative.version is missing');
        manifestVersion = v;
        for (const name of SATELLITES) {
            const sv = manifest.packages?.[name]?.version;
            if (typeof sv !== 'string') throw new Error(`packages.${name}.version is missing`);
            satelliteVersions.set(name, sv);
        }
    } catch (err) {
        console.error(`check-npm-drift: docs/assets/ecosystem.json — ${(err as Error).message}`);
        return 2;
    }
    let registry: RegistryState;
    const problems: string[] = [];
    try {
        registry = queryRegistry();
        problems.push(...decideNpmDrift(manifestVersion, registry));
        for (const [name, version] of satelliteVersions) problems.push(...decideSatelliteDrift(name, version, queryRegistry(name)));
    } catch (err) {
        console.error(`check-npm-drift: the registry could not be read — ${(err as Error).message}`);
        return 2;
    }
    let release: ReleaseState | null = null;
    if (parts(manifestVersion)[0] !== 0) {
        try {
            release = await queryRelease(manifestVersion);
            problems.push(...decideReleaseAssets(manifestVersion, release));
        } catch (err) {
            console.error(`check-npm-drift: the GitHub release could not be read — ${(err as Error).message}`);
            return 2;
        }
    }
    if (argv.includes('--json')) {
        process.stdout.write(`${JSON.stringify({ ok: problems.length === 0, manifest: manifestVersion, satellites: Object.fromEntries(satelliteVersions), registry, release, problems }, null, 2)}\n`);
    } else {
        for (const p of problems) console.log(`drift: ${p}`);
        const seen = registry.found ? `latest ${registry.distTags['latest'] ?? '—'}, ${String(registry.versions.length)} version(s)` : 'absent';
        console.log(`check-npm-drift: manifest ${manifestVersion}, registry ${seen} — ${problems.length === 0 ? 'in agreement' : `${String(problems.length)} problem(s)`}`);
    }
    return problems.length === 0 ? 0 : 1;
}

// Run only when invoked directly (keeps the module import-safe for tests).
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    process.exit(await main(process.argv.slice(2)));
}
