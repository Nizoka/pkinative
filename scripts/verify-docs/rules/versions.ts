/**
 * pkinative — manifest and version rules
 * =======================================
 * `docs/assets/ecosystem.json` is the single source of truth for every
 * version, milestone and count the documentation quotes. These rules hold
 * its shape, and hold package.json, CITATION.cff and CHANGELOG.md to it.
 *
 * @module scripts/verify-docs/rules/versions
 */

import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

export const MANIFEST = 'docs/assets/ecosystem.json';
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

export interface Manifest {
    verifiedOn?: unknown;
    packages?: Record<string, { version?: unknown } | undefined>;
    milestones?: Record<string, unknown>;
    derived?: unknown;
    declared?: unknown;
}

/** The manifest's pkinative version, or null (manifest-shape reports why). */
export function manifestVersion(ctx: RuleContext): string | null {
    const parsed = readJson<Manifest>(ctx, MANIFEST);
    if ('finding' in parsed) return null;
    const v = parsed.value.packages?.['pkinative']?.version;
    return typeof v === 'string' ? v : null;
}

function packageVersion(ctx: RuleContext): string | null {
    const parsed = readJson<{ version?: unknown }>(ctx, 'package.json');
    return 'finding' in parsed || typeof parsed.value.version !== 'string' ? null : parsed.value.version;
}

const manifestShape: Rule = {
    id: 'manifest-shape',
    summary: 'docs/assets/ecosystem.json has a verifiedOn date, a semver pkinative version, milestone versions and the derived/declared blocks.',
    check(ctx) {
        const parsed = readJson<Manifest>(ctx, MANIFEST);
        if ('finding' in parsed) return [parsed.finding];
        const m = parsed.value;
        const out: Finding[] = [];
        if (typeof m.verifiedOn !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(m.verifiedOn)) {
            out.push(error(MANIFEST, 'verifiedOn must be a YYYY-MM-DD date (the day the documentation was last audited)'));
        }
        const version = m.packages?.['pkinative']?.version;
        if (typeof version !== 'string' || !SEMVER.test(version)) out.push(error(MANIFEST, 'packages.pkinative.version must be a semver string'));
        for (const [name, v] of Object.entries(m.milestones ?? {})) {
            if (typeof v !== 'string' || !SEMVER.test(v)) out.push(error(MANIFEST, `milestones.${name} must be a semver string`));
        }
        for (const block of ['derived', 'declared'] as const) {
            if (typeof m[block] !== 'object' || m[block] === null || Array.isArray(m[block])) out.push(error(MANIFEST, `${block} must be an object`));
        }
        return out;
    },
};

const packageVersionSync: Rule = {
    id: 'package-version-sync',
    summary: 'package.json version equals the manifest version.',
    check(ctx) {
        const pkg = packageVersion(ctx);
        const manifest = manifestVersion(ctx);
        if (pkg === null || manifest === null) return [];
        return pkg === manifest ? [] : [error('package.json', `version ${pkg} differs from ${MANIFEST} packages.pkinative.version ${manifest}`)];
    },
};

const installUrlVersion: Rule = {
    id: 'install-url-version',
    summary: 'Every release-tarball install command outside release-notes/ names the current version, in both the tag and the file name, and the prose that names the current minor beside it agrees — a frozen URL does not break, it quietly installs the wrong artefact.',
    check(ctx) {
        const version = packageVersion(ctx);
        if (version === null) return [];
        const minor = version.split('.').slice(0, 2).join('.');
        const sources = ['README.md', 'llms.txt', 'docs/agent-brief.md', ...ctx.list('docs').filter((p) => p.endsWith('.md'))];
        const out: Finding[] = [];
        for (const path of new Set(sources)) {
            const text = ctx.read(path);
            if (text === null) continue;
            for (const m of text.matchAll(/releases\/download\/v([0-9][^/\s]*)\/pkinative-([^\s"')`]+)\.tgz/g)) {
                if (m[1] === version && m[2] === version) continue;
                out.push(error(path, `installs pkinative-${m[2] ?? ''}.tgz from tag v${m[1] ?? ''}; package.json says ${version}`, lineContaining(text, m[0])));
            }
            // The two sentences that carry a bare `X.Y` next to those URLs.
            // release-prepare.ts deliberately does not rewrite them — they
            // change meaning at 1.0, not just digits — so the rule is what
            // remembers they exist.
            for (const m of text.matchAll(/\*\*Status: (\d+\.\d+) |\b(\d+\.\d+) is the release tarball\b/g)) {
                const quoted = m[1] ?? m[2] ?? '';
                if (quoted === minor) continue;
                out.push(error(path, `names minor ${quoted} beside the install command; package.json says ${minor}`, lineContaining(text, m[0])));
            }
        }
        return out;
    },
};

const citationVersionSync: Rule = {
    id: 'citation-version-sync',
    summary: 'CITATION.cff version equals package.json version.',
    check(ctx) {
        const text = ctx.read('CITATION.cff');
        if (text === null) return [error('CITATION.cff', 'missing')];
        const cited = /^version:\s*["']?([^"'\s]+)["']?\s*$/m.exec(text)?.[1];
        const pkg = packageVersion(ctx);
        if (cited === undefined) return [error('CITATION.cff', 'has no version field')];
        return pkg === null || cited === pkg ? [] : [error('CITATION.cff', `version ${cited} differs from package.json ${pkg}`, lineContaining(text, 'version:'))];
    },
};

const changelogCurrent: Rule = {
    id: 'changelog-current',
    summary: 'CHANGELOG.md has an entry for the current version, every release heading reads `## [X.Y.Z] – YYYY-MM-DD`, and the newest entry comes first.',
    check(ctx) {
        const FILE = 'CHANGELOG.md';
        const text = ctx.read(FILE);
        if (text === null) return [error(FILE, 'missing')];
        const out: Finding[] = [];
        const lines = text.replace(/\r\n/g, '\n').split('\n');
        const headings: Array<{ version: string; line: number }> = [];
        lines.forEach((l, i) => {
            if (!l.startsWith('## [')) return;
            const m = /^## \[(Unreleased|\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\](?: – (\d{4}-\d{2}-\d{2}))?$/.exec(l);
            if (!m) {
                out.push(error(FILE, 'release heading must read `## [X.Y.Z] – YYYY-MM-DD` (en dash) or `## [Unreleased]`', i + 1));
                return;
            }
            if (m[1] !== 'Unreleased' && m[2] === undefined) out.push(error(FILE, `release ${m[1]} has no date`, i + 1));
            if (m[1] === 'Unreleased' && m[2] !== undefined) out.push(error(FILE, '[Unreleased] carries no date', i + 1));
            headings.push({ version: m[1], line: i + 1 });
        });
        const unreleased = headings.findIndex((h) => h.version === 'Unreleased');
        if (unreleased > 0) out.push(error(FILE, '[Unreleased] must be the first entry', headings[unreleased].line));
        const pkg = packageVersion(ctx);
        if (pkg !== null && !headings.some((h) => h.version === pkg)) out.push(error(FILE, `has no entry for the current version ${pkg}`));
        const releases = headings.filter((h) => h.version !== 'Unreleased');
        const numeric = (v: string): number[] => v.split(/[.-]/).slice(0, 3).map(Number);
        for (let i = 1; i < releases.length; i++) {
            const [a, b] = [numeric(releases[i - 1].version), numeric(releases[i].version)];
            const newerFirst = a[0] !== b[0] ? a[0] > b[0] : a[1] !== b[1] ? a[1] > b[1] : a[2] >= b[2];
            if (!newerFirst) out.push(error(FILE, `${releases[i].version} is listed above an older release — newest first`, releases[i].line));
        }
        return out;
    },
};

export const VERSION_RULES: readonly Rule[] = [manifestShape, packageVersionSync, installUrlVersion, citationVersionSync, changelogCurrent];
