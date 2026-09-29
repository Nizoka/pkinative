import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { planRelease, parseArgs, type ReleasePlan, type TreeReader } from '../../scripts/release-prepare.js';
import { runRules } from '../../scripts/verify-docs.js';
import { createMemoryContext, loadTextTree } from '../../scripts/verify-docs/context.js';
import { RULES } from '../../scripts/verify-docs/rules/index.js';
import { PRE_1_0_PROSE, stableSwap, type EraProseSwap } from '../../scripts/verify-docs/rules/freeze.js';
import { PRIMARY_INSTALL_DOCS } from '../../scripts/verify-docs/rules/versions.js';

/**
 * The next release, rehearsed on an in-memory copy of the repository: the
 * release commit that can never be amended after its tag is planned here on
 * every run, and the rules that judge it are run on what it would write. The
 * 1.0.0 bump and its prose swap ran once, on the 1.0.0 release commit.
 */

const ROOT = resolve(import.meta.dirname, '..', '..');
const TREE = loadTextTree(ROOT);
const DATE = '2026-09-29';

const readerOf = (files: Readonly<Record<string, string>>): TreeReader => (path) => (Object.prototype.hasOwnProperty.call(files, path) ? files[path] ?? null : null);

/** The tree as the release branch has it: an `[Unreleased]` entry open on top of the CHANGELOG. */
function releaseBranch(files: Readonly<Record<string, string>> = TREE): Record<string, string> {
    const changelog = files['CHANGELOG.md'] ?? '';
    const at = changelog.search(/^## \[/m);
    if (at < 0) throw new Error('CHANGELOG.md has no release heading');
    return { ...files, 'CHANGELOG.md': `${changelog.slice(0, at)}## [Unreleased]\n\n- The release.\n\n${changelog.slice(at)}` };
}

const applied = (files: Readonly<Record<string, string>>, plan: ReleasePlan): Record<string, string> => ({ ...files, ...Object.fromEntries(plan.texts) });
const failures = (plan: ReleasePlan): string[] => plan.lines.filter((l) => l.level === 'FAIL').map((l) => l.text);
const swaps = PRE_1_0_PROSE.filter((row): row is EraProseSwap => row.at1 === 'absent');

async function problems(files: Readonly<Record<string, string>>, rule: string): Promise<string[]> {
    return (await runRules(createMemoryContext(files), RULES, rule)).map((p) => `${p.file}: ${p.message}`);
}

describe('release-prepare — the bumps after 1.0.0', () => {
    // The 1.0.0 bump itself ran once, on its release commit; what is planned
    // here on every run is the next release the tree can make.
    const minor = planRelease(readerOf(releaseBranch()), { version: '1.1.0', date: DATE });
    const after = applied(releaseBranch(), minor);

    it('should plan a 1.x minor without a failing row, a 1.0 swap or an image to re-rasterise', () => {
        expect(failures(minor)).toEqual([]);
        expect(minor.failures).toBe(0);
        expect(after['package.json']).toMatch(/"version": "1\.1\.0"/);
        expect(minor.lines.some((l) => l.text.includes('1.0 prose'))).toBe(false);
        expect(minor.lines.filter((l) => l.level === 'todo')).toEqual([]);
    });

    it('should pass release-era-prose and install-url-version on the tree it writes', async () => {
        expect(await problems(after, 'release-era-prose')).toEqual([]);
        expect(await problems(after, 'install-url-version')).toEqual([]);
        for (const doc of PRIMARY_INSTALL_DOCS) expect(after[doc]).toContain('npm install pkinative');
    });

    it('should move the attested tarball, the alternative install, to the new version and nowhere else', () => {
        for (const doc of ['README.md', 'docs/guides/quickstart.md']) {
            expect(after[doc]).toContain('releases/download/v1.1.0/pkinative-1.1.0.tgz');
            expect(after[doc]).toContain('gh attestation verify pkinative-1.1.0.tgz');
        }
        expect(after['README.md']).toContain('**Status: 1.1 — stable, on npm.**');
        expect(after['docs/index.html']).not.toContain('releases/download/');
        expect(after['docs/agent-brief.md']).not.toContain('releases/download/');
        expect(after['docs/index.html']).toContain('data-copy="npm install pkinative"');
    });

    it('should ratchet the snapshots of the compatibility promise, never rebase them', () => {
        const edits = minor.lines.filter((l) => l.level === 'edit').map((l) => l.text);
        expect(edits.some((l) => l.includes('rebased'))).toBe(false);
        expect(JSON.parse(after['docs/assets/api.frozen.json'] ?? '')).toMatchObject({ frozenAt: '1.0.0', phase: 'stable' });
        expect(JSON.parse(after['docs/data/refusals.frozen.json'] ?? '')).toMatchObject({ frozenAt: '1.0.0', phase: 'stable' });
        expect(JSON.parse(after['docs/data/errors.frozen.json'] ?? '')).toMatchObject({ frozenAt: '0.8.0' });
    });

    it('should keep the JSON it edits parseable', () => {
        const manifest = JSON.parse(after['docs/assets/ecosystem.json'] ?? '') as { packages: { pkinative: { npm: string; version: string } } };
        expect(manifest.packages.pkinative.version).toBe('1.1.0');
        expect(manifest.packages.pkinative.npm).toMatch(/^published from 1\.0\.0/);
    });

    it('should plan a 1.0.1 patch the same way', async () => {
        const patch = planRelease(readerOf(releaseBranch()), { version: '1.0.1', date: DATE });
        expect(failures(patch)).toEqual([]);
        const tree = applied(releaseBranch(), patch);
        expect(await problems(tree, 'release-era-prose')).toEqual([]);
        expect(await problems(tree, 'install-url-version')).toEqual([]);
        expect(tree['README.md']).toContain('releases/download/v1.0.1/pkinative-1.0.1.tgz');
    });

    it('should refuse a swap whose span is found twice, or not at all', () => {
        const row = swaps.find((r) => r.file === 'llms.txt');
        if (row === undefined) throw new Error('no llms.txt row');
        expect(stableSwap(`${row.phrase} ${row.phrase}`, row, '1.0.0')).toEqual({ problem: `"${row.phrase}" is found 2 times, not once` });
        expect(stableSwap('nothing to swap here', row, '1.0.0')).toMatchObject({ problem: expect.stringContaining('0 times') });
    });

    it('should parse the command line as before', () => {
        expect(parseArgs(['--version', '1.0.0', '--date', DATE, '--dry-run'])).toEqual({ version: '1.0.0', date: DATE, dryRun: true });
        expect(parseArgs(['--version', '1.0'])).toBeNull();
    });
});

describe('install-url-version from 1.0.0', () => {
    it('should fire on an install page that does not name the registry', async () => {
        const files = { ...TREE };
        files['docs/agent-brief.md'] = (files['docs/agent-brief.md'] ?? '').replace('`npm install pkinative`', '`npm install` from the registry');
        expect(await problems(files, 'install-url-version')).toEqual([expect.stringContaining('docs/agent-brief.md: does not say `npm install pkinative` with package.json at 1.0.0')]);
    });

    it('should fire when the copy button copies another command than the one shown', async () => {
        const files = { ...TREE, 'docs/index.html': (TREE['docs/index.html'] ?? '').replace(/data-copy="[^"]*"/, 'data-copy="npm install pkinative@0.9.0"') };
        expect(await problems(files, 'install-url-version')).toEqual([expect.stringContaining('docs/index.html: the copy button copies "npm install pkinative@0.9.0"')]);
    });
});
