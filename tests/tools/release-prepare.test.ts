import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { planRelease, parseArgs, type ReleasePlan, type TreeReader } from '../../scripts/release-prepare.js';
import { runRules } from '../../scripts/verify-docs.js';
import { createMemoryContext, loadTextTree } from '../../scripts/verify-docs/context.js';
import { RULES } from '../../scripts/verify-docs/rules/index.js';
import { PRE_1_0_PROSE, eraText, stableSwap, type EraProseSwap } from '../../scripts/verify-docs/rules/freeze.js';
import { PRIMARY_INSTALL_DOCS } from '../../scripts/verify-docs/rules/versions.js';

/**
 * The 1.0.0 bump, rehearsed on an in-memory copy of the repository: the
 * release commit that can never be amended after its tag is planned here on
 * every run, and the rules that judge it are run on what it would write.
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
const kept = PRE_1_0_PROSE.filter((row) => row.at1 === 'kept');

async function problems(files: Readonly<Record<string, string>>, rule: string): Promise<string[]> {
    return (await runRules(createMemoryContext(files), RULES, rule)).map((p) => `${p.file}: ${p.message}`);
}

describe('release-prepare — the 1.0.0 bump', () => {
    const plan = planRelease(readerOf(releaseBranch()), { version: '1.0.0', date: DATE });
    const after = applied(releaseBranch(), plan);

    it('should plan the bump from 0.9 to 1.0.0 without a single failing row', () => {
        expect(failures(plan)).toEqual([]);
        expect(plan.failures).toBe(0);
        expect(after['package.json']).toMatch(/"version": "1\.0\.0"/);
    });

    it('should report one edit line for every stable-era swap of PRE_1_0_PROSE', () => {
        const prose = plan.lines.filter((l) => l.level === 'edit' && l.text.includes(': 1.0 prose — ')).map((l) => l.text);
        expect(prose).toEqual(swaps.map((row) => `${row.file}: 1.0 prose — ${row.why}`));
        expect(plan.lines.filter((l) => l.level === 'todo').map((l) => l.text.split(':')[0])).toEqual(['docs/assets/og-image.svg', 'docs/assets/social-preview.svg']);
    });

    it('should leave no "not on npm" phrase behind, keep every policy statement, and write every replacement', () => {
        for (const row of swaps) {
            expect(after[row.file], `${row.file} still says "${row.phrase}"`).not.toContain(row.phrase);
            expect(after[row.file], `${row.file} lacks the stable text of ${row.why}`).toContain(eraText(row.to, '1.0.0'));
        }
        for (const row of kept) expect(after[row.file]).toContain(row.phrase);
    });

    it('should pass release-era-prose and install-url-version on the tree it writes', async () => {
        expect(await problems(after, 'release-era-prose')).toEqual([]);
        expect(await problems(after, 'install-url-version')).toEqual([]);
        for (const doc of PRIMARY_INSTALL_DOCS) expect(after[doc]).toContain('npm install pkinative');
    });

    it('should keep the attested tarball, at 1.0.0, as the alternative in the README and the quick start', () => {
        for (const doc of ['README.md', 'docs/guides/quickstart.md']) {
            expect(after[doc]).toContain('releases/download/v1.0.0/pkinative-1.0.0.tgz');
            expect(after[doc]).toContain('gh attestation verify pkinative-1.0.0.tgz');
        }
        expect(after['docs/index.html']).not.toContain('releases/download/');
        expect(after['docs/agent-brief.md']).not.toContain('releases/download/');
        expect(after['docs/index.html']).toContain('<code>npm install pkinative</code>');
        expect(after['docs/index.html']).toContain('data-copy="npm install pkinative"');
    });

    it('should keep the JSON it swaps into parseable', () => {
        const manifest = JSON.parse(after['docs/assets/ecosystem.json'] ?? '') as { packages: { pkinative: { npm: string; version: string } } };
        expect(manifest.packages.pkinative.version).toBe('1.0.0');
        expect(manifest.packages.pkinative.npm).toMatch(/^published from 1\.0\.0/);
    });

    it('should refuse the whole bump when one span drifted from the table', () => {
        const drifted = releaseBranch();
        drifted['README.md'] = (drifted['README.md'] ?? '').replace('with Web Crypto doing every signature.', 'with Web Crypto doing most signatures.');
        const refused = planRelease(readerOf(drifted), { version: '1.0.0', date: DATE });
        expect(refused.failures).toBe(1);
        expect(failures(refused)).toEqual([expect.stringMatching(/^README\.md: the 1\.0 swap of the status line — the span it replaces is found 0 times, not once/)]);
    });

    it('should refuse a phrase found twice', () => {
        const row = swaps.find((r) => r.file === 'llms.txt');
        if (row === undefined) throw new Error('no llms.txt row');
        expect(stableSwap(`${row.phrase} ${row.phrase}`, row, '1.0.0')).toEqual({ problem: `"${row.phrase}" is found 2 times, not once` });
    });

    it('should plan a 1.x minor from the 1.0.0 tree without the rows the swap retired', async () => {
        const next = planRelease(readerOf(releaseBranch(after)), { version: '1.1.0', date: DATE });
        expect(failures(next)).toEqual([]);
        expect(next.lines.some((l) => l.text.includes('1.0 prose'))).toBe(false);
        const tree = applied(releaseBranch(after), next);
        expect(await problems(tree, 'release-era-prose')).toEqual([]);
        expect(await problems(tree, 'install-url-version')).toEqual([]);
        expect(tree['README.md']).toContain('releases/download/v1.1.0/pkinative-1.1.0.tgz');
        expect(tree['README.md']).toContain('**Status: 1.1 — stable, on npm.**');
    });

    it('should swap nothing on a 0.x bump', async () => {
        const patch = planRelease(readerOf(releaseBranch()), { version: '0.9.1', date: DATE });
        expect(failures(patch)).toEqual([]);
        expect(patch.lines.some((l) => l.text.includes('1.0 prose'))).toBe(false);
        const tree = applied(releaseBranch(), patch);
        expect(await problems(tree, 'release-era-prose')).toEqual([]);
        expect(await problems(tree, 'install-url-version')).toEqual([]);
    });

    it('should parse the command line as before', () => {
        expect(parseArgs(['--version', '1.0.0', '--date', DATE, '--dry-run'])).toEqual({ version: '1.0.0', date: DATE, dryRun: true });
        expect(parseArgs(['--version', '1.0'])).toBeNull();
    });
});

describe('release-era-prose and install-url-version across the 1.0 boundary', () => {
    it('should fire release-era-prose below 1.0.0 when a sentence drifts from the span its swap replaces', async () => {
        const files = { ...TREE, 'docs/index.html': (TREE['docs/index.html'] ?? '').replace('PKCS#12, with Web Crypto doing every signature.', 'PKCS#12, with Web Crypto doing most signatures.') };
        expect(await problems(files, 'release-era-prose')).toEqual([expect.stringMatching(/^docs\/index\.html: the 1\.0\.0 swap of the landing page hero would fail: the span it replaces is found 0 times/)]);
    });

    it('should fire install-url-version below 1.0.0 on `npm install pkinative`, which installs the name reservation', async () => {
        const files = { ...TREE, 'docs/guides/quickstart.md': `${TREE['docs/guides/quickstart.md'] ?? ''}\nOr: npm install pkinative\n` };
        expect(await problems(files, 'install-url-version')).toEqual([expect.stringContaining('docs/guides/quickstart.md: says `npm install pkinative` with package.json at 0.9.0 — below 1.0.0 that installs the empty 0.0.1 name reservation')]);
    });

    it('should fire install-url-version from 1.0.0 on an install page that does not name the registry', async () => {
        const plan = planRelease(readerOf(releaseBranch()), { version: '1.0.0', date: DATE });
        const files = applied(releaseBranch(), plan);
        files['docs/agent-brief.md'] = (files['docs/agent-brief.md'] ?? '').replace('`npm install pkinative`', '`npm install` from the registry');
        expect(await problems(files, 'install-url-version')).toEqual([expect.stringContaining('docs/agent-brief.md: does not say `npm install pkinative` with package.json at 1.0.0')]);
    });

    it('should fire install-url-version when the copy button copies another command than the one shown', async () => {
        const files = { ...TREE, 'docs/index.html': (TREE['docs/index.html'] ?? '').replace(/data-copy="[^"]*"/, 'data-copy="npm install pkinative"') };
        expect(await problems(files, 'install-url-version')).toEqual([
            expect.stringContaining('docs/index.html: says `npm install pkinative` with package.json at 0.9.0'),
            expect.stringContaining('docs/index.html: the copy button copies "npm install pkinative" beside a command that reads "npm install https://'),
        ]);
    });
});
