import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ARCHIVED_PATHS, CURRENT_FILES, CURRENT_TREES, findAllowList, parseAllowList, tagAvailable, vitestArguments } from '../../scripts/run-compat.js';

/**
 * pkinative — compat-previous
 * ============================================================
 * `scripts/run-compat.ts` runs the previous release's test suite, as tagged,
 * against the current sources. The run itself is the `compat-previous` job
 * of ci.yml; what is held here is what makes that run mean something: the
 * allow-list names a real tag and argues every exclusion, the trees the
 * runner copies exist, and no exclusion can swallow the engine's suites.
 */

const ROOT = resolve(import.meta.dirname, '..', '..');

describe('the allow-list of the previous release', () => {
    const path = findAllowList(ROOT);

    it('should exist, name the previous tag, and be the newest allow-list of the directory', () => {
        expect(path).not.toBeNull();
        const allow = parseAllowList(readFileSync(path as string, 'utf8'));
        expect(allow.tag).toMatch(/^v\d+\.\d+\.\d+$/);
        expect(path).toMatch(new RegExp(`allow-${allow.tag.slice(1).replace(/\./g, '\\.')}\\.json$`));
        // The tag is strictly older than the version under development.
        const current = (JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string }).version.split('.').map(Number);
        const previous = allow.tag.slice(1).split('.').map(Number);
        const cmp = previous.map((n, i) => n - (current[i] ?? 0)).find((d) => d !== 0) ?? 0;
        expect(cmp, `${allow.tag} is not older than ${current.join('.')}`).toBeLessThanOrEqual(0);
    });

    it('should never exclude a suite of the engine wholesale', () => {
        // The point of the run is the engine's behaviour. A directory-wide
        // exclusion is legitimate only for the suites that test the
        // repository itself; an engine directory is excluded file by file.
        const allow = parseAllowList(readFileSync(path as string, 'utf8'));
        const ENGINE = ['asn1', 'build', 'cms', 'core', 'crypto', 'hash', 'keys', 'oid', 'path', 'pem', 'revocation', 'verify', 'x509', 'fuzzing', 'security', 'property'];
        for (const e of allow.exclude) {
            expect(e.pattern, e.pattern).toMatch(/^tests\//);
            if (e.pattern.endsWith('/**')) {
                expect(e.kind, `${e.pattern} excludes a whole directory`).toBe('tree');
                for (const dir of ENGINE) expect(e.pattern, e.pattern).not.toBe(`tests/${dir}/**`);
            }
        }
        expect(allow.exclude.some((e) => e.pattern === 'tests/**' || e.pattern === '**')).toBe(false);
    });

    it('should pass the archived configuration and one --exclude per entry to vitest', () => {
        const args = vitestArguments({ tag: 'v1.0.0', exclude: [{ pattern: 'tests/docs/**', kind: 'tree', reason: 'x'.repeat(40) }, { pattern: 'tests/x509/a.test.ts', kind: 'behaviour', reason: 'y'.repeat(40) }] });
        expect(args).toEqual(['run', '--config', 'vitest.config.ts', '--exclude', 'tests/docs/**', '--exclude', 'tests/x509/a.test.ts']);
    });
});

describe('parseAllowList', () => {
    const entry = { pattern: 'tests/docs/**', kind: 'tree', reason: 'Repository-tree tests, not engine behaviour: covered by the current suite.' };
    const list = (over: Record<string, unknown>, tag: unknown = 'v1.0.0'): string => JSON.stringify({ tag, exclude: [{ ...entry, ...over }] });

    it('should accept a tag and argued exclusions', () => {
        expect(parseAllowList(list({}))).toEqual({ tag: 'v1.0.0', exclude: [entry] });
        expect(parseAllowList(JSON.stringify({ tag: 'v1.0.0', exclude: [] }))).toEqual({ tag: 'v1.0.0', exclude: [] });
    });

    it.each([
        ['a tag that is not vX.Y.Z', list({}, '1.0.0'), '"tag"'],
        ['a missing tag', JSON.stringify({ exclude: [] }), '"tag"'],
        ['exclusions that are not a list', JSON.stringify({ tag: 'v1.0.0', exclude: {} }), '"exclude"'],
        ['an exclusion without a pattern', list({ pattern: '' }), '"pattern"'],
        ['a reason that is a word, not a sentence', list({ reason: 'flaky' }), '"reason"'],
        ['an exclusion without a reason', list({ reason: undefined }), '"reason"'],
        ['a kind that is neither tree nor behaviour', list({ kind: 'skip' }), '"kind"'],
        ['an exclusion without a kind', list({ kind: undefined }), '"kind"'],
    ])('should refuse %s', (_what, text, needle) => {
        expect(() => parseAllowList(text)).toThrow(needle);
    });
});

describe('the trees the runner assembles', () => {
    it('should archive the suite, the recipes and the configuration of the tag — never its sources', () => {
        expect(ARCHIVED_PATHS).toEqual(['tests', 'recipes', 'vitest.config.ts']);
        expect(ARCHIVED_PATHS).not.toContain('src');
    });

    it('should copy the current sources and only paths that exist', () => {
        expect(CURRENT_TREES).toContain('src');
        for (const p of [...CURRENT_TREES, ...CURRENT_FILES]) expect(existsSync(join(ROOT, p)), p).toBe(true);
        // What is archived from the tag is never overwritten by a copy of today's.
        for (const tree of CURRENT_TREES) for (const archived of ARCHIVED_PATHS) expect(tree === archived || tree.startsWith(`${archived}/`), tree).toBe(false);
    });

    it('should say a tag that is not in the clone is not available, rather than run nothing', () => {
        expect(tagAvailable(ROOT, 'v0.0.0-never-tagged')).toBe(false);
    });
});
