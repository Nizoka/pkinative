import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TAG_HISTORY, applyTagHistory, checkTagEntry, openRepository, planTagHistory, tagMessage, type Repository, type TagEntry } from '../../scripts/tag-history.js';

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const ENTRY: TagEntry = { tag: 'v0.4.0', version: '0.4.0', commit: '0c63bf5' };

function fakeRepository(overrides: Partial<Repository> = {}): Repository {
    return {
        resolveCommit: (c) => `${c}0000000000000000000000000000000000`.slice(0, 40),
        isAncestorOfHead: () => true,
        fileAt: (_c, p) => (p === 'package.json' ? JSON.stringify({ version: '0.4.0' }) : null),
        tagTarget: () => null,
        workingFile: (p) => (p === 'CHANGELOG.md' ? '# Changelog\n\n## [0.4.0] – 2026-09-25\n' : p === 'release-notes/v0.4.0.md' ? '# pkinative v0.4.0\n\n> tagged, never released\n' : null),
        ...overrides,
    };
}

describe('TAG_HISTORY', () => {
    it('should list the eight prepared 0.x versions in order, without a 0.6.0', () => {
        expect(TAG_HISTORY.map((e) => e.version)).toEqual(['0.1.0', '0.2.0', '0.3.0', '0.4.0', '0.5.0', '0.7.0', '0.8.0', '0.9.0']);
        for (const e of TAG_HISTORY) expect(e.tag).toBe(`v${e.version}`);
    });

    it('should verify against this repository: every commit exists, is an ancestor of HEAD, carries its version and has its release note and CHANGELOG entry', () => {
        const repo = openRepository(ROOT);
        for (const entry of TAG_HISTORY) expect(checkTagEntry(entry, repo)).toEqual([]);
    });
});

describe('checkTagEntry', () => {
    it('should accept an entry whose commit, manifest, release note and changelog agree', () => {
        expect(checkTagEntry(ENTRY, fakeRepository())).toEqual([]);
    });

    it.each([
        ['a missing commit', { resolveCommit: () => null }, /does not exist/],
        ['a commit off the branch', { isAncestorOfHead: () => false }, /not an ancestor of HEAD/],
        ['a manifest at another version', { fileAt: () => JSON.stringify({ version: '0.3.0' }) }, /says 0\.3\.0, expected 0\.4\.0/],
        ['a missing release note', { workingFile: (p: string) => (p === 'CHANGELOG.md' ? '\n## [0.4.0] – x\n' : null) }, /release-notes\/v0\.4\.0\.md is missing/],
        ['a release note with another title', { workingFile: (p: string) => (p === 'CHANGELOG.md' ? '\n## [0.4.0] – x\n' : '# pkinative v0.5.0\n') }, /does not open with/],
        ['a missing CHANGELOG entry', { workingFile: (p: string) => (p === 'CHANGELOG.md' ? '# Changelog\n' : '# pkinative v0.4.0\n') }, /CHANGELOG\.md has no/],
        ['a tag already on another commit', { tagTarget: () => 'ffffffffffffffffffffffffffffffffffffffff' }, /already exists and points at fffffff/],
    ])('should refuse %s', (_label, overrides, pattern) => {
        const problems = checkTagEntry(ENTRY, fakeRepository(overrides as Partial<Repository>));
        expect(problems.length).toBeGreaterThan(0);
        expect(problems.some((p) => pattern.test(p))).toBe(true);
    });

    it('should accept a tag that already points at the listed commit, and plan nothing for it', () => {
        const repo = fakeRepository({ tagTarget: () => `0c63bf50000000000000000000000000000000000`.slice(0, 40) });
        expect(checkTagEntry(ENTRY, repo)).toEqual([]);
        expect(planTagHistory(repo, [ENTRY]).commands).toEqual([]);
    });
});

describe('planTagHistory', () => {
    it('should produce one annotated-tag command per entry, naming the commit and the release note title', () => {
        const { problems, commands } = planTagHistory(fakeRepository(), [ENTRY]);
        expect(problems).toEqual([]);
        expect(commands).toEqual([['tag', '-a', 'v0.4.0', '0c63bf5', '-m', tagMessage(ENTRY, 'pkinative v0.4.0')]]);
        expect(commands[0]?.[5]).toMatch(/^pkinative v0\.4\.0\n\nTagged after the fact/);
    });

    it('should collect every problem and plan no command when one entry fails', () => {
        const { problems, commands } = planTagHistory(fakeRepository({ isAncestorOfHead: () => false }), [ENTRY]);
        expect(problems).toHaveLength(1);
        expect(commands).toEqual([]);
    });
});

describe('applyTagHistory', () => {
    const plan = planTagHistory(fakeRepository(), [ENTRY]).commands;

    it('should refuse outside an interactive terminal and never call git — the agents\' shells are not interactive', () => {
        let calls = 0;
        const result = applyTagHistory(plan, () => { calls++; return 0; }, false);
        expect(result.ok).toBe(false);
        expect(result.message).toMatch(/interactive terminal/);
        expect(calls).toBe(0);
    });

    it('should run each command in order on a terminal and stop at the first failure', () => {
        const seen: string[][] = [];
        const ok = applyTagHistory(plan, (args) => { seen.push([...args]); return 0; }, true);
        expect(ok).toEqual({ ok: true, message: expect.stringMatching(/1 tag\(s\) created locally/) as string });
        expect(seen).toEqual(plan);
        const failing = applyTagHistory([...plan, ...plan], (args) => (args[2] === 'v0.4.0' ? 128 : 0), true);
        expect(failing.ok).toBe(false);
        expect(failing.message).toMatch(/exited 128; stopped/);
    });
});

describe('this checkout', () => {
    it('should still hold no 0.x tag created by an agent: the dry run plans all eight', () => {
        // If the maintainer has applied the tags, every one points where the table says and nothing is planned.
        const { problems, commands } = planTagHistory(openRepository(ROOT));
        expect(problems).toEqual([]);
        expect(commands.length === 0 || commands.length === TAG_HISTORY.length).toBe(true);
    });
});
