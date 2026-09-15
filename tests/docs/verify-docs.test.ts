import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { runRules } from '../../scripts/verify-docs.js';
import { createFsContext, createMemoryContext, loadTextTree } from '../../scripts/verify-docs/context.js';
import { RULES } from '../../scripts/verify-docs/rules/index.js';

/**
 * Every verify-docs rule, proven in both directions. The repository must pass
 * every rule; then, for each rule, one perturbation of an in-memory copy of
 * the repository must make exactly that rule fail. A rule that silently
 * matches nothing looks identical to a rule that passes — this table is what
 * tells them apart, and a rule without a row fails the suite.
 */

const ROOT = resolve(import.meta.dirname, '..', '..');
const TREE = loadTextTree(ROOT);

type Mutation = (files: Record<string, string>) => void;

function edit(files: Record<string, string>, path: string, from: string | RegExp, to: string): void {
    const text = files[path];
    if (text === undefined) throw new Error(`perturbation: ${path} is not in the tree`);
    const next = text.replace(from, to);
    if (next === text) throw new Error(`perturbation: ${String(from)} not found in ${path}`);
    files[path] = next;
}

const PERTURBATIONS: Readonly<Record<string, Mutation>> = {
    'manifest-shape': (f) => edit(f, 'docs/assets/ecosystem.json', /"verifiedOn": "[^"]+"/, '"verifiedOn": "yesterday"'),
    'package-version-sync': (f) => edit(f, 'package.json', /"version": "[^"]+"/, '"version": "9.9.9"'),
    'citation-version-sync': (f) => edit(f, 'CITATION.cff', /^version: .+$/m, 'version: 9.9.9'),
    'changelog-current': (f) => edit(f, 'CHANGELOG.md', /^## \[(\d+\.\d+\.\d+)\] – /m, '## [$1] - '),
    'claude-md-budget': (f) => edit(f, 'CLAUDE.md', /^@AGENTS\.md\n/, ''),
    'governance-sources': (f) => edit(f, '.github/ai-governance.json', '"AGENTS.md",', '"AGENTS.md",\n      "MISSING.md",'),
    'node-pin-parity': (f) => { f['.nvmrc'] = '20\n'; },
    'ruleset-parity': (f) => edit(f, '.github/rulesets/main.json', '"ci (22)"', '"ci (18)"'),
    'agent-config-parity': (f) => edit(f, '.claude/settings.json', '"commit": ""', '"commit": "Co-Authored-By: an agent"'),
    'claude-rules-sync': (f) => {
        const rule = Object.keys(f).find((p) => p.startsWith('.claude/rules/'));
        if (rule === undefined) throw new Error('no generated rule in the tree — run npm run agents:rules');
        f[rule] = `${f[rule]}\nEdited by hand.\n`;
    },
    'claude-rules-budget': (f) => { f['.claude/rules/unscoped.md'] = '---\ndescription: loads on every session\n---\nbody\n'; },
    'pr-template-parity': (f) => edit(f, '.github/pull_request_template.md', 'No `any` types introduced', 'No `any` types added'),
    'eol-lf': (f) => { f['CHANGELOG.md'] = (f['CHANGELOG.md'] ?? '').replace(/\n/g, '\r\n'); },
    'skills-shape': (f) => { f['.claude/skills/broken/SKILL.md'] = '# a skill without frontmatter\n'; },
    'layer-parity': (f) => edit(f, 'AGENTS.md', /^x509 +→ .+$/m, 'x509   → types, core, asn1, oid'),
    'prose-language': (f) => edit(f, 'README.md', /\n$/, '\nLe certificat est valide pour tous les domaines.\n'),
};

describe('verify-docs on the repository', () => {
    it('should report no error', async () => {
        const problems = await runRules(createFsContext(ROOT));
        expect(problems.filter((p) => p.severity === 'error')).toEqual([]);
    });

    it('should report no error on the in-memory copy either (the perturbation baseline)', async () => {
        const problems = await runRules(createMemoryContext(TREE));
        expect(problems.filter((p) => p.severity === 'error')).toEqual([]);
    });
});

describe('verify-docs rule table', () => {
    it('should have a perturbation for every rule, and no perturbation for a rule that does not exist', () => {
        expect(Object.keys(PERTURBATIONS).sort()).toEqual(RULES.map((r) => r.id).sort());
    });

    it('should give every rule a unique id and a summary', () => {
        expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
        for (const r of RULES) expect(r.summary.length, r.id).toBeGreaterThan(20);
    });

    it.each(Object.entries(PERTURBATIONS))('should fire %s on its perturbation', async (id, mutate) => {
        const files = { ...TREE };
        mutate(files);
        const problems = await runRules(createMemoryContext(files), RULES, id);
        expect(problems.filter((p) => p.severity === 'error').length, id).toBeGreaterThan(0);
    });

    it('should honour a verify-docs:allow suppression on the reported line or the line above', async () => {
        const files = { ...TREE };
        edit(files, 'README.md', /\n$/, '\n<!-- verify-docs:allow prose-language -->\nLe certificat est valide pour tous les domaines.\n');
        expect(await runRules(createMemoryContext(files), RULES, 'prose-language')).toEqual([]);
    });
});
