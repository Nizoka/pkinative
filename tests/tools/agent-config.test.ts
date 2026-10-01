import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
    CLAUDE_CONTEXT_BUDGET,
    EOL_LF_MODE,
    GUARDED_SHELL_TOOLS,
    HITL_BASH_DENY_FAMILIES,
    bannerFor,
    checkAgentConfigParity,
    checkClaudeRulesBudget,
    checkEol,
    checkNodeVersionPin,
    checkPrTemplateParity,
    checkSkillShape,
    checkTagRuleset,
    checklistItems,
    claudeImports,
    crlfTextFiles,
    denyEntryFor,
    diffRules,
    markdownSection,
    neverReadGlobs,
    parseInstruction,
    parseLsFilesEol,
    renderRule,
    ruleHasPaths,
    ruleNameFor,
    skillFileReferences,
} from '../../scripts/lib/agent-config.js';

/**
 * The pure functions behind the verify-docs rules `agent-config-parity`,
 * `claude-rules-sync`, `claude-rules-budget`, `pr-template-parity`, `eol-lf`,
 * `skills-shape` and the `.node-version` / `tags.json` extensions. Each check
 * is exercised with inline fixtures in both directions: the shape that passes
 * and the perturbation it exists to catch.
 */

const INSTRUCTION = `---\r\ndescription: "Core rules"\r\napplyTo: "src/asn1/**,src/x509/**"\r\n---\r\n# Core\r\n\r\n- Be strict.\r\n`;

const SETTINGS = JSON.stringify({
    attribution: { commit: '' },
    permissions: {
        deny: [
            'Read(dist/**)',
            'Read(coverage/**)',
            'Read(package-lock.json)',
            ...GUARDED_SHELL_TOOLS.flatMap((tool) => [
                `${tool}(npm publish*)`,
                `${tool}(git push *)`,
                `${tool}(gh pr create*)`,
                `${tool}(gh issue create*)`,
                `${tool}(gh release *)`,
            ]),
        ],
    },
    hooks: {
        PreToolUse: GUARDED_SHELL_TOOLS.map((matcher) => ({
            matcher,
            hooks: [{ type: 'command', command: 'node .claude/hooks/guard.mjs' }],
        })),
    },
});

const CLAUDE_MD = `@AGENTS.md\n\n## Token discipline\n\n- Never Read \`dist/\`, \`coverage/\`, \`package-lock.json\`.\n  The deny list in \`.claude/settings.json\` applies to Read.\n- Other bullet \`docs/assets/api.json\`.\n`;

const HOOK_OK = { exists: true, checkStatus: 0, checkStderr: '' };

describe('agent-config — generated Claude rules', () => {
    it('should parse applyTo (comma-separated, quoted, CRLF) and strip the frontmatter from the body', () => {
        const parsed = parseInstruction(INSTRUCTION);
        expect(parsed).toMatchObject({ applyTo: ['src/asn1/**', 'src/x509/**'], description: 'Core rules' });
        if ('error' in parsed) throw new Error(parsed.error);
        expect(parsed.body.startsWith('# Core')).toBe(true);
        expect(parsed.body).not.toContain('\r');
    });

    it('should refuse a source without applyTo or without frontmatter', () => {
        expect(parseInstruction('---\ndescription: x\n---\nbody')).toHaveProperty('error', expect.stringContaining('applyTo'));
        expect(parseInstruction('# no frontmatter')).toHaveProperty('error', expect.stringContaining('frontmatter'));
    });

    it('should render a scoped rule with the banner, LF endings and one trailing newline', () => {
        const rendered = renderRule('pki-core.instructions.md', INSTRUCTION);
        expect(typeof rendered).toBe('string');
        expect(rendered).toBe(`---\npaths:\n  - "src/asn1/**"\n  - "src/x509/**"\n---\n${bannerFor('pki-core.instructions.md')}\n\n# Core\n\n- Be strict.\n`);
        expect(ruleHasPaths(rendered as string)).toBe(true);
        expect(ruleNameFor('pki-core.instructions.md')).toBe('pki-core.md');
    });

    it('should report stale, missing, extra and invalid rules, and be clean on a fresh render', () => {
        const fresh = renderRule('pki-core.instructions.md', INSTRUCTION) as string;
        const clean = diffRules({ 'pki-core.instructions.md': INSTRUCTION }, { 'pki-core.md': fresh });
        expect(clean).toMatchObject({ stale: [], missing: [], extra: [], invalid: [] });
        // CRLF in the working copy is not drift (eol-lf owns line endings).
        expect(diffRules({ 'pki-core.instructions.md': INSTRUCTION }, { 'pki-core.md': fresh.replace(/\n/g, '\r\n') }).stale).toEqual([]);
        const drift = diffRules(
            { 'pki-core.instructions.md': INSTRUCTION, 'testing.instructions.md': INSTRUCTION, 'bad.instructions.md': '# nope' },
            { 'pki-core.md': `${fresh}\nedited by hand\n`, 'orphan.md': '---\npaths:\n  - "x"\n---\n' },
        );
        expect(drift.stale).toEqual(['pki-core.md']);
        expect(drift.missing).toEqual(['testing.md']);
        expect(drift.extra).toEqual(['orphan.md']);
        expect(drift.invalid).toEqual([{ source: 'bad.instructions.md', error: expect.stringContaining('frontmatter') }]);
    });

    it('should say an unscoped rule has no paths', () => {
        expect(ruleHasPaths('---\ndescription: x\n---\nbody')).toBe(false);
        expect(ruleHasPaths('no frontmatter')).toBe(false);
    });
});

describe('agent-config — agent-config-parity', () => {
    it('should derive the Never Read globs from the CLAUDE.md bullet and map them to deny entries', () => {
        expect(neverReadGlobs(CLAUDE_MD)).toEqual(['dist/', 'coverage/', 'package-lock.json']);
        expect(denyEntryFor('coverage/')).toBe('Read(coverage/**)');
        expect(denyEntryFor('docs/*.png')).toBe('Read(docs/*.png)');
        expect(neverReadGlobs('# nothing')).toEqual([]);
    });

    it('should pass a consistent settings / CLAUDE.md / hook triple', () => {
        expect(checkAgentConfigParity({ settingsText: SETTINGS, claudeMd: CLAUDE_MD, hook: HOOK_OK })).toEqual([]);
    });

    it('should fail when a Never Read glob has no deny entry', () => {
        const settings = SETTINGS.replace('"Read(coverage/**)",', '');
        const findings = checkAgentConfigParity({ settingsText: settings, claudeMd: CLAUDE_MD, hook: HOOK_OK });
        expect(findings.map((f) => f.message)).toEqual([expect.stringContaining('Read(coverage/**)')]);
    });

    it('should require the deny list and a guard matcher for every shell tool, not only Bash', () => {
        // A family denied for one shell and allowed for the other is not
        // denied. On a Windows machine PowerShell is the primary shell, so
        // the Bash-only list this repository shipped until now had a door
        // in it — and guard.mjs, which already parses `pwsh -Command`
        // payloads, was never invoked to use them.
        expect(GUARDED_SHELL_TOOLS).toEqual(['Bash', 'PowerShell']);
        for (const tool of GUARDED_SHELL_TOOLS) {
            const noRelease = SETTINGS.replace(`"${tool}(gh release *)"`, `"${tool}(gh run *)"`);
            expect(checkAgentConfigParity({ settingsText: noRelease, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message))
                .toEqual([expect.stringContaining(`${tool}(gh release`)]);

            const unmatched = JSON.stringify({
                ...JSON.parse(SETTINGS) as Record<string, unknown>,
                hooks: { PreToolUse: GUARDED_SHELL_TOOLS.filter((t) => t !== tool).map((matcher) => ({ matcher, hooks: [{ type: 'command', command: 'node .claude/hooks/guard.mjs' }] })) },
            });
            expect(checkAgentConfigParity({ settingsText: unmatched, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message))
                .toEqual([expect.stringContaining(`no ${tool} matcher`)]);
        }
    });

    it('should fail on a missing HITL family, a non-empty attribution, an unwired hook, a broken hook and invalid JSON', () => {
        expect(HITL_BASH_DENY_FAMILIES).toHaveLength(5);
        const trailer = SETTINGS.replace('"commit":""', '"commit":"Co-Authored-By: x"');
        expect(checkAgentConfigParity({ settingsText: trailer, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message)).toEqual([expect.stringContaining('attribution.commit')]);
        const unwired = SETTINGS.replace('guard.mjs', 'other.mjs');
        expect(checkAgentConfigParity({ settingsText: unwired, claudeMd: CLAUDE_MD, hook: HOOK_OK }).map((f) => f.message)).toEqual([expect.stringContaining('PreToolUse')]);
        const broken = checkAgentConfigParity({ settingsText: SETTINGS, claudeMd: CLAUDE_MD, hook: { exists: true, checkStatus: 1, checkStderr: 'SyntaxError: x\n' } });
        expect(broken).toEqual([expect.objectContaining({ file: '.claude/hooks/guard.mjs', message: expect.stringContaining('SyntaxError') })]);
        expect(checkAgentConfigParity({ settingsText: SETTINGS, claudeMd: CLAUDE_MD, hook: { exists: false, checkStatus: null, checkStderr: '' } })[0].message).toContain('missing');
        expect(checkAgentConfigParity({ settingsText: '{', claudeMd: CLAUDE_MD, hook: HOOK_OK })[0].message).toContain('not valid JSON');
        expect(checkAgentConfigParity({ settingsText: null, claudeMd: CLAUDE_MD, hook: HOOK_OK })[0].message).toContain('missing');
    });
});

describe('agent-config — claude-rules-budget', () => {
    const scoped = '---\npaths:\n  - "src/**"\n---\nbody\n';
    it('should sum CLAUDE.md, its @imports and unscoped rules against the 16 KiB budget', () => {
        expect(claudeImports(CLAUDE_MD)).toEqual(['AGENTS.md']);
        expect(checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => 'x'.repeat(1000), rules: { 'a.md': scoped } })).toEqual([]);
        const over = checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => 'x'.repeat(CLAUDE_CONTEXT_BUDGET), rules: {} });
        expect(over).toEqual([expect.objectContaining({ severity: 'error', message: expect.stringContaining('always loaded') })]);
    });

    it('should fail an unscoped rule and a missing import, and warn on a scoped rule over 32 KiB', () => {
        const unscoped = checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => '', rules: { 'free.md': '---\ndescription: x\n---\nbody' } });
        expect(unscoped).toEqual([expect.objectContaining({ file: '.claude/rules/free.md', severity: 'error', message: expect.stringContaining('paths') })]);
        expect(checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => null, rules: {} })[0].message).toContain('@AGENTS.md');
        const big = checkClaudeRulesBudget({ claudeMd: CLAUDE_MD, resolveImport: () => '', rules: { 'big.md': `${scoped}${'y'.repeat(33 * 1024)}` } });
        expect(big).toEqual([expect.objectContaining({ severity: 'warn', file: '.claude/rules/big.md' })]);
    });
});

describe('agent-config — pr-template-parity', () => {
    const CONTRIBUTING = '# C\n\n## Pull Request Checklist\n\n- [ ] `npm run gate` passes\n- [ ] New code has tests\n\n## Commit Messages\n\n- [ ] not a checklist item of the section\n';
    it('should extract checklist items and sections', () => {
        expect(checklistItems('- [ ] a\n- [x] b\n- c\n')).toEqual(['a', 'b']);
        expect(markdownSection(CONTRIBUTING, 'Pull Request Checklist')).toContain('New code has tests');
        expect(markdownSection(CONTRIBUTING, 'Pull Request Checklist')).not.toContain('not a checklist item');
        expect(markdownSection(CONTRIBUTING, 'Nope')).toBeNull();
    });

    it('should pass a template whose items are verbatim and mention the gate', () => {
        expect(checkPrTemplateParity('## Checklist\n\n- [ ] `npm run gate` passes\n- [ ] New code has tests\n', CONTRIBUTING)).toEqual([]);
    });

    it('should tolerate re-pointed link targets but not reworded link text', () => {
        const contributing = '## Pull Request Checklist\n\n- [ ] `npm run gate` passes — see [Release](#release)\n';
        expect(checklistItems(contributing)).toEqual(['`npm run gate` passes — see [Release]']);
        expect(checkPrTemplateParity('- [ ] `npm run gate` passes — see [Release](../CONTRIBUTING.md#release)\n', contributing)).toEqual([]);
        expect(checkPrTemplateParity('- [ ] `npm run gate` passes — see [Releasing](../CONTRIBUTING.md#release)\n', contributing)).toHaveLength(1);
    });

    it('should fail a reworded item, a template without the gate, a missing template and a missing section', () => {
        const reworded = checkPrTemplateParity('- [ ] `npm run gate` passes\n- [ ] New code has unit tests\n', CONTRIBUTING);
        expect(reworded).toEqual([expect.objectContaining({ line: 2, message: expect.stringContaining('New code has unit tests') })]);
        expect(checkPrTemplateParity('- [ ] New code has tests\n', CONTRIBUTING).map((f) => f.message)).toEqual([expect.stringContaining('npm run gate')]);
        expect(checkPrTemplateParity(null, CONTRIBUTING)[0].message).toContain('missing');
        expect(checkPrTemplateParity('- [ ] x', '# no section')[0].file).toBe('CONTRIBUTING.md');
    });
});

describe('agent-config — eol-lf', () => {
    const LS = [
        'i/lf    w/lf    attr/text=auto eol=lf     \tsrc/index.ts',
        'i/crlf  w/crlf  attr/text=auto eol=lf     \tCHANGELOG.md',
        'i/mixed w/mixed attr/text=auto eol=lf     \tdocs/x.md',
        'i/crlf  w/crlf  attr/-text linguist-vendored=true\tvendor/data.txt',
        'i/-text w/-text attr/binary               \ttests/fixtures/isrg-root-x1.der',
        'i/crlf  w/crlf  attr/binary                \tweird.bin',
        'i/none  w/none  attr/text=auto eol=lf     \tempty.txt',
    ].join('\n');

    it('should parse the ls-files table and keep only CRLF/mixed text blobs', () => {
        expect(parseLsFilesEol(LS)).toHaveLength(7);
        expect(crlfTextFiles(parseLsFilesEol(LS)).map((e) => e.path)).toEqual(['CHANGELOG.md', 'docs/x.md']);
    });

    it('should fail from the first commit, and warn only when asked to', () => {
        expect(EOL_LF_MODE).toBe('fail');
        expect(checkEol(LS).map((f) => f.severity)).toEqual(['error', 'error']);
        expect(checkEol(LS, 'warn').map((f) => f.severity)).toEqual(['warn', 'warn']);
        expect(checkEol(LS)[0]).toMatchObject({ file: 'CHANGELOG.md', message: expect.stringContaining('CRLF') });
        expect(checkEol('')).toEqual([]);
    });
});

describe('agent-config — node-pin-parity (.node-version)', () => {
    it('should pass when the pin equals the engines major and the CI floor', () => {
        expect(checkNodeVersionPin({ nodeVersion: '22\n', enginesNode: '>=22', ciMatrix: [22, 24] })).toEqual([]);
    });

    it('should fail a missing file, a disagreeing major, a higher CI floor and a non-version', () => {
        expect(checkNodeVersionPin({ nodeVersion: null, enginesNode: '>=22', ciMatrix: [22] })[0].message).toContain('missing');
        expect(checkNodeVersionPin({ nodeVersion: '20\n', enginesNode: '>=22', ciMatrix: [22] }).map((f) => f.message)).toEqual([
            expect.stringContaining('engines.node'),
            expect.stringContaining('lowest CI matrix'),
        ]);
        expect(checkNodeVersionPin({ nodeVersion: 'lts/*\n', enginesNode: '>=22', ciMatrix: [] })[0].message).toContain('not a Node version');
        expect(checkNodeVersionPin({ nodeVersion: '22', enginesNode: '>=22', ciMatrix: [] })).toEqual([expect.objectContaining({ severity: 'warn', message: expect.stringContaining('trailing newline') })]);
    });
});

describe('agent-config — ruleset-parity (tags.json)', () => {
    const TAGS = { name: 'tags', target: 'tag', conditions: { ref_name: { include: ['refs/tags/v*'], exclude: [] } }, rules: [{ type: 'deletion' }, { type: 'non_fast_forward' }, { type: 'update' }] };
    it('should pass a tag ruleset that protects refs/tags/v* against deletion, force and update', () => {
        expect(checkTagRuleset(JSON.stringify(TAGS))).toEqual([]);
    });

    it('should fail a missing file, invalid JSON, a branch target, a missing include, a missing rule and a creation rule', () => {
        expect(checkTagRuleset(null)[0].message).toContain('missing');
        expect(checkTagRuleset('{')[0].message).toContain('not valid JSON');
        expect(checkTagRuleset(JSON.stringify({ ...TAGS, target: 'branch' })).map((f) => f.message)).toEqual([expect.stringContaining('"tag"')]);
        expect(checkTagRuleset(JSON.stringify({ ...TAGS, conditions: { ref_name: { include: ['~ALL'] } } })).map((f) => f.message)).toEqual([expect.stringContaining('refs/tags/v*')]);
        expect(checkTagRuleset(JSON.stringify({ ...TAGS, rules: [{ type: 'deletion' }] })).map((f) => f.message)).toEqual([
            expect.stringContaining('non_fast_forward'),
            expect.stringContaining('"update"'),
        ]);
        expect(checkTagRuleset(JSON.stringify({ ...TAGS, rules: [...TAGS.rules, { type: 'creation' }] })).map((f) => f.message)).toEqual([expect.stringContaining('creation')]);
    });
});

describe('agent-config — skills-shape', () => {
    const SKILL = '---\nname: release-audit\ndescription: Audit a release.\ndisable-model-invocation: true\n---\n# Audit\n\nRead `ledger.md` and `docs/assets/ecosystem.json`; write under `test-output/.audit/<version>/`; the note is `release-notes/vX.Y.Z.md`.\n';
    const files = new Set(['ledger.md']);
    const repo = new Set(['docs/assets/ecosystem.json']);
    const input = (overrides: Partial<Parameters<typeof checkSkillShape>[0]> = {}): Parameters<typeof checkSkillShape>[0] => ({
        dir: 'release-audit',
        text: SKILL,
        existsInSkill: (n: string) => files.has(n),
        existsInRepo: (p: string) => repo.has(p),
        ...overrides,
    });

    it('should collect sibling and repository references and skip placeholders', () => {
        expect(skillFileReferences(SKILL)).toEqual({ siblings: ['ledger.md'], repo: ['docs/assets/ecosystem.json'] });
    });

    it('should pass a well-formed skill', () => {
        expect(checkSkillShape(input())).toEqual([]);
    });

    it('should fail a name that differs from the directory, a missing description, a missing template and a missing SKILL.md', () => {
        expect(checkSkillShape(input({ dir: 'audit' })).map((f) => f.message)).toEqual([expect.stringContaining('"audit"')]);
        expect(checkSkillShape(input({ text: SKILL.replace('description: Audit a release.', 'description:') })).map((f) => f.message)).toEqual([expect.stringContaining('description')]);
        expect(checkSkillShape(input({ existsInSkill: () => false })).map((f) => f.message)).toEqual([expect.stringContaining('ledger.md')]);
        expect(checkSkillShape(input({ existsInRepo: () => false })).map((f) => f.message)).toEqual([expect.stringContaining('ecosystem.json')]);
        expect(checkSkillShape(input({ text: null }))[0].message).toContain('missing');
        expect(checkSkillShape(input({ text: '# no frontmatter' }))[0].message).toContain('frontmatter');
    });
});

describe('agent-config — skills declared both ways (ai-governance.json)', () => {
    // The governance rule checked only declared → exists, so a tracked skill
    // that SECURITY.md cites as a control could sit undeclared in the
    // machine-readable manifest (audit P-13). This holds the other direction
    // on the real tree until the verify-docs rule checks both.
    const ROOT = process.cwd();
    const governance = JSON.parse(readFileSync(join(ROOT, '.github', 'ai-governance.json'), 'utf8')) as {
        capability_manifest: { claude_code: { skills: Array<{ name: string; path: string; model_invocable: boolean }> } };
    };
    const declared = governance.capability_manifest.claude_code.skills;
    const tracked = readdirSync(join(ROOT, '.claude', 'skills'), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();

    it('should declare every tracked skill, and track every declared one', () => {
        expect(declared.map((s) => s.name).sort()).toEqual(tracked);
        for (const skill of declared) {
            expect(skill.path).toBe(`.claude/skills/${skill.name}/SKILL.md`);
            expect(existsSync(join(ROOT, skill.path)), skill.path).toBe(true);
        }
    });

    it('should mark a skill model-invocable exactly when its SKILL.md allows it', () => {
        for (const skill of declared) {
            const text = readFileSync(join(ROOT, skill.path), 'utf8');
            const disabled = /^disable-model-invocation:\s*true\s*$/m.test(text);
            expect(skill.model_invocable, skill.name).toBe(!disabled);
        }
    });
});
