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
    'error-parity': (f) => {
        const registry = JSON.parse(f['docs/data/errors.json'] ?? '{}') as { errors: unknown[] };
        registry.errors.shift();
        f['docs/data/errors.json'] = JSON.stringify(registry, null, 2);
    },
    'diagnostics-parity': (f) => edit(f, 'docs/data/diagnostics.json', '"PKI_DIAG_SAN_EMPTY"', '"PKI_DIAG_SAN_MISSING"'),
    'limits-parity': (f) => edit(f, 'SECURITY.md', /^\| `maxDepth` \| 64 \|/m, '| `maxDepth` | 65 |'),
    'api-json-sync': (f) => edit(f, 'docs/assets/api.json', /"exportCount": \d+/, '"exportCount": 0'),
    'tsdoc-complete': (f) => edit(f, 'src/asn1/asn1-oid.ts', ' * @throws Never.\n */\nexport function isValidOid', ' */\nexport function isValidOid'),
    'guide-render-sync': (f) => edit(f, 'docs/guides/errors.html', '<h1 id=', '<h1 class="stale" id='),
    'llms-sync': (f) => edit(f, 'docs/llms-full.txt', /\n$/, '\nstale\n'),
    'llms-index-sync': (f) => edit(f, 'docs/llms-index.json', /"approxTokens": \d+/, '"approxTokens": 0'),
    'llms-index-quality': (f) => edit(f, 'docs/llms-index.json', /"summary": "[^"]*"/, '"summary": "**too short**"'),
    'internal-links': (f) => edit(f, 'README.md', '[ROADMAP.md](ROADMAP.md)', '[ROADMAP.md](ROADMAP-missing.md)'),
    'anchor-parity': (f) => edit(f, 'docs/guides/quickstart.md', '[error guide](errors.md)', '[error guide](errors.md#no-such-heading)'),
    'seo-head': (f) => edit(f, 'docs/index.html', '<html lang="en">', '<html>'),
    'sitemap-parity': (f) => edit(f, 'docs/sitemap.xml', /\s*<url><loc>https:\/\/pkinative\.dev\/guides\/choose\.html<\/loc><\/url>/, ''),
    // api.json is what the rule reads; dropping a TSDoc in src/ would only make it stale.
    'member-tsdoc': (f) => edit(f, 'docs/assets/api.json', /"summary": "The algorithm OID[^"]*"/, '"summary": null'),
    // encodeSetOf is named in exactly one hand-written file, the primitives recipe.
    'export-named': (f) => edit(f, 'recipes/asn1-primitives.ts', /encodeSetOf/g, 'encodeSetOfXX'),
    'option-fields-named': (f) => edit(f, 'docs/guides/quickstart.md', 'allowTrailingData', 'allowTrailingDataXX'),
    'extension-kinds-complete': (f) => edit(f, 'docs/agent-brief.md', '`nameConstraints`', '`nameConstraint`'),
    'surfaces-parity': (f) => edit(f, 'docs/data/surfaces.json', '"decodePem"', '"decodePemText"'),
    'install-url-version': (f) => edit(f, 'docs/agent-brief.md', /releases\/download\/v[0-9][^/\s]*\//, 'releases/download/v9.9.9/'),
    'clean-url-safe': (f) => edit(f, 'docs/index.html', 'href="guides/"', 'href="guides/index.html"'),
    // Edit the SVG without re-rasterising: the recorded hash no longer matches.
    'social-images': (f) => edit(f, 'docs/assets/og-image.svg', '<rect', '<rect id="x"'),
    'jsonld-version': (f) => edit(f, 'docs/index.html', /"softwareVersion": "[^"]*"/, '"softwareVersion": "9.9.9"'),
    'verified-on-parity': (f) => edit(f, 'docs/index.html', /<time id="verified-on" datetime="[^"]+">[^<]+</, '<time id="verified-on" datetime="2020-01-01">2020-01-01<'),
    'contrast': (f) => edit(f, 'docs/style.css', /--c-text-dim: +#[0-9a-f]{6};/, '--c-text-dim:   #c0c0c0;'),
    'api-exists': (f) => edit(f, 'docs/agent-brief.md', "import { decodePem, getExtension", "import { decodePem, parsePemCertificates, getExtension"),
    'count-tokens': (f) => edit(f, 'README.md', /\d+ public exports/, '999 public exports'),
    'release-notes': (f) => edit(f, 'release-notes/v0.1.0.md', '## Downstream integration notes', '## Downstream notes'),
    'corpus-pin-parity': (f) => edit(f, 'THIRD-PARTY-NOTICES.md', '118721335e675edde10015df89b138cf292d7554', '0000000000000000000000000000000000000000'),
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

    it('should fire error-parity on a throw site whose message lacks the pkinative prefix', async () => {
        const files = { ...TREE };
        edit(files, 'src/core/pki-limits.ts', "'pkinative: options.limits must be", "'options.limits must be");
        const problems = await runRules(createMemoryContext(files), RULES, 'error-parity');
        expect(problems).toEqual([expect.objectContaining({ file: 'src/core/pki-limits.ts', message: expect.stringContaining('must start with "pkinative: "') })]);
    });

    it('should fire limits-parity on a CWE that disagrees between the interface and the registry', async () => {
        const files = { ...TREE };
        edit(files, 'src/types/pki-types.ts', 'nesting depth of constructed ASN.1 values. CWE-674.', 'nesting depth of constructed ASN.1 values. CWE-400.');
        const problems = await runRules(createMemoryContext(files), RULES, 'limits-parity');
        expect(problems.map((p) => p.message)).toEqual([expect.stringContaining('PkiLimits.maxDepth cites CWE-400')]);
    });

    it('should honour a verify-docs:allow suppression on the reported line or the line above', async () => {
        const files = { ...TREE };
        edit(files, 'README.md', /\n$/, '\n<!-- verify-docs:allow prose-language -->\nLe certificat est valide pour tous les domaines.\n');
        expect(await runRules(createMemoryContext(files), RULES, 'prose-language')).toEqual([]);
    });
});
