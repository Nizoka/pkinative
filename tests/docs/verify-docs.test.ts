import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { runRules } from '../../scripts/verify-docs.js';
import { createFsContext, createMemoryContext, loadTextTree } from '../../scripts/verify-docs/context.js';
import { RULES } from '../../scripts/verify-docs/rules/index.js';
import { PRE_1_0_PROSE } from '../../scripts/verify-docs/rules/freeze.js';

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
    // A rename done in the registry: error-parity would also see the union
    // disagree, but only the snapshot knows the old name was a promise.
    'error-codes-frozen': (f) => edit(f, 'docs/data/errors.json', '"PKI_API_MISUSE"', '"PKI_API_MISUSED"'),
    'diagnostics-parity': (f) => edit(f, 'docs/data/diagnostics.json', '"PKI_DIAG_SAN_EMPTY"', '"PKI_DIAG_SAN_MISSING"'),
    'limits-parity': (f) => edit(f, 'SECURITY.md', /^\| `maxDepth` \| 64 \|/m, '| `maxDepth` | 65 |'),
    // The defect that matters: the prose quietly granting an operation the
    // check still refuses. "nowhere" is the only honest value for these.
    'key-operation-parity': (f) => edit(f, 'SECURITY.md', /^\| `generateKey` \| nowhere \|/m, '| `generateKey` | `src/crypto/webcrypto.ts` |'),
    // The same defect for passwords: the prose opening a scheme the code refuses.
    'pkcs12-policy-parity': (f) => edit(f, 'SECURITY.md', /(`1\.2\.840\.113549\.1\.12\.1\.3` \| )refuses/, '$1opens'),
    'api-json-sync': (f) => edit(f, 'docs/assets/api.json', /"exportCount": \d+/, '"exportCount": 0'),
    // The failure to catch is a budget raised for a surface that grew
    // without anyone restating how much it grew.
    'type-surface-parity': (f) => edit(f, 'docs/assets/ecosystem.json', /"exportedTypes": \d+/, '"exportedTypes": 1'),
    // The change a rehearsal exists to refuse: a compatible one. An optional
    // parameter breaks nobody, and 0.9 still admits no new behaviour.
    'api-surface-frozen': (f) => edit(f, 'src/asn1/asn1-oid.ts', 'export function isValidOid(oid: string): boolean {', 'export function isValidOid(oid: string, strict?: boolean): boolean {'),
    // What a regenerated baseline shows when a new check pre-empts an old
    // one: the same certificate, refused with another code.
    'refusal-baseline-frozen': (f) => edit(f, 'scripts/data/limbo-refusals.json', /("0014e18b[0-9a-f]{56}": )"PKI_X509_GENERAL_NAME_INVALID"/, '$1"PKI_X509_EXTENSION_MALFORMED"'),
    // A leg held by a rule that does not exist is a promise held by nothing.
    'contracts-shape': (f) => edit(f, 'docs/assets/ecosystem.json', '"rules": ["refusal-baseline-frozen"]', '"rules": ["refusal-baseline-held"]'),
    // Below 1.0.0 the sentence must be there; the 1.0 direction is proven below.
    'release-era-prose': (f) => edit(f, 'llms.txt', 'Versions below 1.0 are git tags, not npm releases. ', ''),
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
    // A field the quick start alone names: `allowTrailingData` is also the PDF /Contents option of the CMS docs now.
    'option-fields-named': (f) => edit(f, 'docs/guides/quickstart.md', 'timeType', 'timeTypeXX'),
    'extension-kinds-complete': (f) => edit(f, 'docs/agent-brief.md', '`nameConstraints`', '`nameConstraint`'),
    'surfaces-parity': (f) => edit(f, 'docs/data/surfaces.json', '"decodePem"', '"decodePemText"'),
    'install-url-version': (f) => edit(f, 'docs/agent-brief.md', /releases\/download\/v[0-9][^/\s]*\//, 'releases/download/v9.9.9/'),
    // One edit, both halves: the comment states no reason, and the count is now 2 against a declared 1.
    'coverage-ignore-budget': (f) => edit(f, 'src/core/bytes.ts', /^const HEX_DIGITS/m, '/* v8 ignore next */\nconst HEX_DIGITS'),
    // A field L4 compares, dropped from the guide that documents the contract.
    'validator-record-parity': (f) => edit(f, 'docs/guides/conformance.md', '`spkiKeyFp256`', '`spkiKeyFingerprint`'),
    // Strip the first integrity attribute — the Prism theme stylesheet.
    'cdn-sri': (f) => edit(f, 'docs/index.html', /\s+integrity="sha384-[^"]+"/, ''),
    // The landing nav drifting from the one the generator writes into the guides.
    'chrome-parity': (f) => edit(f, 'docs/index.html', '<a class="nav-brand"', '<a class="brand"'),
    'clean-url-safe': (f) => edit(f, 'docs/index.html', 'href="guides/"', 'href="guides/index.html"'),
    // Edit the SVG without re-rasterising: the recorded hash no longer matches.
    'social-images': (f) => edit(f, 'docs/assets/og-image.svg', '<rect', '<rect id="x"'),
    'jsonld-version': (f) => edit(f, 'docs/index.html', /"softwareVersion": "[^"]*"/, '"softwareVersion": "9.9.9"'),
    'verified-on-parity': (f) => edit(f, 'docs/index.html', /<time id="verified-on" datetime="[^"]+">[^<]+</, '<time id="verified-on" datetime="2020-01-01">2020-01-01<'),
    'contrast': (f) => edit(f, 'docs/style.css', /--c-text-dim: +#[0-9a-f]{6};/, '--c-text-dim:   #c0c0c0;'),
    'api-exists': (f) => edit(f, 'docs/agent-brief.md', "import { decodePem, getExtension", "import { decodePem, parsePemCertificates, getExtension"),
    'count-tokens': (f) => edit(f, 'README.md', /\d+ public exports/, '999 public exports'),
    // The defect this rule exists for, and the only one a hermetic run can
    // see: an engine source edited while the committed bundle stays behind.
    // A hash typo would also fire, but proving that would prove nothing.
    'playground-freshness': (f) => edit(f, 'src/oid/oid-names.ts', /\n$/, '\n// a source edited without rebuilding the playground\n'),
    'release-notes': (f) => edit(f, 'release-notes/v0.1.0.md', '## Downstream integration notes', '## Downstream notes'),
    // The defect this rule exists for: a release whose pull-request body is
    // not in the record, so nobody can check a year later whether a figure
    // came from a command or from somebody's memory.
    'release-pr-drafts': (f) => { delete f['release-notes/draft/PR-v0.1.0.md']; },
    'corpus-pin-parity': (f) => edit(f, 'THIRD-PARTY-NOTICES.md', '118721335e675edde10015df89b138cf292d7554', '0000000000000000000000000000000000000000'),
    // Two benchmarks with one name: every results table is keyed by name, so
    // the record becomes unreadable exactly when someone comes back to it.
    'bench-parity': (f) => edit(f, 'bench/asn1-x509.bench.ts', "bench('encodeExtensions — 3 extensions'", "bench('encodeDistinguishedName — 2 RDNs'"),
    // The conformance guide stops describing the level that makes the gate an
    // authority rather than a regression detector.
    'clause-table-complete': (f) => edit(f, 'docs/guides/conformance.md', /- \*\*L5 —[\s\S]*?\n- \*\*Wycheproof/, '- **Wycheproof'),
    // The workflow stops running the write direction, so the matrix becomes a
    // script nothing invokes on the three platforms that matter.
    'interop-matrix-declared': (f) => edit(f, '.github/workflows/conformance.yml', 'run: npm run interop', 'run: echo skipped'),
    // A reason message takes the prefix that belongs to thrown errors, which
    // is how a log reader stops being able to tell a verdict from an
    // exception. Decided from the syntax tree, so this has to be a real
    // string literal and not a mention in a comment.
    'reason-parity': (f) => edit(f, 'src/core/pki-reasons.ts', "'the issuer\\'s public key does not verify", "'pkinative: the issuer\\'s public key does not verify"),
    // A record dropped from the index is a decision nobody finds.
    'adr-index': (f) => edit(f, 'docs/adr/README.md', /^\| \[0003\]\(.*\n/m, ''),
    'prose-language': (f) => edit(f, 'README.md', /\n$/, '\nLe certificat est valide pour tous les domaines.\n'),
    // The one defect only the hermetic half can see without a build: a legal
    // text that ships, edited without the pinned list being regenerated.
    'package-files-parity': (f) => edit(f, 'LICENSE', 'MIT License', 'MIT Licence'),
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

    it.each([
        ['a declared key-container case the guide does not describe', '`openssl:pkcs12-legacy`', '`openssl -legacy`', 'does not describe the key-container case `openssl:pkcs12-legacy`'],
        ['a key-container case the guide describes and nobody declares', '`openssl:pkcs8-pbes1`', '`openssl:pkcs8-pbes1` and `openssl:pkcs8-scrypt`', 'describes the key-container case `openssl:pkcs8-scrypt`'],
    ])('should fire interop-matrix-declared on %s', async (_what, from, to, message) => {
        const files = { ...TREE };
        edit(files, 'docs/guides/conformance.md', from, to);
        const problems = await runRules(createMemoryContext(files), RULES, 'interop-matrix-declared');
        expect(problems).toEqual([expect.objectContaining({ file: 'docs/guides/conformance.md', message: expect.stringContaining(message) })]);
    });

    it('should fire error-parity on a throw site whose message lacks the pkinative prefix', async () => {
        const files = { ...TREE };
        edit(files, 'src/core/pki-limits.ts', "'pkinative: options.limits must be", "'options.limits must be");
        const problems = await runRules(createMemoryContext(files), RULES, 'error-parity');
        expect(problems).toEqual([expect.objectContaining({ file: 'src/core/pki-limits.ts', message: expect.stringContaining('must start with "pkinative: "') })]);
    });

    it('should fire error-parity on a throw site whose code is computed', async () => {
        // The message is a perfect literal; only the code argument is wrong.
        const files = { ...TREE };
        edit(files, 'src/core/pki-limits.ts', "throw new PkiLimitError('PKI_LIMIT_EXCEEDED',", "throw new PkiLimitError(`PKI_LIMIT_${'EXCEEDED'}`,");
        const problems = await runRules(createMemoryContext(files), RULES, 'error-parity');
        expect(problems).toEqual([expect.objectContaining({ file: 'src/core/pki-limits.ts', message: expect.stringContaining('computes its code') })]);
    });

    it('should fire error-parity on a literal code of another class', async () => {
        const files = { ...TREE };
        edit(files, 'src/core/pki-limits.ts', "throw new PkiLimitError('PKI_LIMIT_EXCEEDED',", "throw new PkiLimitError('PKI_INTERNAL',");
        const problems = await runRules(createMemoryContext(files), RULES, 'error-parity');
        expect(problems).toEqual([expect.objectContaining({ message: expect.stringContaining("passes 'PKI_INTERNAL', which is not a code of PkiLimitErrorCode") })]);
    });

    const PASS_THROUGH = [
        "import { PkiLimitError, type PkiLimitErrorCode } from '../types/pki-errors.js';",
        'export function _limitError(code: PkiLimitErrorCode, why: string): PkiLimitError {',
        '    return new PkiLimitError(code, `pkinative: ${why} — raise the limit`);',
        '}',
        '',
    ].join('\n');

    it('should pass error-parity on a typed pass-through helper whose every caller passes a literal', async () => {
        const files = { ...TREE };
        files['src/core/zz-pass-through.ts'] = PASS_THROUGH;
        files['src/core/zz-caller.ts'] = "import { _limitError } from './zz-pass-through.js';\nconst EXCEEDED = 'PKI_LIMIT_EXCEEDED';\nexport function f(big: boolean): Error {\n    return big ? _limitError(EXCEEDED, 'big') : _limitError(big ? 'PKI_LIMIT_INVALID' : 'PKI_LIMIT_EXCEEDED', 'small');\n}\n";
        expect(await runRules(createMemoryContext(files), RULES, 'error-parity')).toEqual([]);
    });

    it('should fire error-parity at the caller of a pass-through helper that computes the code', async () => {
        const files = { ...TREE };
        files['src/core/zz-pass-through.ts'] = PASS_THROUGH;
        files['src/core/zz-caller.ts'] = "import { _limitError } from './zz-pass-through.js';\nexport function f(kind: string): Error {\n    return _limitError(`PKI_LIMIT_${kind}` as never, 'computed');\n}\n";
        const problems = await runRules(createMemoryContext(files), RULES, 'error-parity');
        expect(problems).toEqual([expect.objectContaining({ file: 'src/core/zz-caller.ts', line: 3, message: expect.stringContaining('_limitError(…) computes its code') })]);
    });

    it('should fire error-parity on a pass-through parameter typed wider than the class', async () => {
        const files = { ...TREE };
        files['src/core/zz-pass-through.ts'] = PASS_THROUGH.replace('code: PkiLimitErrorCode', 'code: string');
        const problems = await runRules(createMemoryContext(files), RULES, 'error-parity');
        expect(problems).toEqual([expect.objectContaining({ message: expect.stringContaining('is not typed with a code union of PkiLimitErrorCode') })]);
    });

    it('should fire error-codes-frozen on a frozen code moved to another class, and name the way forward', async () => {
        const files = { ...TREE };
        edit(files, 'src/types/pki-errors.ts', "    | 'PKI_INTERNAL';", ';');
        edit(files, 'src/types/pki-errors.ts', "    | 'PKI_LIMIT_INVALID'", "    | 'PKI_LIMIT_INVALID'\n    | 'PKI_INTERNAL'");
        const problems = await runRules(createMemoryContext(files), RULES, 'error-codes-frozen');
        expect(problems.map((p) => p.message)).toEqual([expect.stringMatching(/PKI_INTERNAL was frozen at 0\.8\.0 as a PkiError and now belongs to the union of PkiLimitError: .*semver-major/)]);
    });

    it('should pass error-codes-frozen on an addition whose since is newer than the freeze, and fire on one that is not', async () => {
        const registry = JSON.parse(TREE['docs/data/errors.json'] ?? '{}') as { errors: Array<Record<string, unknown>> };
        const added = { code: 'PKI_KEY_ADDED', class: 'PkiKeyError', since: '0.9.0', raisedWhen: 'x', remedy: 'x', standard: 'x', cwe: null };
        const withSince = (since: string): Record<string, string> => ({ ...TREE, 'docs/data/errors.json': JSON.stringify({ ...registry, errors: [...registry.errors, { ...added, since }] }, null, 2) });
        expect(await runRules(createMemoryContext(withSince('0.9.0')), RULES, 'error-codes-frozen')).toEqual([]);
        const problems = await runRules(createMemoryContext(withSince('0.8.0')), RULES, 'error-codes-frozen');
        // Once 0.8.0 is released the message names the way forward rather
        // than the regeneration; either way it is the snapshot that refuses.
        expect(problems.map((p) => p.message)).toEqual([expect.stringMatching(/^PKI_KEY_ADDED (\(since 0\.8\.0\) )?is not in the 0\.8\.0 snapshot/)]);
    });

    it('should fire pkcs12-policy-parity on a refused scheme the table omits, and on a row the code does not know', async () => {
        const files = { ...TREE };
        edit(files, 'src/core/key-oids.ts', "    ['1.2.840.113549.1.5.11', 'pbeWithSHA1AndRC2-CBC'],", "    ['1.2.840.113549.1.5.11', 'pbeWithSHA1AndRC2-CBC'],\n    ['1.2.840.113549.1.5.99', 'pbeWithSomethingNew'],");
        edit(files, 'SECURITY.md', '| RFC 7292 Appendix B MAC | — | refuses |', '| RFC 7292 Appendix B MAC | — | refuses |\n| DES-CBC | `1.3.14.3.2.7` | refuses |');
        const problems = await runRules(createMemoryContext(files), RULES, 'pkcs12-policy-parity');
        expect(problems.map((p) => p.message).sort()).toEqual([
            expect.stringContaining('names 1.3.14.3.2.7, which src/core/key-oids.ts neither opens nor refuses'),
            expect.stringContaining('omits `pbeWithSomethingNew` (1.2.840.113549.1.5.99)'),
        ]);
    });

    it('should fire count-tokens on a compound number word, which it used to read as its last half', async () => {
        // "Twenty-two named limits" was parsed as "two" — so a count past
        // twenty written in words could be wrong by any amount and pass.
        const files = { ...TREE };
        edit(files, 'README.md', /\b[A-Z][a-z]+-[a-z]+ named limits/, 'Twenty-two named limits');
        const problems = await runRules(createMemoryContext(files), RULES, 'count-tokens');
        expect(problems).toEqual([expect.objectContaining({ file: 'README.md', message: expect.stringContaining('"Twenty-two named limits"') })]);
    });

    it('should fire coverage-ignore-budget on an ignore comment that states no reason', async () => {
        // The count stays 1, so only the justification finding appears: this
        // proves that half of the rule independently of the budget half.
        const files = { ...TREE };
        edit(files, 'src/x509/x509-extensions.ts', /\/\* v8 ignore next -- [^*]*\*\//, '/* v8 ignore next */');
        const problems = await runRules(createMemoryContext(files), RULES, 'coverage-ignore-budget');
        expect(problems.map((p) => p.message)).toEqual([expect.stringContaining('carries no justification')]);
    });

    it('should fire coverage-ignore-budget on a threshold below 100', async () => {
        const files = { ...TREE };
        edit(files, 'vitest.config.ts', 'branches: 100,', 'branches: 95,');
        const problems = await runRules(createMemoryContext(files), RULES, 'coverage-ignore-budget');
        expect(problems.map((p) => p.message)).toEqual([expect.stringContaining('does not hold branches coverage at 100')]);
    });

    it('should fire limits-parity on a CWE that disagrees between the interface and the registry', async () => {
        const files = { ...TREE };
        edit(files, 'src/types/pki-types.ts', 'nesting depth of constructed ASN.1 values. CWE-674.', 'nesting depth of constructed ASN.1 values. CWE-400.');
        const problems = await runRules(createMemoryContext(files), RULES, 'limits-parity');
        expect(problems.map((p) => p.message)).toEqual([expect.stringContaining('PkiLimits.maxDepth cites CWE-400')]);
    });

    it('should fire adr-index on a record that lacks a MADR section', async () => {
        const files = { ...TREE };
        edit(files, 'docs/adr/0006-no-network-io-in-the-engine.md', '### Confirmation\n', '');
        const problems = await runRules(createMemoryContext(files), RULES, 'adr-index');
        expect(problems).toEqual([expect.objectContaining({ file: 'docs/adr/0006-no-network-io-in-the-engine.md', message: expect.stringContaining('lacks the "### Confirmation" section') })]);
    });

    it('should fire adr-index on a record with no row, a row with no record, and a status the record does not carry', async () => {
        const files = { ...TREE };
        // The next free numbers, so the case outlives the next real record.
        const next = Object.keys(TREE).filter((f) => /^docs\/adr\/\d{4}-/.test(f)).length + 1;
        const [added, gone] = [next, next + 1].map((n) => String(n).padStart(4, '0'));
        files[`docs/adr/${added}-a-new-decision.md`] = (TREE['docs/adr/0003-no-pkcs8-or-pkcs12-writer.md'] ?? '').replace('# No PKCS#8 or PKCS#12 writer', '# A new decision');
        edit(files, 'docs/adr/README.md', '| No external security audit at 1.0 | accepted |', '| No external security audit at 1.0 | proposed |');
        edit(files, 'docs/adr/README.md', /\n\n## Adding a record/, `\n| [${gone}](${gone}-gone.md) | Gone | accepted | 0.9.0 |\n\n## Adding a record`);
        const problems = await runRules(createMemoryContext(files), RULES, 'adr-index');
        expect(problems.map((p) => p.message).sort()).toEqual([
            expect.stringContaining(`does not list ${added}-a-new-decision.md`),
            expect.stringContaining('gives 0010-no-external-security-audit-at-1-0.md the status "proposed"'),
            expect.stringContaining(`lists ${gone}-gone.md, which is not a record`),
        ]);
    });

    it('should fire adr-index on a gap in the numbering and on a version that is not one', async () => {
        const files = { ...TREE };
        const text = TREE['docs/adr/0012-frozen-error-vocabulary.md'] ?? '';
        delete files['docs/adr/0012-frozen-error-vocabulary.md'];
        files['docs/adr/0013-frozen-error-vocabulary.md'] = text.replace('since: 0.8.0', 'since: soon');
        edit(files, 'docs/adr/README.md', '[0012](0012-frozen-error-vocabulary.md)', '[0013](0013-frozen-error-vocabulary.md)');
        const problems = await runRules(createMemoryContext(files), RULES, 'adr-index');
        expect(problems.map((p) => p.message)).toEqual(expect.arrayContaining([
            expect.stringContaining('is record 0013 where 0012 was expected'),
            expect.stringContaining('since is "soon"'),
        ]));
    });

    // ── The freeze, rehearsed ────────────────────────────────────────

    const surfaceProblems = async (files: Record<string, string>): Promise<string[]> =>
        (await runRules(createMemoryContext(files), RULES, 'api-surface-frozen')).map((p) => p.message);

    /** The tree as it will be at the 1.0 release commit: package.json bumped, the snapshot rebased. */
    const atStable = (files: Record<string, string>): void => {
        edit(files, 'package.json', /"version": "[^"]+"/, '"version": "1.0.0"');
        edit(files, 'docs/assets/api.frozen.json', /"frozenAt": "[^"]+",\n {2}"phase": "rehearsal",\n {2}"asOf": "[^"]+"/, '"frozenAt": "1.0.0",\n  "phase": "stable",\n  "asOf": "1.0.0"');
    };

    it('should pass api-surface-frozen on a parameter renamed and a TSDoc rewritten — neither is surface', async () => {
        const files = { ...TREE };
        edit(files, 'src/asn1/asn1-oid.ts', 'export function isValidOid(oid: string): boolean {', 'export function isValidOid(candidate: string): boolean {');
        edit(files, 'src/types/pki-types.ts', /export type PkiDiagnosticCode =/, '/** Reworded. */\nexport type PkiDiagnosticCode =');
        expect(await surfaceProblems(files)).toEqual([]);
    });

    it('should fire api-surface-frozen in the rehearsal on a new error code, whatever its since, while error-codes-frozen accepts it', async () => {
        const registry = JSON.parse(TREE['docs/data/errors.json'] ?? '{}') as { errors: Array<Record<string, unknown>> };
        const added = { code: 'PKI_KEY_ADDED', class: 'PkiKeyError', since: '0.9.0', raisedWhen: 'x', remedy: 'x', standard: 'x', cwe: null };
        const files = { ...TREE, 'docs/data/errors.json': JSON.stringify({ ...registry, errors: [...registry.errors, added] }, null, 2) };
        expect(await runRules(createMemoryContext(files), RULES, 'error-codes-frozen')).toEqual([]);
        expect(await surfaceProblems(files)).toEqual([expect.stringMatching(/^PKI_KEY_ADDED \(since 0\.9\.0\) is a new error code.*rehearsal admits no change/)]);
    });

    it('should fire api-surface-frozen in the rehearsal on a new reason code, and on a reason code removed', async () => {
        const registry = JSON.parse(TREE['docs/data/reasons.json'] ?? '{}') as { reasons: Array<Record<string, unknown>> };
        const [first, ...rest] = registry.reasons;
        const added = { code: 'PKI_REASON_ADDED', since: '0.9.0', returnedWhen: 'x', remedy: 'x', standard: 'x' };
        const files = { ...TREE, 'docs/data/reasons.json': JSON.stringify({ ...registry, reasons: [...rest, added] }, null, 2) };
        expect((await surfaceProblems(files)).sort()).toEqual([
            expect.stringMatching(/^PKI_REASON_ADDED \(since 0\.9\.0\) is a new reason code/),
            expect.stringContaining(`${String(first?.code)} was frozen at 0.8.0 and is gone from the reason registry`),
        ]);
    });

    it('should never freeze a diagnostic code, in either phase', async () => {
        const add = (files: Record<string, string>): void => edit(files, 'src/types/pki-types.ts', "export type PkiDiagnosticCode =\n    | 'PKI_DIAG_SERIAL_TOO_LONG'", "export type PkiDiagnosticCode =\n    | 'PKI_DIAG_ADDED'\n    | 'PKI_DIAG_SERIAL_TOO_LONG'");
        const rehearsal = { ...TREE };
        add(rehearsal);
        expect(await surfaceProblems(rehearsal)).toEqual([]);
        const stable = { ...TREE };
        atStable(stable);
        add(stable);
        expect(await surfaceProblems(stable)).toEqual([]);
    });

    it('should fire api-surface-frozen on a rebaseline that names no accepted ADR', async () => {
        const files = { ...TREE };
        // Beside the log's real entries (ADR 0013 is the first), which must keep passing.
        edit(files, 'docs/assets/api.frozen.json', '"rebaselines": [\n', '"rebaselines": [\n    { "adr": "docs/adr/0099-never-written.md", "asOf": "0.8.0" },\n');
        expect(await surfaceProblems(files)).toEqual([expect.stringContaining('the rebaseline on "docs/adr/0099-never-written.md" names no accepted ADR')]);
    });

    it('should hold api-surface-frozen to package.json: a rehearsal snapshot at 1.0.0 must be rebased', async () => {
        const files = { ...TREE };
        edit(files, 'package.json', /"version": "[^"]+"/, '"version": "1.0.0"');
        expect(await surfaceProblems(files)).toEqual([expect.stringContaining('build-api-frozen.ts --major 1.0.0')]);
    });

    it('should pass api-surface-frozen in the stable phase on additions: an optional parameter, an optional member, a new export', async () => {
        const files = { ...TREE };
        atStable(files);
        expect(await surfaceProblems(files)).toEqual([]);
        edit(files, 'src/asn1/asn1-oid.ts', 'export function isValidOid(oid: string): boolean {', 'export function isValidOid(oid: string, strict?: boolean): boolean {\n    void strict;');
        edit(files, 'src/types/pki-types.ts', /export interface PkiParseOptions \{/, 'export interface PkiParseOptions {\n    readonly addedLater?: boolean | undefined;');
        edit(files, 'src/asn1/asn1-oid.ts', /\n$/, '\nexport function addedLater(): boolean {\n    return true;\n}\n');
        edit(files, 'docs/assets/api.json', '"exports": [', '"exports": [\n    { "name": "addedLater", "kind": "function", "module": "src/asn1/asn1-oid.ts" },');
        expect(await surfaceProblems(files)).toEqual([]);
    });

    it('should fire api-surface-frozen in the stable phase on a required parameter, a removal and a narrowed union, as semver-major', async () => {
        const files = { ...TREE };
        atStable(files);
        edit(files, 'src/asn1/asn1-oid.ts', 'export function isValidOid(oid: string): boolean {', 'export function isValidOid(oid: string, strict: boolean): boolean {\n    void strict;');
        edit(files, 'docs/assets/api.json', /\{\s*"name": "ANY_EXTENDED_KEY_USAGE",[\s\S]*?"members": null\s*\},/, '');
        edit(files, 'src/types/pki-types.ts', "export type EncodingRules = 'der' | 'ber'", "export type EncodingRules = 'der'");
        const problems = await surfaceProblems(files);
        expect(problems.sort()).toEqual([
            expect.stringMatching(/^ANY_EXTENDED_KEY_USAGE \(constant\) is no longer exported.*semver-major/),
            expect.stringMatching(/^EncodingRules: union member\(s\) removed: 'ber'.*semver-major/),
            expect.stringMatching(/^isValidOid: parameter 2 is new and required.*semver-major/),
        ]);
    });

    it('should fire release-era-prose from 1.0.0 on every sentence that says pkinative is not on npm, and keep the policy statements', async () => {
        const files = { ...TREE };
        edit(files, 'package.json', /"version": "[^"]+"/, '"version": "1.0.0"');
        const problems = await runRules(createMemoryContext(files), RULES, 'release-era-prose');
        const absent = PRE_1_0_PROSE.filter((row) => row.at1 === 'absent');
        expect(problems.map((p) => p.file).sort()).toEqual(absent.map((row) => row.file).sort());
        expect(problems.every((p) => p.message.includes('from 1.0.0 pkinative is on npm'))).toBe(true);
        edit(files, 'AGENTS.md', 'Pre-1.0 versions are git tags, never npm releases; `publish.yml` refuses them.', 'Releases go to npm.');
        const kept = await runRules(createMemoryContext(files), RULES, 'release-era-prose');
        expect(kept.filter((p) => p.file === 'AGENTS.md').map((p) => p.message)).toEqual([expect.stringContaining('states the pre-1.0 policy')]);
    });

    // ── The decision surface and the contracts block (ADR 0014) ──────

    const BASELINE = 'scripts/data/limbo-refusals.json';
    const SNAPSHOT = 'docs/data/refusals.frozen.json';
    const NEW_HASH = 'f'.repeat(64);
    const refusalProblems = async (files: Record<string, string>): Promise<string[]> =>
        (await runRules(createMemoryContext(files), RULES, 'refusal-baseline-frozen')).map((p) => p.message);
    const contractProblems = async (files: Record<string, string>): Promise<string[]> =>
        (await runRules(createMemoryContext(files), RULES, 'contracts-shape')).map((p) => p.message);
    const addRefusal = (files: Record<string, string>, path: string, row: string): void => edit(files, path, /("refusals": [[{]\n)/, `$1${row}\n`);
    const liftFirst = (files: Record<string, string>): void => edit(files, BASELINE, /\n {4}"0014e18b[0-9a-f]{56}": "[A-Z0-9_]+",/, '');
    /** The refusal snapshot as the 1.x release commit leaves it, with package.json at `version`. */
    const refusalsStable = (files: Record<string, string>, version: string, asOf = '1.0.0'): void => {
        edit(files, 'package.json', /"version": "[^"]+"/, `"version": "${version}"`);
        edit(files, SNAPSHOT, /"frozenAt": "[^"]+",\n {2}"phase": "rehearsal",\n {2}"asOf": "[^"]+"/, `"frozenAt": "1.0.0",\n  "phase": "stable",\n  "asOf": "${asOf}"`);
    };

    it('should fire refusal-baseline-frozen in the rehearsal on a new refusal and on a lifted one', async () => {
        const files = { ...TREE };
        addRefusal(files, BASELINE, `    "${NEW_HASH}": "PKI_X509_GENERAL_NAME_INVALID",`);
        liftFirst(files);
        const problems = await refusalProblems(files);
        expect(problems).toEqual(expect.arrayContaining([
            expect.stringMatching(/^0014e18b[0-9a-f]+ was promised refused with PKI_X509_GENERAL_NAME_INVALID and the baseline no longer lists it/),
            expect.stringMatching(new RegExp(`^${NEW_HASH} is a new refusal .*the rehearsal admits no new engine behaviour`)),
        ]));
        expect(problems).toHaveLength(2);
    });

    it('should pass refusal-baseline-frozen in the stable phase on a new refusal, and fire on a lifted one as semver-major', async () => {
        const files = { ...TREE };
        refusalsStable(files, '1.0.0');
        addRefusal(files, BASELINE, `    "${NEW_HASH}": "PKI_X509_GENERAL_NAME_INVALID",`);
        expect(await refusalProblems(files)).toEqual([]);
        liftFirst(files);
        expect(await refusalProblems(files)).toEqual([expect.stringContaining('that is semver-major (ADR 0014)')]);
    });

    it('should hold a refusal a 1.x release added to that release\'s note, under its fixed heading', async () => {
        const files = { ...TREE };
        refusalsStable(files, '1.1.0', '1.1.0');
        addRefusal(files, BASELINE, `    "${NEW_HASH}": "PKI_X509_GENERAL_NAME_INVALID",`);
        addRefusal(files, SNAPSHOT, `    { "sha256": "${NEW_HASH}", "code": "PKI_X509_GENERAL_NAME_INVALID", "since": "1.1.0" },`);
        expect(await refusalProblems(files)).toEqual([expect.stringMatching(/^is missing — 1 refusal\(s\) of docs\/data\/refusals\.frozen\.json were added by 1\.1\.0/)]);
        files['release-notes/v1.1.0.md'] = '# pkinative v1.1.0\n\n## Downstream integration notes\n\n### Decision surface\n\n- nothing listed\n';
        expect(await refusalProblems(files)).toEqual([expect.stringContaining(`does not list ${NEW_HASH.slice(0, 16)}`)]);
        files['release-notes/v1.1.0.md'] = `# pkinative v1.1.0\n\n## Downstream integration notes\n\n### Decision surface\n\n- \`${NEW_HASH.slice(0, 16)}\` — now refused with \`PKI_X509_GENERAL_NAME_INVALID\`.\n`;
        expect(await refusalProblems(files)).toEqual([]);
    });

    it('should fire refusal-baseline-frozen on a re-pinned baseline, on a retirement no accepted ADR records, and on the rehearsal at 1.0.0', async () => {
        const repinned = { ...TREE };
        edit(repinned, BASELINE, /"commit": "[0-9a-f]{40}"/, `"commit": "${'2'.repeat(40)}"`);
        expect(await refusalProblems(repinned)).toEqual([expect.stringContaining('--repin')]);
        const retired = { ...TREE };
        edit(retired, SNAPSHOT, /\n {2}\]\n\}\n$/, `\n  ],\n  "retired": [\n    { "sha256": "${NEW_HASH}", "code": "PKI_X509_GENERAL_NAME_INVALID", "commit": "${'2'.repeat(40)}", "adr": "docs/adr/0099-never-written.md" }\n  ]\n}\n`);
        expect(await refusalProblems(retired)).toEqual([expect.stringContaining('not an accepted ADR')]);
        const bumped = { ...TREE };
        edit(bumped, 'package.json', /"version": "[^"]+"/, '"version": "1.0.0"');
        expect(await refusalProblems(bumped)).toEqual([expect.stringContaining('--major 1.0.0')]);
    });

    it('should fire contracts-shape on a snapshot no leg names, on a leg SECURITY.md does not name, on a missing leg, and on a scalar contract that disagrees', async () => {
        const stray = { ...TREE };
        stray['docs/data/reasons.frozen.json'] = '{ "frozenAt": "1.0.0" }\n';
        expect(await contractProblems(stray)).toEqual([expect.stringContaining('docs/data/reasons.frozen.json is a frozen snapshot no leg')]);
        const prose = { ...TREE };
        edit(prose, 'SECURITY.md', /`refusal-baseline-frozen`/g, '`the refusal rule`');
        expect(await contractProblems(prose)).toEqual([expect.stringContaining('does not name the rule `refusal-baseline-frozen`')]);
        const legless = { ...TREE };
        edit(legless, 'docs/assets/ecosystem.json', '"error-vocabulary": {', '"error-codes": {');
        expect(await contractProblems(legless)).toEqual(expect.arrayContaining([expect.stringContaining('lacks "error-vocabulary"'), expect.stringContaining('names "error-codes"')]));
        const scalar = { ...TREE };
        edit(scalar, 'docs/assets/ecosystem.json', '"runtime_dependencies": 0', '"runtime_dependencies": 1');
        expect(await contractProblems(scalar)).toEqual([expect.stringContaining('package.json declares 0')]);
    });

    it('should honour a verify-docs:allow suppression on the reported line or the line above', async () => {
        const files = { ...TREE };
        edit(files, 'README.md', /\n$/, '\n<!-- verify-docs:allow prose-language -->\nLe certificat est valide pour tous les domaines.\n');
        expect(await runRules(createMemoryContext(files), RULES, 'prose-language')).toEqual([]);
    });
});
