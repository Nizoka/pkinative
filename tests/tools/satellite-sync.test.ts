import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import {
    BATCH_IDS,
    INVENTORIES,
    SATELLITE_EDITS,
    SHOW_UNITS,
    batchOf,
    blockObject,
    buildWorklist,
    bumpBadge,
    bumpJsonLdVersion,
    bumpVersionsFallback,
    deltaLines,
    evaluateBlindSpots,
    groupsOf,
    inlineArray,
    jsonValueEnd,
    parseArgs,
    parseVerifyDocsJson,
    planSatellites,
    renderWorklist,
    restampVerifiedOn,
    restampVerifiedTime,
    satelliteKey,
    selectedKeys,
    setPackageField,
    showUnit,
    sourceOf,
    splitCommand,
    syncCounts,
    type Finding,
    type SatellitePlan,
} from '../../scripts/satellite-sync.js';
import { FACTS_MAX_LINES, SHOW_MAX_CHARS, blindSpotTable, normaliseSurface, renderFactsMarkdown, type SatelliteFacts, type SatelliteName, type SatelliteSurface } from '../../scripts/lib/satellite-surface.js';
import type { TreeReader } from '../../scripts/release-prepare.js';
import { runRules } from '../../scripts/verify-docs.js';
import { createMemoryContext, loadTextTree } from '../../scripts/verify-docs/context.js';
import { RULES } from '../../scripts/verify-docs/rules/index.js';

/**
 * The mechanical half of a satellite release, rehearsed on an in-memory copy
 * of the repository: the surfaces are rebuilt from what the tree records
 * today (so the pass must change nothing), then moved to a next release (so
 * the pass must change exactly what a release moves, and the rules that
 * judge those files must accept what it wrote). No satellite is read and no
 * child process runs.
 */

const ROOT = resolve(import.meta.dirname, '..', '..');
const TREE = loadTextTree(ROOT);
const DATE = '2026-11-30';

const readerOf = (files: Readonly<Record<string, string>>): TreeReader => (path) => (Object.prototype.hasOwnProperty.call(files, path) ? files[path] ?? null : null);

interface CliRow { version: string; released: string; pin: string; pinField: string; counts: Record<string, number>; envVars: string[]; completionShells: string[]; exitCodes: number[] }
interface McpRow { version: string; released: string; pin: string; pinField: string; counts: Record<string, number>; tools: string[]; toolGroups: Record<string, number>; toolAnnotations: { writes: string[]; produces: string[] }; prompts: string[]; resourceTemplates: string[]; transports: string[]; mcpRevision: string; legacyRevisions: string[]; envVars: string[] }
const ECO = JSON.parse(TREE['docs/assets/ecosystem.json'] ?? '{}') as { verifiedOn: string; packages: { 'pkinative-cli': CliRow; 'pkinative-mcp': McpRow; pkinative: { version: string } } };
const SNAPSHOT = JSON.parse(TREE['docs/data/cli-surface.json'] ?? '{}') as { pkinative: string; offline: boolean; wire: object; exitCodes: object; errorClasses: { code: string }[]; globalFlags: object[]; commands: { name: string; group: string; subcommands?: { name: string }[] }[] };

/** A copy that shares nothing with the tree's own records: the next release is built by pushing onto it. */
const fresh = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const placeholders = (prefix: string, n: number): string[] => Array.from({ length: n }, (_, i) => `${prefix}-${i + 1}`);

/** pkinative-cli as the tree records it, in the contract form. */
function cliContract(): Record<string, unknown> {
    const row = ECO.packages['pkinative-cli'];
    return fresh({
        kind: 'satellite-surface', package: 'pkinative-cli', version: row.version, previous: null, releasedOn: row.released,
        engine: { pin: row.pin, pinField: row.pinField },
        lists: {
            commands: SNAPSHOT.commands.map((c) => c.name),
            invocations: SNAPSHOT.commands.flatMap((c) => ((c.subcommands ?? []).length === 0 ? [c.name] : (c.subcommands ?? []).map((s) => `${c.name} ${s.name}`))),
            errorClasses: SNAPSHOT.errorClasses.map((e) => e.code),
            schemaSubjects: placeholders('subject', row.counts.schemaSubjects ?? 0),
            exitCodes: row.exitCodes,
            envVars: row.envVars,
            completionShells: row.completionShells,
        },
        structured: { commands: SNAPSHOT.commands, globalFlags: SNAPSHOT.globalFlags, errorClasses: SNAPSHOT.errorClasses, exitCodes: SNAPSHOT.exitCodes, wire: SNAPSHOT.wire, flagDefaults: {}, pkinative: SNAPSHOT.pkinative, offline: SNAPSHOT.offline },
    });
}

/** pkinative-mcp as the tree records it, in the contract form. */
function mcpContract(): Record<string, unknown> {
    const row = ECO.packages['pkinative-mcp'];
    const groups = Object.entries(row.toolGroups).flatMap(([group, n]) => Array.from({ length: n }, () => group));
    const annotation = (t: string): string => (row.toolAnnotations.writes.includes(t) ? 'writes' : row.toolAnnotations.produces.includes(t) ? 'produces' : 'readOnly');
    return fresh({
        kind: 'satellite-surface', package: 'pkinative-mcp', version: row.version, previous: null, releasedOn: row.released,
        engine: { pin: row.pin, pinField: row.pinField },
        lists: { tools: row.tools, prompts: row.prompts, resourceTemplates: row.resourceTemplates, transports: row.transports, legacyRevisions: row.legacyRevisions, envVars: row.envVars, wrapperCodes: placeholders('CODE', row.counts.wrapperCodes ?? 0) },
        structured: { tools: row.tools.map((name, i) => ({ name, group: groups[i], annotation: annotation(name), inputs: ['input'] })), mcpRevision: row.mcpRevision },
    });
}

function factsOf(surfaces: readonly SatelliteSurface[], date = DATE): SatelliteFacts {
    const facts: SatelliteFacts = { generatedOn: date, engineVersion: ECO.packages.pkinative.version, satellites: {} };
    for (const surface of surfaces) {
        const row = ECO.packages[surface.package];
        facts.satellites[surface.package] = { surface, previous: null, delta: surface.delta ?? {}, manifestToday: { version: row.version, released: row.released, pin: row.pin, counts: row.counts } };
    }
    return facts;
}

const CLI_TODAY = normaliseSurface(cliContract(), 'pkinative-cli');
const MCP_TODAY = normaliseSurface(mcpContract(), 'pkinative-mcp');

/** The next release of both: a command, a flag-less invocation, a pin, a tool in each annotation class, a prompt. */
function nextRelease(): SatelliteSurface[] {
    const cli = cliContract() as { version: string; releasedOn: string; engine: { pin: string }; lists: Record<string, unknown[]>; structured: { commands: object[] } };
    cli.version = '1.1.0';
    cli.releasedOn = '2026-11-28';
    cli.engine.pin = '^1.1.0';
    cli.lists.commands?.push('audit');
    cli.lists.invocations?.push('audit');
    cli.lists.envVars?.push('PKINATIVE_NO_COLOR');
    cli.structured.commands.push({ name: 'audit', group: 'Meta', summary: 'Audit a directory of certificates', flags: [{ name: 'recursive' }], operands: { max: 1 } });
    const mcp = mcpContract() as { version: string; releasedOn: string; lists: Record<string, string[]>; structured: { tools: object[] } };
    mcp.version = '1.2.0';
    mcp.releasedOn = '2026-11-29';
    mcp.lists.tools?.push('audit_directory', 'create_crl');
    mcp.lists.prompts?.push('audit_a_directory');
    mcp.lists.wrapperCodes?.push('CODE-NEW');
    mcp.structured.tools.push({ name: 'audit_directory', group: 'Meta', annotation: 'readOnly', inputs: ['path'] }, { name: 'create_crl', group: 'Meta', annotation: 'produces', inputs: ['spec'] });
    return [normaliseSurface(cli, 'pkinative-cli'), normaliseSurface(mcp, 'pkinative-mcp')];
}

const applied = (plan: SatellitePlan, files: Readonly<Record<string, string>> = TREE): Record<string, string> => ({ ...files, ...Object.fromEntries(plan.texts) });
const levels = (plan: SatellitePlan, level: string): string[] => plan.lines.filter((l) => l.level === level).map((l) => l.text);

// ── planSatellites ───────────────────────────────────────────────────

describe('planSatellites — the tree as it is', () => {
    it('should change nothing when the surfaces say what the tree records: every row is unchanged, the stamps stay', () => {
        const plan = planSatellites(readerOf(TREE), factsOf([CLI_TODAY, MCP_TODAY]));
        expect(levels(plan, 'FAIL')).toEqual([]);
        expect(levels(plan, 'edit')).toEqual([]);
        expect(plan.texts.size).toBe(0);
        expect(plan.lines.length).toBe(SATELLITE_EDITS.length);
        expect(levels(plan, 'same')).toEqual(expect.arrayContaining([
            'docs/assets/ecosystem.json — packages.pkinative-mcp.tools',
            'docs/data/cli-surface.json — the command surface (renderCliSurface)',
            'docs/assets/ecosystem.json — verifiedOn: kept (nothing else moved)',
        ]));
    });

    it('should leave alone a package the facts do not hold', () => {
        const plan = planSatellites(readerOf(TREE), factsOf([MCP_TODAY]));
        expect(plan.lines.some((l) => l.text.includes('pkinative-cli'))).toBe(false);
        expect(plan.lines.length).toBe(SATELLITE_EDITS.filter((e) => e.package !== 'pkinative-cli').length);
        expect(planSatellites(readerOf(TREE), factsOf([])).lines).toEqual([]);
    });

    it('should name a file that exists for every row of the table', () => {
        for (const edit of SATELLITE_EDITS) expect(TREE[edit.file], `${edit.file} — ${edit.what}`).toBeDefined();
        // One row per inventory, and no inventory the manifest does not have.
        for (const [name, inventories] of Object.entries(INVENTORIES)) {
            for (const inv of inventories) expect(Object.keys(ECO.packages[name as SatelliteName]), `${name}.${inv.key}`).toContain(inv.key);
        }
    });
});

describe('planSatellites — a release of both satellites', () => {
    const plan = planSatellites(readerOf(TREE), factsOf(nextRelease()));
    const files = applied(plan);

    it('should rewrite every field a release moves, and only those files', () => {
        expect(levels(plan, 'FAIL')).toEqual([]);
        expect([...plan.texts.keys()].sort()).toEqual(['docs/assets/ecosystem.json', 'docs/assets/versions.js', 'docs/data/cli-surface.json', 'docs/index.html', 'docs/playgrounds/cli.html', 'docs/playgrounds/mcp.html']);
        const eco = JSON.parse(files['docs/assets/ecosystem.json'] ?? '{}') as typeof ECO;
        expect(eco.verifiedOn).toBe(DATE);
        expect(eco.packages['pkinative-cli']).toMatchObject({
            version: '1.1.0', released: '2026-11-28', pin: '^1.1.0',
            counts: { commands: 19, invocations: 54, errorClasses: 13, schemaSubjects: 12 },
            envVars: [...ECO.packages['pkinative-cli'].envVars, 'PKINATIVE_NO_COLOR'],
            exitCodes: [0, 1, 2, 130, 143],
        });
        expect((eco.packages['pkinative-cli'] as unknown as { commandGroups: Record<string, string[]> }).commandGroups['Meta']).toContain('audit');
        expect(eco.packages['pkinative-mcp']).toMatchObject({
            version: '1.2.0', released: '2026-11-29', pin: '^1.0.0',
            counts: { tools: 36, prompts: 8, wrapperCodes: 22 },
            tools: [...ECO.packages['pkinative-mcp'].tools, 'audit_directory', 'create_crl'],
            toolGroups: { ...ECO.packages['pkinative-mcp'].toolGroups, Meta: 5 },
            toolAnnotations: { readOnly: 24, writes: ECO.packages['pkinative-mcp'].toolAnnotations.writes, produces: [...ECO.packages['pkinative-mcp'].toolAnnotations.produces, 'create_crl'].sort() },
        });
        // The engine's own record is release-prepare's, never this pass's.
        expect(eco.packages.pkinative).toEqual(ECO.packages.pkinative);
        expect(files['docs/assets/versions.js']).toContain("'pkinative-cli': { version: '1.1.0', pin: '^1.1.0' }");
        expect(files['docs/assets/versions.js']).toContain("'pkinative-mcp': { version: '1.2.0', pin: '^1.0.0' }");
        expect(files['docs/assets/versions.js']).toContain(`'pkinative': { version: '${ECO.packages.pkinative.version}', pin: null }`);
        expect(files['docs/index.html']).toContain(`<time id="verified-on" datetime="${DATE}">${DATE}</time>`);
        expect(JSON.parse(files['docs/data/cli-surface.json'] ?? '{}')).toMatchObject({ version: '1.1.0', package: 'pkinative-cli' });
    });

    it('should keep the manifest\'s own formatting: only the lines of the fields it owns differ', () => {
        const before = (TREE['docs/assets/ecosystem.json'] ?? '').split('\n');
        const after = (files['docs/assets/ecosystem.json'] ?? '').split('\n');
        const untouched = before.filter((l) => after.includes(l)).length;
        expect(before.length - untouched).toBeLessThanOrEqual(22);
        expect(files['docs/assets/ecosystem.json']).toContain('      "envVars": ["PKINATIVE_JSON", "PKINATIVE_QUIET", "PKINATIVE_PASSWORD", "PKINATIVE_DEBUG", "PKINATIVE_NO_COLOR"],');
        expect(files['docs/assets/ecosystem.json']).toContain('        "describe_engine", "explain_code", "draft_governance_issue", "audit_directory", "create_crl"\n      ],');
        expect(files['docs/assets/ecosystem.json']).not.toContain('\r');
    });

    it('should write what the rules that judge those files accept', async () => {
        for (const rule of ['manifest-shape', 'satellite-manifest', 'versions-widget', 'jsonld-version', 'verified-on-parity']) {
            const problems = await runRules(createMemoryContext(files), RULES, rule);
            expect(problems.filter((p) => p.severity === 'error'), rule).toEqual([]);
        }
    });

    it('should change nothing on a second run, the stamps included', () => {
        const again = planSatellites(readerOf(files), factsOf(nextRelease()));
        expect(again.texts.size).toBe(0);
        expect(levels(again, 'FAIL')).toEqual([]);
    });
});

describe('planSatellites — what it refuses and what it keeps', () => {
    it('should fail on a row whose site is gone, name it, and say that nothing is written', () => {
        const files = { ...TREE, 'docs/assets/versions.js': (TREE['docs/assets/versions.js'] ?? '').replace("'pkinative-mcp': {", "'pkinative-server': {") };
        const plan = planSatellites(readerOf(files), factsOf(nextRelease()));
        expect(plan.failures).toBe(1);
        expect(levels(plan, 'FAIL')).toEqual(['docs/assets/versions.js — FALLBACK pkinative-mcp: not found — nothing is written while any row fails']);
        const missing = { ...TREE };
        delete missing['docs/playgrounds/cli.html'];
        expect(levels(planSatellites(readerOf(missing), factsOf(nextRelease())), 'FAIL')).toEqual(['docs/playgrounds/cli.html: missing']);
    });

    it('should keep a field the surface could not establish, and say why', () => {
        const [cli] = nextRelease();
        if (cli === undefined) throw new Error('no CLI surface');
        const degraded: SatelliteSurface = {
            ...cli,
            mode: 'degraded',
            lists: Object.fromEntries(Object.entries(cli.lists).filter(([k]) => k !== 'envVars' && k !== 'completionShells' && k !== 'schemaSubjects')),
            counts: Object.fromEntries(Object.entries(cli.counts).filter(([k]) => k !== 'schemaSubjects')),
            unverified: ['schemaSubjects: not in the manifest', 'envVars, completionShells: contract only', 'releasedOn: 2026-11-28 is the CHANGELOG heading\'s date'],
        };
        const plan = planSatellites(readerOf(TREE), factsOf([degraded]));
        expect(plan.failures).toBe(0);
        expect(levels(plan, 'same')).toEqual(expect.arrayContaining([
            'docs/assets/ecosystem.json — packages.pkinative-cli.released: kept — the release day is not established (2026-11-28 is unconfirmed) — run with --capture',
            'docs/assets/ecosystem.json — packages.pkinative-cli.envVars: kept — the surface does not establish envVars',
            'docs/assets/ecosystem.json — packages.pkinative-cli.completionShells: kept — the surface does not establish completionShells',
        ]));
        const eco = JSON.parse(applied(plan)['docs/assets/ecosystem.json'] ?? '{}') as typeof ECO;
        expect(eco.packages['pkinative-cli']).toMatchObject({ version: '1.1.0', released: ECO.packages['pkinative-cli'].released, envVars: ECO.packages['pkinative-cli'].envVars, counts: { commands: 19, schemaSubjects: 12 } });
        // Without a command inventory there is no snapshot to render, and the manifest's groups stay.
        const bare: SatelliteSurface = { ...degraded, structured: {} };
        expect(levels(planSatellites(readerOf(TREE), factsOf([bare])), 'same')).toEqual(expect.arrayContaining([
            'docs/data/cli-surface.json — the command surface (renderCliSurface): kept — the facts carry no capability manifest — run with --capture',
            'docs/assets/ecosystem.json — packages.pkinative-cli.commandGroups: kept — the surface carries no structured.commands',
        ]));
    });

    it('should keep the three tool inventories when a tool has no group', () => {
        const mcp: SatelliteSurface = { ...MCP_TODAY, structured: { ...MCP_TODAY.structured, tools: (MCP_TODAY.structured.tools ?? []).map((t, i) => (i === 0 ? { ...t, group: null } : t)) } };
        const same = levels(planSatellites(readerOf(TREE), factsOf([mcp])), 'same');
        for (const key of ['tools', 'toolGroups', 'toolAnnotations']) expect(same).toContain(`docs/assets/ecosystem.json — packages.pkinative-mcp.${key}: kept — a tool has no group or no annotation class in the surface`);
    });
});

// ── The rewrites ─────────────────────────────────────────────────────

const MANIFEST = [
    '{',
    '  "verifiedOn": "2026-10-17",',
    '  "packages": {',
    '    "pkinative": {',
    '      "version": "1.0.0"',
    '    },',
    '    "pkinative-mcp": {',
    '      "$comment": "a } brace and a \\" quote in a string",',
    '      "version": "1.0.0",',
    '      "engine": {',
    '        "version": "nested"',
    '      },',
    '      "counts": {',
    '        "tools": 34',
    '      },',
    '      "tools": [',
    '        "a", "b"',
    '      ],',
    '      "pin": null',
    '    }',
    '  },',
    '  "derived": { "pkinative-mcp": { "version": "elsewhere" } }',
    '}',
    '',
].join('\n');

describe('setPackageField and jsonValueEnd', () => {
    it('should rewrite one value of the block and nothing else', () => {
        const r = setPackageField(MANIFEST, 'pkinative-mcp', 'version', () => '"1.1.0"');
        expect(r.matched).toBe(1);
        expect(r.text).toBe(MANIFEST.replace('      "version": "1.0.0",\n      "engine"', '      "version": "1.1.0",\n      "engine"'));
        // The key of the block, not the "tools" of its counts; the indent is the key's.
        const tools = setPackageField(MANIFEST, 'pkinative-mcp', 'tools', (indent) => `[\n${indent}  "c"\n${indent}]`);
        expect(tools.text).toContain('      "tools": [\n        "c"\n      ],\n      "pin": null');
        expect(tools.text).toContain('        "tools": 34');
        expect(setPackageField(MANIFEST, 'pkinative-mcp', 'pin', () => '"^1.0.0"').text).toContain('      "pin": "^1.0.0"\n    }');
        expect(JSON.parse(setPackageField(MANIFEST, 'pkinative-mcp', 'counts', (indent) => blockObject([['tools', '35'], ['prompts', '7']], indent)).text)).toMatchObject({ packages: { 'pkinative-mcp': { counts: { tools: 35, prompts: 7 }, tools: ['a', 'b'] } } });
    });

    it('should match nothing for the engine, an unknown package or an absent key', () => {
        expect(setPackageField(MANIFEST, 'pkinative', 'version', () => '"9.9.9"')).toEqual({ text: MANIFEST, matched: 0 });
        expect(setPackageField(MANIFEST, 'pkinative-cli', 'version', () => '"9.9.9"').matched).toBe(0);
        expect(setPackageField(MANIFEST, 'pkinative-mcp', 'released', () => '"2026-01-01"').matched).toBe(0);
        expect(setPackageField('{ "no": "packages" }', 'pkinative-mcp', 'version', () => '""').matched).toBe(0);
    });

    it('should find the end of a string, an object, an array and a scalar', () => {
        const end = (text: string): string => text.slice(0, jsonValueEnd(text, 0));
        expect(end('"a \\" b", next')).toBe('"a \\" b"');
        expect(end('{ "a": "}", "b": [1, { "c": "]" }] }, next')).toBe('{ "a": "}", "b": [1, { "c": "]" }] }');
        expect(end('[1, [2, 3]]\n')).toBe('[1, [2, 3]]');
        expect(end('null,\n')).toBe('null');
        expect(end('34\n      }')).toBe('34');
        expect(end('[1, 2')).toBe('[1, 2');
    });

    it('should render the manifest\'s inline arrays and block objects, and group in order of first appearance', () => {
        expect(inlineArray(['a', 'b'])).toBe('["a", "b"]');
        expect(inlineArray([0, 130])).toBe('[0, 130]');
        expect(inlineArray([])).toBe('[]');
        expect(blockObject([['a', '1'], ['b c', '["x"]']], '    ')).toBe('{\n      "a": 1,\n      "b c": ["x"]\n    }');
        expect(blockObject([], '  ')).toBe('{}');
        expect([...groupsOf([{ name: 'a', group: 'G1' }, { name: 'b', group: 'G2' }, { name: 'c', group: 'G1' }])]).toEqual([['G1', ['a', 'c']], ['G2', ['b']]]);
    });

    it('should sync only the counters the manifest polices, and only the ones the surface established', () => {
        expect(syncCounts({ commands: 18, schemaSubjects: 12, invocations: 53 }, { commands: 19, schemaSubjects: 9, flags: 96 }, ['schemaSubjects: not in the manifest'])).toEqual({ commands: 19, schemaSubjects: 12, invocations: 53 });
        expect(syncCounts({}, { commands: 19 }, [])).toEqual({});
    });
});

describe('the site rewrites', () => {
    it('should bump the FALLBACK row of one package, pin included', () => {
        const js = "    var FALLBACK = {\n        'pkinative': { version: '1.0.0', pin: null },\n        'pkinative-cli': { version: '1.0.0', pin: '^1.0.0' }\n    };\n";
        expect(bumpVersionsFallback(js, 'pkinative-cli', '1.1.0', '^1.1.0')).toEqual({ text: js.replace("'pkinative-cli': { version: '1.0.0', pin: '^1.0.0' }", "'pkinative-cli': { version: '1.1.0', pin: '^1.1.0' }"), matched: 1 });
        expect(bumpVersionsFallback(js, 'pkinative-cli', '1.1.0', null).text).toContain("'pkinative-cli': { version: '1.1.0', pin: null }");
        expect(bumpVersionsFallback(js, 'pkinative-mcp', '1.1.0', null).matched).toBe(0);
    });

    it('should bump every badge of one package and no other', () => {
        const html = '<strong data-pk-badge="pkinative-cli">v1.0.0</strong> <span data-pk-badge="pkinative-cli">v1.0.0</span> <span data-pk-badge="pkinative">v1.0.0</span>';
        const r = bumpBadge(html, 'pkinative-cli', '1.1.0');
        expect(r.matched).toBe(2);
        expect(r.text).toBe('<strong data-pk-badge="pkinative-cli">v1.1.0</strong> <span data-pk-badge="pkinative-cli">v1.1.0</span> <span data-pk-badge="pkinative">v1.0.0</span>');
    });

    it('should bump the JSON-LD softwareVersion by package name, on the landing page and on a playground', () => {
        const landing = '{ "@id": "https://pkinative.dev/#library", "name": "pkinative",\n "softwareVersion": "1.0.0" },\n{ "@id": "https://pkinative.dev/#cli",\n "name": "pkinative-cli",\n "applicationCategory": "DeveloperApplication",\n "softwareVersion": "1.0.0" },\n{ "name": "pkinative-mcp",\n "softwareVersion": "1.0.0" }';
        const r = bumpJsonLdVersion(landing, 'pkinative-cli', '1.1.0');
        expect(r.matched).toBe(1);
        expect(r.text.match(/"softwareVersion": "[^"]+"/g)).toEqual(['"softwareVersion": "1.0.0"', '"softwareVersion": "1.1.0"', '"softwareVersion": "1.0.0"']);
        const playground = '"about": {\n  "@type": "SoftwareApplication",\n  "name": "pkinative-mcp",\n  "softwareVersion": "1.0.0",\n  "url": "https://github.com/Nizoka/pkinative-mcp"\n}';
        expect(bumpJsonLdVersion(playground, 'pkinative-mcp', '1.2.0').text).toContain('"name": "pkinative-mcp",\n  "softwareVersion": "1.2.0"');
        // A node with no softwareVersion of its own never borrows the next node's.
        expect(bumpJsonLdVersion('{ "name": "pkinative-cli" }, { "name": "other", "softwareVersion": "3.0.0" }', 'pkinative-cli', '1.1.0').matched).toBe(0);
    });

    it('should restamp the two verified-on sites', () => {
        expect(restampVerifiedOn('{ "verifiedOn": "2026-10-17" }', DATE).text).toBe(`{ "verifiedOn": "${DATE}" }`);
        expect(restampVerifiedTime('<time id="verified-on" datetime="2026-10-17">2026-10-17</time>', DATE).text).toBe(`<time id="verified-on" datetime="${DATE}">${DATE}</time>`);
        expect(restampVerifiedTime('<time datetime="2026-10-17">2026-10-17</time>', DATE).matched).toBe(0);
    });
});

// ── Worklist ─────────────────────────────────────────────────────────

const finding = (file: string, rule: string, line = 1, severity: 'error' | 'warn' = 'error'): Finding => ({ file, line, rule, message: `${rule} at ${line}`, severity });

describe('batches', () => {
    it('should send every documented file to its writer, a generated guide page to its source, and the rest to the coordinator', () => {
        const expected: Record<string, string> = {
            'docs/guides/cli.md': 'B1', 'docs/guides/cli.html': 'B1',
            'docs/guides/mcp.md': 'B2', 'docs/guides/mcp.html': 'B2',
            'docs/data/surfaces.json': 'B3', 'docs/guides/choose.md': 'B3', 'docs/guides/choose.html': 'B3',
            'docs/guides/use-cases.md': 'B4', 'docs/guides/use-cases-cli.html': 'B4', 'docs/assets/use-case-mcp-open-keys.svg': 'B4',
            'README.md': 'B5', 'llms.txt': 'B5', 'docs/index.html': 'B5', 'docs/agent-brief.md': 'B5', 'docs/guides/errors.md': 'B5', 'docs/guides/errors.html': 'B5',
            'AGENTS.md': 'B5', 'ROADMAP.md': 'B5', 'CONTRIBUTING.md': 'B5', 'SECURITY.md': 'B5', 'SUPPORT.md': 'B5', '.github/copilot-instructions.md': 'B5',
            'docs/playgrounds/cli.html': 'B6', 'docs/playgrounds/mcp.js': 'B6', 'docs/data/playgrounds.json': 'B6',
            'docs/assets/ecosystem.json': 'B0', 'docs/llms-index.json': 'B0', 'docs/llms.txt': 'B0', 'docs/guides/quickstart.md': 'B0', 'docs/playgrounds/asn1.html': 'B0', 'docs\\guides\\cli.md': 'B1',
        };
        for (const [file, batch] of Object.entries(expected)) expect(batchOf(file), file).toBe(batch);
        expect(BATCH_IDS).toEqual(['B1', 'B2', 'B3', 'B4', 'B5', 'B6', 'B0']);
        expect(sourceOf('docs/guides/cli.html')).toBe('docs/guides/cli.md');
        expect(sourceOf('docs/playgrounds/cli.html')).toBe('docs/playgrounds/cli.html');
        // Every file a batch names exists, and so does every guide source a generated page maps to.
        for (const file of Object.keys(expected).filter((f) => !f.includes('\\'))) expect(TREE[sourceOf(file)], file).toBeDefined();
    });

    it('should read the report verify-docs --json prints, past a banner, and refuse anything else', () => {
        const report = { ok: false, rules: 95, problems: [finding('README.md', 'satellite-counts', 12)] };
        expect(parseVerifyDocsJson(JSON.stringify(report, null, 2))).toEqual({ rules: 95, problems: report.problems });
        expect(parseVerifyDocsJson(`\n> pkinative@1.0.0 verify:docs\n> npx tsx scripts/verify-docs.ts --json\n\n${JSON.stringify(report)}\n`)?.problems).toHaveLength(1);
        expect(parseVerifyDocsJson('{"ok":true,"rules":95,"problems":[]}')).toEqual({ rules: 95, problems: [] });
        expect(parseVerifyDocsJson('[]')).toBeNull();
        expect(parseVerifyDocsJson('{"ok":true,"rules":95,"problems":[{"file":1}]}')).toBeNull();
        expect(parseVerifyDocsJson('verify-docs: crashed')).toBeNull();
    });

    it('should report a blind-spot token that is not the version expected, once per package it speaks for', () => {
        const files = new Map([['ROADMAP.md', '# Roadmap\n\n## Satellites — separate repositories, both 1.0.0\n'], ['docs/playgrounds/mcp.js', '/* src/tools/<name>.ts at the v1.0.0 tag. */\n']]);
        expect(evaluateBlindSpots(blindSpotTable(), files, { 'pkinative-cli': '1.0.0', 'pkinative-mcp': '1.0.0' })).toEqual([]);
        expect(evaluateBlindSpots(blindSpotTable(), files, { 'pkinative-cli': '1.0.0', 'pkinative-mcp': '1.2.0' })).toEqual([
            { id: 'roadmap-both-mcp', file: 'ROADMAP.md', line: 3, package: 'pkinative-mcp', current: '1.0.0', expected: '1.2.0' },
            { id: 'mcp-explorer-tag', file: 'docs/playgrounds/mcp.js', line: 1, package: 'pkinative-mcp', current: '1.0.0', expected: '1.2.0' },
        ]);
        expect(evaluateBlindSpots(blindSpotTable(), new Map(), { 'pkinative-mcp': '1.2.0' })).toEqual([]);
        // The rows match the tree as it is: a site that moved away would silently stop being watched.
        for (const row of blindSpotTable()) expect([...(TREE[row.file] ?? '').matchAll(row.pattern)].length, row.id).toBeGreaterThan(0);
    });

    it('should write one delta line per list that changed', () => {
        expect(deltaLines('pkinative-mcp 1.0.0 → 1.2.0', { tools: { added: ['a', 'b'], removed: ['c'] }, prompts: { added: [], removed: [] }, 'inputs:x': { added: [], removed: ['y'] } })).toEqual(['pkinative-mcp 1.0.0 → 1.2.0 tools: +a, +b / -c', 'pkinative-mcp 1.0.0 → 1.2.0 inputs:x: -y']);
        expect(deltaLines('x', null)).toEqual([]);
    });

    it('should group findings by batch, file and rule, give the deltas to the guide and the playground, and render only the batches with work', () => {
        const worklist = buildWorklist(DATE, 95, [
            finding('docs/guides/mcp.md', 'satellite-counts', 40),
            finding('docs/guides/mcp.md', 'mcp-surface-parity', 1),
            finding('docs/guides/mcp.html', 'guide-render-sync', 1),
            finding('docs/llms-index.json', 'llms-index-sync', 1),
            finding('README.md', 'satellite-stamps', 66, 'warn'),
        ], [{ id: 'roadmap-both-mcp', file: 'ROADMAP.md', line: 153, package: 'pkinative-mcp', current: '1.0.0', expected: '1.2.0' }], { mcp: ['pkinative-mcp 1.0.0 → 1.2.0 tools: +audit_directory'] });
        expect(worklist.verifyDocs).toEqual({ rules: 95, errors: 4, warnings: 1 });
        expect(worklist.batches['B2']).toMatchObject({ files: ['docs/guides/mcp.md'], deltas: ['pkinative-mcp 1.0.0 → 1.2.0 tools: +audit_directory'] });
        expect(worklist.batches['B2']?.findings.map((f) => `${f.file} ${f.rule}`)).toEqual(['docs/guides/mcp.html guide-render-sync', 'docs/guides/mcp.md mcp-surface-parity', 'docs/guides/mcp.md satellite-counts']);
        expect(worklist.batches['B6']?.deltas).toEqual(['pkinative-mcp 1.0.0 → 1.2.0 tools: +audit_directory']);
        expect(worklist.batches['B5']).toMatchObject({ files: ['README.md', 'ROADMAP.md'] });
        const md = renderWorklist(worklist);
        expect(md.split('\n').filter((l) => l.startsWith('## '))).toEqual(['## B2 — docs/guides/mcp.md', '## B5 — README.md, ROADMAP.md', '## B6', '## B0 — docs/llms-index.json']);
        expect(md).toContain('verify-docs: 95 rules, 4 errors, 1 warning');
        expect(md).toContain('Batches with work: B2 (3 findings), B5 (1 finding), B6 (0 findings), B0 (1 finding)');
        expect(md).toContain('- docs/guides/mcp.html (generated — edit docs/guides/mcp.md, then `npm run docs:guides`)\n  - [guide-render-sync]\n    - l.1: guide-render-sync at 1');
        expect(md).toContain('    - warn l.66: satellite-stamps at 66');
        expect(md).toContain('- ROADMAP.md:153 [roadmap-both-mcp] pkinative-mcp 1.0.0 → 1.2.0');
        expect(md.endsWith('\n')).toBe(true);
        expect(renderWorklist(buildWorklist(DATE, 95, [], [], {}))).toContain('Nothing to write: no batch has a finding, a blind spot or a delta.');
    });
});

// ── --show ───────────────────────────────────────────────────────────

describe('showUnit', () => {
    const factsJson = JSON.stringify(factsOf([CLI_TODAY, MCP_TODAY]));
    const many = Array.from({ length: 900 }, (_, i) => finding('docs/guides/cli.md', 'satellite-counts', i + 1));
    const worklistMd = renderWorklist(buildWorklist(DATE, 95, [...many, finding('docs/guides/mcp.md', 'satellite-stamps', 3)], [], {}));

    it(`should keep every unit of the real surfaces within ${SHOW_MAX_CHARS} characters, and the facts sheet within ${FACTS_MAX_LINES} lines`, () => {
        for (const unit of SHOW_UNITS) {
            const text = showUnit(unit, factsJson, worklistMd);
            expect(text, unit).not.toBeNull();
            expect(text?.length, unit).toBeLessThanOrEqual(SHOW_MAX_CHARS);
            expect(text?.endsWith('\n'), unit).toBe(true);
        }
        expect(renderFactsMarkdown(factsOf([CLI_TODAY, MCP_TODAY])).trimEnd().split('\n').length).toBeLessThanOrEqual(FACTS_MAX_LINES);
    });

    it('should print one batch, cut on a line with a pointer to the whole, and say when a batch has no work', () => {
        const b1 = showUnit('B1', factsJson, worklistMd) ?? '';
        expect(b1.startsWith('## B1 — docs/guides/cli.md\n')).toBe(true);
        expect(b1.endsWith('… (cut to the --show ceiling; the whole is in test-output/.satellites/worklist.md)\n')).toBe(true);
        expect(b1).not.toContain('## B2');
        expect(showUnit('B2', factsJson, worklistMd)).toBe('## B2 — docs/guides/mcp.md\n\n### verify-docs\n\n- docs/guides/mcp.md\n  - [satellite-stamps]\n    - l.3: satellite-stamps at 3\n');
        expect(showUnit('B4', factsJson, worklistMd)).toBe('## B4\n\nNothing for this batch in the last run.\n');
        expect(showUnit('worklist', factsJson, worklistMd)).toContain('Batches with work: B1 (900 findings), B2 (1 finding)');
        expect(showUnit('cli', factsJson, null)).toContain('### Command lines and their flags');
    });

    it('should return null for a unit whose file was never written', () => {
        expect(showUnit('facts', null, worklistMd)).toBeNull();
        expect(showUnit('B1', factsJson, null)).toBeNull();
        expect(showUnit('worklist', factsJson, null)).toBeNull();
    });
});

// ── The command line ─────────────────────────────────────────────────

describe('parseArgs', () => {
    it('should read the flags, the checkouts and the expected versions', () => {
        expect(parseArgs(['--expect', 'cli=1.1.0', 'mcp=1.2.0', '--capture', '--apply', '--worklist'], DATE)).toEqual({ roots: { cli: null, mcp: null }, expect: { cli: '1.1.0', mcp: '1.2.0' }, capture: true, apply: true, worklist: true, dryRun: false, date: DATE, show: null });
        expect(parseArgs(['--expect', 'pkinative-cli=1.1.0,mcp=1.2.0', '--cli', '../elsewhere', '--dry-run', '--date', '2026-12-01'], DATE)).toMatchObject({ roots: { cli: '../elsewhere', mcp: null }, expect: { cli: '1.1.0', mcp: '1.2.0' }, dryRun: true, date: '2026-12-01' });
        expect(parseArgs([], DATE)).toMatchObject({ capture: false, apply: false, worklist: false, show: null, expect: {} });
        expect(parseArgs(['--show', 'B3'], DATE)).toMatchObject({ show: 'B3' });
    });

    it('should read only the satellites --expect names, or every checkout when it names none', () => {
        const none = { cli: null, mcp: null };
        expect(selectedKeys({ expect: {}, roots: none })).toEqual(['cli', 'mcp']);
        // A release of one satellite never writes whatever state the other's checkout is in.
        expect(selectedKeys({ expect: { mcp: '1.2.0' }, roots: none })).toEqual(['mcp']);
        expect(selectedKeys({ expect: { cli: '1.1.0', mcp: '1.2.0' }, roots: none })).toEqual(['cli', 'mcp']);
        // A directory given on the command line is a package the caller asked for.
        expect(selectedKeys({ expect: { mcp: '1.2.0' }, roots: { cli: '../elsewhere', mcp: null } })).toEqual(['cli', 'mcp']);
    });

    it('should refuse what it cannot read, with the usage', () => {
        const refused: [string[], string][] = [
            [['--expect'], '--expect needs at least one'],
            [['--expect', 'react=1.0.0'], '--expect "react=1.0.0" is not <cli|mcp>=<X.Y.Z>'],
            [['--expect', 'cli=1.0'], '--expect "cli=1.0" is not'],
            [['--cli'], '--cli needs a directory'],
            [['--mcp', '--apply'], '--mcp needs a directory'],
            [['--date', 'tomorrow'], '--date "tomorrow" is not an ISO date'],
            [['--show', 'B9'], '--show "B9" is not one of'],
            [['--show', 'B1', '--apply'], '--show takes no other flag'],
            [['--json'], 'unknown argument "--json"'],
        ];
        for (const [argv, message] of refused) {
            const r = parseArgs(argv, DATE);
            expect(typeof r === 'string' ? r : '', argv.join(' ')).toContain(message);
            expect(typeof r === 'string' ? r : '', argv.join(' ')).toContain('usage: npm run satellites:sync');
        }
    });

    it('should name a satellite by its key or its package, and split a command line as a shell would', () => {
        expect(satelliteKey('pkinative-cli')).toBe('cli');
        expect(satelliteKey('mcp')).toBe('mcp');
        expect(satelliteKey('pkinative')).toBeNull();
        expect(splitCommand('npx tsx src/bin.ts schema manifest')).toEqual(['npx', 'tsx', 'src/bin.ts', 'schema', 'manifest']);
        expect(splitCommand('  git log  --format="%cs %s" \'v1.0.0\' "" ')).toEqual(['git', 'log', '--format=%cs %s', 'v1.0.0', '']);
    });
});
