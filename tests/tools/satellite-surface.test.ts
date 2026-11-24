import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
    CAPTURE_COMMANDS,
    FACTS_MAX_LINES,
    SATELLITES,
    SHOW_MAX_CHARS,
    annotationOf,
    blindSpotTable,
    bulletsOf,
    clampShow,
    cliManifestOf,
    compareSemver,
    defaultOfDescription,
    diffSurface,
    joinCut,
    normaliseSurface,
    promptNamesOf,
    rangeMinimum,
    readPreviousSurface,
    readSurfaceOrDerive,
    renderFactsMarkdown,
    renderShow,
    resourceTemplatesOf,
    unverifiedKeys,
    wrapperCodesOf,
    type SatelliteFacts,
    type SatelliteSurface,
} from '../../scripts/lib/satellite-surface.js';
import { manifestOf, renderCliSurface } from '../../scripts/build-cli-surface.js';

// The pure half of scripts/satellite-sync.ts. Fake satellite checkouts are
// written under a temporary directory in the real shapes of what
// pkinative-cli and pkinative-mcp commit at 1.0.0, and the derivation is
// checked with and without the optional captures. No child process.

const roots: string[] = [];
afterAll(() => {
    for (const r of roots) rmSync(r, { recursive: true, force: true });
});

function tree(files: Record<string, unknown>): string {
    const root = mkdtempSync(join(tmpdir(), 'satellite-surface-'));
    roots.push(root);
    for (const [rel, content] of Object.entries(files)) {
        const path = join(root, ...rel.split('/'));
        mkdirSync(join(path, '..'), { recursive: true });
        writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    }
    return root;
}

// ── pkinative-cli ────────────────────────────────────────────────────

const input = { name: 'input', alias: 'i', value: 'file' };

/** What `pkinative schema manifest` prints, with the members the site drops (outputs, status). */
const cliManifest = (version = '1.0.0', inspectFlags: unknown[] = [input, { name: 'format', alias: 'f', value: 'text|json' }]): Record<string, unknown> => ({
    name: 'pkinative-cli',
    version,
    pkinative: '1.0.0',
    offline: true,
    wire: { bigint: 'decimal string', bytes: 'lowercase hex' },
    exitCodes: { 0: 'success', 1: 'failure', 2: 'usage error (E_USAGE)', 130: 'SIGINT', 143: 'SIGTERM' },
    errorCodes: [{ code: 'E_USAGE', meaning: 'A flag is missing or invalid (exit 2).' }, { code: 'E_PARSE', meaning: 'The bytes are not what they claim.' }],
    globalFlags: [{ name: 'help', alias: 'h' }, { name: 'json' }, { name: 'max-depth', value: 'n' }],
    commands: [
        {
            name: 'cert', group: 'Certificates', summary: 'Certificates',
            subcommands: [
                { name: 'inspect', summary: 'Decode a certificate', flags: inspectFlags, operands: { max: 1, for: ['input'] }, outputs: ['report'], report: true, status: {} },
                { name: 'create', summary: 'Issue a certificate', flags: [{ name: 'spec', value: 'file' }, { name: 'san', value: 'name', repeatable: true }], operands: { max: 0 }, outputs: ['artifact'] },
            ],
        },
        { name: 'doctor', group: 'Meta', summary: 'Check the runtime', flags: [], operands: { max: 0 }, outputs: ['report'], status: {} },
    ],
    schemas: ['status', 'error'],
});

const cliTree = (extra: Record<string, unknown> = {}): string => tree({
    'package.json': { name: 'pkinative-cli', version: '1.0.0', engines: { node: '^22.22.2 || ^24.14.1 || >=25.8.2' }, dependencies: { pkinative: '^1.0.0' } },
    'CHANGELOG.md': '# Changelog\n\n## [Unreleased]\n\n## [1.0.0] – 2026-10-08\n\nThe first release.\n\n### Added\n\n- **feat(cert):** `cert inspect`\n  and `cert create`.\n- **feat(meta):** `doctor`.\n',
    'docs/data/errors.json': { schemaVersion: 1, cliCodes: [{ code: 'E_USAGE' }, { code: 'E_PARSE' }], pkiToCli: [{ pkiCode: 'PKI_INVALID_INPUT', cliCode: 'E_INPUT', exitCode: 1 }, { pkiCode: 'PKI_ASN1_TRUNCATED', cliCode: 'E_PARSE', exitCode: 1 }] },
    'docs/data/core-exports.json': { counts: { exports: 294, capability: 117, typeOnly: 177 }, exports: [] },
    'docs/AGENT_CONTRACT.md': '# Agent contract\n',
    'src/commands/chain.ts': "// --anchor and --anchors are never both given\nthrow usageError('--at and --now are mutually exclusive.');\n",
    ...extra,
});

describe('readSurfaceOrDerive — pkinative-cli (degraded)', () => {
    it('should derive the version, pin, Node floor, ledger and links without a capture, and name what it could not', () => {
        const s = readSurfaceOrDerive(cliTree(), 'pkinative-cli');
        expect(s).toMatchObject({
            package: 'pkinative-cli', version: '1.0.0', previous: null, releasedOn: '2026-10-08', mode: 'degraded', delta: null,
            engine: { pin: '^1.0.0', pinField: 'dependencies', minimum: '1.0.0' },
            runtime: { node: '^22.22.2 || ^24.14.1 || >=25.8.2' },
            engineCoverage: { exports: 294, capability: 117, typeOnly: 177 },
            docs: { guide: 'https://pkinative.dev/guides/cli.html', agentContract: 'docs/AGENT_CONTRACT.md' },
        });
        expect(s.lists).toEqual({ pkiCodes: ['PKI_INVALID_INPUT', 'PKI_ASN1_TRUNCATED'] });
        expect(s.counts).toEqual({ pkiCodes: 2 });
        expect(s.structured).toEqual({});
        expect(cliManifestOf(s)).toBeNull();
        expect(s.ledger).toEqual([{ id: 'cl-1', summary: '**feat(cert):** `cert inspect` and `cert create`.' }, { id: 'cl-2', summary: '**feat(meta):** `doctor`.' }]);
        // The comment line is skipped; the literal is a constraint.
        expect(s.constraints).toEqual(['pkinative ^1.0.0 (dependencies)', 'node ^22.22.2 || ^24.14.1 || >=25.8.2', "src/commands/chain.ts:2: throw usageError('--at and --now are mutually exclusive.')"]);
        const keys = unverifiedKeys(s.unverified);
        for (const key of ['commands', 'invocations', 'errorClasses', 'schemaSubjects', 'limitFlags', 'configKeys', 'envVars', 'completionShells', 'flagDefaults', 'releasedOn']) expect(keys, key).toContain(key);
        expect(s.sources).toEqual(expect.arrayContaining(['package.json', 'docs/data/errors.json', 'CHANGELOG.md', 'src/commands/chain.ts']));
    });

    it('should take the captured manifest as the lists and the structured half, and count from the lists', () => {
        const s = readSurfaceOrDerive(cliTree(), 'pkinative-cli', { cliManifest: cliManifest(), tagDate: '2026-10-08' });
        expect(s.lists).toMatchObject({
            commands: ['cert', 'doctor'],
            invocations: ['cert inspect', 'cert create', 'doctor'],
            globalFlags: ['help', 'json', 'max-depth'],
            flags: ['input', 'format', 'spec', 'san'],
            errorClasses: ['E_USAGE', 'E_PARSE'],
            exitCodes: ['0', '1', '2', '130', '143'],
        });
        expect(s.counts).toEqual({ commands: 2, invocations: 3, globalFlags: 3, flags: 4, errorClasses: 2, exitCodes: 5, commandsWithoutSubcommands: 1, pkiCodes: 2 });
        expect(s.structured.flagDefaults).toEqual({});
        expect(s.structured.commands?.[0]).toEqual({
            name: 'cert', group: 'Certificates', summary: 'Certificates',
            subcommands: [
                { name: 'inspect', summary: 'Decode a certificate', flags: [input, { name: 'format', alias: 'f', value: 'text|json' }], operands: { max: 1, for: ['input'] } },
                { name: 'create', summary: 'Issue a certificate', flags: [{ name: 'spec', value: 'file' }, { name: 'san', value: 'name', repeatable: true }], operands: { max: 0 } },
            ],
        });
        // A tag date that agrees with the CHANGELOG leaves nothing to say about the release day.
        const keys = unverifiedKeys(s.unverified);
        expect(keys).not.toContain('releasedOn');
        expect(keys).not.toContain('commands');
        expect(keys).toContain('flagDefaults');
    });

    it('should hand renderCliSurface the manifest it was given: the snapshot is the same from a capture and from a surface', () => {
        const s = readSurfaceOrDerive(cliTree(), 'pkinative-cli', { cliManifest: cliManifest() });
        const manifest = cliManifestOf(s);
        expect(manifest).not.toBeNull();
        if (manifest === null) return;
        const fromCapture = renderCliSurface(manifestOf(cliManifest()));
        expect(renderCliSurface(manifest)).toBe(fromCapture);
        // The contract form of the same surface, through `--from surface.json`.
        const contract = { kind: 'satellite-surface', package: 'pkinative-cli', version: '1.0.0', engine: { pin: '^1.0.0' }, structured: s.structured };
        expect(renderCliSurface(manifestOf(contract))).toBe(fromCapture);
        expect(() => manifestOf({ kind: 'satellite-surface', package: 'pkinative-cli', version: '1.0.0' })).toThrow('carries no structured.commands');
    });

    it('should refuse a capture of another version rather than count from it', () => {
        const s = readSurfaceOrDerive(cliTree(), 'pkinative-cli', { cliManifest: cliManifest('0.9.0') });
        expect(s.lists.commands).toBeUndefined();
        expect(s.unverified.join('\n')).toContain("the captured manifest is pkinative-cli 0.9.0's, the checkout is at 1.0.0");
    });

    it('should report a class count that docs/data/errors.json contradicts', () => {
        const root = cliTree({ 'docs/data/errors.json': { cliCodes: [{ code: 'E_USAGE' }], pkiToCli: [{ pkiCode: 'PKI_INTERNAL' }] } });
        const s = readSurfaceOrDerive(root, 'pkinative-cli', { cliManifest: cliManifest() });
        expect(s.unverified).toContain('errorClasses: derived 2 items but docs/data/errors.json says 1');
    });
});

// ── pkinative-mcp ────────────────────────────────────────────────────

const tool = (name: string, readOnly: boolean, idempotent: boolean, inputs: string[]): Record<string, unknown> => ({
    name,
    title: name,
    annotations: { readOnlyHint: readOnly, destructiveHint: false, idempotentHint: idempotent, openWorldHint: false },
    inputSchema: { type: 'object', properties: Object.fromEntries(inputs.map((i) => [i, { type: 'string' }])) },
    exampleCount: 1,
});

const SERVER_TS = [
    "const NOT_A_PROMPT = { name: 'not_a_prompt' };",
    'const PROMPTS: readonly PromptDefinition[] = [',
    '    {',
    "        name: 'governance_contract',",
    "        title: 'AI-governance & HITL contract',",
    '    },',
    '    {',
    "        name: 'verify_before_trust',",
    '    },',
    '];',
    "const AFTER = [{\n        name: 'after_the_table',\n}];",
    '',
].join('\n');

const mcpTree = (extra: Record<string, unknown> = {}): string => tree({
    'package.json': { name: 'pkinative-mcp', version: '1.1.0', engines: { node: '>=22' }, dependencies: { pkinative: '^1.0.0', zod: '^4.2.0' } },
    'CHANGELOG.md': '# Changelog\n\n## [Unreleased]\n\n## [1.1.0] - 2026-11-02\n\n- A new tool.\n\n## [1.0.0] - 2026-10-13\n\n- The first release.\n',
    'release-notes/v1.1.0.md': '# pkinative-mcp v1.1.0\n\n## Highlights\n\n- Not the ledger.\n\n## Downstream integration notes\n\n- `inspect_certificate` takes `fields`.\n- One more prompt.\n\n## Install\n\n- npx.\n',
    'docs/assets/ecosystem.json': {
        derived: { tools: 3, toolGroups: { Encodings: ['convert_pem'], Certificates: ['inspect_certificate', 'create_certificate'] }, prompts: 2, errorCodes: 3, envVars: 2, examples: 2 },
        declared: { wrapperCodes: 2, toolsListBytes: 431641, instructionsBytes: 5469, mcpRevision: '2026-07-28', legacyRevisions: ['2024-11-05', '2025-06-18'], toolApiVersion: '1.0.0' },
    },
    'tests/_fixtures/tool-shape.json': [tool('convert_pem', false, true, ['mode', 'input']), tool('inspect_certificate', true, true, ['certificate', 'fields']), tool('create_certificate', false, false, ['spec'])],
    'tests/_fixtures/tool-shape.v1.0.0.json': [tool('convert_pem', false, true, ['mode', 'input']), tool('inspect_certificate', true, true, ['certificate'])],
    'tests/_fixtures/tool-shape.v1.1.0.json': [tool('convert_pem', false, true, ['mode', 'input'])],
    'server.json': {
        name: 'io.github.Nizoka/pkinative-mcp',
        packages: [{
            transport: { type: 'stdio' },
            environmentVariables: [
                { name: 'PKINATIVE_MCP_OUTPUT_DIR', description: 'The sandbox directory.', isSecret: false },
                { name: 'PKINATIVE_MCP_HTTP_TOKEN', description: 'Bearer token (default 1000; never logged).', isSecret: true },
            ],
        }],
    },
    'src/server.ts': SERVER_TS,
    'src/wrapper-codes.ts': "export const WRAPPER_CODES = [\n    { code: 'VALIDATION_ERROR', meaning: 'x' },\n    { code: 'IO_ERROR', meaning: 'y' },\n];\n",
    'src/resources.ts': "export const RESOURCE_URI_PREFIX = 'pkinative://output/';\nexport function listResourceTemplates() {\n    return [{ uriTemplate: `${RESOURCE_URI_PREFIX}{+path}` }];\n}\n",
    'src/errors.ts': "export class SandboxError extends ToolError {\n    constructor(m: string) { super('SECURITY_VIOLATION', m); }\n}\n",
    'src/tools/a.ts': "throw new ToolError('VALIDATION_ERROR', 'x');\nthrow new ToolError(\n    'IO_ERROR', 'y');\n",
    'examples/a.json': {},
    'examples/b.json': {},
    'examples/README.md': '# not an example\n',
    ...extra,
});

describe('readSurfaceOrDerive — pkinative-mcp (degraded)', () => {
    it('should derive tools with group, annotation and inputs, prompts, variables, both code lists and the scalars — with no capture', () => {
        const s = readSurfaceOrDerive(mcpTree(), 'pkinative-mcp');
        expect(s.lists).toEqual({
            tools: ['convert_pem', 'inspect_certificate', 'create_certificate'],
            prompts: ['governance_contract', 'verify_before_trust'],
            resourceTemplates: ['pkinative://output/{+path}'],
            envVars: ['PKINATIVE_MCP_OUTPUT_DIR', 'PKINATIVE_MCP_HTTP_TOKEN'],
            errorCodes: ['IO_ERROR', 'SECURITY_VIOLATION', 'VALIDATION_ERROR'],
            wrapperCodes: ['VALIDATION_ERROR', 'IO_ERROR'],
            examples: ['a.json', 'b.json'],
            legacyRevisions: ['2024-11-05', '2025-06-18'],
        });
        expect(s.counts).toEqual({ tools: 3, readOnlyTools: 1, writingTools: 1, producingTools: 1, prompts: 2, resourceTemplates: 1, envVars: 2, errorCodes: 3, wrapperCodes: 2, examples: 2, legacyRevisions: 2 });
        expect(s.structured).toEqual({
            tools: [
                { name: 'convert_pem', group: 'Encodings', annotation: 'writes', inputs: ['mode', 'input'] },
                { name: 'inspect_certificate', group: 'Certificates', annotation: 'readOnly', inputs: ['certificate', 'fields'] },
                { name: 'create_certificate', group: 'Certificates', annotation: 'produces', inputs: ['spec'] },
            ],
            envVars: [{ name: 'PKINATIVE_MCP_OUTPUT_DIR', default: null, isSecret: false }, { name: 'PKINATIVE_MCP_HTTP_TOKEN', default: '1000', isSecret: true }],
            registryName: 'io.github.Nizoka/pkinative-mcp',
            mcpRevision: '2026-07-28',
            toolApiVersion: '1.0.0',
            toolsListBytes: 431641,
            instructionsBytes: 5469,
        });
        // The frozen copy of the current release is not a previous one.
        expect(s.previous).toBe('1.0.0');
        expect(s.ledger).toEqual([{ id: 'rn-1', summary: '`inspect_certificate` takes `fields`.' }, { id: 'rn-2', summary: 'One more prompt.' }]);
        expect(unverifiedKeys(s.unverified)).toEqual(new Set(['transports', 'releasedOn']));
        expect(s.releasedOn).toBe('2026-11-02');
    });

    it('should take the tag day over the CHANGELOG heading, and say that they disagree', () => {
        const s = readSurfaceOrDerive(mcpTree(), 'pkinative-mcp', { tagDate: '2026-11-06' });
        expect(s.releasedOn).toBe('2026-11-06');
        expect(s.unverified).toContain('changelogDate: the CHANGELOG heading dates 1.1.0 to 2026-11-02; its tag was committed on 2026-11-06, which is the day used');
        expect(unverifiedKeys(s.unverified)).not.toContain('releasedOn');
    });

    it('should report a count the satellite records differently, and what a missing fixture leaves unknown', () => {
        const drift = readSurfaceOrDerive(mcpTree({ 'src/tools/b.ts': "throw new ToolError('NOT_FOUND', 'z');\n" }), 'pkinative-mcp');
        expect(drift.unverified).toContain('errorCodes: derived 4 items but docs/assets/ecosystem.json derived says 3');
        const bare = readSurfaceOrDerive(tree({ 'package.json': { name: 'pkinative-mcp', version: '1.0.0' } }), 'pkinative-mcp');
        expect(bare.lists).toEqual({});
        expect(bare.engine).toEqual({ pin: null, pinField: null, minimum: null });
        for (const key of ['tools', 'prompts', 'envVars', 'errorCodes', 'wrapperCodes', 'examples', 'resourceTemplates', 'ledger']) expect(unverifiedKeys(bare.unverified), key).toContain(key);
    });

    it('should read the previous release from the frozen fixture below the current version, and diff a tool\'s inputs', () => {
        const root = mcpTree();
        const next = readSurfaceOrDerive(root, 'pkinative-mcp');
        const prev = readPreviousSurface(root, 'pkinative-mcp', next.version);
        expect(prev?.version).toBe('1.0.0');
        expect(prev?.lists.tools).toEqual(['convert_pem', 'inspect_certificate']);
        expect(diffSurface(prev, next)).toEqual({
            tools: { added: ['create_certificate'], removed: [] },
            'inputs:inspect_certificate': { added: ['fields'], removed: [] },
        });
        expect(readPreviousSurface(root, 'pkinative-mcp', '1.0.0')).toBeNull();
        expect(readPreviousSurface(cliTree(), 'pkinative-cli', '1.0.0')).toBeNull();
    });
});

// ── Contract mode ────────────────────────────────────────────────────

const CONTRACT = {
    $schema: 'https://pkinative.dev/schema/surface/1.json',
    kind: 'satellite-surface',
    package: 'pkinative-cli',
    version: '1.1.0',
    previous: '1.0.0',
    releasedOn: '2026-11-20',
    engine: { pin: '^1.1.0', pinField: 'dependencies' },
    runtime: { node: '>=22' },
    lists: { commands: ['cert', 'doctor'], exitCodes: [0, 1, 2], envVars: ['PKINATIVE_JSON'], completionShells: ['bash', 'zsh'] },
    structured: {
        commands: [{ name: 'doctor', group: 'Meta', summary: 'Check the runtime', flags: [{ name: 'deep' }], operands: { max: 0 } }],
        globalFlags: [{ name: 'json' }],
        errorClasses: [{ code: 'E_USAGE', meaning: 'usage' }],
        exitCodes: { 0: 'success' },
        wire: { bytes: 'lowercase hex' },
        flagDefaults: { 'doctor.deep': 'false' },
        pkinative: '1.1.2',
        offline: true,
    },
    counts: { commands: 3, commandsWithoutSubcommands: 1 },
    delta: { 'flags:doctor': { added: ['deep'], removed: [] }, commands: { added: [], removed: [] } },
    constraints: ['--at and --now are never both given'],
    engineCoverage: { exports: 300 },
    ledger: [{ id: 'C1', summary: 'doctor --deep' }, { summary: 'no id' }],
    docs: { guide: 'https://pkinative.dev/guides/cli.html', llms: 'https://example.invalid/llms.txt', agentContract: 'docs/AGENT_CONTRACT.md' },
};

describe('readSurfaceOrDerive — contract mode', () => {
    it('should take docs/assets/surface.json as it is, normalised, and read nothing else', () => {
        const root = cliTree({ 'docs/assets/surface.json': CONTRACT });
        const s = readSurfaceOrDerive(root, 'pkinative-cli', { cliManifest: cliManifest() });
        expect(s).toMatchObject({ mode: 'contract', version: '1.1.0', previous: '1.0.0', releasedOn: '2026-11-20', sources: ['docs/assets/surface.json'] });
        expect(s.engine).toEqual({ pin: '^1.1.0', pinField: 'dependencies', minimum: '1.1.0' });
        expect(s.lists.exitCodes).toEqual(['0', '1', '2']);
        // A count is the list's length wherever the list is given, and the disagreement is said.
        expect(s.counts).toEqual({ commands: 2, commandsWithoutSubcommands: 1, exitCodes: 3, envVars: 1, completionShells: 2 });
        expect(s.unverified).toEqual(['commands: counts says 3, the list has 2 — the list wins']);
        expect(s.delta).toEqual({ 'flags:doctor': { added: ['deep'], removed: [] } });
        expect(s.ledger).toEqual([{ id: 'C1', summary: 'doctor --deep' }, { id: 'c-2', summary: 'no id' }]);
        expect(s.structured.flagDefaults).toEqual({ 'doctor.deep': 'false' });
        expect(cliManifestOf(s)).toMatchObject({ name: 'pkinative-cli', version: '1.1.0', pkinative: '1.1.2', offline: true, commands: [{ name: 'doctor' }] });
    });

    it('should default every field of an empty surface and say when the file is another package\'s', () => {
        const s = normaliseSurface({ package: 'pkinative-cli', structured: { tools: [{ name: 't', annotation: 'destroys', inputs: ['a'] }], envVars: [{ name: 'V', default: '1' }], mcpRevision: '2026-07-28', toolsListBytes: 12 } }, 'pkinative-mcp');
        expect(s).toMatchObject({ version: '0.0.0', previous: null, releasedOn: null, mode: 'contract', delta: null, lists: {}, counts: {}, constraints: [], ledger: [] });
        expect(s.structured).toEqual({ tools: [{ name: 't', group: null, annotation: null, inputs: ['a'] }], envVars: [{ name: 'V', default: '1', isSecret: false }], mcpRevision: '2026-07-28', toolsListBytes: 12 });
        expect(s.docs.guide).toBe('https://pkinative.dev/guides/mcp.html');
        expect(s.unverified).toEqual(['package: the surface says pkinative-cli, read as pkinative-mcp']);
    });
});

// ── Delta, facts, show ───────────────────────────────────────────────

const surface = (over: Partial<SatelliteSurface> = {}): SatelliteSurface => ({ ...normaliseSurface({ version: '1.0.0', engine: { pin: '^1.0.0', pinField: 'dependencies' } }, 'pkinative-cli'), mode: 'degraded', ...over });

describe('diffSurface', () => {
    it('should return {} for a null previous surface', () => {
        expect(diffSurface(null, surface({ lists: { commands: ['a'] } }))).toEqual({});
    });

    it('should sort added and removed, skip unchanged lists and lists absent on one side, and diff an invocation\'s flags', () => {
        const command = (flags: string[]): SatelliteSurface['structured'] => ({ commands: [{ name: 'cert', group: 'Certificates', summary: '', subcommands: [{ name: 'inspect', summary: '', flags: flags.map((name) => ({ name })) }] }] });
        const prev = surface({ lists: { commands: ['pem', 'oid', 'old'], errorClasses: ['E_USAGE'], onlyBefore: ['x'] }, structured: command(['input', 'format']) });
        const next = surface({ lists: { commands: ['zeta', 'pem', 'oid', 'alpha'], errorClasses: ['E_USAGE'], onlyAfter: ['y'] }, structured: command(['input', 'fields']) });
        expect(diffSurface(prev, next)).toEqual({
            commands: { added: ['alpha', 'zeta'], removed: ['old'] },
            'flags:cert inspect': { added: ['fields'], removed: ['format'] },
        });
    });
});

const factsOf = (entries: SatelliteSurface[]): SatelliteFacts => ({
    generatedOn: '2026-11-17',
    engineVersion: '1.0.0',
    satellites: Object.fromEntries(entries.map((s) => [s.package, { surface: s, previous: null, delta: s.delta ?? {}, manifestToday: { version: '1.0.0', released: '2026-10-08', pin: '^1.0.0', counts: { commands: 18 } } }])),
});

describe('renderFactsMarkdown and renderShow', () => {
    it('should keep the fixed heading order and the facts of each satellite', () => {
        const cli = readSurfaceOrDerive(cliTree(), 'pkinative-cli', { cliManifest: cliManifest(), tagDate: '2026-10-08' });
        const mcp = readSurfaceOrDerive(mcpTree(), 'pkinative-mcp');
        const md = renderFactsMarkdown(factsOf([mcp, cli]));
        const headings = md.split('\n').filter((l) => /^#{1,2} /.test(l));
        expect(headings).toEqual(['# Satellite facts — 2026-11-17 (pkinative 1.0.0)', '## pkinative-cli 1.0.0', '## pkinative-mcp 1.1.0', '## Blind spots', '## Capture commands']);
        expect(md).toContain('| pkinative-cli | 1.0.0 | — | 2026-10-08 | ^1.0.0 | dependencies | ^22.22.2 \\|\\| ^24.14.1 \\|\\| >=25.8.2 | 1.0.0 / 2026-10-08 / ^1.0.0 | degraded |');
        expect(md).toContain('| commands | — | 2 | 18 |');
        expect(md).toContain('- invocations (3): cert inspect, cert create, doctor');
        expect(md).toContain('Scalars: mcpRevision 2026-07-28; registryName io.github.Nizoka/pkinative-mcp; toolApiVersion 1.0.0; toolsListBytes 431641; instructionsBytes 5469');
        expect(md).toContain('- pkinative-cli: `npx tsx src/bin.ts schema manifest`');
        expect(md.endsWith('\n')).toBe(true);
        expect(md).not.toContain('\r');
    });

    it(`should never exceed ${FACTS_MAX_LINES} lines: the lists give way first, the ledger second`, () => {
        const many = (prefix: string, n: number): string[] => Array.from({ length: n }, (_, i) => `${prefix}-${i}`);
        const lists = Object.fromEntries(many('list', 120).map((k) => [k, many('item', 40)]));
        const big = surface({ lists, constraints: many('constraint', 12), ledger: many('entry', 12).map((summary, i) => ({ id: `cl-${i}`, summary })), unverified: many('gap', 10).map((g) => `${g}: unknown`) });
        const md = renderFactsMarkdown(factsOf([big, { ...big, package: 'pkinative-mcp' }]));
        const lines = md.trimEnd().split('\n');
        expect(lines.length).toBeLessThanOrEqual(FACTS_MAX_LINES);
        expect(md).toContain('items in `--show cli`');
        expect(md).toContain('## Blind spots');
        // Beyond every budget the sheet is cut, and says so.
        const huge = surface({ unverified: many('gap', 400).map((g) => `${g}: unknown`) });
        const cut = renderFactsMarkdown(factsOf([huge])).trimEnd().split('\n');
        expect(cut.length).toBe(FACTS_MAX_LINES);
        expect(cut[cut.length - 1]).toBe(`… (truncated to ${FACTS_MAX_LINES} lines; see facts.json)`);
    });

    it(`should keep one --show unit within ${SHOW_MAX_CHARS} characters, whatever the surface`, () => {
        const flags = Array.from({ length: 60 }, (_, i) => ({ name: `a-rather-long-flag-name-${i}`, value: 'file' }));
        const manifest = cliManifest('1.0.0', flags);
        (manifest.commands as { name: string; subcommands?: unknown[] }[])[0]?.subcommands?.push(...Array.from({ length: 80 }, (_, i) => ({ name: `sub-${i}`, summary: 's', flags })));
        const cli = readSurfaceOrDerive(cliTree(), 'pkinative-cli', { cliManifest: manifest });
        const mcp = readSurfaceOrDerive(mcpTree(), 'pkinative-mcp');
        const facts = factsOf([cli, mcp]);
        for (const unit of ['facts', 'cli', 'mcp'] as const) {
            const text = renderShow(facts, unit);
            expect(text.length, unit).toBeLessThanOrEqual(SHOW_MAX_CHARS);
            expect(text.endsWith('\n'), unit).toBe(true);
        }
        expect(renderShow(facts, 'mcp')).toContain('- inspect_certificate [Certificates; readOnly]: certificate, fields');
        expect(renderShow(facts, 'mcp')).toContain('- PKINATIVE_MCP_HTTP_TOKEN: default 1000; secret');
        expect(renderShow(facts, 'cli')).toContain('### Command lines and their flags');
        expect(renderShow(factsOf([mcp]), 'cli')).toContain('Not read in the last run');
    });

    it('should show an invocation with its flags when the unit fits', () => {
        const cli = readSurfaceOrDerive(cliTree(), 'pkinative-cli', { cliManifest: cliManifest() });
        const text = renderShow(factsOf([cli]), 'cli');
        expect(text).toContain('- cert inspect [Certificates]: --input/-i <file>, --format/-f <text|json>');
        expect(text).toContain('- cert create [Certificates]: --spec <file>, --san <name>…');
        expect(text).toContain('- doctor [Meta]: no flag of its own');
        expect(text).toContain('- none carried — see Unverified');
    });

    it('should cut an oversized unit on a line boundary and say so', () => {
        const text = clampShow(`${'a line of text\n'.repeat(2000)}`);
        expect(text.length).toBeLessThanOrEqual(SHOW_MAX_CHARS);
        expect(text.endsWith('facts.json)\n')).toBe(true);
        expect(clampShow('short\n')).toBe('short\n');
    });
});

// ── Blind spots and helpers ──────────────────────────────────────────

describe('blindSpotTable', () => {
    it('should hold rows with a global regex, a version group and a package the site documents', () => {
        const rows = blindSpotTable();
        expect(new Set(rows.map((r) => r.id)).size).toBe(rows.length);
        for (const row of rows) {
            expect(row.pattern.flags, row.id).toContain('g');
            expect(SATELLITES, row.id).toContain(row.package);
        }
        const find = (id: string, text: string): string | undefined => [...text.matchAll(rows.find((r) => r.id === id)?.pattern ?? /$^/g)][0]?.[1];
        expect(find('roadmap-both-cli', '# Roadmap\n\n## Satellites — separate repositories, both 1.0.0\n')).toBe('1.0.0');
        expect(find('roadmap-both-mcp', '## Engine — both 1.0.0\n')).toBeUndefined();
        expect(find('mcp-explorer-tag', '   zod schema of the matching src/tools/<name>.ts at the v1.0.0 tag.\n')).toBe('1.0.0');
    });
});

describe('helpers', () => {
    it('should name the two satellites, and capture commands for the CLI only', () => {
        expect(SATELLITES).toEqual(['pkinative-cli', 'pkinative-mcp']);
        expect(CAPTURE_COMMANDS['pkinative-cli']).toEqual(['npx tsx src/bin.ts schema manifest', 'npx -y pkinative-cli@{version} schema manifest']);
        expect(CAPTURE_COMMANDS['pkinative-mcp']).toEqual([]);
    });

    it('should keep whole items in joinCut and count the rest', () => {
        expect(joinCut(['alpha', 'beta', 'gamma'], 100)).toBe('alpha, beta, gamma');
        expect(joinCut(['alpha', 'beta', 'gamma'], 11)).toBe('alpha, beta… (+1)');
        expect(joinCut(['a-single-item-longer-than-the-budget'], 5)).toBe('a-single-item-longer-than-the-budget');
        expect(joinCut([], 10)).toBe('');
    });

    it('should join continuation lines and keep nested bullets in bulletsOf', () => {
        expect(bulletsOf(['- one', '  continued', '', 'prose', '  - nested', '* star'])).toEqual(['one continued', 'nested', 'star']);
    });

    it('should read the small extractors', () => {
        expect(defaultOfDescription('Ceiling of limits.maxInputBytes (default 67108864 = 64 MiB).')).toBe('67108864');
        expect(defaultOfDescription('Ceiling (default 1000, the engine default).')).toBe('1000');
        expect(defaultOfDescription('No default here, and the engine default applies.')).toBeNull();
        expect(promptNamesOf(SERVER_TS)).toEqual(['governance_contract', 'verify_before_trust']);
        expect(promptNamesOf('const TOOLS = [];')).toEqual([]);
        expect(wrapperCodesOf("{ code: 'A_B', x }, { code: 'A_B' }, { code: 'IO_ERROR' }")).toEqual(['A_B', 'IO_ERROR']);
        expect(resourceTemplatesOf("uriTemplate: 'pkinative://fixed/{id}', uriTemplate: `${UNKNOWN}{+path}`")).toEqual(['pkinative://fixed/{id}']);
        expect(annotationOf({ readOnlyHint: true })).toBe('readOnly');
        expect(annotationOf({ readOnlyHint: false, idempotentHint: true })).toBe('writes');
        expect(annotationOf({ readOnlyHint: false, idempotentHint: false })).toBe('produces');
        expect(annotationOf({})).toBeNull();
    });

    it('should compare versions and read the floor of a range', () => {
        expect(compareSemver('1.10.0', '1.9.0')).toBeGreaterThan(0);
        expect(compareSemver('1.0.0', '1.0.0')).toBe(0);
        expect(compareSemver('1.0.0', '2.0.0')).toBeLessThan(0);
        expect(rangeMinimum('^1.0.0')).toBe('1.0.0');
        expect(rangeMinimum('>=1.2.3 <2')).toBe('1.2.3');
        expect(rangeMinimum(null)).toBeNull();
        expect(rangeMinimum('latest')).toBeNull();
    });
});
