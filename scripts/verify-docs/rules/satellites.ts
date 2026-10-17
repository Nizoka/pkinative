/**
 * pkinative — satellite rules
 * ===========================
 * pkinative-cli and pkinative-mcp are separate repositories, published on
 * their own cadence; this site documents them. Their counts and names live
 * once, in `packages.pkinative-cli` / `packages.pkinative-mcp` of
 * docs/assets/ecosystem.json, and the CLI's whole command surface in
 * docs/data/cli-surface.json, a projection of its own capability manifest
 * (`scripts/build-cli-surface.ts`). These rules hold the manifest to itself
 * and to that snapshot (`satellite-manifest`), every count the prose quotes to
 * the manifest (`satellite-counts`), the capability × surface registry to
 * both (`surfaces-shape`), and the CLI and MCP guides to the surfaces they
 * document (`cli-surface-parity`, `mcp-surface-parity`).
 *
 * pdfnative learned why the hard way: its site came to advertise 19 MCP tools
 * against a server registering 24.
 *
 * @module scripts/verify-docs/rules/satellites
 */

import { error, lineContaining, lineOf, readJson, type Finding, type Rule, type RuleContext } from '../context.js';
import { NUMBER, PROSE_SOURCES, quotedValue, topEntryOnly } from './site.js';

const MANIFEST = 'docs/assets/ecosystem.json';
export const CLI_SURFACE = 'docs/data/cli-surface.json';
const SURFACES = 'docs/data/surfaces.json';
export const CLI_GUIDE = 'docs/guides/cli.md';
export const MCP_GUIDE = 'docs/guides/mcp.md';

/** `packages.pkinative-cli` of the manifest. */
export interface CliPackage {
    readonly version?: unknown;
    readonly status?: unknown;
    readonly repo?: unknown;
    readonly binary?: unknown;
    readonly pin?: unknown;
    readonly commandCount?: unknown;
    readonly invocationCount?: unknown;
    readonly commandGroups?: Record<string, string[]>;
    readonly errorClassCount?: unknown;
    readonly envVars?: unknown;
}

/** `packages.pkinative-mcp` of the manifest. */
export interface McpPackage {
    readonly version?: unknown;
    readonly status?: unknown;
    readonly repo?: unknown;
    readonly binary?: unknown;
    readonly pin?: unknown;
    readonly toolCount?: unknown;
    readonly tools?: string[];
    readonly toolGroups?: Record<string, number>;
    readonly toolAnnotations?: { readonly readOnly?: unknown; readonly writes?: string[]; readonly produces?: string[] };
    readonly promptCount?: unknown;
    readonly prompts?: string[];
    readonly resourceTemplates?: string[];
    readonly envVars?: string[];
    readonly wrapperCodeCount?: unknown;
}

interface Flag { readonly name: string }
interface Invocation { readonly name: string; readonly flags?: readonly Flag[] }
interface CliCommand extends Invocation { readonly group: string; readonly subcommands?: readonly Invocation[] }
/** docs/data/cli-surface.json. */
export interface CliSurface {
    readonly version?: unknown;
    readonly errorClasses?: ReadonlyArray<{ readonly code: string }>;
    readonly globalFlags?: readonly Flag[];
    readonly commands?: readonly CliCommand[];
}

/** The two satellite records and the CLI snapshot, or the finding that stops a rule. */
export function readSatellites(ctx: RuleContext): { cli: CliPackage; mcp: McpPackage; surface: CliSurface } | { finding: Finding } {
    const manifest = readJson<{ packages?: Record<string, unknown> }>(ctx, MANIFEST);
    if ('finding' in manifest) return manifest;
    const surface = readJson<CliSurface>(ctx, CLI_SURFACE);
    if ('finding' in surface) return surface;
    const cli = manifest.value.packages?.['pkinative-cli'] as CliPackage | undefined;
    const mcp = manifest.value.packages?.['pkinative-mcp'] as McpPackage | undefined;
    if (cli === undefined || mcp === undefined) return { finding: error(MANIFEST, 'packages.pkinative-cli and packages.pkinative-mcp must both be recorded — the site documents them') };
    return { cli, mcp, surface: surface.value };
}

/** Every runnable command line of the CLI: `command subcommand`, or `command` when it takes none. */
export function invocations(surface: CliSurface): string[] {
    return (surface.commands ?? []).flatMap((c) => ((c.subcommands ?? []).length === 0 ? [c.name] : (c.subcommands ?? []).map((s) => `${c.name} ${s.name}`)));
}

const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string');

// ── satellite-manifest ───────────────────────────────────────────────

const satelliteManifest: Rule = {
    id: 'satellite-manifest',
    summary: 'packages.pkinative-cli and packages.pkinative-mcp of docs/assets/ecosystem.json are complete and agree with themselves — published with a semver version, a Nizoka repository, a binary and a ^ pin; the command count with the command groups and with docs/data/cli-surface.json (version, groups, invocations, error classes); the tool count with the tool list, its groups and its three annotation classes; the prompt count with the prompt list.',
    check(ctx) {
        const sat = readSatellites(ctx);
        if ('finding' in sat) return [sat.finding];
        const { cli, mcp, surface } = sat;
        const out: Finding[] = [];
        for (const [name, pkg] of [['pkinative-cli', cli], ['pkinative-mcp', mcp]] as const) {
            if (pkg.status !== 'published') out.push(error(MANIFEST, `packages.${name}.status is ${String(pkg.status)}; the satellite is on npm — "published"`));
            if (typeof pkg.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(pkg.version)) out.push(error(MANIFEST, `packages.${name}.version must be a semver triple`));
            if (pkg.repo !== `https://github.com/Nizoka/${name}`) out.push(error(MANIFEST, `packages.${name}.repo must be https://github.com/Nizoka/${name}`));
            if (typeof pkg.binary !== 'string' || pkg.binary === '') out.push(error(MANIFEST, `packages.${name}.binary must name the executable it installs`));
            if (typeof pkg.pin !== 'string' || !/^\^\d+\.\d+\.\d+$/.test(pkg.pin)) out.push(error(MANIFEST, `packages.${name}.pin must be the caret range it pins pkinative with`));
        }

        // The CLI: groups, count and the snapshot of its own manifest.
        const groups = cli.commandGroups ?? {};
        const grouped = Object.values(groups).flat();
        if (cli.commandCount !== grouped.length) out.push(error(MANIFEST, `packages.pkinative-cli.commandCount is ${String(cli.commandCount)}; its commandGroups list ${String(grouped.length)}`));
        if (surface.version !== cli.version) out.push(error(CLI_SURFACE, `snapshots pkinative-cli ${String(surface.version)}; the manifest records ${String(cli.version)} — re-run scripts/build-cli-surface.ts on the published CLI`));
        const snapshot = new Map((surface.commands ?? []).map((c) => [c.name, c.group]));
        for (const [group, names] of Object.entries(groups)) {
            for (const name of names) if (snapshot.get(name) !== group) out.push(error(MANIFEST, `packages.pkinative-cli.commandGroups puts ${name} in "${group}"; the CLI's own manifest says ${snapshot.has(name) ? `"${String(snapshot.get(name))}"` : 'it does not exist'}`));
        }
        for (const name of snapshot.keys()) if (!grouped.includes(name)) out.push(error(MANIFEST, `the CLI ships the command ${name}, which packages.pkinative-cli.commandGroups does not list`));
        if (cli.invocationCount !== invocations(surface).length) out.push(error(MANIFEST, `packages.pkinative-cli.invocationCount is ${String(cli.invocationCount)}; the CLI surface has ${String(invocations(surface).length)} runnable command lines`));
        if (cli.errorClassCount !== (surface.errorClasses ?? []).length) out.push(error(MANIFEST, `packages.pkinative-cli.errorClassCount is ${String(cli.errorClassCount)}; the CLI surface declares ${String((surface.errorClasses ?? []).length)} error classes`));

        // The MCP server: tools, their groups and annotations, prompts.
        const tools = isStringArray(mcp.tools) ? mcp.tools : [];
        if (mcp.toolCount !== tools.length) out.push(error(MANIFEST, `packages.pkinative-mcp.toolCount is ${String(mcp.toolCount)}; its tools list ${String(tools.length)}`));
        if (new Set(tools).size !== tools.length) out.push(error(MANIFEST, 'packages.pkinative-mcp.tools names a tool twice'));
        const groupTotal = Object.values(mcp.toolGroups ?? {}).reduce((a, b) => a + b, 0);
        if (groupTotal !== tools.length) out.push(error(MANIFEST, `packages.pkinative-mcp.toolGroups add up to ${String(groupTotal)}; the server registers ${String(tools.length)} tools`));
        const writes = mcp.toolAnnotations?.writes ?? [];
        const produces = mcp.toolAnnotations?.produces ?? [];
        for (const t of [...writes, ...produces]) if (!tools.includes(t)) out.push(error(MANIFEST, `packages.pkinative-mcp.toolAnnotations names ${t}, which is not one of its tools`));
        if (Number(mcp.toolAnnotations?.readOnly) + writes.length + produces.length !== tools.length) out.push(error(MANIFEST, `packages.pkinative-mcp.toolAnnotations: ${String(mcp.toolAnnotations?.readOnly)} read-only + ${String(writes.length)} writing + ${String(produces.length)} producing is not ${String(tools.length)} tools`));
        if (!isStringArray(mcp.prompts) || mcp.promptCount !== mcp.prompts.length) out.push(error(MANIFEST, `packages.pkinative-mcp.promptCount is ${String(mcp.promptCount)}; its prompts list ${String(isStringArray(mcp.prompts) ? mcp.prompts.length : 0)}`));
        return out;
    },
};

// ── satellite-counts ─────────────────────────────────────────────────

/**
 * The phrases a satellite count is quoted with. `context` keeps a phrase to
 * the satellite it counts: "ten tools run" on the interop line of ROADMAP.md
 * is the foreign-tool matrix, not the MCP server, and is never read.
 */
interface CountPhrase {
    readonly phrase: string;
    readonly value: (cli: CliPackage, mcp: McpPackage) => unknown;
    readonly context?: RegExp;
}

const MCP_CONTEXT = /\bMCP\b|pkinative-mcp/;
const CLI_CONTEXT = /\bCLI\b|pkinative-cli|`pkinative [a-z]/;

const COUNT_PHRASES: readonly CountPhrase[] = [
    { phrase: '(?:MCP )?tools', value: (_c, m) => m.toolCount, context: MCP_CONTEXT },
    { phrase: '(?:MCP )?prompts', value: (_c, m) => m.promptCount, context: MCP_CONTEXT },
    { phrase: 'wrapper codes', value: (_c, m) => m.wrapperCodeCount },
    // "the 6 commands that take none" counts the commands without subcommands, not the commands.
    { phrase: '(?:CLI )?commands(?! that take none| without)', value: (c) => c.commandCount, context: CLI_CONTEXT },
    { phrase: 'invocations', value: (c) => c.invocationCount },
    { phrase: 'error classes', value: (c) => c.errorClassCount, context: /`E_|\bCLI\b|pkinative-cli/ },
];

/** The prose a satellite count may appear in: the documentation, plus the root files that describe the ecosystem. */
const COUNT_SOURCES = (ctx: RuleContext): string[] => [...new Set([...PROSE_SOURCES(ctx), 'AGENTS.md', 'ROADMAP.md', 'CONTRIBUTING.md', 'SECURITY.md', 'SUPPORT.md', '.github/copilot-instructions.md'])];

const satelliteCounts: Rule = {
    id: 'satellite-counts',
    summary: 'Every count of a satellite quoted in the README, the root documents, the guides and the site — "34 tools", "seven prompts", "18 commands", "53 invocations", "13 error classes", "21 wrapper codes", in digits or in words — equals packages.pkinative-cli / packages.pkinative-mcp of docs/assets/ecosystem.json; a tools or prompts count is read on a line about the MCP server, a commands or error-classes count on a line about the CLI.',
    check(ctx) {
        const sat = readSatellites(ctx);
        if ('finding' in sat) return [sat.finding];
        const out: Finding[] = [];
        for (const path of COUNT_SOURCES(ctx)) {
            const text = topEntryOnly(path, ctx.read(path) ?? '');
            const lines = text.split('\n');
            for (const { phrase, value, context } of COUNT_PHRASES) {
                const want = value(sat.cli, sat.mcp);
                // (?<![\d.]) keeps "pkinative-cli 1.0.0 commands" from reading as "0 commands".
                for (const m of text.matchAll(new RegExp(`(?<![\\d.\\-])\\b${NUMBER}\\s+${phrase}\\b`, 'gi'))) {
                    const line = lineOf(text, m.index);
                    if (context !== undefined && !context.test(lines[line - 1] ?? '')) continue;
                    if (quotedValue(m[1] ?? '') !== want) out.push(error(path, `quotes "${m[0]}"; docs/assets/ecosystem.json says ${String(want)}`, line));
                }
            }
        }
        return out;
    },
};

// ── surfaces-shape ───────────────────────────────────────────────────

interface Surfaces {
    readonly surfaces?: { readonly cli?: { readonly meta?: string[] }; readonly mcp?: { readonly meta?: string[] } };
    readonly capabilities?: ReadonlyArray<{ readonly id?: string; readonly cli?: { readonly commands?: string[] }; readonly mcp?: { readonly tools?: string[] } }>;
}

const surfacesShape: Rule = {
    id: 'surfaces-shape',
    summary: 'Every capability of docs/data/surfaces.json names the pkinative-cli command lines (docs/data/cli-surface.json) and the pkinative-mcp tools (packages.pkinative-mcp.tools) that expose it, and only real ones; and every command line and every tool belongs to a capability or to the surface\'s declared meta list — the matrix a reader chooses a surface from cannot be smaller than the satellites.',
    check(ctx) {
        const sat = readSatellites(ctx);
        if ('finding' in sat) return [sat.finding];
        const parsed = readJson<Surfaces>(ctx, SURFACES);
        if ('finding' in parsed) return [parsed.finding];
        const out: Finding[] = [];
        const lines = new Set(invocations(sat.surface));
        const tools = new Set(sat.mcp.tools ?? []);
        const usedLines = new Set(parsed.value.surfaces?.cli?.meta ?? []);
        const usedTools = new Set(parsed.value.surfaces?.mcp?.meta ?? []);
        for (const meta of usedLines) if (!lines.has(meta)) out.push(error(SURFACES, `surfaces.cli.meta names ${meta}, which the CLI does not ship`));
        for (const meta of usedTools) if (!tools.has(meta)) out.push(error(SURFACES, `surfaces.mcp.meta names ${meta}, which the MCP server does not register`));
        for (const c of parsed.value.capabilities ?? []) {
            const id = c.id ?? '?';
            const commands = c.cli?.commands;
            const capabilityTools = c.mcp?.tools;
            if (!isStringArray(commands) || commands.length === 0) out.push(error(SURFACES, `capability "${id}" has no cli.commands — name the command lines that expose it`));
            if (!isStringArray(capabilityTools) || capabilityTools.length === 0) out.push(error(SURFACES, `capability "${id}" has no mcp.tools — name the tools that expose it`));
            for (const command of commands ?? []) {
                if (!lines.has(command)) out.push(error(SURFACES, `capability "${id}" names the CLI command line "${command}", which docs/data/cli-surface.json does not have`));
                usedLines.add(command);
            }
            for (const tool of capabilityTools ?? []) {
                if (!tools.has(tool)) out.push(error(SURFACES, `capability "${id}" names the MCP tool ${tool}, which packages.pkinative-mcp.tools does not list`));
                usedTools.add(tool);
            }
        }
        for (const line of lines) if (!usedLines.has(line)) out.push(error(SURFACES, `the CLI command line "${line}" belongs to no capability and is not in surfaces.cli.meta`));
        for (const tool of tools) if (!usedTools.has(tool)) out.push(error(SURFACES, `the MCP tool ${tool} belongs to no capability and is not in surfaces.mcp.meta`));
        return out;
    },
};

// ── cli-surface-parity ───────────────────────────────────────────────

const cliSurfaceParity: Rule = {
    id: 'cli-surface-parity',
    summary: 'docs/guides/cli.md documents the whole surface of docs/data/cli-surface.json: a `#### `pkinative <command>`` section per command in the CLI\'s order, every command line, every flag, every global flag and every error class — and names no command the CLI does not ship.',
    check(ctx) {
        const sat = readSatellites(ctx);
        if ('finding' in sat) return [sat.finding];
        const guide = ctx.read(CLI_GUIDE);
        if (guide === null) return [error(CLI_GUIDE, 'missing — the CLI is documented on this site')];
        const out: Finding[] = [];
        const commands = (sat.surface.commands ?? []).map((c) => c.name);
        const sections = [...guide.matchAll(/^#{3,4} `pkinative ([a-z0-9-]+)`/gm)].map((m) => m[1] ?? '');
        const meta = new Set((sat.surface.commands ?? []).filter((c) => c.group === 'Meta').map((c) => c.name));
        const documented = sections.filter((s) => commands.includes(s));
        const expectedOrder = commands.filter((c) => sections.includes(c));
        if (documented.join(' ') !== expectedOrder.join(' ')) out.push(error(CLI_GUIDE, `documents the commands in the order ${documented.join(', ')}; the CLI lists them ${expectedOrder.join(', ')}`));
        for (const s of sections) if (!commands.includes(s)) out.push(error(CLI_GUIDE, `has a section for pkinative ${s}, which the CLI does not ship`, lineContaining(guide, `\`pkinative ${s}\``)));
        for (const c of commands) {
            if (!sections.includes(c) && !(meta.has(c) && guide.includes(`\`pkinative ${c}`))) out.push(error(CLI_GUIDE, `does not document pkinative ${c} — a section \`#### \`pkinative ${c}\`\` (or, for a Meta command, its name in the Meta table)`));
        }
        for (const line of invocations(sat.surface)) {
            if (!guide.includes(line)) out.push(error(CLI_GUIDE, `never names the command line "pkinative ${line}"`));
        }
        const flags = new Set<string>([
            ...(sat.surface.globalFlags ?? []).map((f) => f.name),
            ...(sat.surface.commands ?? []).flatMap((c) => [...(c.flags ?? []), ...(c.subcommands ?? []).flatMap((s) => s.flags ?? [])].map((f) => f.name)),
        ]);
        for (const flag of flags) if (!new RegExp(`--${flag}\\b`).test(guide)) out.push(error(CLI_GUIDE, `never names the flag --${flag}, which the CLI accepts`));
        for (const { code } of sat.surface.errorClasses ?? []) if (!guide.includes(`\`${code}\``)) out.push(error(CLI_GUIDE, `never names the error class ${code}`));
        return out;
    },
};

// ── mcp-surface-parity ───────────────────────────────────────────────

const mcpSurfaceParity: Rule = {
    id: 'mcp-surface-parity',
    summary: 'docs/guides/mcp.md has exactly one `### `tool`` heading per tool of packages.pkinative-mcp.tools, in tools/list order, and names every prompt, every environment variable and every resource template the manifest records.',
    check(ctx) {
        const sat = readSatellites(ctx);
        if ('finding' in sat) return [sat.finding];
        const guide = ctx.read(MCP_GUIDE);
        if (guide === null) return [error(MCP_GUIDE, 'missing — the MCP server is documented on this site')];
        const out: Finding[] = [];
        const tools = sat.mcp.tools ?? [];
        const headings = [...guide.matchAll(/^### `([a-z0-9_]+)`\s*$/gm)].map((m) => m[1] ?? '');
        if (headings.join(' ') !== tools.join(' ')) {
            const missing = tools.filter((t) => !headings.includes(t));
            const extra = headings.filter((h) => !tools.includes(h));
            out.push(error(MCP_GUIDE, `its tool headings are not the server's tools in tools/list order${missing.length > 0 ? ` — missing ${missing.join(', ')}` : ''}${extra.length > 0 ? ` — not registered: ${extra.join(', ')}` : ''}${missing.length + extra.length === 0 ? ' — the order differs' : ''}`));
        }
        for (const prompt of sat.mcp.prompts ?? []) if (!guide.includes(`\`${prompt}\``)) out.push(error(MCP_GUIDE, `never names the prompt ${prompt}`));
        for (const env of sat.mcp.envVars ?? []) if (!guide.includes(env)) out.push(error(MCP_GUIDE, `never names the environment variable ${env}`));
        for (const template of sat.mcp.resourceTemplates ?? []) if (!guide.includes(template)) out.push(error(MCP_GUIDE, `never names the resource template ${template}`));
        return out;
    },
};

export const SATELLITE_RULES: readonly Rule[] = [satelliteManifest, satelliteCounts, surfacesShape, cliSurfaceParity, mcpSurfaceParity];
