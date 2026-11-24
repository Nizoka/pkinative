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
 * the manifest (`satellite-counts`), every version, release day and pin it
 * writes (`satellite-stamps`), the capability × surface registry to
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
const CLI_BUILDER = 'docs/playgrounds/cli.js';
const MCP_EXPLORER = 'docs/playgrounds/mcp.js';

/** `packages.pkinative-cli` of the manifest. */
export interface CliPackage {
    readonly version?: unknown;
    readonly released?: unknown;
    readonly status?: unknown;
    readonly repo?: unknown;
    readonly binary?: unknown;
    readonly pin?: unknown;
    readonly counts?: { readonly commands?: unknown; readonly invocations?: unknown; readonly errorClasses?: unknown; readonly schemaSubjects?: unknown };
    readonly commandGroups?: Record<string, string[]>;
    readonly envVars?: unknown;
}

/** `packages.pkinative-mcp` of the manifest. */
export interface McpPackage {
    readonly version?: unknown;
    readonly released?: unknown;
    readonly status?: unknown;
    readonly repo?: unknown;
    readonly binary?: unknown;
    readonly pin?: unknown;
    readonly counts?: { readonly tools?: unknown; readonly prompts?: unknown; readonly wrapperCodes?: unknown };
    readonly tools?: string[];
    readonly toolGroups?: Record<string, number>;
    readonly toolAnnotations?: { readonly readOnly?: unknown; readonly writes?: string[]; readonly produces?: string[] };
    readonly prompts?: string[];
    readonly resourceTemplates?: string[];
    readonly envVars?: string[];
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
    summary: 'packages.pkinative-cli and packages.pkinative-mcp of docs/assets/ecosystem.json are complete and agree with themselves — published with a semver version, a Nizoka repository, a binary and a ^ pin; counts.commands with the command groups and with docs/data/cli-surface.json (version, groups, invocations, error classes); counts.tools with the tool list, its groups and its three annotation classes; counts.prompts with the prompt list.',
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
        if (cli.counts?.commands !== grouped.length) out.push(error(MANIFEST, `packages.pkinative-cli.counts.commands is ${String(cli.counts?.commands)}; its commandGroups list ${String(grouped.length)}`));
        if (surface.version !== cli.version) out.push(error(CLI_SURFACE, `snapshots pkinative-cli ${String(surface.version)}; the manifest records ${String(cli.version)} — re-run scripts/build-cli-surface.ts on the published CLI`));
        const snapshot = new Map((surface.commands ?? []).map((c) => [c.name, c.group]));
        for (const [group, names] of Object.entries(groups)) {
            for (const name of names) if (snapshot.get(name) !== group) out.push(error(MANIFEST, `packages.pkinative-cli.commandGroups puts ${name} in "${group}"; the CLI's own manifest says ${snapshot.has(name) ? `"${String(snapshot.get(name))}"` : 'it does not exist'}`));
        }
        for (const name of snapshot.keys()) if (!grouped.includes(name)) out.push(error(MANIFEST, `the CLI ships the command ${name}, which packages.pkinative-cli.commandGroups does not list`));
        if (cli.counts?.invocations !== invocations(surface).length) out.push(error(MANIFEST, `packages.pkinative-cli.counts.invocations is ${String(cli.counts?.invocations)}; the CLI surface has ${String(invocations(surface).length)} runnable command lines`));
        if (cli.counts?.errorClasses !== (surface.errorClasses ?? []).length) out.push(error(MANIFEST, `packages.pkinative-cli.counts.errorClasses is ${String(cli.counts?.errorClasses)}; the CLI surface declares ${String((surface.errorClasses ?? []).length)} error classes`));

        // The MCP server: tools, their groups and annotations, prompts.
        const tools = isStringArray(mcp.tools) ? mcp.tools : [];
        if (mcp.counts?.tools !== tools.length) out.push(error(MANIFEST, `packages.pkinative-mcp.counts.tools is ${String(mcp.counts?.tools)}; its tools list ${String(tools.length)}`));
        if (new Set(tools).size !== tools.length) out.push(error(MANIFEST, 'packages.pkinative-mcp.tools names a tool twice'));
        const groupTotal = Object.values(mcp.toolGroups ?? {}).reduce((a, b) => a + b, 0);
        if (groupTotal !== tools.length) out.push(error(MANIFEST, `packages.pkinative-mcp.toolGroups add up to ${String(groupTotal)}; the server registers ${String(tools.length)} tools`));
        const writes = mcp.toolAnnotations?.writes ?? [];
        const produces = mcp.toolAnnotations?.produces ?? [];
        for (const t of [...writes, ...produces]) if (!tools.includes(t)) out.push(error(MANIFEST, `packages.pkinative-mcp.toolAnnotations names ${t}, which is not one of its tools`));
        if (Number(mcp.toolAnnotations?.readOnly) + writes.length + produces.length !== tools.length) out.push(error(MANIFEST, `packages.pkinative-mcp.toolAnnotations: ${String(mcp.toolAnnotations?.readOnly)} read-only + ${String(writes.length)} writing + ${String(produces.length)} producing is not ${String(tools.length)} tools`));
        if (!isStringArray(mcp.prompts) || mcp.counts?.prompts !== mcp.prompts.length) out.push(error(MANIFEST, `packages.pkinative-mcp.counts.prompts is ${String(mcp.counts?.prompts)}; its prompts list ${String(isStringArray(mcp.prompts) ? mcp.prompts.length : 0)}`));
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
    readonly value: (cli: CliPackage, mcp: McpPackage, surface: CliSurface) => unknown;
    readonly context?: RegExp;
    /** Words that must come right before the number: "commands in" makes "six groups" the command groups. */
    readonly prefix?: string;
}

const MCP_CONTEXT = /\bMCP\b|pkinative-mcp/;
const CLI_CONTEXT = /\bCLI\b|pkinative-cli|`pkinative [a-z]/;

const withoutSubcommands = (surface: CliSurface): number => (surface.commands ?? []).filter((c) => (c.subcommands ?? []).length === 0).length;

const COUNT_PHRASES: readonly CountPhrase[] = [
    { phrase: '(?:MCP )?tools', value: (_c, m) => m.counts?.tools, context: MCP_CONTEXT },
    { phrase: '(?:MCP )?prompts', value: (_c, m) => m.counts?.prompts, context: MCP_CONTEXT },
    { phrase: 'wrapper codes', value: (_c, m) => m.counts?.wrapperCodes },
    // "the 6 commands that take none" counts the commands without subcommands, not the commands.
    { phrase: '(?:CLI )?commands(?! that take none| without)', value: (c) => c.counts?.commands, context: CLI_CONTEXT },
    { phrase: 'invocations', value: (c) => c.counts?.invocations },
    { phrase: 'error classes', value: (c) => c.counts?.errorClasses, context: /`E_|\bCLI\b|pkinative-cli/ },
    // The wider counts, each only in the words the prose already uses and on a line that says what is counted.
    { phrase: 'subcommands', value: (_c, _m, s) => invocations(s).length - withoutSubcommands(s), context: /\binvocations\b/ },
    { phrase: 'commands that take none', value: (_c, _m, s) => withoutSubcommands(s), context: /\binvocations\b|\bCLI\b|pkinative-cli/ },
    { phrase: '(?:schema )?subjects', value: (c) => c.counts?.schemaSubjects, context: /\bschema\b/ },
    { phrase: 'groups', prefix: 'commands in ', value: (c) => Object.keys(c.commandGroups ?? {}).length },
    { phrase: 'groups', prefix: 'tools in ', value: (_c, m) => Object.keys(m.toolGroups ?? {}).length },
    { phrase: 'environment variables', value: (_c, m) => (m.envVars ?? []).length, context: MCP_CONTEXT },
];

/** The prose a satellite count may appear in: the documentation, plus the root files that describe the ecosystem. */
const COUNT_SOURCES = (ctx: RuleContext): string[] => [...new Set([...PROSE_SOURCES(ctx), 'AGENTS.md', 'ROADMAP.md', 'CONTRIBUTING.md', 'SECURITY.md', 'SUPPORT.md', '.github/copilot-instructions.md'])];

const satelliteCounts: Rule = {
    id: 'satellite-counts',
    summary: 'Every count of a satellite quoted in the README, the root documents, the guides and the site — "34 tools", "seven prompts", "18 commands", "53 invocations", "13 error classes", "21 wrapper codes", "47 subcommands", "the 6 commands that take none", "twelve subjects", "commands in six groups", "tools in six groups", "nine environment variables", in digits or in words — equals packages.pkinative-cli / packages.pkinative-mcp of docs/assets/ecosystem.json (their counts, their inventories) or docs/data/cli-surface.json; a tools, prompts or variables count is read on a line about the MCP server, a commands or error-classes count on a line about the CLI.',
    check(ctx) {
        const sat = readSatellites(ctx);
        if ('finding' in sat) return [sat.finding];
        const out: Finding[] = [];
        for (const path of COUNT_SOURCES(ctx)) {
            const text = topEntryOnly(path, ctx.read(path) ?? '');
            const lines = text.split('\n');
            for (const { phrase, value, context, prefix } of COUNT_PHRASES) {
                const want = value(sat.cli, sat.mcp, sat.surface);
                // (?<![\d.]) keeps "pkinative-cli 1.0.0 commands" from reading as "0 commands".
                for (const m of text.matchAll(new RegExp(`${prefix === undefined ? '' : `\\b${prefix}`}(?<![\\d.\\-])\\b${NUMBER}\\s+${phrase}\\b`, 'gi'))) {
                    const line = lineOf(text, m.index);
                    if (context !== undefined && !context.test(lines[line - 1] ?? '')) continue;
                    if (quotedValue(m[1] ?? '') !== want) out.push(error(path, `quotes "${m[0]}"; docs/assets/ecosystem.json says ${String(want)}`, line));
                }
            }
        }
        return out;
    },
};

// ── satellite-stamps ─────────────────────────────────────────────────

type Short = 'cli' | 'mcp';

/** The package a file is about, by its name: the CLI guide, an MCP use case, a playground, a diagram. */
const packageOfPath = (path: string): Short | undefined => (/(?:^|[/-])(cli|mcp)(?:[.-][\w.-]+)?$/.exec(path)?.[1] as Short | undefined);

/** Where a satellite's version, release day or pin is written: the count sources but the histories, plus the two playground scripts, the use-case diagrams and two registries. */
const STAMP_SOURCES = (ctx: RuleContext): string[] => [...new Set([
    ...COUNT_SOURCES(ctx).filter((p) => p !== 'CHANGELOG.md' && !p.startsWith('docs/adr/')),
    ...ctx.list('docs/playgrounds').filter((p) => /^docs\/playgrounds\/(cli|mcp)\.js$/.test(p)),
    ...ctx.list('docs/assets').filter((p) => /^docs\/assets\/use-case-[\w-]+\.svg$/.test(p)),
    SURFACES,
    'docs/data/playgrounds.json',
])];

const TRIPLE = '(\\d+\\.\\d+\\.\\d+)';
/** `pkinative-cli 1.0.0`, `pkinative-cli@1.0.0`, `pkinative-cli-1.0.0.tgz`, the linked and code forms, "at the v1.0.0 tag", and a script's `name: …, version: …`. */
const VERSION_TOKEN = new RegExp(`pkinative-(cli|mcp)(?:\`|\\)|</a>)?(?:[ @-]v?| at the v|',\\s*version: ')${TRIPLE}(?![\\d.]*\\d)`, 'g');
const DATE_TOKEN = /\b(?:released on|published) (\d{4}-\d{2}-\d{2})\b/g;
const PIN_TOKEN = new RegExp(`(?<![\\w-])pkinative \\^${TRIPLE}`, 'g');

const satelliteStamps: Rule = {
    id: 'satellite-stamps',
    summary: 'Every version, release day and engine pin of a satellite written in the README, the root documents, the guides, the playgrounds and their scripts, the use-case diagrams and the surface registries — "pkinative-cli 1.0.0", "pkinative-mcp@1.0.0", "released on 2026-10-08", "pkinative ^1.0.0" — equals packages.<name>.version, .released and .pin of docs/assets/ecosystem.json; a pin on a line about one satellite is that satellite\'s, any other is both\'s; a historical floor ("since pkinative-mcp 1.0.0") is exempt, the changelog and the decision records are not read.',
    check(ctx) {
        const sat = readSatellites(ctx);
        if ('finding' in sat) return [sat.finding];
        const record: Record<Short, { version: unknown; released: unknown; pin: unknown }> = {
            cli: { version: sat.cli.version, released: sat.cli.released, pin: sat.cli.pin },
            mcp: { version: sat.mcp.version, released: sat.mcp.released, pin: sat.mcp.pin },
        };
        const out: Finding[] = [];
        for (const path of STAMP_SOURCES(ctx)) {
            const text = ctx.read(path);
            if (text === null) continue;
            const lines = text.split('\n');
            /** The one satellite a line names, if it names exactly one. */
            const named = (line: number): Short | undefined => {
                const names = new Set([...(lines[line - 1] ?? '').matchAll(/pkinative-(cli|mcp)/g)].map((m) => m[1] as Short));
                return names.size === 1 ? [...names][0] : undefined;
            };
            for (const m of text.matchAll(VERSION_TOKEN)) {
                // "`1.0.0` since pkinative-mcp 1.0.0" dates a fact; it does not say which version is current.
                if (/\bsince\s+[`(]?$/.test(text.slice(Math.max(0, m.index - 12), m.index))) continue;
                const short = m[1] as Short;
                if (m[2] !== record[short].version) out.push(error(path, `names pkinative-${short} ${m[2] ?? ''}; ${MANIFEST} records ${String(record[short].version)} — npm run satellites:sync -- --apply moves the manifest, a writer moves the prose`, lineOf(text, m.index)));
            }
            for (const m of text.matchAll(DATE_TOKEN)) {
                const line = lineOf(text, m.index);
                const short = named(line);
                if (short !== undefined && m[1] !== record[short].released) out.push(error(path, `dates pkinative-${short} to ${m[1] ?? ''}; ${MANIFEST} records its release on ${String(record[short].released)}`, line));
            }
            for (const m of text.matchAll(PIN_TOKEN)) {
                const line = lineOf(text, m.index);
                const short = named(line) ?? packageOfPath(path);
                // A sentence about no satellite in particular speaks for both: one finding, naming each pin it contradicts.
                const differing = (short === undefined ? (['cli', 'mcp'] as const) : [short]).filter((s) => `^${m[1] ?? ''}` !== record[s].pin);
                if (differing.length > 0) out.push(error(path, `says pkinative ^${m[1] ?? ''}; ${MANIFEST} records that ${differing.map((s) => `pkinative-${s} pins ${String(record[s].pin)}`).join(' and ')}`, line));
            }
        }
        return out;
    },
};

// ── surfaces-shape ───────────────────────────────────────────────────

interface Surfaces {
    readonly surfaces?: { readonly cli?: { readonly meta?: string[] }; readonly mcp?: { readonly meta?: string[] } };
    readonly capabilities?: ReadonlyArray<{
        readonly id?: string;
        readonly cli?: { readonly commands?: string[]; readonly pending?: unknown };
        readonly mcp?: { readonly tools?: string[]; readonly pending?: unknown };
    }>;
}

/** The shortest `pending` that can say which satellite release is awaited and what it should expose. */
const PENDING_REASON_MIN = 40;

/**
 * The names one satellite exposes a capability under — or none, when the
 * capability says in so many words that the satellite does not expose it yet.
 *
 * The engine releases first: an export of a minor has no command and no tool
 * until each satellite's own next minor, and the two honest ways to write that
 * are to leave the export out of the matrix (which `surfaces-parity` refuses)
 * or to say it is awaited. `pending` is that sentence. It replaces the names
 * and never accompanies them — a surface exposes a capability or awaits it —
 * and it is a reason somebody can act on, not a flag.
 */
function exposedNames(id: string, field: 'cli.commands' | 'mcp.tools', names: unknown, pending: unknown, what: string, out: Finding[]): readonly string[] {
    const side = field.slice(0, 3);
    if (pending === undefined) {
        if (!isStringArray(names) || names.length === 0) {
            out.push(error(SURFACES, `capability "${id}" has no ${field} — name the ${what} that expose it, or say under ${side}.pending what the satellite has yet to ship`));
            return [];
        }
        return names;
    }
    if (typeof pending !== 'string' || pending.trim().length < PENDING_REASON_MIN) {
        out.push(error(SURFACES, `capability "${id}" marks ${side} pending without a reason anyone could act on — say which release of the satellite is awaited and what it should expose`));
    }
    if (names !== undefined) {
        out.push(error(SURFACES, `capability "${id}" has both ${field} and ${side}.pending — a surface exposes a capability or awaits it, never both`));
    }
    return [];
}

const surfacesShape: Rule = {
    id: 'surfaces-shape',
    summary: 'Every capability of docs/data/surfaces.json names the pkinative-cli command lines (docs/data/cli-surface.json) and the pkinative-mcp tools (packages.pkinative-mcp.tools) that expose it, and only real ones — or says under cli.pending / mcp.pending, in a sentence and instead of any name, what that satellite has yet to ship; and every command line and every tool belongs to a capability or to the surface\'s declared meta list — the matrix a reader chooses a surface from cannot be smaller than the satellites, and cannot claim a command no satellite has.',
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
            const commands = exposedNames(id, 'cli.commands', c.cli?.commands, c.cli?.pending, 'command lines', out);
            const capabilityTools = exposedNames(id, 'mcp.tools', c.mcp?.tools, c.mcp?.pending, 'tools', out);
            for (const command of commands) {
                if (!lines.has(command)) out.push(error(SURFACES, `capability "${id}" names the CLI command line "${command}", which docs/data/cli-surface.json does not have`));
                usedLines.add(command);
            }
            for (const tool of capabilityTools) {
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
    summary: 'docs/guides/cli.md documents the whole surface of docs/data/cli-surface.json, and the command builder (docs/playgrounds/cli.js) loads that file: a `#### `pkinative <command>`` section per command in the CLI\'s order, every command line, every flag, every global flag and every error class — and names no command the CLI does not ship.',
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
        // The builder reads the snapshot itself rather than a copy that could drift from it.
        const builder = ctx.read(CLI_BUILDER);
        if (builder === null) out.push(error(CLI_BUILDER, 'missing — the CLI command builder'));
        else if (!/^const SURFACE_URL = '\.\.\/data\/cli-surface\.json';$/m.test(builder)) out.push(error(CLI_BUILDER, 'does not load ../data/cli-surface.json (const SURFACE_URL) — the builder must offer exactly the surface the snapshot records'));
        return out;
    },
};

// ── mcp-surface-parity ───────────────────────────────────────────────

const mcpSurfaceParity: Rule = {
    id: 'mcp-surface-parity',
    summary: 'docs/guides/mcp.md has exactly one `### `tool`` heading per tool of packages.pkinative-mcp.tools, in tools/list order, and names every prompt, every environment variable and every resource template the manifest records; the tool explorer (docs/playgrounds/mcp.js) has one card per tool in the same order.',
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
        // The explorer: one card per tool, in tools/list order.
        const explorer = ctx.read(MCP_EXPLORER);
        if (explorer === null) out.push(error(MCP_EXPLORER, 'missing — the MCP tool explorer'));
        else {
            const cards = [...explorer.matchAll(/^ {4}id: '([a-z0-9_]+)',$/gm)].map((m) => m[1] ?? '');
            if (cards.join(' ') !== tools.join(' ')) out.push(error(MCP_EXPLORER, `its tool cards are ${cards.join(', ')}; the server registers ${tools.join(', ')} in that order`));
        }
        return out;
    },
};

// ── versions-widget ──────────────────────────────────────────────────

export const VERSIONS_WIDGET = 'docs/assets/versions.js';

const versionsWidget: Rule = {
    id: 'versions-widget',
    summary: 'docs/assets/versions.js falls back to the version and pin docs/assets/ecosystem.json records for pkinative, pkinative-cli and pkinative-mcp, and every `data-pk-badge` under docs/ ships that version written in — the page says something true without JavaScript or with the registry unreachable.',
    check(ctx) {
        const manifest = readJson<{ packages?: Record<string, { version?: unknown; pin?: unknown } | undefined> }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const packages = manifest.value.packages ?? {};
        const widget = ctx.read(VERSIONS_WIDGET);
        if (widget === null) return [error(VERSIONS_WIDGET, 'missing — the landing page shows the versions npm serves through it')];
        const out: Finding[] = [];
        for (const name of ['pkinative', 'pkinative-cli', 'pkinative-mcp']) {
            const entry = packages[name];
            const m = new RegExp(`'${name}': \\{ version: '([^']+)', pin: (null|'[^']+') \\}`).exec(widget);
            if (m === null) { out.push(error(VERSIONS_WIDGET, `FALLBACK has no entry for ${name}`)); continue; }
            if (m[1] !== entry?.version) out.push(error(VERSIONS_WIDGET, `FALLBACK says ${name} ${m[1] ?? ''}; the manifest says ${String(entry?.version)}`, lineContaining(widget, `'${name}':`)));
            const pin = m[2] === 'null' ? undefined : m[2]?.slice(1, -1);
            if (pin !== entry?.pin) out.push(error(VERSIONS_WIDGET, `FALLBACK pins ${name} at ${String(pin)}; the manifest says ${String(entry?.pin)}`, lineContaining(widget, `'${name}':`)));
        }
        for (const path of ctx.list('docs').filter((p) => p.endsWith('.html'))) {
            const html = ctx.read(path) ?? '';
            for (const m of html.matchAll(/data-pk-badge="([^"]+)">v([^<]*)</g)) {
                const want = packages[m[1] ?? '']?.version;
                if (want === undefined) out.push(error(path, `a badge names ${m[1] ?? ''}, which is not a package of the manifest`, lineOf(html, m.index)));
                else if (m[2] !== want) out.push(error(path, `the ${m[1] ?? ''} badge ships v${m[2] ?? ''}; the manifest says ${String(want)}`, lineOf(html, m.index)));
            }
        }
        return out;
    },
};

export const SATELLITE_RULES: readonly Rule[] = [satelliteManifest, satelliteCounts, satelliteStamps, surfacesShape, cliSurfaceParity, mcpSurfaceParity, versionsWidget];
