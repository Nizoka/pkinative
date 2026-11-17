/**
 * pkinative — satellite surface: what each companion package exposes, read as data
 * =================================================================================
 * `scripts/satellite-sync.ts` aligns pkinative.dev with pkinative-cli and
 * pkinative-mcp. This module is its pure half: given a satellite checkout it
 * returns one `SatelliteSurface` (version, pin, lists, structured items,
 * counts, constraints, ledger), diffs two surfaces, renders the facts sheet
 * and the `--show` units the alignment agents read, and holds the table of
 * version sites no `verify:docs` rule sees.
 *
 * Two modes:
 *   contract  the satellite ships `docs/assets/surface.json`
 *             (.claude/skills/satellite-align/surface-contract.md) — taken
 *             as it is after normalisation;
 *   degraded  derived from what the satellites commit today —
 *             pkinative-cli: `package.json`, `docs/data/errors.json`,
 *             `docs/data/core-exports.json`, and the capability manifest the
 *             caller captured by running `CAPTURE_COMMANDS`;
 *             pkinative-mcp: `package.json`, `tests/_fixtures/tool-shape.json`,
 *             `server.json`, `docs/assets/ecosystem.json` (`derived` and
 *             `declared`), `src/server.ts`, `src/wrapper-codes.ts`,
 *             `src/resources.ts`, `examples/` — no capture, no install.
 *
 * Everything that could not be derived is named in `unverified`, as
 * `<key>[, <key>]: <why>`; every file read is named in `sources`. Zero
 * dependency: `node:fs` and `node:path` only — no child process, no network.
 *
 * @module scripts/lib/satellite-surface
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

// ── Contract ─────────────────────────────────────────────────────────

export type SatelliteName = 'pkinative-cli' | 'pkinative-mcp';

/** The satellites the site documents: separate repositories, published from 1.0.0. */
export const SATELLITES: readonly SatelliteName[] = ['pkinative-cli', 'pkinative-mcp'];

/** The short key of each satellite: the `--cli` / `--mcp` flags, the guide's file name. */
export const SHORT: Readonly<Record<SatelliteName, 'cli' | 'mcp'>> = { 'pkinative-cli': 'cli', 'pkinative-mcp': 'mcp' };

/** One flag of the CLI's capability manifest (`pkinative schema manifest`). */
export interface Flag { readonly name: string; readonly alias?: string; readonly value?: string; readonly repeatable?: boolean }
export interface Operands { readonly max?: number | null; readonly for?: readonly string[] }
export interface Invocation { readonly name: string; readonly summary: string; readonly flags?: readonly Flag[]; readonly operands?: Operands }
export interface Command extends Invocation { readonly group: string; readonly subcommands?: readonly Invocation[] }
/** What `pkinative schema manifest` prints, reduced to what this site projects. */
export interface CliManifest {
    readonly name: string;
    readonly version: string;
    readonly pkinative: string;
    readonly offline: boolean;
    readonly wire: Record<string, string>;
    readonly exitCodes: Record<string, string>;
    readonly errorCodes: ReadonlyArray<{ readonly code: string; readonly meaning: string }>;
    readonly globalFlags: readonly Flag[];
    readonly commands: readonly Command[];
}

export type ToolAnnotation = 'readOnly' | 'writes' | 'produces';
export interface ToolItem { readonly name: string; readonly group: string | null; readonly annotation: ToolAnnotation | null; readonly inputs: readonly string[] }
export interface EnvVarItem { readonly name: string; readonly default: string | null; readonly isSecret: boolean }

/** The structured half of a surface: the CLI members are exactly what `renderCliSurface` projects. */
export interface SurfaceStructured {
    // pkinative-cli
    commands?: readonly Command[];
    globalFlags?: readonly Flag[];
    errorClasses?: ReadonlyArray<{ readonly code: string; readonly meaning: string }>;
    exitCodes?: Readonly<Record<string, string>>;
    wire?: Readonly<Record<string, string>>;
    /** `"<invocation>.<flag>": "<default>"` — empty until the CLI's `FlagSpec` carries a default. */
    flagDefaults?: Readonly<Record<string, string>>;
    /** The engine version the CLI resolved when it printed its manifest. */
    pkinative?: string;
    offline?: boolean;
    // pkinative-mcp
    tools?: readonly ToolItem[];
    envVars?: readonly EnvVarItem[];
    mcpRevision?: string;
    registryName?: string;
    toolApiVersion?: string;
    toolsListBytes?: number;
    instructionsBytes?: number;
}

export interface SurfaceDelta {
    [list: string]: { added: readonly string[]; removed: readonly string[] };
}

export interface SatelliteSurface {
    package: SatelliteName;
    version: string;
    previous: string | null;
    releasedOn: string | null;
    engine: { pin: string | null; pinField: 'dependencies' | 'peerDependencies' | null; minimum: string | null };
    runtime: { node: string | null };
    /** Named lists (command names, tool names, error codes, …) — the unit of `diffSurface`. */
    lists: Record<string, readonly string[]>;
    structured: SurfaceStructured;
    /** List lengths, plus the derived splits (`commandsWithoutSubcommands`, `readOnlyTools`, …). */
    counts: Record<string, number>;
    /** The delta the satellite shipped (contract mode); null when this side has to compute it. */
    delta: SurfaceDelta | null;
    constraints: readonly string[];
    engineCoverage: Readonly<Record<string, number>>;
    ledger: readonly { id: string; summary: string }[];
    docs: { guide: string; llms: string; agentContract: string | null };
    mode: 'contract' | 'degraded';
    /** Files read, relative to the satellite root. */
    sources: readonly string[];
    /** What this surface could not establish, `<key>[, <key>]: <why>` — a writer marks it, never looks it up. */
    unverified: readonly string[];
}

/** What the caller obtained by running `CAPTURE_COMMANDS` and `TAG_DATE_ARGV` in the satellite root. */
export interface Captures {
    /** stdout of `pkinative schema manifest`, parsed. */
    cliManifest?: unknown;
    /** `YYYY-MM-DD`, the committer date of the `v<version>` tag — the release day, whatever the CHANGELOG says. */
    tagDate?: string;
}

/** What pkinative's own `docs/assets/ecosystem.json` says about one satellite today. */
export interface ManifestRow { version: string; released: string | null; pin: string | null; counts: Record<string, number> }

export interface SatelliteFacts {
    generatedOn: string;
    engineVersion: string;
    satellites: Partial<Record<SatelliteName, { surface: SatelliteSurface; previous: SatelliteSurface | null; delta: SurfaceDelta; manifestToday: ManifestRow }>>;
}

export interface BlindSpot {
    id: string;
    /** A path relative to the pkinative root. */
    file: string;
    /** Global; `versionGroup` captures the version. */
    pattern: RegExp;
    package: SatelliteName;
    versionGroup: number;
    kind: 'version' | 'pin';
    description: string;
}

/**
 * Command lines a caller runs in the satellite root, in order, until one
 * prints the JSON capture on stdout; `{version}` is the checkout's version.
 * pkinative-mcp needs none: its fixtures are committed.
 */
export const CAPTURE_COMMANDS: Readonly<Record<SatelliteName, readonly string[]>> = {
    'pkinative-cli': ['npx tsx src/bin.ts schema manifest', 'npx -y pkinative-cli@{version} schema manifest'],
    'pkinative-mcp': [],
};

/** `git` arguments printing the release day of a version; run in the satellite root, without a shell. */
export const TAG_DATE_ARGV = (version: string): readonly string[] => ['log', '-1', '--format=%cs', `v${version}`];

// ── Small helpers ────────────────────────────────────────────────────

type Dict = Record<string, unknown>;

const isRecord = (v: unknown): v is Dict => typeof v === 'object' && v !== null && !Array.isArray(v);
const asString = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const asNumber = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const stringArray = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const recordArray = (v: unknown): Dict[] => (Array.isArray(v) ? v.filter(isRecord) : []);
const get = (v: unknown, ...path: string[]): unknown => path.reduce<unknown>((o, k) => (isRecord(o) ? o[k] : undefined), v);
const unique = (items: readonly string[]): string[] => [...new Set(items)];
const collapse = (s: string): string => s.replace(/\s+/g, ' ').trim();
const cut = (s: string, max: number): string => (s.length > max ? `${s.slice(0, max - 1)}…` : s);
const stringRecord = (v: unknown): Record<string, string> => Object.fromEntries(Object.entries(isRecord(v) ? v : {}).filter((e): e is [string, string] => typeof e[1] === 'string'));
const numberRecord = (v: unknown): Record<string, number> => Object.fromEntries(Object.entries(isRecord(v) ? v : {}).filter((e): e is [string, number] => typeof e[1] === 'number'));

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export function compareSemver(a: string, b: string): number {
    const pa = SEMVER.exec(a);
    const pb = SEMVER.exec(b);
    if (!pa || !pb) return a.localeCompare(b);
    for (let i = 1; i <= 3; i++) {
        const d = Number(pa[i]) - Number(pb[i]);
        if (d !== 0) return d;
    }
    return 0;
}

/** The bare version of a range (`^1.0.0`, `~1.0.0`, `>=1.0.0` → `1.0.0`). */
export function rangeMinimum(range: string | null): string | null {
    const m = range === null ? null : /(\d+\.\d+\.\d+)/.exec(range);
    return m ? m[1] ?? null : null;
}

/** The keys an `unverified` entry names before its colon. */
export function unverifiedKeys(unverified: readonly string[]): Set<string> {
    return new Set(unverified.flatMap((u) => (u.split(':')[0] ?? '').split(/[\s,]+/).filter((k) => k.length > 0)));
}

/** One satellite checkout; records every file read. */
interface Reader {
    readonly root: string;
    readonly sources: string[];
    readonly unverified: string[];
}

function readText(r: Reader, rel: string): string | null {
    const path = join(r.root, rel);
    if (!existsSync(path) || !statSync(path).isFile()) return null;
    if (!r.sources.includes(rel)) r.sources.push(rel);
    return readFileSync(path, 'utf8').replace(/^﻿/, '');
}

function readJson(r: Reader, rel: string): unknown {
    const text = readText(r, rel);
    if (text === null) return undefined;
    try {
        return JSON.parse(text) as unknown;
    } catch {
        r.unverified.push(`${rel}: not valid JSON`);
        return undefined;
    }
}

function walkTs(dir: string, out: string[]): void {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir).sort()) {
        if (entry === 'node_modules' || entry.startsWith('.')) continue;
        const path = join(dir, entry);
        if (statSync(path).isDirectory()) walkTs(path, out);
        else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) out.push(path);
    }
}

/** The highest `<prefix><semver><suffix>` of a directory strictly below `below` — a previous release's capture. */
function highestVersionBelow(dir: string, prefix: string, suffix: string, below: string): string | null {
    if (!existsSync(dir)) return null;
    let best: string | null = null;
    for (const file of readdirSync(dir)) {
        if (!file.startsWith(prefix) || !file.endsWith(suffix)) continue;
        const v = file.slice(prefix.length, file.length - suffix.length);
        if (!SEMVER.test(v) || compareSemver(v, below) >= 0) continue;
        if (best === null || compareSemver(v, best) > 0) best = v;
    }
    return best;
}

// ── Common extraction ────────────────────────────────────────────────

interface PackageFacts {
    version: string;
    engine: SatelliteSurface['engine'];
    runtime: SatelliteSurface['runtime'];
}

function readPackage(r: Reader): PackageFacts {
    const pkg = readJson(r, 'package.json');
    if (pkg === undefined) r.unverified.push('version, pin, node: package.json is missing');
    const dep = asString(get(pkg, 'dependencies', 'pkinative'));
    const peer = asString(get(pkg, 'peerDependencies', 'pkinative'));
    const pin = dep ?? peer;
    return {
        version: asString(get(pkg, 'version')) ?? '0.0.0',
        engine: { pin, pinField: dep !== null ? 'dependencies' : peer !== null ? 'peerDependencies' : null, minimum: rangeMinimum(pin) },
        runtime: { node: asString(get(pkg, 'engines', 'node')) },
    };
}

/** The lines of one `## ` section (heading matched by `heading`), without the heading. */
function sectionLines(text: string, heading: RegExp): string[] | null {
    const lines = text.split(/\r?\n/);
    const start = lines.findIndex((l) => heading.test(l));
    if (start === -1) return null;
    const out: string[] = [];
    for (let i = start + 1; i < lines.length && !/^## /.test(lines[i] ?? ''); i++) out.push(lines[i] ?? '');
    return out;
}

/** Top-level and nested bullets of a section, continuation lines joined. */
export function bulletsOf(lines: readonly string[]): string[] {
    const out: string[] = [];
    let open = false;
    for (const line of lines) {
        const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
        if (bullet) {
            out.push((bullet[1] ?? '').trim());
            open = true;
        } else if (open && /^\s{2,}\S/.test(line)) {
            out[out.length - 1] += ` ${line.trim()}`;
        } else {
            open = false;
        }
    }
    return out.map(collapse).filter((s) => s.length > 0);
}

const LEDGER_MAX = 12;

/**
 * The release's ledger and day. The ledger is the `## Downstream integration
 * notes` of the release note when it has one, else the bullets of the top
 * CHANGELOG entry. The day is the tag's when the caller captured it — a
 * CHANGELOG heading is stamped when the release is prepared, which is not
 * always the day it ships — else the heading's (`-` or `–` before the date).
 */
function readLedger(r: Reader, version: string, tagDate: string | undefined): { ledger: SatelliteSurface['ledger']; releasedOn: string | null } {
    let heading: string | null = null;
    let changelogBullets: string[] = [];
    const changelog = readText(r, 'CHANGELOG.md');
    if (changelog !== null) {
        const lines = changelog.split(/\r?\n/);
        const top = lines.findIndex((l) => /^## \[?\d+\.\d+\.\d+\]?/.test(l));
        if (top !== -1) {
            const date = /(\d{4}-\d{2}-\d{2})/.exec(lines[top] ?? '');
            const topVersion = /(\d+\.\d+\.\d+)/.exec(lines[top] ?? '');
            if (date && topVersion && topVersion[1] === version) heading = date[1] ?? null;
            const section: string[] = [];
            for (let i = top + 1; i < lines.length && !/^## /.test(lines[i] ?? ''); i++) section.push(lines[i] ?? '');
            changelogBullets = bulletsOf(section);
        }
    }
    const tagged = tagDate !== undefined && ISO_DATE.test(tagDate) ? tagDate : null;
    if (tagged !== null && heading !== null && tagged !== heading) r.unverified.push(`changelogDate: the CHANGELOG heading dates ${version} to ${heading}; its tag was committed on ${tagged}, which is the day used`);
    if (tagged === null && heading !== null) r.unverified.push(`releasedOn: ${heading} is the CHANGELOG heading's date, not confirmed by the v${version} tag — run with --capture`);
    if (tagged === null && heading === null) r.unverified.push(`releasedOn: no v${version} tag date captured and no dated CHANGELOG heading for ${version}`);

    let bullets: string[] = [];
    let prefix = 'rn';
    const note = readText(r, `release-notes/v${version}.md`);
    const section = note === null ? null : sectionLines(note, /^## Downstream/);
    if (section !== null) bullets = bulletsOf(section);
    if (bullets.length === 0) {
        bullets = changelogBullets;
        prefix = 'cl';
    }
    if (bullets.length === 0) r.unverified.push('ledger: no Downstream section in the release note and no bullet in the top CHANGELOG entry');
    return { ledger: bullets.slice(0, LEDGER_MAX).map((summary, i) => ({ id: `${prefix}-${i + 1}`, summary: cut(summary, 220) })), releasedOn: tagged ?? heading };
}

function docsFor(root: string, name: SatelliteName): SatelliteSurface['docs'] {
    return {
        guide: `https://pkinative.dev/guides/${SHORT[name]}.html`,
        llms: `https://raw.githubusercontent.com/Nizoka/${name}/main/llms.txt`,
        agentContract: existsSync(join(root, 'docs', 'AGENT_CONTRACT.md')) ? 'docs/AGENT_CONTRACT.md' : null,
    };
}

const CONSTRAINT_WORDS = /mutually exclusive|not combinable|cannot be combined|incompatible with|never both/i;
const CONSTRAINTS_MAX = 12;

/** Cross-field constraints stated as literals in `src/**\/*.ts` — the sentence around each hit. */
function scanConstraints(r: Reader): string[] {
    const files: string[] = [];
    walkTs(join(r.root, 'src'), files);
    const out: string[] = [];
    for (const path of files) {
        const rel = path.slice(r.root.length + 1).replace(/\\/g, '/');
        const lines = readFileSync(path, 'utf8').split(/\r?\n/);
        for (let i = 0; i < lines.length && out.length < CONSTRAINTS_MAX; i++) {
            const line = lines[i] ?? '';
            if (!CONSTRAINT_WORDS.test(line) || /^\s*(?:\/\/|\/?\*)/.test(line)) continue;
            if (!r.sources.includes(rel)) r.sources.push(rel);
            out.push(`${rel}:${i + 1}: ${cut(collapse(line).replace(/^[`'"+\s]+/, '').replace(/[`'"+,;\s]+$/, ''), 160)}`);
        }
    }
    return out;
}

function pinConstraints(pkg: PackageFacts): string[] {
    const out: string[] = [];
    if (pkg.engine.pin !== null) out.push(`pkinative ${pkg.engine.pin} (${pkg.engine.pinField ?? '?'})`);
    if (pkg.runtime.node !== null) out.push(`node ${pkg.runtime.node}`);
    return out;
}

/** Lists as they are established, and the counts their lengths give. */
interface Bag {
    readonly r: Reader;
    readonly lists: Record<string, string[]>;
    readonly counts: Record<string, number>;
}

function addList(bag: Bag, key: string, items: readonly string[]): void {
    bag.lists[key] = [...items];
    bag.counts[key] = items.length;
}

/** A count the satellite records about itself, against the list this side derived. */
function checkOwnCount(bag: Bag, key: string, own: number | null, origin: string): void {
    const derived = bag.counts[key];
    if (own !== null && derived !== undefined && own !== derived) bag.r.unverified.push(`${key}: derived ${derived} items but ${origin} says ${own}`);
}

type Derived = Pick<SatelliteSurface, 'version' | 'previous' | 'engine' | 'runtime' | 'lists' | 'structured' | 'counts' | 'constraints' | 'engineCoverage'>;

// ── pkinative-cli ────────────────────────────────────────────────────

export const flagOf = (f: Flag): Flag => ({ name: f.name, ...(f.alias === undefined ? {} : { alias: f.alias }), ...(f.value === undefined ? {} : { value: f.value }), ...(f.repeatable === true ? { repeatable: true } : {}) });
export const invocationOf = (i: Invocation): Invocation => ({ name: i.name, summary: i.summary, flags: (i.flags ?? []).map(flagOf), ...(i.operands === undefined ? {} : { operands: i.operands }) });
/** A command as the site keeps it: the per-command JSON Schemas and status fields of the manifest are dropped. */
export const commandOf = (c: Command): Command => ({
    name: c.name,
    group: c.group,
    summary: c.summary,
    ...((c.subcommands ?? []).length === 0
        ? { flags: (c.flags ?? []).map(flagOf), ...(c.operands === undefined ? {} : { operands: c.operands }) }
        : { subcommands: (c.subcommands ?? []).map(invocationOf) }),
});

/** A capability manifest, or null when the value is not one. */
export function parseCliManifest(raw: unknown): CliManifest | null {
    if (!isRecord(raw) || raw.name !== 'pkinative-cli' || !Array.isArray(raw.commands) || !Array.isArray(raw.errorCodes)) return null;
    const flags = (v: unknown): Flag[] => recordArray(v).filter((f) => typeof f.name === 'string').map((f) => flagOf(f as unknown as Flag));
    const invocation = (v: Dict): Invocation => ({
        name: asString(v.name) ?? '',
        summary: asString(v.summary) ?? '',
        flags: flags(v.flags),
        ...(isRecord(v.operands) ? { operands: v.operands as Operands } : {}),
    });
    return {
        name: 'pkinative-cli',
        version: asString(raw.version) ?? '0.0.0',
        pkinative: asString(raw.pkinative) ?? '',
        offline: raw.offline === true,
        wire: stringRecord(raw.wire),
        exitCodes: stringRecord(raw.exitCodes),
        errorCodes: recordArray(raw.errorCodes).map((e) => ({ code: asString(e.code) ?? '', meaning: asString(e.meaning) ?? '' })),
        globalFlags: flags(raw.globalFlags),
        commands: recordArray(raw.commands).map((c) => ({
            ...invocation(c),
            group: asString(c.group) ?? '',
            ...(Array.isArray(c.subcommands) && c.subcommands.length > 0 ? { subcommands: recordArray(c.subcommands).map(invocation) } : {}),
        })),
    };
}

/** Every runnable command line: `command subcommand`, or `command` when it takes none. */
export function invocationsOf(commands: readonly Command[]): { name: string; flags: readonly Flag[] }[] {
    return commands.flatMap((c) => ((c.subcommands ?? []).length === 0
        ? [{ name: c.name, flags: c.flags ?? [] }]
        : (c.subcommands ?? []).map((s) => ({ name: `${c.name} ${s.name}`, flags: s.flags ?? [] }))));
}

/**
 * The capability manifest a CLI surface carries in `structured`, in the shape
 * `renderCliSurface` (scripts/build-cli-surface.ts) takes; null when the
 * surface has no command inventory (degraded mode without a capture).
 */
export function cliManifestOf(surface: SatelliteSurface): CliManifest | null {
    const s = surface.structured;
    if (surface.package !== 'pkinative-cli' || s.commands === undefined || s.errorClasses === undefined || s.globalFlags === undefined) return null;
    return {
        name: 'pkinative-cli',
        version: surface.version,
        pkinative: s.pkinative ?? surface.engine.minimum ?? '',
        offline: s.offline !== false,
        wire: { ...(s.wire ?? {}) },
        exitCodes: { ...(s.exitCodes ?? {}) },
        errorCodes: s.errorClasses,
        globalFlags: s.globalFlags,
        commands: s.commands,
    };
}

function cliStructured(manifest: CliManifest): SurfaceStructured {
    return {
        commands: manifest.commands.map(commandOf),
        globalFlags: manifest.globalFlags.map(flagOf),
        errorClasses: manifest.errorCodes.map(({ code, meaning }) => ({ code, meaning })),
        exitCodes: manifest.exitCodes,
        wire: manifest.wire,
        flagDefaults: {},
        pkinative: manifest.pkinative,
        offline: manifest.offline,
    };
}

function cliLists(bag: Bag, structured: SurfaceStructured): void {
    const commands = structured.commands ?? [];
    const invocations = invocationsOf(commands);
    addList(bag, 'commands', commands.map((c) => c.name));
    addList(bag, 'invocations', invocations.map((i) => i.name));
    addList(bag, 'globalFlags', (structured.globalFlags ?? []).map((f) => f.name));
    addList(bag, 'flags', unique(invocations.flatMap((i) => i.flags.map((f) => f.name))));
    addList(bag, 'errorClasses', (structured.errorClasses ?? []).map((e) => e.code));
    addList(bag, 'exitCodes', Object.keys(structured.exitCodes ?? {}));
    bag.counts.commandsWithoutSubcommands = commands.filter((c) => (c.subcommands ?? []).length === 0).length;
}

function readCli(r: Reader, captures: Captures): Derived {
    const pkg = readPackage(r);
    const bag: Bag = { r, lists: {}, counts: {} };
    let structured: SurfaceStructured = {};

    const manifest = parseCliManifest(captures.cliManifest);
    if (manifest === null) {
        r.unverified.push(`commands, invocations, globalFlags, flags, errorClasses, exitCodes, commandsWithoutSubcommands: no capture of the capability manifest — run with --capture (${CAPTURE_COMMANDS['pkinative-cli'][0] ?? ''})`);
    } else if (manifest.version !== pkg.version) {
        r.unverified.push(`commands, invocations, globalFlags, flags, errorClasses, exitCodes, commandsWithoutSubcommands: the captured manifest is pkinative-cli ${manifest.version}'s, the checkout is at ${pkg.version} — delete the cached capture and run with --capture`);
    } else {
        structured = cliStructured(manifest);
        cliLists(bag, structured);
    }

    const errors = readJson(r, 'docs/data/errors.json');
    const pkiCodes = recordArray(get(errors, 'pkiToCli')).map((e) => asString(e.pkiCode)).filter((c): c is string => c !== null);
    if (pkiCodes.length > 0) addList(bag, 'pkiCodes', pkiCodes);
    else r.unverified.push('pkiCodes: docs/data/errors.json is missing or has no pkiToCli table');
    checkOwnCount(bag, 'errorClasses', Array.isArray(get(errors, 'cliCodes')) ? recordArray(get(errors, 'cliCodes')).length : null, 'docs/data/errors.json');

    r.unverified.push('schemaSubjects: the manifest names its JSON Schema subjects only, not the documents `pkinative schema list` adds — the count stays the one recorded');
    r.unverified.push('limitFlags, configKeys, envVars, completionShells: carried by docs/assets/surface.json only — the inventories recorded stay as they are');
    r.unverified.push('flagDefaults: the CLI\'s FlagSpec has no default field — a default is read in the command\'s own help, never inferred');

    const coverage = numberRecord(get(readJson(r, 'docs/data/core-exports.json'), 'counts'));
    return { version: pkg.version, previous: null, engine: pkg.engine, runtime: pkg.runtime, lists: bag.lists, structured, counts: bag.counts, constraints: [...pinConstraints(pkg), ...scanConstraints(r)], engineCoverage: coverage };
}

// ── pkinative-mcp ────────────────────────────────────────────────────

interface ToolShape { readonly name: string; readonly annotation: ToolAnnotation | null; readonly inputs: string[] }

/** The annotation class of a tool: read-only, writes a deterministic artefact, or produces a non-idempotent one. */
export function annotationOf(annotations: unknown): ToolAnnotation | null {
    if (!isRecord(annotations) || typeof annotations.readOnlyHint !== 'boolean') return null;
    if (annotations.readOnlyHint) return 'readOnly';
    return annotations.idempotentHint === true ? 'writes' : 'produces';
}

/** `tests/_fixtures/tool-shape*.json`: the `tools/list` payload in registration order, or null. */
export function parseToolShape(raw: unknown): ToolShape[] | null {
    if (!Array.isArray(raw)) return null;
    return recordArray(raw)
        .filter((t) => typeof t.name === 'string')
        .map((t) => ({ name: t.name as string, annotation: annotationOf(t.annotations), inputs: isRecord(get(t, 'inputSchema', 'properties')) ? Object.keys(get(t, 'inputSchema', 'properties') as Dict) : [] }));
}

/**
 * `default <value>` inside an environment variable description (`default 1000`,
 * `(default 67108864 = 64 MiB)`): a value starts with a digit or a quote, so
 * "the engine default" and "by default it …" are not read as one.
 */
export function defaultOfDescription(description: string): string | null {
    const m = /\bdefault\s+([\d`'"][^\s;,)]*)/i.exec(description);
    return m ? m[1] ?? null : null;
}

function parseServerEnv(raw: unknown): EnvVarItem[] | null {
    const pkgs = recordArray(get(raw, 'packages'));
    if (pkgs.length === 0 || !Array.isArray(pkgs[0]?.environmentVariables)) return null;
    return recordArray(pkgs[0]?.environmentVariables)
        .filter((v) => typeof v.name === 'string')
        .map((v) => ({ name: v.name as string, default: defaultOfDescription(asString(v.description) ?? ''), isSecret: v.isSecret === true }));
}

/** The `name: '<prompt>'` entries of the `PROMPTS` table of `src/server.ts`. */
export function promptNamesOf(serverText: string): string[] {
    const start = serverText.search(/^(?:export )?const PROMPTS\b/m);
    if (start === -1) return [];
    const rest = serverText.slice(start);
    const end = rest.search(/^\];/m);
    return [...(end === -1 ? rest : rest.slice(0, end)).matchAll(/^\s+name:\s*'([a-z][a-z0-9_]*)'\s*,/gm)].map((m) => m[1] ?? '');
}

/** The `code: 'CODE'` rows of the wrapper-code table (`src/wrapper-codes.ts`). */
export function wrapperCodesOf(wrapperText: string): string[] {
    return unique([...wrapperText.matchAll(/\bcode:\s*'([A-Z][A-Z0-9_]+)'/g)].map((m) => m[1] ?? ''));
}

/** The `uriTemplate` literals of `src/resources.ts`, with `${RESOURCE_URI_PREFIX}` resolved. */
export function resourceTemplatesOf(resourcesText: string): string[] {
    const prefix = /\bRESOURCE_URI_PREFIX\s*=\s*'([^']+)'/.exec(resourcesText)?.[1];
    return unique([...resourcesText.matchAll(/\buriTemplate:\s*[`'"]([^`'"]+)[`'"]/g)]
        .map((m) => (m[1] ?? '').replace('${RESOURCE_URI_PREFIX}', prefix ?? '${RESOURCE_URI_PREFIX}'))
        .filter((t) => !t.includes('${')));
}

/** Every `ToolError('CODE'` literal of `src/**\/*.ts` plus the `super('CODE'` of `src/errors.ts`, sorted. */
function mcpErrorCodes(r: Reader): string[] | null {
    const files: string[] = [];
    walkTs(join(r.root, 'src'), files);
    if (files.length === 0) return null;
    const codes: string[] = [];
    for (const path of files) {
        const text = readFileSync(path, 'utf8');
        for (const m of text.matchAll(/ToolError\(\s*'([A-Z][A-Z0-9_]+)'/g)) codes.push(m[1] ?? '');
        if (path.replace(/\\/g, '/').endsWith('/src/errors.ts')) for (const m of text.matchAll(/super\(\s*'([A-Z][A-Z0-9_]+)'/g)) codes.push(m[1] ?? '');
    }
    if (!r.sources.includes('src/**/*.ts')) r.sources.push('src/**/*.ts');
    return unique(codes).sort();
}

function groupIndex(groups: unknown): Map<string, string> {
    const index = new Map<string, string>();
    if (isRecord(groups)) for (const [group, members] of Object.entries(groups)) for (const m of stringArray(members)) index.set(m, group);
    return index;
}

function mcpTools(bag: Bag, shape: readonly ToolShape[], groups: Map<string, string>): ToolItem[] {
    const tools = shape.map((t) => ({ name: t.name, group: groups.get(t.name) ?? null, annotation: t.annotation, inputs: t.inputs }));
    addList(bag, 'tools', tools.map((t) => t.name));
    const count = (a: ToolAnnotation): number => tools.filter((t) => t.annotation === a).length;
    bag.counts.readOnlyTools = count('readOnly');
    bag.counts.writingTools = count('writes');
    bag.counts.producingTools = count('produces');
    return tools;
}

function readMcp(r: Reader): Derived {
    const pkg = readPackage(r);
    const eco = readJson(r, 'docs/assets/ecosystem.json');
    const groups = groupIndex(get(eco, 'derived', 'toolGroups'));
    const bag: Bag = { r, lists: {}, counts: {} };
    const structured: SurfaceStructured = {};
    const own = (...path: string[]): number | null => asNumber(get(eco, ...path));
    if (eco === undefined) r.unverified.push('group, mcpRevision, legacyRevisions, toolApiVersion, toolsListBytes, instructionsBytes: docs/assets/ecosystem.json is missing');

    const shape = parseToolShape(readJson(r, 'tests/_fixtures/tool-shape.json'));
    if (shape === null) r.unverified.push('tools, readOnlyTools, writingTools, producingTools: tests/_fixtures/tool-shape.json is missing');
    else {
        structured.tools = mcpTools(bag, shape, groups);
        if (structured.tools.some((t) => t.group === null)) r.unverified.push('toolGroups: a tool of tests/_fixtures/tool-shape.json is in no group of docs/assets/ecosystem.json derived.toolGroups');
        if (structured.tools.some((t) => t.annotation === null)) r.unverified.push('toolAnnotations: a tool of tests/_fixtures/tool-shape.json carries no readOnlyHint');
    }
    checkOwnCount(bag, 'tools', own('derived', 'tools'), 'docs/assets/ecosystem.json derived');

    const server = readText(r, 'src/server.ts');
    const prompts = server === null ? [] : promptNamesOf(server);
    if (prompts.length > 0) addList(bag, 'prompts', prompts);
    else r.unverified.push('prompts: no PROMPTS table in src/server.ts');
    checkOwnCount(bag, 'prompts', own('derived', 'prompts'), 'docs/assets/ecosystem.json derived');

    const resources = readText(r, 'src/resources.ts');
    const templates = resources === null ? [] : resourceTemplatesOf(resources);
    if (templates.length > 0) addList(bag, 'resourceTemplates', templates);
    else r.unverified.push('resourceTemplates: no uriTemplate literal in src/resources.ts');

    const serverJson = readJson(r, 'server.json');
    const env = parseServerEnv(serverJson);
    if (env !== null) {
        structured.envVars = env;
        addList(bag, 'envVars', env.map((v) => v.name));
    } else r.unverified.push('envVars: server.json is missing or has no packages[0].environmentVariables');
    checkOwnCount(bag, 'envVars', own('derived', 'envVars'), 'docs/assets/ecosystem.json derived');
    const registryName = asString(get(serverJson, 'name'));
    if (registryName !== null) structured.registryName = registryName;

    const codes = mcpErrorCodes(r);
    if (codes !== null) addList(bag, 'errorCodes', codes);
    else r.unverified.push('errorCodes: src/ is missing');
    checkOwnCount(bag, 'errorCodes', own('derived', 'errorCodes'), 'docs/assets/ecosystem.json derived');

    const wrapper = readText(r, 'src/wrapper-codes.ts');
    const wrapperCodes = wrapper === null ? [] : wrapperCodesOf(wrapper);
    if (wrapperCodes.length > 0) addList(bag, 'wrapperCodes', wrapperCodes);
    else r.unverified.push('wrapperCodes: no code table in src/wrapper-codes.ts');
    checkOwnCount(bag, 'wrapperCodes', own('declared', 'wrapperCodes'), 'docs/assets/ecosystem.json declared');

    const examples = join(r.root, 'examples');
    if (existsSync(examples) && statSync(examples).isDirectory()) {
        r.sources.push('examples/*.json');
        addList(bag, 'examples', readdirSync(examples).filter((f) => f.endsWith('.json')).sort());
    } else r.unverified.push('examples: no examples/ directory');
    checkOwnCount(bag, 'examples', own('derived', 'examples'), 'docs/assets/ecosystem.json derived');

    const legacy = stringArray(get(eco, 'declared', 'legacyRevisions'));
    if (legacy.length > 0) addList(bag, 'legacyRevisions', legacy);
    r.unverified.push('transports: server.json declares the registry transport only — the list recorded stays as it is');

    const revision = asString(get(eco, 'declared', 'mcpRevision'));
    if (revision !== null) structured.mcpRevision = revision;
    const toolApi = asString(get(eco, 'declared', 'toolApiVersion'));
    if (toolApi !== null) structured.toolApiVersion = toolApi;
    const listBytes = own('declared', 'toolsListBytes');
    if (listBytes !== null) structured.toolsListBytes = listBytes;
    const instructionsBytes = own('declared', 'instructionsBytes');
    if (instructionsBytes !== null) structured.instructionsBytes = instructionsBytes;

    const previous = highestVersionBelow(join(r.root, 'tests', '_fixtures'), 'tool-shape.v', '.json', pkg.version);
    return { version: pkg.version, previous, engine: pkg.engine, runtime: pkg.runtime, lists: bag.lists, structured, counts: bag.counts, constraints: [...pinConstraints(pkg), ...scanConstraints(r)], engineCoverage: {} };
}

// ── Public: normalise, read, previous ────────────────────────────────

function normaliseStructured(raw: unknown): SurfaceStructured {
    const out: SurfaceStructured = {};
    if (!isRecord(raw)) return out;
    const manifest = parseCliManifest({ name: 'pkinative-cli', commands: raw.commands ?? [], errorCodes: raw.errorClasses ?? [], globalFlags: raw.globalFlags, wire: raw.wire, exitCodes: raw.exitCodes });
    if (manifest !== null && Array.isArray(raw.commands)) {
        out.commands = manifest.commands.map(commandOf);
        out.globalFlags = manifest.globalFlags;
        out.errorClasses = manifest.errorCodes;
        out.exitCodes = manifest.exitCodes;
        out.wire = manifest.wire;
        out.flagDefaults = stringRecord(raw.flagDefaults);
        if (typeof raw.pkinative === 'string') out.pkinative = raw.pkinative;
        if (typeof raw.offline === 'boolean') out.offline = raw.offline;
    }
    if (Array.isArray(raw.tools)) {
        out.tools = recordArray(raw.tools).map((t) => {
            const annotation = asString(t.annotation);
            return { name: asString(t.name) ?? '', group: asString(t.group), annotation: annotation === 'readOnly' || annotation === 'writes' || annotation === 'produces' ? annotation : null, inputs: stringArray(t.inputs) };
        });
    }
    if (Array.isArray(raw.envVars)) out.envVars = recordArray(raw.envVars).map((v) => ({ name: asString(v.name) ?? '', default: asString(v.default), isSecret: v.isSecret === true }));
    for (const key of ['mcpRevision', 'registryName', 'toolApiVersion'] as const) {
        const value = asString(raw[key]);
        if (value !== null) out[key] = value;
    }
    for (const key of ['toolsListBytes', 'instructionsBytes'] as const) {
        const value = asNumber(raw[key]);
        if (value !== null) out[key] = value;
    }
    return out;
}

function normaliseDelta(raw: unknown): SurfaceDelta | null {
    if (!isRecord(raw)) return null;
    const out: SurfaceDelta = {};
    for (const [key, value] of Object.entries(raw)) {
        const added = stringArray(get(value, 'added'));
        const removed = stringArray(get(value, 'removed'));
        if (added.length > 0 || removed.length > 0) out[key] = { added, removed };
    }
    return out;
}

/** A full surface from a `surface.json`-shaped value (contract mode), every field defaulted. */
export function normaliseSurface(raw: unknown, name: SatelliteName, sources: readonly string[] = ['docs/assets/surface.json']): SatelliteSurface {
    const lists: Record<string, readonly string[]> = {};
    const rawLists = get(raw, 'lists');
    if (isRecord(rawLists)) for (const [k, v] of Object.entries(rawLists)) if (Array.isArray(v)) lists[k] = v.map((x) => String(x));
    const pinField = asString(get(raw, 'engine', 'pinField'));
    const pin = asString(get(raw, 'engine', 'pin'));
    const unverified = stringArray(get(raw, 'unverified'));
    const declared = asString(get(raw, 'package'));
    if (declared !== null && declared !== name) unverified.push(`package: the surface says ${declared}, read as ${name}`);
    // A count is a list's length wherever the list is given: a surface cannot count 18 commands and list 17.
    const counts = numberRecord(get(raw, 'counts'));
    for (const [key, items] of Object.entries(lists)) {
        if (counts[key] !== undefined && counts[key] !== items.length) unverified.push(`${key}: counts says ${String(counts[key])}, the list has ${items.length} — the list wins`);
        counts[key] = items.length;
    }
    return {
        package: name,
        version: asString(get(raw, 'version')) ?? '0.0.0',
        previous: asString(get(raw, 'previous')),
        releasedOn: asString(get(raw, 'releasedOn')),
        engine: { pin, pinField: pinField === 'dependencies' || pinField === 'peerDependencies' ? pinField : null, minimum: asString(get(raw, 'engine', 'minimum')) ?? rangeMinimum(pin) },
        runtime: { node: asString(get(raw, 'runtime', 'node')) },
        lists,
        structured: normaliseStructured(get(raw, 'structured')),
        counts,
        delta: normaliseDelta(get(raw, 'delta')),
        constraints: stringArray(get(raw, 'constraints')),
        engineCoverage: numberRecord(get(raw, 'engineCoverage')),
        ledger: recordArray(get(raw, 'ledger')).map((l, i) => ({ id: asString(l.id) ?? `c-${i + 1}`, summary: asString(l.summary) ?? '' })),
        docs: {
            guide: asString(get(raw, 'docs', 'guide')) ?? `https://pkinative.dev/guides/${SHORT[name]}.html`,
            llms: asString(get(raw, 'docs', 'llms')) ?? `https://raw.githubusercontent.com/Nizoka/${name}/main/llms.txt`,
            agentContract: asString(get(raw, 'docs', 'agentContract')),
        },
        mode: get(raw, 'mode') === 'degraded' ? 'degraded' : 'contract',
        sources: [...sources],
        unverified,
    };
}

/**
 * The surface of one satellite checkout: `docs/assets/surface.json` when the
 * satellite ships the contract, else derived from its committed artefacts and
 * the optional `captures`.
 */
export function readSurfaceOrDerive(root: string, name: SatelliteName, captures: Captures = {}): SatelliteSurface {
    const r: Reader = { root, sources: [], unverified: [] };
    const contract = readJson(r, 'docs/assets/surface.json');
    if (contract !== undefined) return normaliseSurface(contract, name, r.sources);
    const read = name === 'pkinative-cli' ? readCli(r, captures) : readMcp(r);
    const { ledger, releasedOn } = readLedger(r, read.version, captures.tagDate);
    return { package: name, ...read, releasedOn, delta: null, ledger, docs: docsFor(root, name), mode: 'degraded', sources: r.sources, unverified: unique(r.unverified) };
}

/**
 * The previous release's surface, from the capture the satellite commits for
 * it — the `prev` side of `diffSurface` in degraded mode. pkinative-mcp
 * freezes `tests/_fixtures/tool-shape.v<version>.json` at each release;
 * pkinative-cli commits no such capture, and a contract surface carries its
 * own `delta`: null for both.
 */
export function readPreviousSurface(root: string, name: SatelliteName, current: string): SatelliteSurface | null {
    if (name !== 'pkinative-mcp') return null;
    const version = highestVersionBelow(join(root, 'tests', '_fixtures'), 'tool-shape.v', '.json', current);
    if (version === null) return null;
    const r: Reader = { root, sources: [], unverified: [] };
    const bag: Bag = { r, lists: {}, counts: {} };
    const shape = parseToolShape(readJson(r, `tests/_fixtures/tool-shape.v${version}.json`));
    const structured: SurfaceStructured = shape === null ? {} : { tools: mcpTools(bag, shape, groupIndex(get(readJson(r, 'docs/assets/ecosystem.json'), 'derived', 'toolGroups'))) };
    return {
        package: name,
        version,
        previous: null,
        releasedOn: null,
        engine: { pin: null, pinField: null, minimum: null },
        runtime: { node: null },
        lists: bag.lists,
        structured,
        counts: bag.counts,
        delta: null,
        constraints: [],
        engineCoverage: {},
        ledger: [],
        docs: docsFor(root, name),
        mode: 'degraded',
        sources: r.sources,
        unverified: unique(r.unverified),
    };
}

// ── Delta ────────────────────────────────────────────────────────────

function setDiff(prev: readonly string[], next: readonly string[]): { added: string[]; removed: string[] } {
    const p = new Set(prev);
    const n = new Set(next);
    return { added: [...n].filter((x) => !p.has(x)).sort(), removed: [...p].filter((x) => !n.has(x)).sort() };
}

/**
 * Added and removed items per list present on both sides, plus the
 * pseudo-lists `flags:<invocation>` and `inputs:<tool>` for structured items
 * present on both sides. Unchanged lists are omitted; a null `prev` gives `{}`.
 */
export function diffSurface(prev: SatelliteSurface | null, next: SatelliteSurface): SurfaceDelta {
    const out: SurfaceDelta = {};
    if (prev === null) return out;
    for (const [key, items] of Object.entries(next.lists)) {
        const before = prev.lists[key];
        if (before === undefined) continue;
        const d = setDiff(before, items);
        if (d.added.length > 0 || d.removed.length > 0) out[key] = d;
    }
    const structuredDiff = (prefix: string, a: readonly { name: string; items: readonly string[] }[], b: readonly { name: string; items: readonly string[] }[]): void => {
        const byName = new Map(a.map((x) => [x.name, x.items]));
        for (const item of b) {
            const before = byName.get(item.name);
            if (before === undefined) continue;
            const d = setDiff(before, item.items);
            if (d.added.length > 0 || d.removed.length > 0) out[`${prefix}:${item.name}`] = d;
        }
    };
    const flags = (s: SatelliteSurface): { name: string; items: string[] }[] => invocationsOf(s.structured.commands ?? []).map((i) => ({ name: i.name, items: i.flags.map((f) => f.name) }));
    const inputs = (s: SatelliteSurface): { name: string; items: readonly string[] }[] => (s.structured.tools ?? []).map((t) => ({ name: t.name, items: t.inputs }));
    structuredDiff('flags', flags(prev), flags(next));
    structuredDiff('inputs', inputs(prev), inputs(next));
    return out;
}

// ── Facts sheet ──────────────────────────────────────────────────────

/** The facts sheet never exceeds this many lines: it is read whole by the coordinator. */
export const FACTS_MAX_LINES = 200;
/** One `--show` unit never exceeds this many characters: a shell tool returns 16 000 at most. */
export const SHOW_MAX_CHARS = 15_000;

/** Comma-joined items cut at `max` characters, the remainder counted. */
export function joinCut(items: readonly string[], max: number): string {
    let out = '';
    let shown = 0;
    for (const item of items) {
        const next = shown === 0 ? item : `${out}, ${item}`;
        if (next.length > max && shown > 0) break;
        out = next;
        shown++;
    }
    return shown < items.length ? `${out}… (+${items.length - shown})` : out;
}

interface RenderBudget {
    /** Characters per list line; 0 omits the lists. */
    readonly listChars: number;
    readonly ledger: number;
    /** Characters per structured item (an invocation's flags, a tool's inputs); 0 omits the structured section. */
    readonly itemChars: number;
}

const FACTS_BUDGETS: readonly RenderBudget[] = [
    { listChars: 160, ledger: LEDGER_MAX, itemChars: 0 },
    { listChars: 80, ledger: 5, itemChars: 0 },
    { listChars: 0, ledger: 3, itemChars: 0 },
    { listChars: 0, ledger: 0, itemChars: 0 },
];

const SHOW_BUDGETS: readonly RenderBudget[] = [
    { listChars: 2000, ledger: LEDGER_MAX, itemChars: 400 },
    { listChars: 600, ledger: LEDGER_MAX, itemChars: 160 },
    { listChars: 300, ledger: 5, itemChars: 80 },
    { listChars: 120, ledger: 3, itemChars: 0 },
];

const dash = (v: string | number | null | undefined): string => (v === null || v === undefined || v === '' ? '—' : String(v));
// A Markdown table cell: backslashes first, then pipes, so an escaped pipe cannot be un-escaped by a preceding backslash.
const cell = (s: string): string => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');

type Entry = NonNullable<SatelliteFacts['satellites'][SatelliteName]>;

function entriesOf(facts: SatelliteFacts): (readonly [SatelliteName, Entry])[] {
    return SATELLITES.flatMap((n) => {
        const e = facts.satellites[n];
        return e === undefined ? [] : [[n, e] as const];
    });
}

function headerLines(facts: SatelliteFacts): string[] {
    const lines = [`# Satellite facts — ${facts.generatedOn} (pkinative ${dash(facts.engineVersion)})`, ''];
    const entries = entriesOf(facts);
    if (entries.length === 0) lines.push('No satellite checkout was read.');
    else {
        lines.push('| package | version | previous | released on | engine pin | pin field | node | manifest today (version / released / pin) | mode |', '|---|---|---|---|---|---|---|---|---|');
        for (const [name, e] of entries) {
            const s = e.surface;
            lines.push(`| ${name} | ${s.version} | ${dash(s.previous)} | ${dash(s.releasedOn)} | ${dash(s.engine.pin)} | ${dash(s.engine.pinField)} | ${cell(dash(s.runtime.node))} | ${dash(e.manifestToday.version)} / ${dash(e.manifestToday.released)} / ${dash(e.manifestToday.pin)} | ${s.mode} |`);
        }
    }
    return lines;
}

function flagText(f: Flag): string {
    return `--${f.name}${f.alias === undefined ? '' : `/-${f.alias}`}${f.value === undefined ? '' : ` <${f.value}>`}${f.repeatable === true ? '…' : ''}`;
}

function structuredLines(s: SatelliteSurface, budget: RenderBudget): string[] {
    if (budget.itemChars === 0) return [];
    const lines: string[] = [];
    const st = s.structured;
    if (st.commands !== undefined) {
        lines.push('', '### Command lines and their flags', '');
        const groups = new Map(st.commands.map((c) => [c.name, c.group]));
        for (const i of invocationsOf(st.commands)) lines.push(`- ${i.name} [${groups.get(i.name.split(' ')[0] ?? '') ?? '?'}]: ${i.flags.length === 0 ? 'no flag of its own' : joinCut(i.flags.map(flagText), budget.itemChars)}`);
        if (st.globalFlags !== undefined) lines.push('', '### Global flags', '', `- ${joinCut(st.globalFlags.map(flagText), budget.itemChars * 4)}`);
        if (st.errorClasses !== undefined) {
            lines.push('', '### Error classes', '');
            for (const e of st.errorClasses) lines.push(`- ${e.code}: ${cut(e.meaning, budget.itemChars)}`);
        }
        if (st.exitCodes !== undefined) lines.push('', '### Exit codes', '', `- ${Object.entries(st.exitCodes).map(([code, meaning]) => `${code} ${meaning}`).join('; ')}`);
        if (st.wire !== undefined) lines.push('', '### Wire form', '', `- ${Object.entries(st.wire).map(([k, v]) => `${k}: ${v}`).join('; ')}`);
        const defaults = Object.entries(st.flagDefaults ?? {});
        lines.push('', '### Flag defaults', '', defaults.length === 0 ? '- none carried — see Unverified' : `- ${joinCut(defaults.map(([k, v]) => `${k}=${v}`), budget.itemChars * 4)}`);
    }
    if (st.tools !== undefined) {
        lines.push('', '### Tools (tools/list order): group, annotation, top-level inputs', '');
        for (const t of st.tools) lines.push(`- ${t.name} [${dash(t.group)}; ${dash(t.annotation)}]: ${joinCut(t.inputs, budget.itemChars)}`);
    }
    if (st.envVars !== undefined) {
        lines.push('', '### Environment variables', '');
        for (const v of st.envVars) lines.push(`- ${v.name}: default ${dash(v.default)}${v.isSecret ? '; secret' : ''}`);
    }
    return lines;
}

function scalarLine(s: SatelliteSurface): string | null {
    const st = s.structured;
    const parts = [
        st.pkinative === undefined ? null : `engine resolved ${st.pkinative}`,
        st.offline === undefined ? null : `offline ${String(st.offline)}`,
        st.mcpRevision === undefined ? null : `mcpRevision ${st.mcpRevision}`,
        st.registryName === undefined ? null : `registryName ${st.registryName}`,
        st.toolApiVersion === undefined ? null : `toolApiVersion ${st.toolApiVersion}`,
        st.toolsListBytes === undefined ? null : `toolsListBytes ${st.toolsListBytes}`,
        st.instructionsBytes === undefined ? null : `instructionsBytes ${st.instructionsBytes}`,
        ...Object.entries(s.engineCoverage).map(([k, v]) => `engineCoverage.${k} ${v}`),
    ].filter((p): p is string => p !== null);
    return parts.length === 0 ? null : parts.join('; ');
}

function packageLines(name: SatelliteName, e: Entry, budget: RenderBudget): string[] {
    const s = e.surface;
    const lines = [`## ${name} ${s.version}`, '', '### Counts', '', '| key | previous | current | manifest today |', '|---|---|---|---|'];
    for (const key of unique([...Object.keys(e.manifestToday.counts), ...Object.keys(s.counts), ...Object.keys(e.previous?.counts ?? {})])) {
        lines.push(`| ${key} | ${dash(e.previous?.counts[key])} | ${dash(s.counts[key])} | ${dash(e.manifestToday.counts[key])} |`);
    }
    const scalars = scalarLine(s);
    if (scalars !== null) lines.push('', `Scalars: ${scalars}`);

    lines.push('', '### Lists', '');
    const listKeys = Object.keys(s.lists);
    if (listKeys.length === 0) lines.push('- none');
    else if (budget.listChars === 0) lines.push(`- ${listKeys.map((k) => `${k} (${s.lists[k]?.length ?? 0})`).join(', ')} — items in \`--show ${SHORT[name]}\``);
    else for (const key of listKeys) lines.push(`- ${key} (${s.lists[key]?.length ?? 0}): ${joinCut(s.lists[key] ?? [], budget.listChars)}`);

    lines.push(...structuredLines(s, budget));

    lines.push('', `### Delta${s.previous === null ? '' : ` against ${s.previous}`}`, '');
    const deltaKeys = Object.keys(e.delta);
    if (deltaKeys.length === 0) lines.push(e.previous === null && s.delta === null ? '- no previous surface to compare with' : '- none');
    for (const key of deltaKeys) {
        const d = e.delta[key];
        if (d === undefined) continue;
        lines.push(`- ${key}: ${joinCut([...d.added.map((x) => `+${x}`), ...d.removed.map((x) => `−${x}`)], Math.max(budget.listChars, 120))}`);
    }

    lines.push('', '### Constraints', '');
    if (s.constraints.length === 0) lines.push('- none derived');
    for (const c of s.constraints) lines.push(`- ${c}`);

    lines.push('', '### Ledger', '');
    const ledger = s.ledger.slice(0, budget.ledger);
    if (ledger.length === 0) lines.push(s.ledger.length === 0 ? '- none' : `- ${s.ledger.length} entries — in \`--show ${SHORT[name]}\``);
    for (const l of ledger) lines.push(`- [${l.id}] ${l.summary}`);
    if (ledger.length > 0 && ledger.length < s.ledger.length) lines.push(`- … (+${s.ledger.length - ledger.length})`);

    lines.push('', '### Unverified', '');
    if (s.unverified.length === 0) lines.push('- nothing');
    for (const u of s.unverified) lines.push(`- ${u}`);
    return lines;
}

function tailLines(): string[] {
    const lines = ['## Blind spots', '', 'Version sites no `verify:docs` rule sees; the expected value is `packages.<name>` of `docs/assets/ecosystem.json`.', '', '| id | file | kind | package | description |', '|---|---|---|---|---|'];
    for (const b of blindSpotTable()) lines.push(`| ${b.id} | ${cell(b.file)} | ${b.kind} | ${b.package} | ${cell(b.description)} |`);
    lines.push('', '## Capture commands', '', 'Run in the satellite root, in order, until one prints JSON on stdout (`--capture` does it).', '');
    for (const name of SATELLITES) {
        const cmds = CAPTURE_COMMANDS[name];
        if (cmds.length === 0) lines.push(`- ${name}: none (the committed fixtures are current)`);
        for (const c of cmds) lines.push(`- ${name}: \`${c}\``);
    }
    lines.push(`- both: \`git ${TAG_DATE_ARGV('<version>').join(' ')}\` (the release day)`);
    return lines;
}

function factsLines(facts: SatelliteFacts, budget: RenderBudget): string[] {
    const lines = headerLines(facts);
    for (const [name, e] of entriesOf(facts)) lines.push('', ...packageLines(name, e, budget));
    lines.push('', ...tailLines());
    return lines;
}

/** The compact facts sheet — the coordinator's view; never more than `FACTS_MAX_LINES` lines. */
export function renderFactsMarkdown(facts: SatelliteFacts): string {
    let lines: string[] = [];
    for (const budget of FACTS_BUDGETS) {
        lines = factsLines(facts, budget);
        if (lines.length <= FACTS_MAX_LINES) return `${lines.join('\n')}\n`;
    }
    const kept = lines.slice(0, FACTS_MAX_LINES - 1);
    kept.push(`… (truncated to ${FACTS_MAX_LINES} lines; see facts.json)`);
    return `${kept.join('\n')}\n`;
}

/** Cuts a unit to `SHOW_MAX_CHARS`, on a line boundary, and says where the whole is. */
export function clampShow(text: string, whole = 'test-output/.satellites/facts.json'): string {
    if (text.length <= SHOW_MAX_CHARS) return text;
    const note = `… (cut to the --show ceiling; the whole is in ${whole})\n`;
    const head = text.slice(0, SHOW_MAX_CHARS - note.length);
    return `${head.slice(0, head.lastIndexOf('\n') + 1)}${note}`;
}

/**
 * One unit of the facts for stdout — `facts` (the sheet) or one package with
 * its structured items — within `SHOW_MAX_CHARS`. The alignment agents read
 * facts through this, never from a file under test-output/.
 */
export function renderShow(facts: SatelliteFacts, unit: 'facts' | 'cli' | 'mcp'): string {
    if (unit === 'facts') return clampShow(renderFactsMarkdown(facts));
    const name: SatelliteName = unit === 'cli' ? 'pkinative-cli' : 'pkinative-mcp';
    const e = facts.satellites[name];
    if (e === undefined) return `# ${name}\n\nNot read in the last run: no checkout was found for it.\n`;
    let text = '';
    for (const budget of SHOW_BUDGETS) {
        text = `${[`# ${name} — facts of ${facts.generatedOn} (${e.surface.mode} mode)`, '', ...packageLines(name, e, budget).slice(2)].join('\n')}\n`;
        if (text.length <= SHOW_MAX_CHARS) return text;
    }
    return clampShow(text);
}

// ── Blind spots ──────────────────────────────────────────────────────

const VER = '(\\d+\\.\\d+\\.\\d+)';

/**
 * The version sites of the pkinative tree that neither `satellite-stamps`,
 * `versions-widget`, `jsonld-version` nor `satellite-manifest` polices: they
 * name no package beside the version, so no token rule can attribute them.
 * Each regex is global; the expected value is `packages.<package>.version`.
 */
export function blindSpotTable(): readonly BlindSpot[] {
    const both = (name: SatelliteName): BlindSpot => ({
        id: `roadmap-both-${SHORT[name]}`,
        file: 'ROADMAP.md',
        pattern: new RegExp(`^## Satellites\\b[^\\n]*\\bboth ${VER}`, 'gm'),
        package: name,
        versionGroup: 1,
        kind: 'version',
        description: 'the "both X.Y.Z" of the Satellites heading — reword it when the two versions differ',
    });
    return [
        both('pkinative-cli'),
        both('pkinative-mcp'),
        {
            id: 'mcp-explorer-tag',
            file: 'docs/playgrounds/mcp.js',
            pattern: new RegExp(`\\.ts at the v${VER} tag`, 'g'),
            package: 'pkinative-mcp',
            versionGroup: 1,
            kind: 'version',
            description: 'the header comment naming the tag the tool cards were written from',
        },
    ];
}
