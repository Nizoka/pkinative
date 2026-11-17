#!/usr/bin/env tsx
/**
 * pkinative — satellite synchronisation (`npm run satellites:sync`)
 * =================================================================
 * Reads the two satellite checkouts (pkinative-cli, pkinative-mcp) through
 * scripts/lib/satellite-surface.ts and turns what it finds into three
 * artefacts under test-output/.satellites/ (never committed):
 *
 *   facts.json + facts.md   versions, pins, counts, lists, deltas,
 *                           constraints, ledger and what could not be
 *                           derived — the only source the alignment agents
 *                           have; no agent opens a satellite
 *   worklist.md             (--worklist) what `verify:docs` still reports
 *                           after the mechanical edits, grouped by file and
 *                           rule into the writer batches B1…B6 (B0: the
 *                           coordinator), the version sites no rule sees,
 *                           and each package's surface delta
 *
 * `--apply` performs the mechanical edits of a satellite release, the rows of
 * `SATELLITE_EDITS`, each a targeted rewrite of the one field it owns (never
 * a reserialisation), planned by `planSatellites` and written only when no
 * row fails:
 *   docs/assets/ecosystem.json   packages.<name>: version, released, pin,
 *                                counts, the inventories
 *   docs/assets/versions.js      the FALLBACK rows
 *   docs/index.html              the `data-pk-badge` badges, JSON-LD
 *   docs/playgrounds/{cli,mcp}.html   JSON-LD softwareVersion
 *   docs/data/cli-surface.json   through renderCliSurface (build-cli-surface.ts)
 *   verifiedOn + <time id="verified-on">   when anything above moved
 * A field the surface could not establish (its `unverified` list) is kept as
 * it is and reported, never overwritten. An aligned tree reports only `=`.
 *
 * `--show <unit>` prints one unit of the last run to stdout, 15 000
 * characters at most: `facts`, `cli`, `mcp`, `worklist`, or a batch `B0`…`B6`.
 * It is how an agent reads the facts: test-output/ is denied to its Read tool.
 *
 * Usage:
 *   npm run satellites:sync -- --expect cli=1.1.0 mcp=1.1.0 --capture --apply --worklist
 *   npm run satellites:sync -- --capture --apply --dry-run
 *   npm run satellites:sync -- --show B1
 *
 * Flags: --cli/--mcp <dir> (default ../pkinative-<name> beside this
 * repository), --expect <name>=<semver>… (the checkout must be at that
 * version; only the packages it names are read, every checkout found when it
 * names none), --capture (run the satellites' capture commands: the CLI's
 * capability manifest, each tag's date), --apply, --worklist, --dry-run (the
 * repository edits are reported, not written; the reports always are),
 * --date YYYY-MM-DD (default today, UTC), --show <unit>.
 *
 * Exit: 0 done; 1 an --apply row found nothing to rewrite (nothing was
 * written), or --show before any run; 2 bad usage, or a checkout that is
 * missing or not at its --expect version; 3 verify-docs could not be run.
 *
 * Never a gate step: it reads sibling repositories and, under --capture,
 * runs them. It never pushes, tags, publishes or installs anything.
 *
 * @module scripts/satellite-sync
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderCliSurface, CLI_SURFACE } from './build-cli-surface.js';
import {
    CAPTURE_COMMANDS,
    SATELLITES,
    SHORT,
    TAG_DATE_ARGV,
    blindSpotTable,
    clampShow,
    cliManifestOf,
    diffSurface,
    readPreviousSurface,
    readSurfaceOrDerive,
    renderFactsMarkdown,
    renderShow,
    unverifiedKeys,
    type BlindSpot,
    type Captures,
    type ManifestRow,
    type SatelliteFacts,
    type SatelliteName,
    type SatelliteSurface,
    type SurfaceDelta,
} from './lib/satellite-surface.js';
import type { TreeReader } from './release-prepare.js';

// ── Types ────────────────────────────────────────────────────────────

/** The short satellite keys; the npm package is `pkinative-<key>`. */
export type SatelliteKey = 'cli' | 'mcp';

export const SATELLITE_KEYS: readonly SatelliteKey[] = ['cli', 'mcp'];

export const packageOf = (key: SatelliteKey): SatelliteName => `pkinative-${key}`;

export interface Options {
    /** Explicit checkout directories; null means `../pkinative-<key>`. */
    readonly roots: Readonly<Record<SatelliteKey, string | null>>;
    readonly expect: Readonly<Partial<Record<SatelliteKey, string>>>;
    readonly capture: boolean;
    readonly apply: boolean;
    readonly worklist: boolean;
    readonly dryRun: boolean;
    readonly date: string;
    readonly show: string | null;
}

/** A rewrite and how many sites it found: zero means the pattern is gone, which is a failure, not a no-op. */
export interface Rewrite {
    readonly text: string;
    readonly matched: number;
}

/** A row that leaves its field alone, and why — the surface could not establish the value. */
export interface Kept {
    readonly kept: string;
}

/** One mechanical edit: a file, the one thing it owns there, and the package whose facts it writes. */
export interface SatelliteEdit {
    readonly file: string;
    readonly what: string;
    /** null: a stamp, applied only when a package row changed something. */
    readonly package: SatelliteName | null;
    readonly apply: (text: string, ctx: EditContext) => Rewrite | Kept;
}

export interface EditContext {
    /** The surface of the row's package (a stamp row gets the first one read). */
    readonly surface: SatelliteSurface;
    readonly today: ManifestRow;
    readonly date: string;
}

/** `same` prints `=`, `edit` prints `+` (`~` in a dry run), `FAIL` prints `!` on stderr. */
export interface PlanLine {
    readonly level: 'same' | 'edit' | 'FAIL';
    readonly text: string;
}

export interface SatellitePlan {
    /** Every file the pass changes, with its new text. */
    readonly texts: ReadonlyMap<string, string>;
    readonly lines: readonly PlanLine[];
    readonly failures: number;
}

/** One verify-docs finding, as `scripts/verify-docs.ts --json` prints it under `problems`. */
export interface Finding {
    readonly file: string;
    readonly line: number;
    readonly rule: string;
    readonly message: string;
    readonly severity: 'error' | 'warn';
}

/** A blind-spot token whose live value differs from the version it should carry. */
export interface BlindSpotFinding {
    readonly id: string;
    readonly file: string;
    readonly line: number;
    readonly package: SatelliteName;
    readonly current: string;
    readonly expected: string;
}

export interface Batch {
    readonly files: string[];
    readonly findings: Finding[];
    readonly blindSpots: BlindSpotFinding[];
    readonly deltas: string[];
}

export interface Worklist {
    readonly generatedOn: string;
    readonly verifyDocs: { readonly rules: number; readonly errors: number; readonly warnings: number };
    readonly batches: Readonly<Record<string, Batch>>;
}

// ── Small helpers ────────────────────────────────────────────────────

const SEMVER = /^\d+\.\d+\.\d+$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

function escapeRe(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Replace with a counter, so the caller learns whether the pattern existed at all. */
function replaceCounting(text: string, re: RegExp, replacement: (...groups: string[]) => string): Rewrite {
    let matched = 0;
    const out = text.replace(re, (...args: unknown[]) => {
        matched++;
        return replacement(...(args as string[]));
    });
    return { text: out, matched };
}

/** The line number (1-based) of a character offset. */
function lineAt(text: string, index: number): number {
    let line = 1;
    for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
    return line;
}

/** `pkinative-cli` → `cli`; `cli` → `cli`; anything else → null. */
export function satelliteKey(name: string): SatelliteKey | null {
    const key = name.replace(/^pkinative-/, '');
    return (SATELLITE_KEYS as readonly string[]).includes(key) ? (key as SatelliteKey) : null;
}

/** A command line as argv, honouring quotes — what a spawn without a shell takes. */
export function splitCommand(cmd: string): string[] {
    const out: string[] = [];
    let cur = '';
    let quote: '"' | "'" | null = null;
    let has = false;
    for (const ch of cmd) {
        if (quote) {
            if (ch === quote) quote = null;
            else cur += ch;
        } else if (ch === '"' || ch === "'") {
            quote = ch;
            has = true;
        } else if (/\s/.test(ch)) {
            if (has) out.push(cur);
            cur = '';
            has = false;
        } else {
            cur += ch;
            has = true;
        }
    }
    if (has) out.push(cur);
    return out;
}

// ── 1. docs/assets/ecosystem.json: one field of packages.<name> ──────

/** The offset just past the JSON value that starts at `at` (a string, an object, an array or a scalar). */
export function jsonValueEnd(text: string, at: number): number {
    const skipString = (from: number): number => {
        let i = from + 1;
        while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
        return i + 1;
    };
    const first = text[at];
    if (first === '"') return skipString(at);
    if (first !== '{' && first !== '[') {
        let i = at;
        while (i < text.length && !/[,\n\r}\]]/.test(text[i] ?? '')) i++;
        return i;
    }
    let depth = 0;
    let i = at;
    while (i < text.length) {
        const c = text[i];
        if (c === '"') {
            i = skipString(i);
            continue;
        }
        if (c === '{' || c === '[') depth++;
        if (c === '}' || c === ']') {
            depth--;
            if (depth === 0) return i + 1;
        }
        i++;
    }
    return text.length;
}

/**
 * Rewrites the value of `packages.<name>.<key>` with what `render` returns
 * for the key's indent. The block is located inside `"packages": {` by its
 * indent, so a `"<name>"` or `"<key>"` anywhere else in the manifest is never
 * touched; `packages.pkinative` — the engine, owned by release-prepare — is
 * refused. `matched` is 0 when the package or the key is not there.
 */
export function setPackageField(text: string, name: string, key: string, render: (indent: string) => string): Rewrite {
    if (name === 'pkinative') return { text, matched: 0 };
    const pkgs = /^([ \t]*)"packages":[ \t]*\{[ \t]*\r?\n/m.exec(text);
    if (!pkgs) return { text, matched: 0 };
    const sectionStart = pkgs.index + pkgs[0].length;
    const outerClose = new RegExp(`^${pkgs[1] ?? ''}\\}`, 'mg');
    outerClose.lastIndex = sectionStart;
    const sectionEnd = outerClose.exec(text)?.index ?? text.length;
    const head = new RegExp(`^([ \\t]+)"${escapeRe(name)}":[ \\t]*\\{[ \\t]*\\r?\\n`, 'mg');
    head.lastIndex = sectionStart;
    const block = head.exec(text);
    if (!block || block.index >= sectionEnd) return { text, matched: 0 };
    const indent = block[1] ?? '';
    const bodyStart = block.index + block[0].length;
    const close = new RegExp(`^${indent}\\}`, 'mg');
    close.lastIndex = bodyStart;
    const bodyEnd = close.exec(text)?.index ?? sectionEnd;
    // Only a key of the block itself, at the indent of its first member: never the "tools" of its counts.
    const inner = /^([ \t]+)"/m.exec(text.slice(bodyStart, bodyEnd))?.[1] ?? `${indent}  `;
    const field = new RegExp(`^${inner}"${escapeRe(key)}":[ \\t]*`, 'mg');
    field.lastIndex = bodyStart;
    const at = field.exec(text);
    if (!at || at.index >= bodyEnd) return { text, matched: 0 };
    const valueStart = at.index + at[0].length;
    return { text: text.slice(0, valueStart) + render(inner) + text.slice(jsonValueEnd(text, valueStart)), matched: 1 };
}

const quoted = (s: string): string => JSON.stringify(s);
/** `["a", "b"]` — the manifest's inline form. */
export const inlineArray = (items: readonly (string | number)[]): string => `[${items.map((i) => (typeof i === 'number' ? String(i) : quoted(i))).join(', ')}]`;
/** A one-member-per-line object; each value is already rendered. */
export function blockObject(entries: readonly (readonly [string, string])[], indent: string): string {
    return entries.length === 0 ? '{}' : `{\n${entries.map(([k, v]) => `${indent}  ${quoted(k)}: ${v}`).join(',\n')}\n${indent}}`;
}

/** Items grouped in order of first appearance — the command groups, the tool groups. */
export function groupsOf(items: readonly { readonly name: string; readonly group: string | null }[]): Map<string, string[]> {
    const groups = new Map<string, string[]>();
    for (const item of items) {
        const key = item.group ?? '';
        groups.set(key, [...(groups.get(key) ?? []), item.name]);
    }
    return groups;
}

/**
 * The counters to write into `packages.<name>.counts`: only the keys the
 * manifest already polices, and only when the surface established them — a
 * count named under `unverified` keeps the manifest's value.
 */
export function syncCounts(existing: Readonly<Record<string, number>>, surfaceCounts: Readonly<Record<string, number>>, unverified: readonly string[]): Record<string, number> {
    const unknown = unverifiedKeys(unverified);
    const synced: Record<string, number> = {};
    for (const [k, cur] of Object.entries(existing)) {
        const v = surfaceCounts[k];
        synced[k] = v !== undefined && !unknown.has(k) ? v : cur;
    }
    return synced;
}

// ── 2. The site: versions.js, badges, JSON-LD, stamps ────────────────

/** The FALLBACK row `'<name>': { version: 'X', pin: '^Y' }` of docs/assets/versions.js. */
export function bumpVersionsFallback(js: string, name: string, version: string, pin: string | null): Rewrite {
    const pinValue = pin === null ? 'null' : `'${pin}'`;
    return replaceCounting(js, new RegExp(`('${escapeRe(name)}': \\{ version: ')[^']*(', pin: )(?:null|'[^']*')`), (_m, a, b) => `${a}${version}${b}${pinValue}`);
}

/** Every `data-pk-badge="<name>">vX.Y.Z<` of one page. */
export function bumpBadge(html: string, name: string, version: string): Rewrite {
    return replaceCounting(html, new RegExp(`(data-pk-badge="${escapeRe(name)}">v)[^<]*(<)`, 'g'), (_m, a, b) => `${a}${version}${b}`);
}

/**
 * The `softwareVersion` of every schema.org node named `<name>`, keyed on the
 * name: the landing page identifies its nodes by `#cli` / `#mcp`, the
 * playgrounds by the page URL, and the name is what all three share.
 */
export function bumpJsonLdVersion(html: string, name: string, version: string): Rewrite {
    return replaceCounting(html, new RegExp(`("name": "${escapeRe(name)}",[^{}]*?"softwareVersion": ")[^"]*(")`, 'g'), (_m, a, b) => `${a}${version}${b}`);
}

export function restampVerifiedOn(json: string, date: string): Rewrite {
    return replaceCounting(json, /("verifiedOn": ")[^"]+(")/, (_m, a, b) => `${a}${date}${b}`);
}

export function restampVerifiedTime(html: string, date: string): Rewrite {
    return replaceCounting(html, /(<time id="verified-on" datetime=")[^"]+(">)[^<]+(<\/time>)/, (_m, a, b, c) => `${a}${date}${b}${date}${c}`);
}

// ── 3. The table ─────────────────────────────────────────────────────

const MANIFEST = 'docs/assets/ecosystem.json';

/** An inventory of `packages.<name>`: its key and the value the surface gives it, or the reason it has none. */
interface Inventory {
    readonly key: string;
    readonly render: (s: SatelliteSurface, indent: string) => string | Kept;
}

/** A list the surface established, or the reason the manifest's stays. */
function listOf(s: SatelliteSurface, key: string): readonly string[] | Kept {
    const items = s.lists[key];
    if (items === undefined || unverifiedKeys(s.unverified).has(key)) return { kept: `the surface does not establish ${key}` };
    return items;
}

const inlineList = (key: string, listKey = key): Inventory => ({
    key,
    render: (s) => {
        const items = listOf(s, listKey);
        return 'kept' in items ? items : inlineArray(items);
    },
});

const scalar = (key: 'mcpRevision'): Inventory => ({
    key,
    render: (s) => {
        const value = s.structured[key];
        return value === undefined ? { kept: `the surface does not carry ${key}` } : quoted(value);
    },
});

/** The tools of a surface when each has a group and an annotation class — what the three tool inventories need. */
function classifiedTools(s: SatelliteSurface): NonNullable<SatelliteSurface['structured']['tools']> | Kept {
    const tools = s.structured.tools;
    if (tools === undefined) return { kept: 'the surface carries no structured.tools' };
    if (tools.some((t) => t.group === null || t.annotation === null)) return { kept: 'a tool has no group or no annotation class in the surface' };
    return tools;
}

export const INVENTORIES: Readonly<Record<SatelliteName, readonly Inventory[]>> = {
    'pkinative-cli': [
        {
            key: 'commandGroups',
            render: (s, indent) => {
                const commands = s.structured.commands;
                if (commands === undefined) return { kept: 'the surface carries no structured.commands' };
                return blockObject([...groupsOf(commands)].map(([group, names]) => [group, inlineArray(names)] as const), indent);
            },
        },
        inlineList('completionShells'),
        inlineList('envVars'),
        {
            key: 'exitCodes',
            render: (s) => {
                const codes = listOf(s, 'exitCodes');
                return 'kept' in codes ? codes : inlineArray(codes.map(Number));
            },
        },
    ],
    'pkinative-mcp': [
        {
            // One line per tool group, in tools/list order.
            key: 'tools',
            render: (s, indent) => {
                const tools = classifiedTools(s);
                if ('kept' in tools) return tools;
                return `[\n${[...groupsOf(tools).values()].map((names) => `${indent}  ${names.map(quoted).join(', ')}`).join(',\n')}\n${indent}]`;
            },
        },
        {
            key: 'toolGroups',
            render: (s, indent) => {
                const tools = classifiedTools(s);
                return 'kept' in tools ? tools : blockObject([...groupsOf(tools)].map(([group, names]) => [group, String(names.length)] as const), indent);
            },
        },
        {
            key: 'toolAnnotations',
            render: (s, indent) => {
                const tools = classifiedTools(s);
                if ('kept' in tools) return tools;
                const of = (a: string): string[] => tools.filter((t) => t.annotation === a).map((t) => t.name).sort();
                return blockObject([['readOnly', String(of('readOnly').length)], ['writes', inlineArray(of('writes'))], ['produces', inlineArray(of('produces'))]], indent);
            },
        },
        inlineList('prompts'),
        inlineList('resourceTemplates'),
        inlineList('transports'),
        scalar('mcpRevision'),
        inlineList('legacyRevisions'),
        inlineList('envVars'),
    ],
};

function rowsFor(name: SatelliteName): SatelliteEdit[] {
    const field = (key: string, value: (ctx: EditContext, indent: string) => string | Kept): SatelliteEdit => ({
        file: MANIFEST,
        what: `packages.${name}.${key}`,
        package: name,
        apply: (text, ctx) => {
            // The value needs the key's indent, which only the locator knows: a kept field is noted from inside it.
            const state: { kept: Kept | null } = { kept: null };
            const r = setPackageField(text, name, key, (indent) => {
                const v = value(ctx, indent);
                if (typeof v === 'string') return v;
                state.kept = v;
                return '';
            });
            return state.kept ?? r;
        },
    });
    const rows: SatelliteEdit[] = [
        field('version', (ctx) => quoted(ctx.surface.version)),
        field('released', (ctx) => {
            const s = ctx.surface;
            if (s.releasedOn === null || unverifiedKeys(s.unverified).has('releasedOn')) return { kept: `the release day is not established${s.releasedOn === null ? '' : ` (${s.releasedOn} is unconfirmed)`} — run with --capture` };
            return quoted(s.releasedOn);
        }),
        field('pin', (ctx) => (ctx.surface.engine.pin === null ? { kept: 'the surface carries no engine pin' } : quoted(ctx.surface.engine.pin))),
        field('counts', (ctx, indent) => blockObject(Object.entries(syncCounts(ctx.today.counts, ctx.surface.counts, ctx.surface.unverified)).map(([k, n]) => [k, String(n)] as const), indent)),
        ...INVENTORIES[name].map((inv) => field(inv.key, (ctx, indent) => inv.render(ctx.surface, indent))),
        { file: 'docs/assets/versions.js', what: `FALLBACK ${name}`, package: name, apply: (text, ctx) => bumpVersionsFallback(text, name, ctx.surface.version, ctx.surface.engine.pin) },
        { file: 'docs/index.html', what: `${name} badges`, package: name, apply: (text, ctx) => bumpBadge(text, name, ctx.surface.version) },
        { file: 'docs/index.html', what: `JSON-LD softwareVersion of ${name}`, package: name, apply: (text, ctx) => bumpJsonLdVersion(text, name, ctx.surface.version) },
        { file: `docs/playgrounds/${SHORT[name]}.html`, what: `JSON-LD softwareVersion of ${name}`, package: name, apply: (text, ctx) => bumpJsonLdVersion(text, name, ctx.surface.version) },
    ];
    if (name === 'pkinative-cli') {
        rows.push({
            file: CLI_SURFACE,
            what: 'the command surface (renderCliSurface)',
            package: name,
            apply: (_text, ctx) => {
                const manifest = cliManifestOf(ctx.surface);
                return manifest === null ? { kept: 'the facts carry no capability manifest — run with --capture' } : { text: renderCliSurface(manifest), matched: 1 };
            },
        });
    }
    return rows;
}

/** Every mechanical edit of a satellite release, in order: the package rows, then the two stamps. */
export const SATELLITE_EDITS: readonly SatelliteEdit[] = [
    ...SATELLITES.flatMap(rowsFor),
    { file: MANIFEST, what: 'verifiedOn', package: null, apply: (text, ctx) => restampVerifiedOn(text, ctx.date) },
    { file: 'docs/index.html', what: 'verified-on date', package: null, apply: (text, ctx) => restampVerifiedTime(text, ctx.date) },
];

/**
 * The whole pass, planned against `read` and written nowhere: the CLI writes
 * `texts` when `failures` is zero, and a test runs it on an in-memory tree.
 * A package the facts do not hold is left alone; the stamps move only when a
 * package row changed something, so a second run changes nothing.
 */
export function planSatellites(read: TreeReader, facts: SatelliteFacts): SatellitePlan {
    const texts = new Map<string, string>();
    const lines: PlanLine[] = [];
    let failures = 0;
    const current = (path: string): string | null => texts.get(path) ?? read(path);
    const first = SATELLITES.map((n) => facts.satellites[n]).find((e) => e !== undefined);
    for (const edit of SATELLITE_EDITS) {
        const entry = edit.package === null ? first : facts.satellites[edit.package];
        if (entry === undefined) continue;
        const label = `${edit.file} — ${edit.what}`;
        if (edit.package === null && texts.size === 0) {
            lines.push({ level: 'same', text: `${label}: kept (nothing else moved)` });
            continue;
        }
        const before = current(edit.file);
        if (before === null) {
            lines.push({ level: 'FAIL', text: `${edit.file}: missing` });
            failures++;
            continue;
        }
        const result = edit.apply(before, { surface: entry.surface, today: entry.manifestToday, date: facts.generatedOn });
        if ('kept' in result) lines.push({ level: 'same', text: `${label}: kept — ${result.kept}` });
        else if (result.matched === 0) {
            lines.push({ level: 'FAIL', text: `${label}: not found — nothing is written while any row fails` });
            failures++;
        } else if (result.text === before) lines.push({ level: 'same', text: label });
        else {
            texts.set(edit.file, result.text);
            lines.push({ level: 'edit', text: label });
        }
    }
    return { texts, lines, failures };
}

// ── 4. Worklist: batches, blind spots, deltas ────────────────────────

/** Writer batches: the first pattern that matches a repository-relative path wins; B0 — the coordinator — is the rest. */
export const BATCH_OF: readonly (readonly [RegExp, string])[] = [
    [/^docs\/guides\/cli\.(md|html)$/, 'B1'],
    [/^docs\/guides\/mcp\.(md|html)$/, 'B2'],
    [/^(docs\/data\/surfaces\.json|docs\/guides\/choose\.(md|html))$/, 'B3'],
    [/^(docs\/guides\/use-cases(-[\w-]+)?\.(md|html)|docs\/assets\/use-case-[\w-]+\.svg)$/, 'B4'],
    [/^(README\.md|llms\.txt|docs\/index\.html|docs\/agent-brief\.md|docs\/guides\/errors\.(md|html)|AGENTS\.md|ROADMAP\.md|CONTRIBUTING\.md|SECURITY\.md|SUPPORT\.md|\.github\/copilot-instructions\.md)$/, 'B5'],
    [/^(docs\/playgrounds\/(cli|mcp)\.(html|js)|docs\/data\/playgrounds\.json)$/, 'B6'],
];

export const BATCH_IDS: readonly string[] = ['B1', 'B2', 'B3', 'B4', 'B5', 'B6', 'B0'];

/** Which batches receive each satellite's surface delta: its guide, and the playground that mirrors its surface. */
export const DELTA_BATCHES: Readonly<Record<SatelliteKey, readonly string[]>> = { cli: ['B1', 'B6'], mcp: ['B2', 'B6'] };

export function batchOf(file: string): string {
    const path = file.replace(/\\/g, '/');
    for (const [re, batch] of BATCH_OF) if (re.test(path)) return batch;
    return 'B0';
}

/** The file a writer edits for a finding: a generated guide page is fixed in its Markdown source. */
export function sourceOf(file: string): string {
    const path = file.replace(/\\/g, '/');
    return /^docs\/guides\/[^/]+\.html$/.test(path) ? path.replace(/\.html$/, '.md') : path;
}

function isFinding(x: unknown): x is Finding {
    if (typeof x !== 'object' || x === null) return false;
    const f = x as Record<string, unknown>;
    return typeof f.file === 'string' && typeof f.line === 'number' && typeof f.rule === 'string' && typeof f.message === 'string' && (f.severity === 'error' || f.severity === 'warn');
}

/**
 * `verify-docs --json` prints `{ ok, rules, problems }`; anything else on the
 * stream (an npm banner) is skipped by locating the object. Null when there
 * is no such object.
 */
export function parseVerifyDocsJson(stdout: string): { rules: number; problems: Finding[] } | null {
    const first = stdout.indexOf('{');
    const last = stdout.lastIndexOf('}');
    for (const candidate of [stdout.trim(), first !== -1 && last > first ? stdout.slice(first, last + 1) : '']) {
        try {
            const parsed = JSON.parse(candidate) as { rules?: unknown; problems?: unknown };
            if (typeof parsed === 'object' && parsed !== null && typeof parsed.rules === 'number' && Array.isArray(parsed.problems) && parsed.problems.every(isFinding)) return { rules: parsed.rules, problems: parsed.problems };
        } catch {
            // try the next candidate
        }
    }
    return null;
}

/** Runs every blind-spot row over the files given and keeps the tokens whose version is not the one expected. */
export function evaluateBlindSpots(rows: readonly BlindSpot[], files: ReadonlyMap<string, string>, expected: Readonly<Partial<Record<SatelliteName, string>>>): BlindSpotFinding[] {
    const out: BlindSpotFinding[] = [];
    for (const row of rows) {
        const text = files.get(row.file);
        const want = expected[row.package];
        if (text === undefined || want === undefined) continue;
        const re = new RegExp(row.pattern.source, row.pattern.flags.includes('g') ? row.pattern.flags : `${row.pattern.flags}g`);
        for (const m of text.matchAll(re)) {
            const live = m[row.versionGroup];
            if (live !== undefined && live !== want) out.push({ id: row.id, file: row.file, line: lineAt(text, m.index), package: row.package, current: live, expected: want });
        }
    }
    return out;
}

/** `pkinative-mcp 1.0.0 → 1.1.0 tools: +foo, +bar / -baz` — one line per list that changed. */
export function deltaLines(name: string, delta: SurfaceDelta | null | undefined): string[] {
    const lines: string[] = [];
    for (const [list, d] of Object.entries(delta ?? {})) {
        const parts: string[] = [];
        if (d.added.length > 0) parts.push(d.added.map((x) => `+${x}`).join(', '));
        if (d.removed.length > 0) parts.push(d.removed.map((x) => `-${x}`).join(', '));
        if (parts.length > 0) lines.push(`${name} ${list}: ${parts.join(' / ')}`);
    }
    return lines;
}

/** Groups findings, blind spots and deltas into the writer batches. */
export function buildWorklist(generatedOn: string, rules: number, findings: readonly Finding[], blindSpots: readonly BlindSpotFinding[], deltas: Readonly<Partial<Record<SatelliteKey, readonly string[]>>>): Worklist {
    const batches: Record<string, Batch> = {};
    for (const id of BATCH_IDS) batches[id] = { files: [], findings: [], blindSpots: [], deltas: [] };
    const batch = (file: string): Batch => {
        const b = batches[batchOf(file)] as Batch;
        if (!b.files.includes(sourceOf(file))) b.files.push(sourceOf(file));
        return b;
    };
    for (const f of [...findings].sort((a, b) => a.file.localeCompare(b.file) || a.rule.localeCompare(b.rule) || a.line - b.line)) batch(f.file).findings.push(f);
    for (const s of blindSpots) batch(s.file).blindSpots.push(s);
    for (const key of SATELLITE_KEYS) {
        const lines = deltas[key] ?? [];
        if (lines.length > 0) for (const id of DELTA_BATCHES[key]) (batches[id] as Batch).deltas.push(...lines);
    }
    for (const b of Object.values(batches)) b.files.sort();
    return {
        generatedOn,
        verifyDocs: { rules, errors: findings.filter((f) => f.severity === 'error').length, warnings: findings.filter((f) => f.severity === 'warn').length },
        batches,
    };
}

const isActive = (b: Batch): boolean => b.findings.length > 0 || b.blindSpots.length > 0 || b.deltas.length > 0;

/** The worklist as Markdown: a summary, then one `## B<n>` section per batch that has work. */
export function renderWorklist(w: Worklist): string {
    const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`;
    const lines: string[] = [
        `# Satellite worklist — ${w.generatedOn}`,
        '',
        `verify-docs: ${plural(w.verifyDocs.rules, 'rule')}, ${plural(w.verifyDocs.errors, 'error')}, ${plural(w.verifyDocs.warnings, 'warning')}`,
        '',
    ];
    const active = BATCH_IDS.filter((id) => isActive(w.batches[id] as Batch));
    lines.push(active.length === 0 ? 'Nothing to write: no batch has a finding, a blind spot or a delta.' : `Batches with work: ${active.map((id) => `${id} (${plural((w.batches[id] as Batch).findings.length, 'finding')})`).join(', ')}`, '');
    for (const id of active) {
        const b = w.batches[id] as Batch;
        lines.push(`## ${id}${b.files.length > 0 ? ` — ${b.files.join(', ')}` : ''}`, '');
        if (b.findings.length > 0) {
            lines.push('### verify-docs', '');
            let file = '';
            let rule = '';
            for (const f of b.findings) {
                if (f.file !== file) {
                    file = f.file;
                    rule = '';
                    lines.push(`- ${file}${sourceOf(file) === file ? '' : ` (generated — edit ${sourceOf(file)}, then \`npm run docs:guides\`)`}`);
                }
                if (f.rule !== rule) {
                    rule = f.rule;
                    lines.push(`  - [${rule}]`);
                }
                lines.push(`    - ${f.severity === 'warn' ? 'warn ' : ''}l.${f.line}: ${f.message}`);
            }
            lines.push('');
        }
        if (b.blindSpots.length > 0) {
            lines.push('### Blind spots (no rule sees them)', '');
            for (const s of b.blindSpots) lines.push(`- ${s.file}:${s.line} [${s.id}] ${s.package} ${s.current} → ${s.expected}`);
            lines.push('');
        }
        if (b.deltas.length > 0) {
            lines.push('### Surface delta', '');
            for (const d of b.deltas) lines.push(`- ${d}`);
            lines.push('');
        }
    }
    return `${lines.join('\n').replace(/\n+$/, '')}\n`;
}

// ── 5. --show ────────────────────────────────────────────────────────

export const SHOW_UNITS: readonly string[] = ['facts', 'cli', 'mcp', 'worklist', ...BATCH_IDS];

/**
 * One unit of the last run for stdout, `SHOW_MAX_CHARS` at most: `facts`,
 * `cli` and `mcp` from facts.json, `worklist` (its summary) and a batch from
 * worklist.md. Null when the file the unit needs was never written.
 */
export function showUnit(unit: string, factsJson: string | null, worklistMd: string | null): string | null {
    if (unit === 'facts' || unit === 'cli' || unit === 'mcp') return factsJson === null ? null : renderShow(JSON.parse(factsJson) as SatelliteFacts, unit);
    if (worklistMd === null) return null;
    const sections = worklistMd.split(/^(?=## )/m);
    if (unit === 'worklist') return clampShow(sections[0] ?? '', 'test-output/.satellites/worklist.md');
    const section = sections.find((s) => new RegExp(`^## ${escapeRe(unit)}\\b`).test(s));
    return section === undefined ? `## ${unit}\n\nNothing for this batch in the last run.\n` : clampShow(`${section.replace(/\n+$/, '')}\n`, 'test-output/.satellites/worklist.md');
}

// ── CLI ──────────────────────────────────────────────────────────────

export const USAGE =
    'usage: npm run satellites:sync -- [--expect cli=X.Y.Z mcp=X.Y.Z] [--cli <dir>] [--mcp <dir>] [--capture] [--apply] [--worklist] [--dry-run] [--date YYYY-MM-DD]\n'
    + `       npm run satellites:sync -- --show <${SHOW_UNITS.join('|')}>`;

/** Returns the options, or a usage error message. */
export function parseArgs(argv: readonly string[], today: string = new Date().toISOString().slice(0, 10)): Options | string {
    const roots: Record<SatelliteKey, string | null> = { cli: null, mcp: null };
    const expect: Partial<Record<SatelliteKey, string>> = {};
    const flags = { capture: false, apply: false, worklist: false, 'dry-run': false };
    let date = today;
    let show: string | null = null;
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i] ?? '';
        const value = (): string => argv[++i] ?? '';
        if (arg === '--capture' || arg === '--apply' || arg === '--worklist' || arg === '--dry-run') flags[arg.slice(2) as keyof typeof flags] = true;
        else if (arg === '--cli' || arg === '--mcp') {
            const dir = value();
            if (dir === '' || dir.startsWith('--')) return `${arg} needs a directory\n${USAGE}`;
            roots[arg.slice(2) as SatelliteKey] = dir;
        } else if (arg === '--date') {
            date = value();
            if (!ISO_DATE.test(date)) return `--date "${date}" is not an ISO date (YYYY-MM-DD)\n${USAGE}`;
        } else if (arg === '--show') {
            show = value();
            if (!SHOW_UNITS.includes(show)) return `--show "${show}" is not one of ${SHOW_UNITS.join(', ')}\n${USAGE}`;
        } else if (arg === '--expect') {
            // Every following `<key>=<version>` word, comma-separated or not.
            const entries: string[] = [];
            while (i + 1 < argv.length && /^[^-][^=]*=/.test(argv[i + 1] ?? '')) entries.push(...(argv[++i] ?? '').split(',').filter((e) => e !== ''));
            if (entries.length === 0) return `--expect needs at least one <cli|mcp>=<X.Y.Z>\n${USAGE}`;
            for (const entry of entries) {
                const [name = '', version = ''] = entry.split('=');
                const key = satelliteKey(name);
                if (key === null || !SEMVER.test(version)) return `--expect "${entry}" is not <cli|mcp>=<X.Y.Z>\n${USAGE}`;
                expect[key] = version;
            }
        } else return `unknown argument "${arg}"\n${USAGE}`;
    }
    if (show !== null && argv.length !== 2) return `--show takes no other flag\n${USAGE}`;
    return { roots, expect, capture: flags.capture, apply: flags.apply, worklist: flags.worklist, dryRun: flags['dry-run'], date, show };
}

/**
 * The satellites a run reads. With `--expect`, only the packages it names and
 * those given a directory: a release of one satellite must not write whatever
 * state the other's checkout happens to be in. Without it, every checkout found.
 */
export function selectedKeys(opts: Pick<Options, 'expect' | 'roots'>): SatelliteKey[] {
    const named = Object.keys(opts.expect).length > 0;
    return SATELLITE_KEYS.filter((key) => !named || opts.expect[key] !== undefined || opts.roots[key] !== null);
}

// ── main ─────────────────────────────────────────────────────────────

const OUT = 'test-output/.satellites';

/** Runs one command line in `cwd`: through the shell on Windows (npx is a .cmd there), as argv elsewhere. */
function run(cmd: string, cwd: string): { ok: boolean; stdout: string; why: string } {
    const shell = process.platform === 'win32';
    const argv = splitCommand(cmd);
    const r = spawnSync(shell ? cmd : argv[0] ?? '', shell ? [] : argv.slice(1), { cwd, shell, encoding: 'utf8', windowsHide: true, timeout: 180_000, maxBuffer: 64 * 1024 * 1024 });
    const ok = r.error === undefined && r.status === 0;
    return { ok, stdout: r.stdout ?? '', why: ok ? '' : r.error?.message ?? `exit ${String(r.status)}: ${(r.stderr ?? '').trim().split('\n').slice(-2).join(' ')}` };
}

/** What `--capture` obtains from one satellite checkout; the notes say what it could not. */
function capture(name: SatelliteName, dir: string, version: string): { captures: Captures; notes: string[] } {
    const captures: Captures = {};
    const notes: string[] = [];
    // git is an executable on every platform: no shell, so the `%cs` of the format is passed as it is.
    const tag = spawnSync('git', [...TAG_DATE_ARGV(version)], { cwd: dir, encoding: 'utf8', windowsHide: true, timeout: 30_000 });
    const day = (tag.stdout ?? '').trim();
    if (tag.status === 0 && ISO_DATE.test(day)) captures.tagDate = day;
    else notes.push(`${name}: no v${version} tag in the checkout — the release day stays the CHANGELOG's`);
    for (const template of CAPTURE_COMMANDS[name]) {
        const cmd = template.replace('{version}', version);
        const r = run(cmd, dir);
        if (r.ok) {
            try {
                captures.cliManifest = JSON.parse(r.stdout.replace(/^﻿/, '')) as unknown;
                break;
            } catch {
                notes.push(`${name}: \`${cmd}\` did not print JSON`);
            }
        } else notes.push(`${name}: \`${cmd}\` failed — ${r.why}`);
    }
    return { captures, notes };
}

function main(argv: readonly string[]): number {
    const parsed = parseArgs(argv);
    if (typeof parsed === 'string') {
        console.error(`satellite-sync: ${parsed}`);
        return 2;
    }
    const opts = parsed;
    const root = resolve(import.meta.dirname, '..');
    const outDir = join(root, OUT);
    const rel = (p: string): string => relative(root, p).replace(/\\/g, '/');
    const read: TreeReader = (path) => (existsSync(join(root, path)) ? readFileSync(join(root, path), 'utf8') : null);

    if (opts.show !== null) {
        const text = showUnit(opts.show, read(`${OUT}/facts.json`), read(`${OUT}/worklist.md`));
        if (text === null) {
            console.error(`satellite-sync: nothing to show for "${opts.show}" — run \`npm run satellites:sync -- --capture${opts.show === 'worklist' || /^B\d$/.test(opts.show) ? ' --worklist' : ''}\` first`);
            return 1;
        }
        process.stdout.write(text);
        return 0;
    }

    // 1. Checkouts and --expect
    const dirs = new Map<SatelliteName, string>();
    const versions = new Map<SatelliteName, string>();
    const skipped: string[] = [];
    const refused: string[] = [];
    for (const key of SATELLITE_KEYS) {
        const name = packageOf(key);
        const dir = resolve(root, opts.roots[key] ?? join('..', name));
        const expected = opts.expect[key];
        if (!selectedKeys(opts).includes(key)) {
            skipped.push(`${name} (not named by --expect)`);
            continue;
        }
        let version: string;
        try {
            version = String((JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { version?: unknown }).version ?? '');
        } catch {
            if (expected !== undefined || opts.roots[key] !== null) refused.push(`${name}: ${rel(dir)} has no readable package.json${expected === undefined ? '' : ` (expected ${expected})`}`);
            else skipped.push(`${name} (${rel(dir)} not found)`);
            continue;
        }
        if (expected !== undefined && version !== expected) {
            refused.push(`${name}: the checkout ${rel(dir)} is at ${version}, --expect says ${expected} — check out the released tag`);
            continue;
        }
        dirs.set(name, dir);
        versions.set(name, version);
    }
    if (refused.length > 0) {
        for (const r of refused) console.error(`satellite-sync: ${r}`);
        return 2;
    }
    console.log(`satellite-sync: ${[...versions].map(([n, v]) => `${n} ${v}`).join(', ') || 'no satellite checkout'}${skipped.length > 0 ? ` — skipped ${skipped.join(', ')}` : ''}${opts.dryRun ? ' — dry run, the repository is not written' : ''}`);

    // 2. Facts
    let manifest: { packages?: Record<string, { version?: string; released?: string; pin?: string | null; counts?: Record<string, number> } | undefined> };
    try {
        manifest = JSON.parse(read(MANIFEST) ?? '') as typeof manifest;
    } catch {
        console.error(`satellite-sync: ${MANIFEST} is missing or not JSON`);
        return 1;
    }
    const facts: SatelliteFacts = { generatedOn: opts.date, engineVersion: manifest.packages?.['pkinative']?.version ?? '', satellites: {} };
    for (const [name, dir] of dirs) {
        const version = versions.get(name) ?? '';
        const captured = opts.capture ? capture(name, dir, version) : { captures: {}, notes: [] };
        for (const note of captured.notes) console.log(`  capture: ${note}`);
        const surface = readSurfaceOrDerive(dir, name, captured.captures);
        const previous = readPreviousSurface(dir, name, surface.version);
        const row = manifest.packages?.[name];
        facts.satellites[name] = {
            surface,
            previous,
            delta: surface.delta ?? diffSurface(previous, surface),
            manifestToday: { version: row?.version ?? '', released: row?.released ?? null, pin: row?.pin ?? null, counts: row?.counts ?? {} },
        };
    }
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'facts.json'), `${JSON.stringify(facts, null, 2)}\n`);
    writeFileSync(join(outDir, 'facts.md'), renderFactsMarkdown(facts));
    console.log(`  facts: ${OUT}/facts.md + facts.json — ${dirs.size} satellite(s), ${[...dirs.keys()].map((n) => `${SHORT[n]} ${facts.satellites[n]?.surface.mode ?? ''}`).join(', ')}`);

    // 3. --apply
    let failures = 0;
    if (opts.apply) {
        const plan = planSatellites(read, facts);
        failures = plan.failures;
        for (const line of plan.lines) {
            if (line.level === 'FAIL') console.error(`  !  ${line.text}`);
            else console.log(`  ${line.level === 'same' ? '=' : opts.dryRun ? '~' : '+'}  ${line.text}`);
        }
        if (failures === 0 && !opts.dryRun) for (const [file, text] of plan.texts) writeFileSync(join(root, file), text);
        const changed = plan.lines.filter((l) => l.level === 'edit').length;
        console.log(`  apply: ${changed} row(s) ${opts.dryRun || failures > 0 ? 'would change' : 'changed'} in ${plan.texts.size} file(s), ${plan.lines.filter((l) => l.level === 'same').length} unchanged, ${failures} failed${failures > 0 ? ' — nothing was written' : ''}`);
    }

    // 4. --worklist
    if (opts.worklist) {
        const r = run('npx tsx scripts/verify-docs.ts --json', root);
        const report = parseVerifyDocsJson(r.stdout);
        if (report === null) {
            console.error(`satellite-sync: verify-docs --json printed no report — ${r.why || 'unreadable output'}`);
            return 3;
        }
        const expected: Partial<Record<SatelliteName, string>> = {};
        const deltas: Partial<Record<SatelliteKey, string[]>> = {};
        for (const name of SATELLITES) {
            const entry = facts.satellites[name];
            const recorded = manifest.packages?.[name]?.version;
            if (entry !== undefined) {
                expected[name] = entry.surface.version;
                deltas[SHORT[name]] = deltaLines(`${name} ${entry.surface.previous ?? '?'} → ${entry.surface.version}`, entry.delta);
            } else if (recorded !== undefined) expected[name] = recorded;
        }
        const rows = blindSpotTable();
        const files = new Map<string, string>();
        for (const file of new Set(rows.map((row) => row.file))) {
            const text = read(file);
            if (text !== null) files.set(file, text);
        }
        const spots = evaluateBlindSpots(rows, files, expected);
        const worklist = buildWorklist(opts.date, report.rules, report.problems, spots, deltas);
        writeFileSync(join(outDir, 'worklist.md'), renderWorklist(worklist));
        const active = BATCH_IDS.filter((id) => isActive(worklist.batches[id] as Batch));
        console.log(`  worklist: ${OUT}/worklist.md — ${report.problems.length} finding(s), ${spots.length} blind spot(s), batches ${active.join(' ') || 'none'}`);
    }

    console.log(failures === 0 ? 'satellite-sync: done' : `satellite-sync: ${failures} row(s) found nothing to rewrite — see above`);
    return failures === 0 ? 0 : 1;
}

// Run only when invoked directly (keeps the module import-safe for tests).
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    process.exitCode = main(process.argv.slice(2));
}
