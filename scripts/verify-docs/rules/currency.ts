/**
 * pkinative — documentation currency rules
 * =========================================
 * The documents a reader meets first must describe the release they are
 * reading about. The 1.0.0 audit found a README that still promised
 * "signature verification before 0.3", an errors guide missing seven codes
 * the quick start said it listed, a guide naming a reason code that does not
 * exist, a README export table without the one-call chain verdict, and a
 * Copilot file still describing the seven layers of 0.1. Each of these rules
 * holds one of those surfaces to its source, so the drift fails the day it
 * happens rather than at the next audit.
 *
 * `stale-milestone`: on the current-surface documents (the README, llms.txt,
 * docs/ outside the decision records), a phrase that promises a feature to a
 * version already released ("arrives in 0.3", "will run on it from 0.7",
 * "the 1.0 freeze will") or dates one to a version older than the current
 * minor ("from 0.3", "before 0.5", "pkinative 0.1", a "(0.7)" milestone tag,
 * a "0.3" comparison cell). History lives in CHANGELOG.md, ROADMAP.md, the
 * release notes and the decision records, none of which it reads. A line
 * that must keep such a phrase carries `verify-docs:allow stale-milestone`, on
 * that line or the line above.
 *
 * `standards-evidence`: docs/guides/standards.md is a self-assessment, and
 * says so; every file, rule, clause, code and conformance level it cites as
 * evidence exists.
 *
 * `errors-guide-complete`: docs/guides/errors.md names every code of the
 * three registries — the quick start promises the guide "lists every code".
 *
 * `code-token-registered`: every `PKI_…` code the documentation names is a
 * code of one of the three registries.
 *
 * `readme-surfaces`: the README names at least one export of every
 * capability docs/data/surfaces.json lists — the npm front page is where a
 * capability is discovered or missed.
 *
 * `copilot-layer-parity`: the layer diagram of .github/copilot-instructions.md,
 * the file AGENTS.md calls the canonical detail, equals LAYERS.
 *
 * @module scripts/verify-docs/rules/currency
 */

import { LAYERS, parseLayerDiagram } from '../../lib/architecture.js';
import { error, lineContaining, lineOf, readJson, type Finding, type Rule, type RuleContext } from '../context.js';
import { DIAGNOSTICS_REGISTRY, ERRORS_REGISTRY, REASONS_REGISTRY } from './registries.js';

// ── Shared ───────────────────────────────────────────────────────────

const ALLOW_MILESTONE = 'verify-docs:allow stale-milestone';
const STANDARDS_GUIDE = 'docs/guides/standards.md';
const ERRORS_GUIDE = 'docs/guides/errors.md';
const COPILOT = '.github/copilot-instructions.md';

/** The current-surface documents: what a reader takes as describing the release in hand. */
export function currentSurfaceDocs(ctx: RuleContext): string[] {
    return [
        'README.md',
        'llms.txt',
        ...ctx.list('docs').filter((p) => !p.startsWith('docs/adr/') && (p.endsWith('.md') || p.endsWith('.html'))),
    ].filter((p) => ctx.exists(p));
}

function packageVersion(ctx: RuleContext): readonly [number, number, number] | null {
    const pkg = readJson<{ version?: unknown }>(ctx, 'package.json');
    if ('finding' in pkg || typeof pkg.value.version !== 'string') return null;
    const m = /^(\d+)\.(\d+)\.(\d+)/.exec(pkg.value.version);
    return m === null ? null : [Number(m[1]), Number(m[2]), Number(m[3])];
}

/** Every code of the three registries. */
function registeredCodes(ctx: RuleContext): { readonly codes: ReadonlyMap<string, string> } | { readonly finding: Finding } {
    const codes = new Map<string, string>();
    for (const [path, key] of [[ERRORS_REGISTRY, 'errors'], [DIAGNOSTICS_REGISTRY, 'diagnostics'], [REASONS_REGISTRY, 'reasons']] as const) {
        const parsed = readJson<Record<string, Array<{ code?: unknown }> | undefined>>(ctx, path);
        if ('finding' in parsed) return parsed;
        for (const entry of parsed.value[key] ?? []) if (typeof entry.code === 'string') codes.set(entry.code, path);
    }
    return { codes };
}

/** A complete `PKI_…` code; `PKI_CMS_*` and `PKI_<SUBJECT>_…` patterns do not match. */
const CODE_TOKEN = /\bPKI_[A-Z0-9_]*[A-Z0-9]\b(?![*<])/g;

// ── stale-milestone ──────────────────────────────────────────────────

/** A version as prose writes it; never a section number (§4.1), a dotted triple's prefix, or a measurement. */
const V = String.raw`(?<![\w.§])v?(\d+)\.(\d+)(?:\.(\d+)([a-z])?)?(?![\d.]*\d)(?!\s*(?:%|ms|µs|s\b|KB|kB|MB|GB|x\b|×))`;

interface MilestonePattern {
    readonly what: string;
    readonly re: RegExp;
    /** `promise`: stale once that version is released (≤ current). `dated`: stale once older than the current minor. */
    readonly kind: 'promise' | 'dated';
}

const MILESTONE_PATTERNS: readonly MilestonePattern[] = [
    { what: 'promises a feature to a released version', kind: 'promise', re: new RegExp(String.raw`\barriv(?:e|es|ed|ing)\s+(?:in|with|at)\s+${V}`, 'gi') },
    { what: 'promises a feature to a released version', kind: 'promise', re: new RegExp(String.raw`\bwill\b[^.;:!?\n<]{0,60}?\b(?:in|from|at|by|with)\s+${V}`, 'gi') },
    { what: 'speaks of a released version in the future tense', kind: 'promise', re: new RegExp(String.raw`${V}\s+(?:[A-Za-z]+\s+){0,2}will\b`, 'gi') },
    { what: 'dates a feature to an older version', kind: 'dated', re: new RegExp(String.raw`\b(?:from|before)\s+${V}`, 'gi') },
    { what: 'names an older version as the current one', kind: 'dated', re: new RegExp(String.raw`\bpkinative\s+${V}`, 'gi') },
    { what: 'carries an older milestone tag', kind: 'dated', re: new RegExp(String.raw`\(${V}\)`, 'g') },
    { what: 'shows an older version where a capability belongs', kind: 'dated', re: new RegExp(String.raw`<td[^>]*>\s*${V}\s*</td>`, 'g') },
];

const compare = (a: readonly number[], b: readonly number[]): number => {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        const d = (a[i] ?? 0) - (b[i] ?? 0);
        if (d !== 0) return d;
    }
    return 0;
};

/** Every stale-milestone phrase of one text, at the given current version. */
export function findStaleMilestones(text: string, current: readonly [number, number, number], released?: ReadonlySet<string>): Array<{ readonly index: number; readonly match: string; readonly what: string }> {
    const out: Array<{ index: number; match: string; what: string }> = [];
    const lines = text.split('\n');
    for (const pattern of MILESTONE_PATTERNS) {
        for (const m of text.matchAll(pattern.re)) {
            const index = m.index;
            // Another product's version is not a pkinative milestone: a letter
            // suffix (OpenSSL's 0.9.7k) never names one, and a patch number
            // counts only when pkinative released that version.
            if (m[4] !== undefined) continue;
            if (m[3] !== undefined && released !== undefined && !released.has(`${m[1]}.${m[2]}.${m[3]}`)) continue;
            const at = [Number(m[1]), Number(m[2])] as const;
            const stale = pattern.kind === 'promise' ? compare(at, current) <= 0 : compare(at, current.slice(0, 2)) < 0;
            if (!stale) continue;
            const line = lineOf(text, index);
            if ((lines[line - 1] ?? '').includes(ALLOW_MILESTONE) || (lines[line - 2] ?? '').includes(ALLOW_MILESTONE)) continue;
            out.push({ index, match: m[0], what: pattern.what });
        }
    }
    // One phrase, one report: a span inside a longer one already reported
    // ("from 0.7" inside "will run on it from 0.7") says nothing new.
    out.sort((a, b) => a.index - b.index || b.match.length - a.match.length);
    let end = -1;
    return out.filter((hit) => {
        if (hit.index + hit.match.length <= end) return false;
        end = Math.max(end, hit.index + hit.match.length);
        return true;
    });
}

const staleMilestone: Rule = {
    id: 'stale-milestone',
    summary: 'The README, llms.txt and docs/ outside the decision records neither promise a feature to a version already released ("arrives in 0.3", "the 1.0 freeze will") nor date one to a version older than the current minor ("from 0.3", "pkinative 0.1", a "(0.7)" tag, a "0.3" table cell).',
    check(ctx) {
        const current = packageVersion(ctx);
        if (current === null) return [error('package.json', 'has no X.Y.Z version — stale-milestone cannot tell a released version from a planned one')];
        // The versions pkinative released, from the CHANGELOG headings.
        const released = new Set([...(ctx.read('CHANGELOG.md') ?? '').matchAll(/^## \[(\d+\.\d+\.\d+)\]/gm)].map((m) => m[1] ?? ''));
        const out: Finding[] = [];
        for (const path of currentSurfaceDocs(ctx)) {
            const text = ctx.read(path) ?? '';
            for (const hit of findStaleMilestones(text, current, released)) {
                const message = `"${hit.match}" ${hit.what} (package.json: ${current.join('.')}) — describe the release as it is, or move the history to CHANGELOG.md, ROADMAP.md or a release note`;
                out.push(error(path, message, lineOf(text, hit.index)));
            }
        }
        return out;
    },
};

// ── standards-evidence ───────────────────────────────────────────────

const PATH_TOKEN = /^(?:[\w.@-]+\/)+[\w.*@-]*$|^[\w-]+(?:\.[\w-]+)*\.(?:ts|js|mjs|json|md|yml|yaml|txt|css|html)$/;
const KEBAB_TOKEN = /^[a-z0-9][a-z0-9.]*(?:-[a-z0-9.]+)+$/;

function globMatches(ctx: RuleContext, pattern: string): boolean {
    const dir = pattern.slice(0, pattern.lastIndexOf('/', pattern.indexOf('*')));
    const re = new RegExp(`^${pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*')}$`);
    return ctx.list(dir).some((p) => re.test(p));
}

const standardsEvidence: Rule = {
    id: 'standards-evidence',
    summary: 'docs/guides/standards.md says it is a self-assessment and not a certification, and every file, verify-docs rule, L5 clause, inventory term, error code, conformance level and relative link it cites as evidence exists.',
    check(ctx) {
        const text = ctx.read(STANDARDS_GUIDE);
        if (text === null) return [error(STANDARDS_GUIDE, 'missing — the standards self-assessment the README links to')];
        const out: Finding[] = [];
        for (const phrase of ['self-assessment', 'not a certification']) {
            if (!text.includes(phrase)) out.push(error(STANDARDS_GUIDE, `does not say "${phrase}" — a standards table without that sentence reads as a certification claim`));
        }
        const ruleIds = new Set<string>();
        for (const path of ctx.list('scripts/verify-docs/rules').filter((p) => p.endsWith('.ts'))) {
            for (const m of (ctx.read(path) ?? '').matchAll(/\bid: '([a-z0-9-]+)'/g)) ruleIds.add(m[1] ?? '');
        }
        const clauses = ctx.read('scripts/lib/clauses.ts') ?? '';
        const inventory = ctx.read('scripts/data/rfc5280-requirements.json') ?? '';
        const conformance = ctx.read('docs/guides/conformance.md') ?? '';
        const codes = registeredCodes(ctx);
        if ('finding' in codes) return [codes.finding];
        const cite = (token: string, why: string): void => { out.push(error(STANDARDS_GUIDE, `cites \`${token}\`, ${why}`, lineContaining(text, `\`${token}\``))); };
        for (const m of text.matchAll(/`([^`\n]+)`/g)) {
            const token = m[1] ?? '';
            if (/^PKI_[A-Z0-9_]+$/.test(token)) {
                if (!codes.codes.has(token)) cite(token, 'which is in none of the three code registries');
            } else if (/^L\d$/.test(token)) {
                if (!conformance.includes(`**${token} — `)) cite(token, 'a level the conformance guide does not define');
            } else if (PATH_TOKEN.test(token)) {
                const path = token.replace(/\/$/, '');
                if (path.includes('*') ? !globMatches(ctx, path) : !ctx.exists(path)) cite(token, 'which is not in the repository');
            } else if (KEBAB_TOKEN.test(token) && /[a-z]/.test(token)) {
                if (!ruleIds.has(token) && !clauses.includes(`id: '${token}'`) && !inventory.includes(`"${token}"`)) {
                    cite(token, 'which is no verify-docs rule, L5 clause of scripts/lib/clauses.ts or term of the requirement inventory');
                }
            }
        }
        for (const m of text.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)) {
            const target = m[1] ?? '';
            if (/^[a-z]+:/.test(target)) continue;
            const parts = ['docs', 'guides', ...target.split('/')];
            const resolved: string[] = [];
            for (const part of parts) {
                if (part === '..') resolved.pop();
                else if (part !== '.' && part !== '') resolved.push(part);
            }
            if (!ctx.exists(resolved.join('/'))) out.push(error(STANDARDS_GUIDE, `links ${target}, which is not in the repository`, lineContaining(text, target)));
        }
        return out;
    },
};

// ── errors-guide-complete ────────────────────────────────────────────

const errorsGuideComplete: Rule = {
    id: 'errors-guide-complete',
    summary: 'docs/guides/errors.md names every code of docs/data/errors.json, diagnostics.json and reasons.json — the quick start promises the guide lists every code.',
    check(ctx) {
        const guide = ctx.read(ERRORS_GUIDE);
        if (guide === null) return [error(ERRORS_GUIDE, 'missing — the guide every thrown message and quick start points to')];
        const codes = registeredCodes(ctx);
        if ('finding' in codes) return [codes.finding];
        const named = new Set(guide.match(CODE_TOKEN) ?? []);
        return [...codes.codes]
            .filter(([code]) => !named.has(code))
            .map(([code, registry]) => error(ERRORS_GUIDE, `does not name ${code} (${registry}) — add it to its section with its cause and remedy`));
    },
};

// ── code-token-registered ────────────────────────────────────────────

const codeTokenRegistered: Rule = {
    id: 'code-token-registered',
    summary: 'Every PKI_… code the README, llms.txt, the agent brief and the guides name is a code of docs/data/errors.json, diagnostics.json or reasons.json — a reader greps for it.',
    check(ctx) {
        const codes = registeredCodes(ctx);
        if ('finding' in codes) return [codes.finding];
        const out: Finding[] = [];
        for (const path of currentSurfaceDocs(ctx)) {
            const text = ctx.read(path) ?? '';
            const seen = new Set<string>();
            for (const m of text.matchAll(CODE_TOKEN)) {
                const code = m[0];
                if (codes.codes.has(code) || seen.has(code)) continue;
                seen.add(code);
                out.push(error(path, `names ${code}, which is in none of the three code registries — check the spelling against docs/data/`, lineOf(text, m.index)));
            }
        }
        return out;
    },
};

// ── readme-surfaces ──────────────────────────────────────────────────

const readmeSurfaces: Rule = {
    id: 'readme-surfaces',
    summary: 'The README names at least one export of every capability docs/data/surfaces.json lists, so the npm front page leaves no capability undiscoverable.',
    check(ctx) {
        const readme = ctx.read('README.md');
        if (readme === null) return [error('README.md', 'missing')];
        const surfaces = readJson<Record<string, unknown>>(ctx, 'docs/data/surfaces.json');
        if ('finding' in surfaces) return [surfaces.finding];
        const list = Object.values(surfaces.value).find(Array.isArray) as Array<{ id?: string; exports?: string[] }> | undefined;
        if (list === undefined) return [error('docs/data/surfaces.json', 'has no capability list')];
        return list
            .filter((s) => (s.exports ?? []).length > 0 && !(s.exports ?? []).some((name) => new RegExp(`\\b${name}\\b`).test(readme)))
            .map((s) => error('README.md', `names no export of the capability "${s.id ?? '?'}" (${(s.exports ?? []).slice(0, 3).join(', ')}, …) — add it to "What you get"`));
    },
};

// ── copilot-layer-parity ─────────────────────────────────────────────

const copilotLayerParity: Rule = {
    id: 'copilot-layer-parity',
    summary: 'The layer diagram in the Architecture section of .github/copilot-instructions.md equals LAYERS, as AGENTS.md\'s does.',
    check(ctx) {
        const text = ctx.read(COPILOT);
        if (text === null) return [error(COPILOT, 'missing — the canonical detail AGENTS.md points to')];
        const diagram = parseLayerDiagram(text);
        if (diagram === null) return [error(COPILOT, 'has no "## Architecture" section with a fenced layer diagram (`layer → allowed, layers`)')];
        const line = lineContaining(text, '## Architecture');
        const out: Finding[] = [];
        for (const [layer, allowed] of Object.entries(LAYERS)) {
            const documented = diagram[layer];
            const want = [...allowed].sort().join(', ');
            if (documented === undefined) out.push(error(COPILOT, `the diagram omits layer "${layer}" (LAYERS: ${layer} → ${want || '(nothing)'})`, line));
            else if ([...documented].sort().join(', ') !== want) out.push(error(COPILOT, `the diagram says ${layer} → ${[...documented].sort().join(', ') || '(nothing)'}, LAYERS says ${layer} → ${want || '(nothing)'}`, line));
        }
        for (const layer of Object.keys(diagram)) {
            if (!Object.hasOwn(LAYERS, layer)) out.push(error(COPILOT, `the diagram names layer "${layer}", which LAYERS does not register`, line));
        }
        return out;
    },
};

export const CURRENCY_RULES: readonly Rule[] = [staleMilestone, standardsEvidence, errorsGuideComplete, codeTokenRegistered, readmeSurfaces, copilotLayerParity];
