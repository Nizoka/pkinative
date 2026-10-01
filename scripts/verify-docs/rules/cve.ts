/**
 * pkinative — CVE-class rules
 * ===========================
 * `cve-class-parity`: the CVE-class corpus is a registry, a test suite and a
 * table in the security guide, and the three say the same thing.
 *
 * `docs/data/cve-classes.json` lists every published vulnerability of a PKI
 * library whose class pkinative could share: the library it hit, the class,
 * the CWE, whether it applies to pkinative and why, who stops it (pkinative
 * itself, or the host's Web Crypto for the arithmetic pkinative delegates),
 * and the name of the test in `tests/security/cve-classes.test.ts` that
 * replays it. A registry row whose test does not exist is a claim; a test
 * that names an identifier the registry does not list is an answer nobody
 * can find; a guide table that drifts from either tells a reader the wrong
 * thing about a security decision. All three are refused here, both ways.
 *
 * @module scripts/verify-docs/rules/cve
 */

import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

export const CVE_REGISTRY = 'docs/data/cve-classes.json';
export const CVE_TESTS = 'tests/security/cve-classes.test.ts';
export const CVE_GUIDE = 'docs/guides/security.md';

/** A CVE or a GitHub Security Advisory identifier. */
const ID = /\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b/g;
const APPLIES = new Set(['yes', 'no', 'n.a.']);
const DEFENCES = new Set(['pkinative', 'host', 'pkinative and host', 'by construction']);

interface CveEntry {
    readonly id: string;
    readonly aliases?: readonly string[];
    readonly library: string;
    readonly class: string;
    readonly cwe: readonly string[];
    readonly applies: string;
    readonly why: string;
    readonly defence: string;
    readonly test: string;
}

/**
 * The names of the tests of a vitest file: the first argument of every
 * `it(…)`, `it.skip(…)`, `it.skipIf(cond)(…)` written as a single-quoted
 * literal, unescaped. Names built at run time are invisible here, which is
 * why the suite writes its CVE tests as literals.
 */
export function testNames(source: string): string[] {
    const out: string[] = [];
    for (const m of source.matchAll(/\bit(?:\.\w+(?:\([^()]*\))?)?\(\s*'((?:[^'\\]|\\.)*)'/g)) {
        out.push((m[1] ?? '').replace(/\\(.)/g, '$1'));
    }
    return out;
}

/** The identifiers a text names, in order, deduplicated. */
export function idsIn(text: string): string[] {
    return [...new Set([...text.matchAll(ID)].map((m) => m[1] ?? ''))];
}

/** The identifiers of the guide's CVE-class table: the first cell of each row under `## CVE classes`. */
function guideIds(guide: string): string[] | null {
    const at = guide.search(/^## CVE classes\b/m);
    if (at < 0) return null;
    const section = guide.slice(at).split(/^## /m)[1] ?? '';
    const ids: string[] = [];
    for (const line of section.split('\n')) {
        const cell = /^\|\s*([^|]+?)\s*\|/.exec(line)?.[1];
        if (cell !== undefined) ids.push(...idsIn(cell));
    }
    return ids;
}

function checkEntry(entry: CveEntry, index: number, out: Finding[], text: string): void {
    const where = (needle: string): number => lineContaining(text, needle);
    const at = `entry ${String(index)}${typeof entry.id === 'string' ? ` (${entry.id})` : ''}`;
    if (typeof entry.id !== 'string' || idsIn(entry.id).join() !== entry.id) out.push(error(CVE_REGISTRY, `${at}: id must be one CVE or GHSA identifier`, where(String(entry.id))));
    for (const alias of entry.aliases ?? []) {
        if (idsIn(alias).join() !== alias) out.push(error(CVE_REGISTRY, `${at}: alias ${JSON.stringify(alias)} is not a CVE or GHSA identifier`, where(alias)));
    }
    for (const field of ['library', 'class', 'why', 'test'] as const) {
        if (typeof entry[field] !== 'string' || entry[field].trim().length < 3) out.push(error(CVE_REGISTRY, `${at}: ${field} is missing`, where(entry.id)));
    }
    if (!Array.isArray(entry.cwe) || entry.cwe.length === 0 || !entry.cwe.every((c) => /^(CWE-\d+|NVD-CWE-noinfo|unassigned)$/.test(c))) {
        out.push(error(CVE_REGISTRY, `${at}: cwe must list CWE-<n> identifiers as NVD records them (NVD-CWE-noinfo, or unassigned when the record has no weakness)`, where(entry.id)));
    }
    if (!APPLIES.has(entry.applies)) out.push(error(CVE_REGISTRY, `${at}: applies must be one of ${[...APPLIES].join(', ')}`, where(entry.id)));
    if (!DEFENCES.has(entry.defence)) out.push(error(CVE_REGISTRY, `${at}: defence must be one of ${[...DEFENCES].join(', ')} — say who stops it`, where(entry.id)));
}

function check(ctx: RuleContext): readonly Finding[] {
    const out: Finding[] = [];
    const registry = readJson<{ entries?: CveEntry[] }>(ctx, CVE_REGISTRY);
    if ('finding' in registry) return [registry.finding];
    const text = ctx.read(CVE_REGISTRY) ?? '';
    const entries = registry.value.entries ?? [];
    if (entries.length === 0) out.push(error(CVE_REGISTRY, 'lists no entry'));
    const source = ctx.read(CVE_TESTS);
    if (source === null) return [...out, error(CVE_TESTS, 'missing — the registry names tests in it')];
    const names = new Set(testNames(source));

    const ids = new Map<string, CveEntry>();
    entries.forEach((entry, i) => {
        checkEntry(entry, i, out, text);
        if (ids.has(entry.id)) out.push(error(CVE_REGISTRY, `${entry.id} is listed twice`, lineContaining(text, `"${entry.id}"`)));
        ids.set(entry.id, entry);
        // Registry → tests: the named test exists and answers this identifier.
        if (typeof entry.test === 'string' && !names.has(entry.test)) {
            out.push(error(CVE_REGISTRY, `${entry.id} names the test ${JSON.stringify(entry.test)}, which ${CVE_TESTS} does not contain`, lineContaining(text, entry.test)));
        } else if (typeof entry.test === 'string' && !idsIn(entry.test).includes(entry.id)) {
            out.push(error(CVE_REGISTRY, `${entry.id} names a test whose name does not carry ${entry.id}`, lineContaining(text, entry.test)));
        }
    });

    // Tests → registry: every identifier a test name carries is listed.
    for (const name of names) {
        for (const id of idsIn(name)) {
            if (!ids.has(id)) out.push(error(CVE_TESTS, `the test ${JSON.stringify(name)} names ${id}, which ${CVE_REGISTRY} does not list`, lineContaining(source, id)));
        }
    }

    // The guide's table: the same identifiers, each once.
    const guide = ctx.read(CVE_GUIDE);
    const table = guide === null ? null : guideIds(guide);
    if (guide === null || table === null) {
        out.push(error(CVE_GUIDE, 'has no "## CVE classes" section — the guide is where a reader finds the registry'));
    } else {
        for (const id of ids.keys()) {
            if (!table.includes(id)) out.push(error(CVE_GUIDE, `the CVE classes table does not list ${id}`, lineContaining(guide, '## CVE classes')));
        }
        const seen = new Set<string>();
        for (const id of table) {
            if (!ids.has(id) && ![...ids.values()].some((e) => (e.aliases ?? []).includes(id))) out.push(error(CVE_GUIDE, `the CVE classes table lists ${id}, which ${CVE_REGISTRY} does not`, lineContaining(guide, id)));
            if (ids.has(id) && seen.has(id)) out.push(error(CVE_GUIDE, `the CVE classes table lists ${id} twice`, lineContaining(guide, id)));
            seen.add(id);
        }
    }
    return out;
}

const cveClassParity: Rule = {
    id: 'cve-class-parity',
    summary: 'docs/data/cve-classes.json, the replays in tests/security/cve-classes.test.ts and the CVE classes table of docs/guides/security.md list the same identifiers: every entry names a test that exists and carries its id, every id a test carries is an entry, and every entry says whether it applies and who stops it.',
    check,
};

export const CVE_RULES: readonly Rule[] = [cveClassParity];
