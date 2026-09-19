/**
 * pkinative — API manifest (`npm run docs:api`)
 * =============================================
 * Emits docs/assets/api.json from the export statements of src/index.ts and
 * the declarations they point at — plain text reading, no compiler API, no
 * build. dist/*.d.ts is not committed, so without this file an agent has no
 * ground truth for the public surface (the root cause of hallucinated APIs).
 *
 * Honesty rule (zipnative): a field that cannot be read mechanically is
 * `null`, never guessed. The signature is the declaration as written; the
 * error classes of a function are the `@throws {Class}` tags of its TSDoc.
 *
 * The generator reads through a `Reader`, so the verify-docs rules
 * `api-json-sync` and `tsdoc-complete` run it on the in-memory tree the
 * perturbation suite builds, exactly as on disk. Output is deterministic:
 * LF-normalised, sorted by name.
 *
 * @module scripts/build-api-json
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Repository-relative POSIX path → text, or null when absent. */
export type Reader = (path: string) => string | null;

export type ApiKind = 'function' | 'constant' | 'class' | 'type';

export interface ApiExport {
    readonly name: string;
    readonly kind: ApiKind;
    readonly module: string;
    readonly signature: string | null;
    readonly summary: string | null;
    /** Error classes named by `@throws {Class}`, for functions; null for other kinds. */
    readonly throws: readonly string[] | null;
}

export interface ApiManifest {
    readonly $comment: string;
    readonly package: string;
    readonly source: string;
    readonly exportCount: number;
    readonly exports: readonly ApiExport[];
}

const ENTRY = 'src/index.ts';
const DECLARATION = '(?:async\\s+)?(function\\*?|const|let|class|type|interface|enum)';

const lf = (text: string): string => text.replace(/\r\n/g, '\n');

function declarationMatch(moduleText: string, name: string): RegExpMatchArray | null {
    return moduleText.match(new RegExp(`export\\s+${DECLARATION}\\s+${name}\\b[^\\n]*`));
}

function kindOf(keyword: string): ApiKind {
    if (keyword.startsWith('function')) return 'function';
    if (keyword === 'class') return 'class';
    if (keyword === 'type' || keyword === 'interface' || keyword === 'enum') return 'type';
    return 'constant';
}

/** The declaration as written, extended to the closing parenthesis of a wrapped parameter list. */
function signatureOf(moduleText: string, match: RegExpMatchArray): string {
    let signature = match[0];
    if (signature.includes('(') && !balancedParens(signature)) {
        const start = (match.index ?? 0) + signature.length;
        const rest = moduleText.slice(start, start + 2000);
        let depth = [...signature].reduce((d, c) => d + (c === '(' ? 1 : c === ')' ? -1 : 0), 0);
        for (let i = 0; i < rest.length; i++) {
            const c = rest[i];
            if (c === '(') depth++;
            if (c === ')') depth--;
            if (depth === 0) {
                signature += rest.slice(0, i + 1) + (/^[^\n{]*/.exec(rest.slice(i + 1))?.[0] ?? '');
                break;
            }
        }
    }
    signature = signature.replace(/\s+/g, ' ').replace(/\s*[{=]\s*$/, '').trim();
    return signature.length > 400 ? `${signature.slice(0, 400)}…` : signature;
}

function balancedParens(text: string): boolean {
    let depth = 0;
    for (const c of text) {
        if (c === '(') depth++;
        if (c === ')') depth--;
    }
    return depth === 0;
}

/** The TSDoc block immediately above a declaration (a tempered body cannot reach the file banner). */
function docBlockAbove(moduleText: string, match: RegExpMatchArray): string | null {
    const before = moduleText.slice(0, match.index ?? 0);
    const block = /\/\*\*((?:[^*]|\*(?!\/))*)\*\/\s*$/.exec(before);
    if (block === null) return null;
    return block[1].split('\n').map((line) => line.replace(/^\s*\*? ?/, '')).join('\n');
}

function summaryOf(doc: string | null): string | null {
    if (doc === null) return null;
    const prose = doc.split('\n').filter((l) => !l.trim().startsWith('@') && !/^[=\-─]{3,}/.test(l.trim())).join(' ');
    const joined = prose.replace(/\s+/g, ' ').trim();
    if (joined === '') return null;
    const sentence = /^(.*?[.!?])(\s|$)/.exec(joined);
    const summary = (sentence !== null ? sentence[1] : joined).replace(/\{@link\s+([^}]+)\}/g, '$1').trim();
    return summary.length > 240 ? `${summary.slice(0, 240)}…` : summary;
}

function throwsOf(doc: string | null): string[] {
    if (doc === null) return [];
    return [...new Set([...doc.matchAll(/@throws\s+\{(\w+)\}/g)].map((m) => m[1] ?? ''))].sort();
}

/** The parameter names of a function signature, generics and default values skipped. */
export function parameterNames(signature: string): string[] {
    let at = signature.indexOf('(');
    const generic = signature.indexOf('<');
    if (generic >= 0 && generic < at) {
        let depth = 0;
        for (let i = generic; i < signature.length; i++) {
            if (signature[i] === '<') depth++;
            if (signature[i] === '>') depth--;
            if (depth === 0) { at = signature.indexOf('(', i); break; }
        }
    }
    const names: string[] = [];
    let depth = 0;
    let current = '';
    for (let i = at + 1; i < signature.length; i++) {
        const c = signature[i] ?? '';
        if ('([{<'.includes(c)) depth++;
        if (')]}>'.includes(c)) {
            if (depth === 0) break;
            depth--;
        }
        if (c === ',' && depth === 0) {
            names.push(current);
            current = '';
            continue;
        }
        current += c;
    }
    names.push(current);
    return names.map((p) => /^\s*(?:\.\.\.)?([A-Za-z_$][\w$]*)/.exec(p)?.[1] ?? '').filter((n) => n !== '');
}

interface Entry {
    readonly export: ApiExport;
    readonly doc: string | null;
}

function collect(read: Reader): Entry[] {
    const index = lf(read(ENTRY) ?? '');
    const entries = new Map<string, Entry>();
    for (const m of index.matchAll(/export\s*(type\s*)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g)) {
        const module = posix.normalize(posix.join(posix.dirname(ENTRY), (m[3] ?? '').replace(/\.js$/, '.ts')));
        const text = lf(read(module) ?? '');
        for (const piece of (m[2] ?? '').split(',').map((p) => p.trim()).filter((p) => p !== '')) {
            const name = (piece.replace(/^type\s+/, '').split(/\s+as\s+/).pop() ?? '').trim();
            if (name === '' || entries.has(name)) continue;
            const match = declarationMatch(text, name);
            const kind = match === null ? (m[1] !== undefined ? 'type' : 'constant') : kindOf(match[1] ?? '');
            const doc = match === null ? null : docBlockAbove(text, match);
            entries.set(name, {
                export: {
                    name,
                    kind,
                    module,
                    signature: match === null ? null : signatureOf(text, match),
                    summary: summaryOf(doc),
                    throws: kind === 'function' ? throwsOf(doc) : null,
                },
                doc,
            });
        }
    }
    return [...entries.values()].sort((a, b) => (a.export.name < b.export.name ? -1 : a.export.name > b.export.name ? 1 : 0));
}

export function buildApiJson(read: Reader): ApiManifest {
    const exports = collect(read).map((e) => e.export);
    return {
        $comment: 'Machine-generated public surface of pkinative (the single entry point src/index.ts) — the ground truth for agents, since dist/*.d.ts is not committed. '
            + 'Fields that cannot be read mechanically are null, never guessed; `throws` lists the @throws classes of a function. '
            + 'Regenerate with `npm run docs:api`; the verify-docs rule api-json-sync enforces freshness.',
        package: 'pkinative',
        source: ENTRY,
        exportCount: exports.length,
        exports,
    };
}

/** The serialised manifest, byte for byte what docs/assets/api.json must hold. */
export function renderApiJson(read: Reader): string {
    return `${JSON.stringify(buildApiJson(read), null, 2)}\n`;
}

/**
 * Every documentation gap of the public surface (AGENTS.md §Conventions):
 * an export without a summary, a function without `@returns` or `@throws`,
 * or a parameter without its `@param`.
 */
export function documentationGaps(read: Reader): string[] {
    const gaps: string[] = [];
    for (const { export: exp, doc } of collect(read)) {
        const where = `${exp.module} › ${exp.name}`;
        if (exp.summary === null) gaps.push(`${where}: no TSDoc summary`);
        if (exp.kind !== 'function' || doc === null) continue;
        if (!/@returns?\b/.test(doc)) gaps.push(`${where}: no @returns`);
        if (!/@throws\b/.test(doc)) gaps.push(`${where}: no @throws (write "@throws Never — …" when it cannot throw)`);
        const documented = new Set([...doc.matchAll(/@param\s+(?:\{[^}]*\}\s+)?\[?([A-Za-z_$][\w$]*)/g)].map((m) => m[1]));
        for (const param of parameterNames(exp.signature ?? '')) {
            if (!documented.has(param)) gaps.push(`${where}: no @param ${param}`);
        }
    }
    return gaps;
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
    const root = join(dirname(fileURLToPath(import.meta.url)), '..');
    const read: Reader = (path) => (existsSync(join(root, path)) ? readFileSync(join(root, path), 'utf8') : null);
    const text = renderApiJson(read);
    writeFileSync(join(root, 'docs', 'assets', 'api.json'), text);
    console.error(`docs/assets/api.json: ${buildApiJson(read).exportCount} exports`);
}
