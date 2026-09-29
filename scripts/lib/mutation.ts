/**
 * pkinative — Mutation testing, the pure half
 * ===========================================
 * What `scripts/mutate.ts` needs that can be decided from file contents
 * alone: the mutants of a source file (enumerated on the TypeScript syntax
 * tree, each with a stable id), the deterministic sampler, the import graph
 * that picks the test files able to observe a module, and the reviewed
 * equivalent-mutant table. No process is spawned here and nothing is
 * written, so `tests/tools/mutation.test.ts` exercises all of it in memory.
 *
 * Line coverage proves that code ran; a mutant proves that a test would
 * notice the code being wrong. A surviving mutant is either a test gap or an
 * equivalent mutant — a change no input can observe — and the second kind is
 * recorded, with its reason, in `scripts/data/mutation-equivalents.json`.
 *
 * @module scripts/lib/mutation
 */

import ts from 'typescript';

// ── Mutants ──

/** The mutation operators, one family per kind of decision a test must pin. */
export type MutationOperator =
    | 'relational'      // <  ↔ <=,  > ↔ >=
    | 'equality'        // === ↔ !==, == ↔ !=
    | 'logical'         // && ↔ ||
    | 'not-removal'     // !x → x
    | 'conditional'     // c ? a : b → c ? b : a
    | 'if-true'         // if (c) → if (true)
    | 'if-false'        // if (c) → if (false), when the branch does not throw
    | 'throw-guard'     // if (c) throw … → if (false) throw …
    | 'number'          // a limit or an offset ± 1
    | 'return-boolean'; // return true ↔ return false

export interface Mutant {
    /** `<file>:<line>:<column>:<operator>` (`number+1`, `number-1` for the two limit mutants) — stable while the file is unchanged. */
    readonly id: string;
    readonly file: string;
    readonly line: number;
    readonly column: number;
    readonly operator: MutationOperator;
    /** The source text the mutant replaces, and what it puts there. */
    readonly original: string;
    readonly replacement: string;
    readonly start: number;
    readonly end: number;
}

const BINARY_SWAPS: ReadonlyMap<ts.SyntaxKind, readonly [string, MutationOperator]> = new Map([
    [ts.SyntaxKind.LessThanToken, ['<=', 'relational']],
    [ts.SyntaxKind.LessThanEqualsToken, ['<', 'relational']],
    [ts.SyntaxKind.GreaterThanToken, ['>=', 'relational']],
    [ts.SyntaxKind.GreaterThanEqualsToken, ['>', 'relational']],
    [ts.SyntaxKind.EqualsEqualsEqualsToken, ['!==', 'equality']],
    [ts.SyntaxKind.ExclamationEqualsEqualsToken, ['===', 'equality']],
    [ts.SyntaxKind.EqualsEqualsToken, ['!=', 'equality']],
    [ts.SyntaxKind.ExclamationEqualsToken, ['==', 'equality']],
    [ts.SyntaxKind.AmpersandAmpersandToken, ['||', 'logical']],
    [ts.SyntaxKind.BarBarToken, ['&&', 'logical']],
]);

/** Binary operators whose numeric operand is a limit, an offset, a width or a mask. */
const NUMERIC_CONTEXT_OPERATORS: ReadonlySet<ts.SyntaxKind> = new Set([
    ts.SyntaxKind.PlusToken, ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.SlashToken, ts.SyntaxKind.PercentToken,
    ts.SyntaxKind.LessThanLessThanToken, ts.SyntaxKind.GreaterThanGreaterThanToken, ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken,
    ts.SyntaxKind.AmpersandToken, ts.SyntaxKind.BarToken, ts.SyntaxKind.CaretToken,
    ts.SyntaxKind.LessThanToken, ts.SyntaxKind.LessThanEqualsToken, ts.SyntaxKind.GreaterThanToken, ts.SyntaxKind.GreaterThanEqualsToken,
    ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken,
    ts.SyntaxKind.PlusEqualsToken, ts.SyntaxKind.MinusEqualsToken,
]);

/** Byte-window methods whose numeric arguments are offsets. */
const OFFSET_METHODS: ReadonlySet<string> = new Set(['subarray', 'slice', 'at', 'fill', 'copyWithin', 'set']);

const UPPER_SNAKE = /^[A-Z][A-Z0-9_]*$/;

/** True when a `then` branch is a guard: it throws, directly or as a block's statement. */
function throwsDirectly(statement: ts.Statement): boolean {
    if (ts.isThrowStatement(statement)) return true;
    return ts.isBlock(statement) && statement.statements.some((s) => ts.isThrowStatement(s));
}

/** True when a numeric literal is a limit or an offset rather than a table entry or a tag. */
function isLimitOrOffset(node: ts.NumericLiteral): boolean {
    const parent = node.parent;
    if (ts.isBinaryExpression(parent)) return NUMERIC_CONTEXT_OPERATORS.has(parent.operatorToken.kind);
    if (ts.isElementAccessExpression(parent)) return parent.argumentExpression === node;
    if (ts.isCallExpression(parent) && parent.arguments.includes(node)) {
        const callee = parent.expression;
        return ts.isPropertyAccessExpression(callee) && OFFSET_METHODS.has(callee.name.text);
    }
    // `const MAX_FOO = 16` — a named constant is a limit by convention.
    if (ts.isVariableDeclaration(parent) && parent.initializer === node) return ts.isIdentifier(parent.name) && UPPER_SNAKE.test(parent.name.text);
    return false;
}

/**
 * Every mutant of one source file, in source order. `file` is the
 * repository-relative path with forward slashes; it is part of each id.
 */
export function enumerateMutants(file: string, source: string): Mutant[] {
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const out: Mutant[] = [];
    const add = (operator: MutationOperator, start: number, end: number, replacement: string, variant = ''): void => {
        const original = source.slice(start, end);
        const { line, character } = sf.getLineAndCharacterOfPosition(start);
        out.push({ id: `${file}:${line + 1}:${character + 1}:${operator}${variant}`, file, line: line + 1, column: character + 1, operator, original, replacement, start, end });
    };

    const visit = (node: ts.Node): void => {
        if (ts.isBinaryExpression(node)) {
            const swap = BINARY_SWAPS.get(node.operatorToken.kind);
            if (swap !== undefined) add(swap[1], node.operatorToken.getStart(sf), node.operatorToken.getEnd(), swap[0]);
        } else if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) {
            add('not-removal', node.getStart(sf), node.getEnd(), `(${node.operand.getText(sf)})`);
        } else if (ts.isConditionalExpression(node)) {
            add('conditional', node.getStart(sf), node.getEnd(),
                `(${node.condition.getText(sf)} ? ${node.whenFalse.getText(sf)} : ${node.whenTrue.getText(sf)})`);
        } else if (ts.isIfStatement(node)) {
            const start = node.expression.getStart(sf);
            const end = node.expression.getEnd();
            add('if-true', start, end, 'true');
            add(throwsDirectly(node.thenStatement) ? 'throw-guard' : 'if-false', start, end, 'false');
        } else if (ts.isNumericLiteral(node) && isLimitOrOffset(node)) {
            const value = Number(node.text);
            if (Number.isSafeInteger(value)) {
                const negative = ts.isBinaryExpression(node.parent) && node.parent.operatorToken.kind === ts.SyntaxKind.MinusToken;
                add('number', node.getStart(sf), node.getEnd(), String(value + 1), '+1');
                // `x - 0` → `x - -1` is valid, but parenthesised for the reader.
                add('number', node.getStart(sf), node.getEnd(), value === 0 && negative ? '(-1)' : String(value - 1), '-1');
            }
        } else if (ts.isReturnStatement(node) && node.expression !== undefined) {
            const kind = node.expression.kind;
            if (kind === ts.SyntaxKind.TrueKeyword || kind === ts.SyntaxKind.FalseKeyword) {
                add('return-boolean', node.expression.getStart(sf), node.expression.getEnd(), kind === ts.SyntaxKind.TrueKeyword ? 'false' : 'true');
            }
        }
        // Types never run: nothing below a type node is a mutant.
        if (ts.isTypeNode(node) || ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) return;
        ts.forEachChild(node, visit);
    };
    visit(sf);
    return out.sort((x, y) => x.start - y.start || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
}

/** The source with one mutant applied. */
export function applyMutant(source: string, mutant: Mutant): string {
    return source.slice(0, mutant.start) + mutant.replacement + source.slice(mutant.end);
}

// ── Deterministic sampling ──

/** mulberry32: a 32-bit seeded PRNG, so a sample is the same on every machine. */
function prng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

/**
 * `size` mutants chosen by a seeded Fisher–Yates shuffle, returned in source
 * order. The same list, size and seed always give the same sample; a size at
 * or above the list length returns the whole list.
 */
export function sampleMutants(mutants: readonly Mutant[], size: number, seed: number): Mutant[] {
    if (size >= mutants.length) return [...mutants];
    const pool = [...mutants];
    const rand = prng(seed);
    for (let i = pool.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        const tmp = pool[i] as Mutant;
        pool[i] = pool[j] as Mutant;
        pool[j] = tmp;
    }
    return pool.slice(0, Math.max(0, size)).sort((x, y) => x.start - y.start || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
}

// ── Test selection ──

/** Repository-relative path → the repository-relative files it imports. */
export type ImportGraph = ReadonlyMap<string, readonly string[]>;

function posixJoin(dir: string, rel: string): string {
    const parts = dir === '' ? [] : dir.split('/');
    for (const seg of rel.split('/')) {
        if (seg === '' || seg === '.') continue;
        if (seg === '..') parts.pop();
        else parts.push(seg);
    }
    return parts.join('/');
}

/**
 * The import graph of a set of TypeScript files, from their import and
 * export specifiers (static and dynamic). Relative `.js` specifiers resolve
 * to the `.ts` file beside them; `pkinative` resolves to `src/index.ts`, as
 * the vitest alias does; anything else is a package and is dropped.
 */
export function buildImportGraph(files: ReadonlyMap<string, string>): ImportGraph {
    const graph = new Map<string, string[]>();
    for (const [file, text] of files) {
        const dir = file.includes('/') ? file.slice(0, file.lastIndexOf('/')) : '';
        const deps = new Set<string>();
        for (const ref of ts.preProcessFile(text, true, true).importedFiles) {
            const spec = ref.fileName;
            let target: string | null = null;
            if (spec === 'pkinative') target = 'src/index.ts';
            else if (spec.startsWith('.')) {
                const joined = posixJoin(dir, spec);
                const candidates = [joined.replace(/\.(m?js)$/, '.ts'), joined, `${joined}.ts`, `${joined}/index.ts`];
                target = candidates.find((c) => files.has(c)) ?? null;
            }
            if (target !== null) deps.add(target);
        }
        graph.set(file, [...deps].sort());
    }
    return graph;
}

/** Every file that reaches `target` through imports, `target` included. */
export function reverseClosure(graph: ImportGraph, target: string): Set<string> {
    const importers = new Map<string, string[]>();
    for (const [file, deps] of graph) for (const d of deps) importers.set(d, [...(importers.get(d) ?? []), file]);
    const seen = new Set<string>([target]);
    const queue = [target];
    while (queue.length > 0) {
        const next = queue.pop() as string;
        for (const importer of importers.get(next) ?? []) {
            if (!seen.has(importer)) { seen.add(importer); queue.push(importer); }
        }
    }
    return seen;
}

const isTestFile = (f: string): boolean => f.startsWith('tests/') && f.endsWith('.test.ts');

export interface TestSelection {
    /** The suites that name the module: fast, and where a mutant is expected to die. */
    readonly direct: string[];
    /** Every suite whose imports reach the module: the second opinion for a survivor. */
    readonly reach: string[];
}

/**
 * The test files able to observe `target`. `direct` is the suites that
 * import it themselves (or, failing any, the suites of its nearest
 * importers); `reach` is every suite that reaches it transitively, minus the
 * `exclude` prefixes. A mutant is first run against `direct`, and only a
 * survivor pays for `reach`.
 */
export function selectTests(graph: ImportGraph, target: string, exclude: readonly string[] = []): TestSelection {
    const allowed = (f: string): boolean => isTestFile(f) && !exclude.some((p) => f.startsWith(p));
    const reach = [...reverseClosure(graph, target)].filter(allowed).sort();
    let frontier = new Set<string>([target]);
    const seen = new Set<string>(frontier);
    let direct: string[] = [];
    while (direct.length === 0 && frontier.size > 0) {
        direct = reach.filter((t) => (graph.get(t) ?? []).some((d) => frontier.has(d)));
        const next = new Set<string>();
        for (const [file, deps] of graph) {
            if (!seen.has(file) && !isTestFile(file) && deps.some((d) => frontier.has(d))) { next.add(file); seen.add(file); }
        }
        frontier = next;
    }
    return { direct, reach };
}

// ── Equivalent mutants ──

/**
 * One reviewed equivalent mutant: a change no input can observe. `id`,
 * `original` and `replacement` must all still match an enumerated mutant, or
 * the entry is stale (the source moved) and the run says so; `reason` is the
 * argument for equivalence, never the word TODO.
 */
export interface EquivalentEntry {
    readonly id: string;
    readonly original: string;
    readonly replacement: string;
    readonly reason: string;
}

export interface EquivalentsFile {
    readonly $comment?: string;
    readonly schema: 1;
    readonly equivalents: readonly EquivalentEntry[];
}

/** Structural problems of an equivalents file; empty when it is well-formed. */
export function checkEquivalentsFile(value: unknown): string[] {
    const problems: string[] = [];
    if (typeof value !== 'object' || value === null) return ['the equivalents file is not a JSON object'];
    const v = value as { schema?: unknown; equivalents?: unknown };
    if (v.schema !== 1) problems.push('"schema" must be 1');
    if (!Array.isArray(v.equivalents)) return [...problems, '"equivalents" must be an array'];
    const ids = new Set<string>();
    for (const [i, e] of (v.equivalents as unknown[]).entries()) {
        const entry = (typeof e === 'object' && e !== null ? e : {}) as Record<string, unknown>;
        for (const key of ['id', 'original', 'replacement', 'reason']) {
            if (typeof entry[key] !== 'string' || entry[key] === '') problems.push(`equivalents[${i}] needs a non-empty "${key}"`);
        }
        const id = String(entry['id']);
        if (ids.has(id)) problems.push(`equivalents[${i}] repeats ${id}`);
        ids.add(id);
        if (typeof entry['reason'] === 'string' && /\bTODO\b/i.test(entry['reason'])) problems.push(`equivalents[${i}] (${id}) has no reason yet — an equivalent mutant is an argument, not a placeholder`);
    }
    return problems;
}

/**
 * Splits the equivalents of the enumerated files into the ones that still
 * match a mutant (by id, original and replacement) and the stale ones.
 * Entries for files that were not enumerated are neither.
 */
export function matchEquivalents(entries: readonly EquivalentEntry[], mutants: readonly Mutant[]): { matched: Map<string, EquivalentEntry>; stale: EquivalentEntry[] } {
    const byId = new Map(mutants.map((m) => [m.id, m]));
    const files = new Set(mutants.map((m) => m.file));
    const matched = new Map<string, EquivalentEntry>();
    const stale: EquivalentEntry[] = [];
    for (const e of entries) {
        const file = e.id.slice(0, e.id.indexOf(':'));
        if (!files.has(file)) continue;
        const m = byId.get(e.id);
        if (m !== undefined && m.original === e.original && m.replacement === e.replacement) matched.set(e.id, e);
        else stale.push(e);
    }
    return { matched, stale };
}

// ── Scores ──

export type MutantStatus = 'killed' | 'survived' | 'timeout' | 'compile-error' | 'equivalent';

export interface FileScore {
    readonly total: number;
    readonly killed: number;
    readonly survived: number;
    readonly timeout: number;
    readonly compileError: number;
    readonly equivalent: number;
    /** (killed + timeout) / (total − compile errors − equivalents), in percent. */
    readonly score: number;
}

/** The mutation score of a set of classified mutants, Stryker's definition with reviewed equivalents set aside. */
export function scoreOf(statuses: readonly MutantStatus[]): FileScore {
    const count = (s: MutantStatus): number => statuses.filter((x) => x === s).length;
    const killed = count('killed');
    const timeout = count('timeout');
    const compileError = count('compile-error');
    const equivalent = count('equivalent');
    const valid = statuses.length - compileError - equivalent;
    return {
        total: statuses.length, killed, survived: count('survived'), timeout, compileError, equivalent,
        score: valid === 0 ? 100 : Math.round(((killed + timeout) / valid) * 10000) / 100,
    };
}
