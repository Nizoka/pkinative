/**
 * pkinative — architecture checks
 * ================================
 * The layer table of `src/` and the checks that hold the source tree to it,
 * as pure functions over file contents (`path → text`). One definition, two
 * consumers: `tests/tools/architecture.test.ts` runs the checks over `src/`,
 * and the `layer-parity` rule of `scripts/verify-docs.ts` holds the diagram
 * in AGENTS.md §Architecture to the same table.
 *
 * pdfnative documented its dependency flow but enforced none of it, and its
 * "no classes" rule had two exceptions nobody noticed. Here every rule of
 * AGENTS.md §Conventions that can be decided from the syntax tree is decided
 * from the syntax tree:
 *
 *   - imports follow LAYERS (no reverse edge, no cycle, no unregistered layer);
 *   - imports are relative with a `.js` extension — no `node:` built-in, no
 *     bare package specifier, no dynamic `import()`, no `require`;
 *   - `class` appears only in the error module;
 *   - `console` appears only in the diagnostics module;
 *   - no runtime escape hatch (`eval`, `Function`, `fetch`, `process`, …).
 *
 * @module scripts/lib/architecture
 */

import { posix } from 'node:path';
import ts from 'typescript';
import { markdownSection, type Finding } from './agent-config.js';

/**
 * Layer → the layers it may import. A layer always imports within itself;
 * `src/index.ts` imports every layer and nothing imports it.
 */
export const LAYERS: Readonly<Record<string, readonly string[]>> = Object.freeze({
    types: [],
    core: ['types'],
    hash: ['types', 'core'],
    asn1: ['types', 'core'],
    pem: ['types', 'core'],
    oid: [],
    x509: ['types', 'core', 'asn1'],
});

export const ENTRY = 'src/index.ts';
/** The only module allowed to declare classes (the `PkiError` family). */
export const ERRORS_MODULE = 'src/types/pki-errors.ts';
/** The only module allowed to reference `console` (the diagnostics sink). */
export const DIAGNOSTICS_MODULE = 'src/core/pki-diagnostics.ts';

/** Globals the engine never touches: dynamic code, I/O, and host-specific objects. */
export const FORBIDDEN_GLOBALS: ReadonlySet<string> = new Set([
    'eval', 'Function', 'fetch', 'WebSocket', 'XMLHttpRequest', 'EventSource',
    'process', 'require', 'module', 'exports', 'Buffer', 'setImmediate', 'importScripts', 'Deno', 'Bun',
]);

function finding(file: string, line: number, message: string): Finding {
    return { severity: 'error', file, line, message };
}

/** The layer of a source path: `src/asn1/asn1-decode.ts` → `asn1`; the entry → `index`; anything else → null. */
export function layerOf(path: string): string | null {
    if (path === ENTRY) return 'index';
    const m = /^src\/([^/]+)\/.+\.ts$/.exec(path);
    return m ? m[1] : null;
}

/** True when an identifier node is a property name, not a reference to a binding or a global. */
function isPropertyName(node: ts.Identifier): boolean {
    const p = node.parent;
    if (ts.isPropertyAccessExpression(p) && p.name === node) return true;
    if ((ts.isPropertyAssignment(p) || ts.isPropertyDeclaration(p) || ts.isPropertySignature(p)
        || ts.isMethodDeclaration(p) || ts.isMethodSignature(p) || ts.isGetAccessorDeclaration(p)
        || ts.isSetAccessorDeclaration(p) || ts.isEnumMember(p)) && p.name === node) return true;
    if (ts.isQualifiedName(p) && p.right === node) return true;
    if ((ts.isImportSpecifier(p) || ts.isExportSpecifier(p)) && p.propertyName === node) return true;
    if (ts.isBindingElement(p) && p.propertyName === node) return true;
    if (ts.isLabeledStatement(p) || ts.isBreakOrContinueStatement(p)) return true;
    return false;
}

interface ModuleFacts {
    readonly imports: Array<{ readonly specifier: string; readonly line: number }>;
    readonly findings: Finding[];
}

function inspectModule(path: string, text: string): ModuleFacts {
    const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const imports: Array<{ specifier: string; line: number }> = [];
    const findings: Finding[] = [];
    const lineAt = (node: ts.Node): number => source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;

    const visit = (node: ts.Node): void => {
        if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
            imports.push({ specifier: node.moduleSpecifier.text, line: lineAt(node) });
        } else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteral(node.argument.literal)) {
            imports.push({ specifier: node.argument.literal.text, line: lineAt(node) });
        } else if (ts.isImportEqualsDeclaration(node)) {
            findings.push(finding(path, lineAt(node), '`import x = require(…)` is forbidden — use an ES import'));
        } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
            findings.push(finding(path, lineAt(node), 'dynamic `import()` is forbidden in src/ — every dependency is static and relative'));
        } else if ((ts.isClassDeclaration(node) || ts.isClassExpression(node)) && path !== ERRORS_MODULE) {
            findings.push(finding(path, lineAt(node), `\`class\` is forbidden outside ${ERRORS_MODULE} — use a closure factory returning an interface`));
        } else if (ts.isIdentifier(node) && !isPropertyName(node)) {
            if (node.text === 'console' && path !== DIAGNOSTICS_MODULE) {
                findings.push(finding(path, lineAt(node), `\`console\` is forbidden outside ${DIAGNOSTICS_MODULE} — emit a diagnostic instead`));
            } else if (FORBIDDEN_GLOBALS.has(node.text)) {
                findings.push(finding(path, lineAt(node), `\`${node.text}\` is forbidden in src/ — the engine has no dynamic code, no I/O and no host-specific globals`));
            }
        }
        ts.forEachChild(node, visit);
    };
    visit(source);
    return { imports, findings };
}

/**
 * Check a source tree (`src/**` paths → text) against the layer table and the
 * syntactic conventions. Returns every violation; an empty array is a pass.
 */
export function checkArchitecture(files: Readonly<Record<string, string>>): Finding[] {
    const out: Finding[] = [];
    const graph = new Map<string, string[]>();
    const paths = Object.keys(files).filter((p) => p.endsWith('.ts')).sort();

    for (const path of paths) {
        const from = layerOf(path);
        if (from === null) {
            out.push(finding(path, 1, 'is outside every layer — source files live in src/<layer>/ or are src/index.ts'));
            continue;
        }
        if (from !== 'index' && !(from in LAYERS)) {
            out.push(finding(path, 1, `layer "${from}" is not registered in LAYERS (scripts/lib/architecture.ts) — register it and update AGENTS.md §Architecture first`));
            continue;
        }
        const facts = inspectModule(path, files[path]);
        out.push(...facts.findings);
        const edges: string[] = [];
        for (const { specifier, line } of facts.imports) {
            if (specifier.startsWith('node:')) {
                out.push(finding(path, line, `imports "${specifier}" — src/ runs on every runtime and imports no Node built-in`));
                continue;
            }
            if (!specifier.startsWith('./') && !specifier.startsWith('../')) {
                out.push(finding(path, line, `imports "${specifier}" — a bare specifier is a runtime dependency, and pkinative has none`));
                continue;
            }
            if (!specifier.endsWith('.js')) {
                out.push(finding(path, line, `imports "${specifier}" without the .js extension ESM resolution needs`));
                continue;
            }
            const target = posix.normalize(posix.join(posix.dirname(path), specifier)).replace(/\.js$/, '.ts');
            if (!(target in files)) {
                out.push(finding(path, line, `imports "${specifier}", which resolves to ${target}, a file that does not exist`));
                continue;
            }
            edges.push(target);
            const to = layerOf(target);
            if (to === 'index') {
                out.push(finding(path, line, `imports ${ENTRY} — nothing inside the library imports the public entry point`));
            } else if (to !== null && from !== 'index' && to !== from && !(LAYERS[from] ?? []).includes(to)) {
                out.push(finding(path, line, `layer "${from}" imports layer "${to}" (${target}) — LAYERS allows ${from} → ${(LAYERS[from] ?? []).join(', ') || '(nothing)'}`));
            }
        }
        graph.set(path, edges);
    }

    // Cycles, reported once each, from the first module that closes one.
    const state = new Map<string, 'visiting' | 'done'>();
    const stack: string[] = [];
    const reported = new Set<string>();
    const dfs = (node: string): void => {
        state.set(node, 'visiting');
        stack.push(node);
        for (const next of graph.get(node) ?? []) {
            if (state.get(next) === 'visiting') {
                const cycle = [...stack.slice(stack.indexOf(next)), next];
                const key = [...cycle].sort().join('|');
                if (!reported.has(key)) {
                    reported.add(key);
                    out.push(finding(node, 1, `import cycle: ${cycle.join(' → ')}`));
                }
            } else if (!state.has(next)) {
                dfs(next);
            }
        }
        stack.pop();
        state.set(node, 'done');
    };
    for (const node of graph.keys()) if (!state.has(node)) dfs(node);

    return out;
}

// ── layer-parity (AGENTS.md §Architecture) ───────────────────────────

/**
 * The diagram in the first fenced block of AGENTS.md §Architecture, one line
 * per layer: `x509   → types, core, asn1`, or `oid    → (nothing)`. Returns
 * null when the section or the block is missing.
 */
export function parseLayerDiagram(markdown: string): Record<string, string[]> | null {
    const section = markdownSection(markdown, 'Architecture');
    if (section === null) return null;
    const block = /```[^\n]*\n([\s\S]*?)```/.exec(section);
    if (!block) return null;
    const out: Record<string, string[]> = {};
    for (const line of block[1].split('\n')) {
        const m = /^([a-z0-9]+)\s+→\s+(.+?)\s*$/.exec(line);
        if (!m || m[1] === 'index') continue;
        out[m[1]] = m[2] === '(nothing)' ? [] : m[2].split(/,\s*/).map((s) => s.trim()).filter((s) => s.length > 0);
    }
    return out;
}

export function checkLayerParity(agentsMd: string | null): Finding[] {
    const FILE = 'AGENTS.md';
    if (agentsMd === null) return [finding(FILE, 1, 'missing — it carries the layer diagram agents read before touching src/')];
    const diagram = parseLayerDiagram(agentsMd);
    if (diagram === null) return [finding(FILE, 1, 'has no "## Architecture" section with a fenced layer diagram (`layer → allowed, layers`)')];
    const out: Finding[] = [];
    const line = Math.max(1, agentsMd.split('\n').findIndex((l) => l.trim() === '## Architecture') + 1);
    for (const layer of Object.keys(LAYERS)) {
        const documented = diagram[layer];
        if (documented === undefined) {
            out.push(finding(FILE, line, `the diagram omits layer "${layer}" (LAYERS: ${layer} → ${LAYERS[layer].join(', ') || '(nothing)'})`));
            continue;
        }
        const want = [...LAYERS[layer]].sort().join(', ');
        const got = [...documented].sort().join(', ');
        if (want !== got) out.push(finding(FILE, line, `the diagram says ${layer} → ${got || '(nothing)'}, LAYERS says ${layer} → ${want || '(nothing)'}`));
    }
    for (const layer of Object.keys(diagram)) {
        if (!(layer in LAYERS)) out.push(finding(FILE, line, `the diagram names layer "${layer}", which LAYERS does not register`));
    }
    return out;
}
