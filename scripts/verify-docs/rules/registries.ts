/**
 * pkinative — registry rules
 * ===========================
 * The error vocabulary, the diagnostic vocabulary and the security bounds
 * each exist in code and in a machine-readable registry under `docs/data/`
 * (and the bounds a third and fourth time, in the limits module header and
 * in SECURITY.md). Agents and downstream packages read the registries; these
 * rules make sure what they read is what the code does.
 *
 * The TypeScript sources are read as syntax trees, never by regex, so a
 * reformatting cannot hide a code.
 *
 * @module scripts/verify-docs/rules/registries
 */

import { posix } from 'node:path';
import ts from 'typescript';
import { KEY_OPERATION_POLICY, WEBCRYPTO_HOST_MODULES } from '../../lib/architecture.js';
import { error, lineContaining, lineOf, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

export const ERRORS_SOURCE = 'src/types/pki-errors.ts';
export const TYPES_SOURCE = 'src/types/pki-types.ts';
export const DIAGNOSTICS_SOURCE = 'src/core/pki-diagnostics.ts';
export const LIMITS_SOURCE = 'src/core/pki-limits.ts';
export const ERRORS_REGISTRY = 'docs/data/errors.json';
export const DIAGNOSTICS_REGISTRY = 'docs/data/diagnostics.json';
export const LIMITS_REGISTRY = 'docs/data/limits.json';
export const REASONS_SOURCE = 'src/types/pki-reasons.ts';
export const REASON_FACTORIES = 'src/core/pki-reasons.ts';
export const REASONS_REGISTRY = 'docs/data/reasons.json';
const SECURITY = 'SECURITY.md';
const SEMVER = /^\d+\.\d+\.\d+$/;
const MESSAGE_PREFIX = 'pkinative: ';

function parse(path: string, text: string): ts.SourceFile {
    return ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

/** Type alias name → its string literal members, with aliases referenced inside a union resolved. */
export function stringLiteralUnions(source: ts.SourceFile): Map<string, string[]> {
    const raw = new Map<string, ts.TypeNode>();
    for (const s of source.statements) if (ts.isTypeAliasDeclaration(s)) raw.set(s.name.text, s.type);
    const resolved = new Map<string, string[]>();
    const resolveAlias = (name: string, seen: ReadonlySet<string>): string[] => {
        const cached = resolved.get(name);
        if (cached) return cached;
        const node = raw.get(name);
        if (node === undefined || seen.has(name)) return [];
        const inner = new Set([...seen, name]);
        const out: string[] = [];
        const visit = (t: ts.TypeNode): void => {
            if (ts.isUnionTypeNode(t)) t.types.forEach(visit);
            else if (ts.isParenthesizedTypeNode(t)) visit(t.type);
            else if (ts.isLiteralTypeNode(t) && ts.isStringLiteral(t.literal)) out.push(t.literal.text);
            else if (ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName)) out.push(...resolveAlias(t.typeName.text, inner));
        };
        visit(node);
        resolved.set(name, out);
        return out;
    };
    for (const name of raw.keys()) resolveAlias(name, new Set());
    return resolved;
}

/** The literal prefix of a message argument, or null when it is not a literal. */
function literalPrefix(node: ts.Expression): string | null {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
    if (ts.isTemplateExpression(node)) return node.head.text;
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return literalPrefix(node.left);
    if (ts.isParenthesizedExpression(node)) return literalPrefix(node.expression);
    return null;
}

/** Every `new Pki…Error(code, message, …)` whose message is not a literal starting with `pkinative: `. */
export function throwSiteFindings(file: string, text: string): Finding[] {
    const source = parse(file, text);
    const out: Finding[] = [];
    const visit = (node: ts.Node): void => {
        if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && /^Pki\w*Error$/.test(node.expression.text)) {
            const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
            const message = node.arguments?.[1];
            const prefix = message === undefined ? null : literalPrefix(message);
            if (prefix === null) {
                out.push(error(file, `new ${node.expression.text}(…) must pass its message as a string or template literal starting with "${MESSAGE_PREFIX}"`, line));
            } else if (!prefix.startsWith(MESSAGE_PREFIX)) {
                out.push(error(file, `new ${node.expression.text}(…) message must start with "${MESSAGE_PREFIX}" and name the remedy — found "${prefix.slice(0, 40)}"`, line));
            }
        }
        ts.forEachChild(node, visit);
    };
    visit(source);
    return out;
}

// ── The code argument of a throw site ────────────────────────────────

/**
 * The code argument of every `new Pki…Error(code, …)`, decided statically.
 *
 * Checking the message alone left the other half of a throw site open:
 * `new PkiEncodingError(codeFor(kind), 'pkinative: …')` passed, and the set
 * of codes reachable at run time could differ from the registry — which,
 * once the vocabulary is frozen, is the set downstream code branches on.
 *
 * A code argument is accepted when it is, after parentheses, `as const` and
 * `satisfies`:
 *
 *   - a string literal that is a member of the class's code union;
 *   - a conditional whose two branches are each accepted;
 *   - a `const` bound to an accepted expression in an enclosing scope;
 *   - a parameter whose declared type is a code union of that class (or a
 *     subset of one) — a pass-through helper such as `_cmsError(code, …)`.
 *     Then every call site of that helper is decided the same way, against
 *     the parameter's type, so a chain of helpers always ends at literals.
 *
 * Anything else — a call, a template, a concatenation, an element access, a
 * `let`, an untyped parameter, a helper used as a value — is a finding.
 * Helpers are followed through relative imports by name: `src/` has no
 * barrels, and a renamed import is followed under its local name.
 */

interface HelperSlot {
    readonly file: string;
    readonly name: string;
    readonly index: number;
    readonly allowed: ReadonlySet<string>;
    readonly union: string;
}

type FunctionLike = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration | ts.ConstructorDeclaration;

function isFunctionLike(node: ts.Node): node is FunctionLike {
    return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node);
}

function functionName(fn: FunctionLike): string | null {
    if (ts.isFunctionDeclaration(fn)) return fn.name?.text ?? null;
    if ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isVariableDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name)) return fn.parent.name.text;
    return null;
}

/** The codes a declared type admits, or null when it is not made of code literals. */
function typeCodes(node: ts.TypeNode, unions: ReadonlyMap<string, readonly string[]>): Set<string> | null {
    if (ts.isParenthesizedTypeNode(node)) return typeCodes(node.type, unions);
    if (ts.isLiteralTypeNode(node) && ts.isStringLiteral(node.literal)) return new Set([node.literal.text]);
    if (ts.isTypeReferenceNode(node) && ts.isIdentifier(node.typeName) && node.typeArguments === undefined) {
        const members = unions.get(node.typeName.text);
        return members === undefined || members.length === 0 ? null : new Set(members);
    }
    if (ts.isUnionTypeNode(node)) {
        const out = new Set<string>();
        for (const member of node.types) {
            const codes = typeCodes(member, unions);
            if (codes === null) return null;
            for (const c of codes) out.add(c);
        }
        return out;
    }
    return null;
}

type Binding =
    | { readonly kind: 'parameter'; readonly fn: FunctionLike; readonly index: number; readonly param: ts.ParameterDeclaration }
    | { readonly kind: 'variable'; readonly decl: ts.VariableDeclaration; readonly isConst: boolean }
    | { readonly kind: 'unresolved' };

/** Where an identifier is declared, walking outwards from its use. */
function resolveBinding(id: ts.Identifier): Binding {
    for (let scope: ts.Node | undefined = id.parent; scope !== undefined; scope = scope.parent) {
        if (isFunctionLike(scope)) {
            const index = scope.parameters.findIndex((p) => ts.isIdentifier(p.name) && p.name.text === id.text);
            const param = scope.parameters[index];
            if (param !== undefined) return { kind: 'parameter', fn: scope, index, param };
        }
        if (ts.isBlock(scope) || ts.isSourceFile(scope) || ts.isModuleBlock(scope) || ts.isCaseClause(scope) || ts.isDefaultClause(scope)) {
            for (const statement of scope.statements) {
                if (!ts.isVariableStatement(statement)) continue;
                for (const decl of statement.declarationList.declarations) {
                    if (ts.isIdentifier(decl.name) && decl.name.text === id.text) {
                        return { kind: 'variable', decl, isConst: (statement.declarationList.flags & ts.NodeFlags.Const) !== 0 };
                    }
                }
            }
        }
    }
    return { kind: 'unresolved' };
}

function unwrapCode(node: ts.Expression): ts.Expression {
    let current = node;
    for (;;) {
        if (ts.isParenthesizedExpression(current) || ts.isSatisfiesExpression(current)) current = current.expression;
        else if (ts.isAsExpression(current) && ts.isTypeReferenceNode(current.type) && ts.isIdentifier(current.type.typeName) && current.type.typeName.text === 'const') current = current.expression;
        else return current;
    }
}

/** POSIX path of the `.ts` file a relative import specifier names, or null for a bare one. */
function resolveImport(from: string, specifier: string): string | null {
    if (!specifier.startsWith('.')) return null;
    return posix.normalize(posix.join(posix.dirname(from), specifier)).replace(/\.js$/, '.ts');
}

/**
 * Findings for every code argument in `files` (path → text) that is not
 * decided statically. `unions` are the code unions of the error module;
 * `classCodes` maps each error class to the codes it may carry.
 */
export function codeArgumentFindings(
    files: ReadonlyMap<string, string>,
    unions: ReadonlyMap<string, readonly string[]>,
    classCodes: ReadonlyMap<string, ReadonlySet<string>>,
): Finding[] {
    const out: Finding[] = [];
    const sources = new Map<string, ts.SourceFile>();
    for (const [file, text] of files) sources.set(file, parse(file, text));
    const lineAt = (source: ts.SourceFile, node: ts.Node): number => source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
    const queue: HelperSlot[] = [];
    const seen = new Set<string>();

    /** The initializer of `export const <name>` in the module `source` imports `name` from, if any. */
    const importedConst = (source: ts.SourceFile, name: string): { source: ts.SourceFile; initializer: ts.Expression } | null => {
        for (const statement of source.statements) {
            if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || statement.importClause?.isTypeOnly === true) continue;
            const bindings = statement.importClause?.namedBindings;
            if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
            const spec = bindings.elements.find((e) => e.name.text === name && !e.isTypeOnly);
            const target = resolveImport(source.fileName, statement.moduleSpecifier.text);
            const targetSource = target === null ? undefined : sources.get(target);
            if (spec === undefined || targetSource === undefined) continue;
            const exported = (spec.propertyName ?? spec.name).text;
            for (const s of targetSource.statements) {
                if (!ts.isVariableStatement(s) || (s.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
                if (!s.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
                const decl = s.declarationList.declarations.find((d) => ts.isIdentifier(d.name) && d.name.text === exported);
                if (decl?.initializer !== undefined) return { source: targetSource, initializer: decl.initializer };
            }
        }
        return null;
    };

    /** Decide one code expression against `allowed`; `what` names the throw site or helper in a finding. */
    const decide = (source: ts.SourceFile, node: ts.Expression, allowed: ReadonlySet<string>, union: string, what: string, depth = 0): void => {
        const file = source.fileName;
        const expr = unwrapCode(node);
        const line = lineAt(source, expr);
        if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
            if (!allowed.has(expr.text)) out.push(error(file, `${what} passes '${expr.text}', which is not a code of ${union} — the class and the registry would disagree on who throws it`, line));
            return;
        }
        if (ts.isConditionalExpression(expr)) {
            decide(source, expr.whenTrue, allowed, union, what, depth);
            decide(source, expr.whenFalse, allowed, union, what, depth);
            return;
        }
        if (ts.isIdentifier(expr) && depth < 8) {
            const binding = resolveBinding(expr);
            if (binding.kind === 'variable' && binding.isConst && binding.decl.initializer !== undefined) {
                decide(source, binding.decl.initializer, allowed, union, what, depth + 1);
                return;
            }
            if (binding.kind === 'parameter') {
                const declared = binding.param.type === undefined ? null : typeCodes(binding.param.type, unions);
                const name = functionName(binding.fn);
                if (declared === null || [...declared].some((c) => !allowed.has(c))) {
                    out.push(error(file, `${what} passes parameter "${expr.text}", which is not typed with a code union of ${union} — type it, so that its callers are checked in turn`, line));
                    return;
                }
                if (name === null || binding.param.dotDotDotToken !== undefined) {
                    out.push(error(file, `${what} passes "${expr.text}" through an anonymous function — name the helper so its call sites can be checked`, line));
                    return;
                }
                const key = `${file}#${name}#${String(binding.index)}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    queue.push({ file, name, index: binding.index, allowed: declared, union: binding.param.type?.getText(source) ?? union });
                }
                return;
            }
            if (binding.kind === 'unresolved') {
                const imported = importedConst(source, expr.text);
                if (imported !== null) {
                    decide(imported.source, imported.initializer, allowed, union, what, depth + 1);
                    return;
                }
            }
        }
        out.push(error(file, `${what} computes its code (${ts.SyntaxKind[expr.kind]}) — pass a literal of ${union}, a const bound to one, or a parameter typed ${union}, so the codes reachable at run time are exactly the ones ${ERRORS_REGISTRY} lists`, line));
    };

    for (const source of sources.values()) {
        const visit = (node: ts.Node): void => {
            if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && /^Pki\w*Error$/.test(node.expression.text)) {
                const cls = node.expression.text;
                const allowed = classCodes.get(cls);
                const code = node.arguments?.[0];
                const what = `new ${cls}(…)`;
                if (allowed === undefined) out.push(error(source.fileName, `${what} names a class ${ERRORS_SOURCE} does not declare`, lineAt(source, node)));
                else if (code === undefined || ts.isSpreadElement(code)) out.push(error(source.fileName, `${what} passes no code argument the rule can read`, lineAt(source, node)));
                else decide(source, code, allowed, cls === 'PkiError' ? 'PkiBaseErrorCode' : `${cls}Code`, what);
            }
            ts.forEachChild(node, visit);
        };
        visit(source);
    }

    // Follow each pass-through helper to its call sites: in its own file,
    // and in every file that imports it from that file.
    for (let slot = queue.shift(); slot !== undefined; slot = queue.shift()) {
        const helper = slot;
        for (const source of sources.values()) {
            let local: string | null = source.fileName === helper.file ? helper.name : null;
            for (const statement of source.statements) {
                if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
                if (resolveImport(source.fileName, statement.moduleSpecifier.text) !== helper.file) continue;
                const bindings = statement.importClause?.namedBindings;
                if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
                for (const spec of bindings.elements) {
                    if ((spec.propertyName ?? spec.name).text === helper.name) local = spec.name.text;
                }
            }
            if (local === null) continue;
            const name = local;
            const what = `${helper.name}(…)`;
            const visit = (node: ts.Node): void => {
                if (ts.isIdentifier(node) && node.text === name) {
                    const parent = node.parent;
                    const isDeclaration = (ts.isFunctionDeclaration(parent) || ts.isVariableDeclaration(parent)) && parent.name === node;
                    const isBinding = ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent);
                    if (ts.isCallExpression(parent) && parent.expression === node) {
                        const spread = parent.arguments.findIndex((a) => ts.isSpreadElement(a));
                        const arg = parent.arguments[helper.index];
                        if ((spread >= 0 && spread <= helper.index) || arg === undefined) {
                            out.push(error(source.fileName, `${what} is called without a readable code argument at position ${String(helper.index + 1)}`, lineAt(source, parent)));
                        } else {
                            decide(source, arg, helper.allowed, helper.union, what);
                        }
                    } else if (!isDeclaration && !isBinding) {
                        out.push(error(source.fileName, `${what} passes a code through and is used as a value here — its call sites can no longer be checked; call it directly`, lineAt(source, node)));
                    }
                }
                ts.forEachChild(node, visit);
            };
            visit(source);
        }
    }
    return out;
}

interface ErrorEntry {
    readonly code?: unknown;
    readonly class?: unknown;
    readonly since?: unknown;
    readonly raisedWhen?: unknown;
    readonly remedy?: unknown;
    readonly standard?: unknown;
    readonly cwe?: unknown;
}

function nonEmpty(value: unknown): boolean {
    return typeof value === 'string' && value.trim().length > 0;
}

/** The error module read as a vocabulary: its code unions, and the class each code belongs to. */
interface ErrorVocabulary {
    readonly unions: ReadonlyMap<string, readonly string[]>;
    readonly codeClass: ReadonlyMap<string, string>;
    readonly classCodes: ReadonlyMap<string, ReadonlySet<string>>;
    readonly findings: readonly Finding[];
}

function errorVocabulary(text: string): ErrorVocabulary {
    const findings: Finding[] = [];
    const source = parse(ERRORS_SOURCE, text);
    const unions = stringLiteralUnions(source);
    const classes = new Set(source.statements.filter(ts.isClassDeclaration).map((c) => c.name?.text).filter((n): n is string => n !== undefined));
    const codeClass = new Map<string, string>();
    const classCodes = new Map<string, Set<string>>();
    for (const [alias, codes] of unions) {
        const m = /^Pki(\w+)ErrorCode$/.exec(alias);
        if (!m) continue;
        const cls = m[1] === 'Base' ? 'PkiError' : `Pki${m[1]}Error`;
        if (!classes.has(cls)) findings.push(error(ERRORS_SOURCE, `${alias} implies class ${cls}, which the module does not declare`, lineContaining(text, alias)));
        const own = classCodes.get(cls) ?? new Set<string>();
        classCodes.set(cls, own);
        for (const code of codes) {
            if (codeClass.has(code)) findings.push(error(ERRORS_SOURCE, `${code} belongs to two code unions`, lineContaining(text, `'${code}'`)));
            codeClass.set(code, cls);
            own.add(code);
        }
    }
    return { unions, codeClass, classCodes, findings };
}

const errorParity: Rule = {
    id: 'error-parity',
    summary: 'docs/data/errors.json lists exactly the codes of src/types/pki-errors.ts with their class, since, cause, remedy, standard and CWE; every throw site message starts with "pkinative: "; and every throw site code is a literal of its class\'s union, or passes through helpers whose every caller passes one.',
    check(ctx) {
        const text = ctx.read(ERRORS_SOURCE);
        if (text === null) return [error(ERRORS_SOURCE, 'missing — the error hierarchy and its code unions')];
        const { unions, codeClass, classCodes, findings } = errorVocabulary(text);
        const out: Finding[] = [...findings];
        const all = new Set(unions.get('PkiErrorCode') ?? []);
        for (const code of codeClass.keys()) {
            if (!all.has(code)) out.push(error(ERRORS_SOURCE, `${code} is missing from the PkiErrorCode union`, lineContaining(text, `'${code}'`)));
        }

        const registry = readJson<{ errors?: ErrorEntry[] }>(ctx, ERRORS_REGISTRY);
        if ('finding' in registry) return [...out, registry.finding];
        const regText = ctx.read(ERRORS_REGISTRY) ?? '';
        const listed = new Set<string>();
        for (const entry of registry.value.errors ?? []) {
            const code = typeof entry.code === 'string' ? entry.code : '';
            const line = lineContaining(regText, `"${code}"`);
            if (listed.has(code)) out.push(error(ERRORS_REGISTRY, `${code} is listed twice`, line));
            listed.add(code);
            const cls = codeClass.get(code);
            if (cls === undefined) {
                out.push(error(ERRORS_REGISTRY, `"${code}" is not a code of ${ERRORS_SOURCE} — remove it, or add it to the right union`, line));
                continue;
            }
            if (entry.class !== cls) out.push(error(ERRORS_REGISTRY, `${code} is thrown by ${cls}, not ${String(entry.class)}`, line));
            if (typeof entry.since !== 'string' || !SEMVER.test(entry.since)) out.push(error(ERRORS_REGISTRY, `${code} needs "since": the version that introduced it`, line));
            for (const field of ['raisedWhen', 'remedy', 'standard'] as const) {
                if (!nonEmpty(entry[field])) out.push(error(ERRORS_REGISTRY, `${code} needs a non-empty "${field}"`, line));
            }
            if (!(entry.cwe === null || (typeof entry.cwe === 'string' && /^CWE-\d+$/.test(entry.cwe)))) {
                out.push(error(ERRORS_REGISTRY, `${code} "cwe" must be "CWE-<n>" or null`, line));
            }
        }
        for (const code of codeClass.keys()) {
            if (!listed.has(code)) out.push(error(ERRORS_REGISTRY, `${code} has no entry — add it with class, since, raisedWhen, remedy, standard and cwe`));
        }

        const sources = new Map<string, string>();
        for (const file of ctx.list('src').filter((f) => f.endsWith('.ts'))) {
            const source = ctx.read(file) ?? '';
            sources.set(file, source);
            out.push(...throwSiteFindings(file, source));
        }
        out.push(...codeArgumentFindings(sources, unions, classCodes));
        return out;
    },
};

// ── error-codes-frozen ───────────────────────────────────────────────

export const FROZEN_REGISTRY = 'docs/data/errors.frozen.json';
export const FROZEN_GENERATOR = 'npx tsx scripts/build-errors-frozen.ts';

/** `a < b` → negative, `a > b` → positive, for `x.y.z` versions. */
export function compareSemver(a: string, b: string): number {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) {
        const d = (pa[i] ?? 0) - (pb[i] ?? 0);
        if (d !== 0) return d;
    }
    return 0;
}

interface FrozenSnapshot {
    readonly frozenAt?: unknown;
    readonly codes?: Array<{ readonly code?: unknown; readonly class?: unknown }>;
}

/**
 * The error-code vocabulary under semantic versioning.
 *
 * `error-parity` keeps the registry and the unions equal to each other; it
 * cannot see a code that leaves both in the same commit, which is exactly
 * what a rename looks like. The snapshot is the third copy that does not
 * move with them: every code frozen at `frozenAt` must still exist, in the
 * registry and in its union, under the same class — the class is part of
 * the contract, because callers branch with `instanceof` before they read
 * `code`. A code missing from the snapshot is an addition, and must say so
 * with a `since` newer than `frozenAt`.
 *
 * Until `frozenAt` is released the snapshot may still be regenerated, and
 * the finding says how; from then on there is no command that makes a
 * removal pass, only a major version.
 */
const errorCodesFrozen: Rule = {
    id: 'error-codes-frozen',
    summary: 'Every code of docs/data/errors.frozen.json still exists in docs/data/errors.json and in its code union with the same class, and every code outside the snapshot carries a "since" newer than frozenAt — a removal, rename or class move of a frozen code is semver-major.',
    check(ctx) {
        const out: Finding[] = [];
        const snapshot = readJson<FrozenSnapshot>(ctx, FROZEN_REGISTRY);
        if ('finding' in snapshot) return [snapshot.finding];
        const snapText = ctx.read(FROZEN_REGISTRY) ?? '';
        const frozenAt = snapshot.value.frozenAt;
        if (typeof frozenAt !== 'string' || !SEMVER.test(frozenAt)) return [error(FROZEN_REGISTRY, '"frozenAt" must be the x.y.z version the vocabulary froze at')];

        const sourceText = ctx.read(ERRORS_SOURCE);
        if (sourceText === null) return [error(ERRORS_SOURCE, 'missing — the error hierarchy and its code unions')];
        const { codeClass } = errorVocabulary(sourceText);
        const registry = readJson<{ errors?: ErrorEntry[] }>(ctx, ERRORS_REGISTRY);
        if ('finding' in registry) return [registry.finding];
        const regText = ctx.read(ERRORS_REGISTRY) ?? '';
        const listed = new Map<string, ErrorEntry>();
        for (const entry of registry.value.errors ?? []) if (typeof entry.code === 'string') listed.set(entry.code, entry);

        const pkg = readJson<{ version?: unknown }>(ctx, 'package.json');
        const version = 'finding' in pkg || typeof pkg.value.version !== 'string' ? '0.0.0' : pkg.value.version;
        const released = compareSemver(version, frozenAt) >= 0;
        const howTo = released
            ? `${frozenAt} is released: that is semver-major — restore the code (a rename keeps the old code alongside the new one), or make the change part of the next major and move "frozenAt" with it`
            : `that is semver-major once ${frozenAt} is released — until it is tagged, a deliberate change is recorded by regenerating the snapshot with \`${FROZEN_GENERATOR}\``;

        const frozen = new Set<string>();
        for (const row of snapshot.value.codes ?? []) {
            const code = typeof row.code === 'string' ? row.code : '';
            const line = lineContaining(snapText, `"${code}"`);
            if (code === '' || typeof row.class !== 'string') {
                out.push(error(FROZEN_REGISTRY, 'every row needs a "code" and a "class"', line));
                continue;
            }
            if (frozen.has(code)) out.push(error(FROZEN_REGISTRY, `${code} is frozen twice`, line));
            frozen.add(code);
            const entry = listed.get(code);
            const union = codeClass.get(code);
            if (entry === undefined) out.push(error(ERRORS_REGISTRY, `${code} was frozen at ${frozenAt} and is gone from the registry — removing or renaming a frozen code: ${howTo}`));
            else if (entry.class !== row.class) out.push(error(ERRORS_REGISTRY, `${code} was frozen at ${frozenAt} as a ${row.class} and is now a ${String(entry.class)} — moving a code to another class breaks every instanceof check: ${howTo}`, lineContaining(regText, `"${code}"`)));
            else if (typeof entry.since === 'string' && SEMVER.test(entry.since) && compareSemver(entry.since, frozenAt) > 0) out.push(error(ERRORS_REGISTRY, `${code} is frozen at ${frozenAt} but claims "since": "${entry.since}" — a frozen code cannot be younger than the freeze`, lineContaining(regText, `"${code}"`)));
            if (union === undefined) out.push(error(ERRORS_SOURCE, `${code} was frozen at ${frozenAt} and is gone from the code unions — removing or renaming a frozen code: ${howTo}`));
            else if (union !== row.class) out.push(error(ERRORS_SOURCE, `${code} was frozen at ${frozenAt} as a ${row.class} and now belongs to the union of ${union}: ${howTo}`, lineContaining(sourceText, `'${code}'`)));
        }

        for (const [code, entry] of listed) {
            if (frozen.has(code)) continue;
            const since = typeof entry.since === 'string' && SEMVER.test(entry.since) ? entry.since : null;
            if (since !== null && compareSemver(since, frozenAt) > 0) continue;
            out.push(error(ERRORS_REGISTRY, released
                ? `${code} is not in the ${frozenAt} snapshot, so it is an addition — give it the "since" of the release that adds it, newer than ${frozenAt}`
                : `${code} (since ${since ?? '?'}) is not in the ${frozenAt} snapshot — a code introduced up to ${frozenAt} is part of the freeze: regenerate it with \`${FROZEN_GENERATOR}\``, lineContaining(regText, `"${code}"`)));
        }
        return out;
    },
};

interface DiagnosticEntry {
    readonly code?: unknown;
    readonly severity?: unknown;
    readonly since?: unknown;
    readonly raisedWhen?: unknown;
    readonly remedy?: unknown;
    readonly standard?: unknown;
}

const diagnosticsParity: Rule = {
    id: 'diagnostics-parity',
    summary: 'docs/data/diagnostics.json lists exactly the PkiDiagnosticCode union, each with severity, since, cause, remedy and standard, and each code has a payload factory.',
    check(ctx) {
        const out: Finding[] = [];
        const typesText = ctx.read(TYPES_SOURCE);
        if (typesText === null) return [error(TYPES_SOURCE, 'missing — the PkiDiagnosticCode union')];
        const codes = stringLiteralUnions(parse(TYPES_SOURCE, typesText)).get('PkiDiagnosticCode') ?? [];
        if (codes.length === 0) out.push(error(TYPES_SOURCE, 'declares no PkiDiagnosticCode union'));
        const factories = ctx.read(DIAGNOSTICS_SOURCE) ?? '';
        for (const code of codes) {
            if (!factories.includes(`'${code}'`)) out.push(error(DIAGNOSTICS_SOURCE, `${code} has no payload factory — every diagnostic code is built in one place`));
        }
        const registry = readJson<{ diagnostics?: DiagnosticEntry[] }>(ctx, DIAGNOSTICS_REGISTRY);
        if ('finding' in registry) return [...out, registry.finding];
        const regText = ctx.read(DIAGNOSTICS_REGISTRY) ?? '';
        const known = new Set(codes);
        const listed = new Set<string>();
        for (const entry of registry.value.diagnostics ?? []) {
            const code = typeof entry.code === 'string' ? entry.code : '';
            const line = lineContaining(regText, `"${code}"`);
            if (listed.has(code)) out.push(error(DIAGNOSTICS_REGISTRY, `${code} is listed twice`, line));
            listed.add(code);
            if (!known.has(code)) {
                out.push(error(DIAGNOSTICS_REGISTRY, `"${code}" is not in the PkiDiagnosticCode union`, line));
                continue;
            }
            if (entry.severity !== 'warning' && entry.severity !== 'info') out.push(error(DIAGNOSTICS_REGISTRY, `${code} "severity" must be "warning" or "info"`, line));
            if (typeof entry.since !== 'string' || !SEMVER.test(entry.since)) out.push(error(DIAGNOSTICS_REGISTRY, `${code} needs "since"`, line));
            for (const field of ['raisedWhen', 'remedy', 'standard'] as const) {
                if (!nonEmpty(entry[field])) out.push(error(DIAGNOSTICS_REGISTRY, `${code} needs a non-empty "${field}"`, line));
            }
        }
        for (const code of codes) {
            if (!listed.has(code)) out.push(error(DIAGNOSTICS_REGISTRY, `${code} has no entry — add it with severity, since, raisedWhen, remedy and standard`));
        }
        return out;
    },
};

// ── reason-parity ────────────────────────────────────────────────────

/**
 * The third vocabulary, and the rules that keep it a third one.
 *
 * Bidirectional sync with the registry and a factory per code are the same
 * contract the other two registries carry. Four more are specific to
 * reasons, and each closes a way this vocabulary could quietly collapse back
 * into one of the others:
 *
 *   - **A reason is never thrown.** A `PKI_REASON_*` literal inside a `throw`
 *     means a composition that was supposed to report has started raising,
 *     and every caller's `try` block silently changes meaning.
 *   - **A reason message never starts with `pkinative: `.** That prefix marks
 *     what is thrown. This is the *inverse* of the rule `error-parity`
 *     enforces, and keeping the prefix exclusive is what lets someone reading
 *     a log tell an exception from a verdict.
 *   - **The three registries are disjoint.** One condition reported under two
 *     codes is two answers to the same question.
 *   - **The reason registry never duplicates the error registry.** It wraps
 *     it: `PKI_REASON_INPUT_MALFORMED` carries the `PkiErrorCode` that would
 *     have been thrown, which is what keeps 47 encoding codes out of a second
 *     vocabulary that would then have to be frozen too.
 */
const reasonParity: Rule = {
    id: 'reason-parity',
    summary: 'docs/data/reasons.json lists exactly the PkiReasonCode union, each with since, returnedWhen, remedy and standard and a factory; no reason is ever thrown, no reason message carries the thrown-error prefix, and the three vocabularies are disjoint.',
    check(ctx) {
        const out: Finding[] = [];
        const typesText = ctx.read(REASONS_SOURCE);
        if (typesText === null) return [error(REASONS_SOURCE, 'missing — the PkiReasonCode union')];
        const codes = stringLiteralUnions(parse(REASONS_SOURCE, typesText)).get('PkiReasonCode') ?? [];
        if (codes.length === 0) out.push(error(REASONS_SOURCE, 'declares no PkiReasonCode union'));

        const factories = ctx.read(REASON_FACTORIES) ?? '';
        for (const code of codes) {
            if (!factories.includes(`'${code}'`)) out.push(error(REASON_FACTORIES, `${code} has no factory — every reason message is written in one place`));
            if (!/^PKI_REASON_[A-Z0-9_]+$/.test(code)) out.push(error(REASONS_SOURCE, `${code} does not follow PKI_REASON_<SUBJECT>_<CONDITION>`));
        }

        const registry = readJson<{ reasons?: Array<{ code?: unknown; since?: unknown; returnedWhen?: unknown; remedy?: unknown; standard?: unknown }> }>(ctx, REASONS_REGISTRY);
        if ('finding' in registry) return [...out, registry.finding];
        const regText = ctx.read(REASONS_REGISTRY) ?? '';
        const known = new Set(codes);
        const listed = new Set<string>();
        for (const entry of registry.value.reasons ?? []) {
            const code = typeof entry.code === 'string' ? entry.code : '';
            const line = lineContaining(regText, `"${code}"`);
            if (listed.has(code)) out.push(error(REASONS_REGISTRY, `${code} is listed twice`, line));
            listed.add(code);
            if (!known.has(code)) { out.push(error(REASONS_REGISTRY, `"${code}" is not in the PkiReasonCode union`, line)); continue; }
            if (typeof entry.since !== 'string' || !SEMVER.test(entry.since)) out.push(error(REASONS_REGISTRY, `${code} needs "since"`, line));
            for (const field of ['returnedWhen', 'remedy', 'standard'] as const) {
                if (!nonEmpty(entry[field])) out.push(error(REASONS_REGISTRY, `${code} needs a non-empty "${field}"`, line));
            }
        }
        for (const code of codes) {
            if (!listed.has(code)) out.push(error(REASONS_REGISTRY, `${code} has no entry — add it with since, returnedWhen, remedy and standard`));
        }

        // A reason that can be thrown is not a reason. Decided from the
        // syntax tree, not from the text: a regex over the source reads doc
        // comments too, and the sentence "the code that would have been
        // thrown" is exactly what this module has to be able to write about
        // itself. The first draft of this rule failed on its own explanation.
        for (const path of ctx.list('src').filter((p) => p.endsWith('.ts'))) {
            const text = ctx.read(path) ?? '';
            if (!text.includes('PKI_REASON_')) continue;
            const walk = (node: ts.Node, inThrow: boolean): void => {
                const throwing = inThrow || ts.isThrowStatement(node);
                if (throwing && ts.isStringLiteral(node) && /^PKI_REASON_[A-Z0-9_]+$/.test(node.text)) {
                    out.push(error(path, `${node.text} appears inside a throw — reasons are returned in a report, never raised; a composition that starts throwing changes what every caller's try block means`, lineOf(text, node.getStart())));
                }
                node.forEachChild((child) => { walk(child, throwing); });
            };
            walk(parse(path, text), false);
        }

        // The prefix belongs to thrown errors, exclusively — and again the
        // test is on what a message *is*, not on what the file mentions:
        // `detail.replace(/^pkinative: /, '')` strips the prefix rather than
        // adding one, and a text scan cannot tell those apart.
        const factoryFile = parse(REASON_FACTORIES, factories);
        const startsWithPrefix = (node: ts.Node): boolean => {
            if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text.startsWith(MESSAGE_PREFIX);
            if (ts.isTemplateExpression(node)) return node.head.text.startsWith(MESSAGE_PREFIX);
            return false;
        };
        const walkFactories = (node: ts.Node): void => {
            if (startsWithPrefix(node)) {
                out.push(error(REASON_FACTORIES, `a reason message starts with "${MESSAGE_PREFIX}" — that prefix marks what is thrown, and a log reader tells a verdict from an exception by it`, lineOf(factories, node.getStart())));
            }
            node.forEachChild(walkFactories);
        };
        walkFactories(factoryFile);

        // Three vocabularies, no overlap.
        const errorCodes = new Set(stringLiteralUnions(parse(ERRORS_SOURCE, ctx.read(ERRORS_SOURCE) ?? '')).get('PkiErrorCode') ?? []);
        const diagnosticCodes = new Set(stringLiteralUnions(parse(TYPES_SOURCE, ctx.read(TYPES_SOURCE) ?? '')).get('PkiDiagnosticCode') ?? []);
        for (const code of codes) {
            if (errorCodes.has(code)) out.push(error(REASONS_SOURCE, `${code} is also a PkiErrorCode — one condition reported under two codes is two answers to the same question`));
            if (diagnosticCodes.has(code)) out.push(error(REASONS_SOURCE, `${code} is also a PkiDiagnosticCode`));
        }
        return out;
    },
};

// ── limits-parity ────────────────────────────────────────────────────

interface LimitFacts {
    readonly cwe: string | null;
    readonly defaultValue: number | null;
    readonly display: string | null;
}

/** Evaluate the numeric initialisers DEFAULT_PKI_LIMITS uses: literals, `*`, `+` and Infinity. */
function evaluate(node: ts.Expression): number {
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (ts.isIdentifier(node) && node.text === 'Infinity') return Infinity;
    if (ts.isParenthesizedExpression(node)) return evaluate(node.expression);
    if (ts.isBinaryExpression(node)) {
        const [l, r] = [evaluate(node.left), evaluate(node.right)];
        if (node.operatorToken.kind === ts.SyntaxKind.AsteriskToken) return l * r;
        if (node.operatorToken.kind === ts.SyntaxKind.PlusToken) return l + r;
    }
    return NaN;
}

function unwrapInitializer(node: ts.Expression): ts.Expression {
    let current = node;
    for (;;) {
        if (ts.isCallExpression(current) && current.arguments.length === 1 && current.arguments[0] !== undefined) current = current.arguments[0];
        else if (ts.isAsExpression(current) || ts.isParenthesizedExpression(current) || ts.isSatisfiesExpression(current)) current = current.expression;
        else return current;
    }
}

/** `64 MiB` → 67108864, `200 000` → 200000, `Infinity` → Infinity; NaN when unreadable. */
export function parseDisplay(display: string): number {
    if (display.trim() === 'Infinity') return Infinity;
    const m = /^(\d[\d ]*)(?:\s+(KiB|MiB|GiB))?$/.exec(display.trim());
    if (!m) return NaN;
    const unit = m[2] === 'KiB' ? 1024 : m[2] === 'MiB' ? 1024 ** 2 : m[2] === 'GiB' ? 1024 ** 3 : 1;
    return Number((m[1] ?? '').replace(/ /g, '')) * unit;
}

function tableRows(text: string, row: RegExp): Map<string, { display: string; cwe: string; line: number }> {
    const out = new Map<string, { display: string; cwe: string; line: number }>();
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    lines.forEach((l, i) => {
        const m = row.exec(l);
        if (m && m[1] !== undefined && m[2] !== undefined && m[3] !== undefined) out.set(m[1], { display: m[2].trim(), cwe: `CWE-${m[3]}`, line: i + 1 });
    });
    return out;
}

const limitsParity: Rule = {
    id: 'limits-parity',
    summary: 'The PkiLimits interface, DEFAULT_PKI_LIMITS and its header table, docs/data/limits.json and the SECURITY.md Resource Limits table agree on every limit, default and CWE.',
    check(ctx) {
        const out: Finding[] = [];
        const typesText = ctx.read(TYPES_SOURCE);
        const limitsText = ctx.read(LIMITS_SOURCE);
        const security = ctx.read(SECURITY);
        if (typesText === null || limitsText === null) return [error(typesText === null ? TYPES_SOURCE : LIMITS_SOURCE, 'missing')];
        if (security === null) return [error(SECURITY, 'missing')];

        const interfaceFacts = new Map<string, LimitFacts>();
        const typesSource = parse(TYPES_SOURCE, typesText);
        const limitsInterface = typesSource.statements.find((s): s is ts.InterfaceDeclaration => ts.isInterfaceDeclaration(s) && s.name.text === 'PkiLimits');
        if (limitsInterface === undefined) return [error(TYPES_SOURCE, 'declares no PkiLimits interface')];
        for (const member of limitsInterface.members) {
            if (!ts.isPropertySignature(member) || !ts.isIdentifier(member.name)) continue;
            const doc = typesText.slice(member.getFullStart(), member.getStart(typesSource));
            const cwe = /(CWE-\d+)\.\s*\*\/\s*$/.exec(doc)?.[1] ?? null;
            if (cwe === null) out.push(error(TYPES_SOURCE, `PkiLimits.${member.name.text} has no TSDoc line ending with its CWE (e.g. "… CWE-400.")`, typesSource.getLineAndCharacterOfPosition(member.getStart(typesSource)).line + 1));
            interfaceFacts.set(member.name.text, { cwe, defaultValue: null, display: null });
        }

        const defaults = new Map<string, number>();
        const limitsSource = parse(LIMITS_SOURCE, limitsText);
        for (const statement of limitsSource.statements) {
            if (!ts.isVariableStatement(statement)) continue;
            for (const decl of statement.declarationList.declarations) {
                if (!ts.isIdentifier(decl.name) || decl.name.text !== 'DEFAULT_PKI_LIMITS' || decl.initializer === undefined) continue;
                const literal = unwrapInitializer(decl.initializer);
                if (!ts.isObjectLiteralExpression(literal)) continue;
                for (const prop of literal.properties) {
                    if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) defaults.set(prop.name.text, evaluate(prop.initializer));
                }
            }
        }
        if (defaults.size === 0) out.push(error(LIMITS_SOURCE, 'DEFAULT_PKI_LIMITS is not an object literal the rule can read'));

        const header = tableRows(limitsText, /^\s*\*\s*\|\s*(max\w+)\s*\|\s*([^|]+?)\s*\|\s*CWE-(\d+)\s*\|/);
        const securityRows = tableRows(security, /^\|\s*`(max\w+)`\s*\|\s*([^|]+?)\s*\|\s*CWE-(\d+)\s*\|/);
        const registry = readJson<{ limits?: Array<{ limit?: unknown; default?: unknown; display?: unknown; cwe?: unknown; guards?: unknown }> }>(ctx, LIMITS_REGISTRY);
        if ('finding' in registry) return [...out, registry.finding];
        const regText = ctx.read(LIMITS_REGISTRY) ?? '';
        const regRows = new Map<string, { default: unknown; display: unknown; cwe: unknown; guards: unknown }>();
        for (const row of registry.value.limits ?? []) {
            if (typeof row.limit === 'string') regRows.set(row.limit, { default: row.default, display: row.display, cwe: row.cwe, guards: row.guards });
        }

        const names = new Set([...interfaceFacts.keys(), ...defaults.keys(), ...header.keys(), ...securityRows.keys(), ...regRows.keys()]);
        for (const name of [...names].sort()) {
            const iface = interfaceFacts.get(name);
            const value = defaults.get(name);
            const head = header.get(name);
            const sec = securityRows.get(name);
            const reg = regRows.get(name);
            if (iface === undefined) out.push(error(TYPES_SOURCE, `${name} is documented elsewhere but is not a PkiLimits member`));
            if (value === undefined) out.push(error(LIMITS_SOURCE, `${name} has no default in DEFAULT_PKI_LIMITS`));
            if (head === undefined) out.push(error(LIMITS_SOURCE, `${name} is missing from the module header table`));
            if (sec === undefined) out.push(error(SECURITY, `${name} is missing from the Resource Limits table`));
            if (reg === undefined) {
                out.push(error(LIMITS_REGISTRY, `${name} has no entry — add limit, default, display, cwe and guards`));
                continue;
            }
            const regLine = lineContaining(regText, `"${name}"`);
            if (!nonEmpty(reg.guards)) out.push(error(LIMITS_REGISTRY, `${name} needs a non-empty "guards"`, regLine));
            if (value !== undefined && reg.default !== value) out.push(error(LIMITS_REGISTRY, `${name} default ${String(reg.default)} differs from DEFAULT_PKI_LIMITS (${value})`, regLine));
            const display = typeof reg.display === 'string' ? reg.display : '';
            if (typeof reg.default === 'number' && parseDisplay(display) !== reg.default) out.push(error(LIMITS_REGISTRY, `${name} display "${display}" does not read as ${reg.default}`, regLine));
            if (head !== undefined && head.display !== display) out.push(error(LIMITS_SOURCE, `${name} header shows ${head.display}, the registry ${display}`, head.line));
            if (sec !== undefined && sec.display !== display) out.push(error(SECURITY, `${name} is documented as ${sec.display}, the registry says ${display}`, sec.line));
            const cwe = typeof reg.cwe === 'string' ? reg.cwe : '';
            if (iface?.cwe && iface.cwe !== cwe) out.push(error(TYPES_SOURCE, `PkiLimits.${name} cites ${iface.cwe}, the registry ${cwe}`));
            if (head !== undefined && head.cwe !== cwe) out.push(error(LIMITS_SOURCE, `${name} header cites ${head.cwe}, the registry ${cwe}`, head.line));
            if (sec !== undefined && sec.cwe !== cwe) out.push(error(SECURITY, `${name} cites ${sec.cwe}, the registry ${cwe}`, sec.line));
        }
        return out;
    },
};

/**
 * The Web Crypto key-operation policy, in SECURITY.md and in code.
 *
 * This is the project's central security promise — "pkinative creates,
 * exports and wraps no key material" — and before 0.3 it was a sentence
 * listing eleven operations as forbidden. That sentence became false the
 * moment verification landed. Prose that states a guarantee must not be
 * able to drift from the check that gives it, so the table is held to
 * `KEY_OPERATION_POLICY` in both directions.
 */
const keyOperationParity: Rule = {
    id: 'key-operation-parity',
    summary: 'The Web Crypto key-operation table of SECURITY.md lists exactly the operations of KEY_OPERATION_POLICY, with the same modules allowed for each — the prose that states pkinative touches no key material cannot drift from the check that enforces it.',
    check(ctx) {
        const security = ctx.read(SECURITY);
        if (security === null) return [error(SECURITY, 'missing — it carries the cryptographic scope promise')];
        const out: Finding[] = [];

        // `| \`op\` | a, b | since |`, the rows of the §Cryptographic
        // Implementation Scope table. "nowhere" is the empty list.
        const documented = new Map<string, string>();
        for (const m of security.matchAll(/^\|\s*`(\w+)`\s*\|\s*([^|]+?)\s*\|[^|]*\|$/gm)) {
            const name = m[1] ?? '';
            if (Object.hasOwn(KEY_OPERATION_POLICY, name)) documented.set(name, m[2] ?? '');
        }

        for (const [operation, allowed] of Object.entries(KEY_OPERATION_POLICY)) {
            const row = documented.get(operation);
            if (row === undefined) {
                out.push(error(SECURITY, `the key-operation table omits \`${operation}\`, which KEY_OPERATION_POLICY ${allowed.length === 0 ? 'refuses everywhere' : `allows in ${allowed.join(', ')}`}`));
                continue;
            }
            const want = allowed.length === 0 ? 'nowhere' : allowed.map((p) => `\`${p}\``).join(', ');
            if (row !== want) {
                out.push(error(SECURITY, `the key-operation table says \`${operation}\` is allowed in "${row}"; KEY_OPERATION_POLICY says ${want}`, lineContaining(security, `\`${operation}\``)));
            }
        }
        for (const operation of documented.keys()) {
            if (!Object.hasOwn(KEY_OPERATION_POLICY, operation)) {
                out.push(error(SECURITY, `the key-operation table names \`${operation}\`, which KEY_OPERATION_POLICY does not`));
            }
        }

        // The single-sink claim, which is the other half of the promise.
        for (const module of WEBCRYPTO_HOST_MODULES) {
            if (!security.includes(module)) out.push(error(SECURITY, `does not name ${module}, one of the two modules allowed to reach globalThis.crypto`));
        }
        return out;
    },
};

// ── pkcs12-policy-parity ─────────────────────────────────────────────

export const KEY_OIDS_SOURCE = 'src/core/key-oids.ts';
const PBE_HEADING = /^#### Password-based encryption\s*$/m;
const APPENDIX_B_MAC = 'RFC 7292 Appendix B MAC';

/** The `[key, value]` pairs of `export const <name> = new Map([...])`, read from the syntax tree. */
function mapEntries(source: ts.SourceFile, name: string): Array<[string, string]> | null {
    for (const statement of source.statements) {
        if (!ts.isVariableStatement(statement)) continue;
        for (const decl of statement.declarationList.declarations) {
            if (!ts.isIdentifier(decl.name) || decl.name.text !== name || decl.initializer === undefined) continue;
            const init = decl.initializer;
            const list = ts.isNewExpression(init) ? init.arguments?.[0] : undefined;
            if (list === undefined || !ts.isArrayLiteralExpression(list)) return null;
            const out: Array<[string, string]> = [];
            for (const pair of list.elements) {
                if (!ts.isArrayLiteralExpression(pair)) return null;
                const [k, v] = pair.elements;
                if (k === undefined || v === undefined || !ts.isStringLiteral(k)) return null;
                if (ts.isStringLiteral(v) || ts.isNumericLiteral(v)) out.push([k.text, v.text]);
                else return null;
            }
            return out;
        }
    }
    return null;
}

/** The value of `export const <name> = '<literal>'`. */
function stringConst(source: ts.SourceFile, name: string): string | null {
    for (const statement of source.statements) {
        if (!ts.isVariableStatement(statement)) continue;
        for (const decl of statement.declarationList.declarations) {
            if (ts.isIdentifier(decl.name) && decl.name.text === name && decl.initializer !== undefined && ts.isStringLiteral(decl.initializer)) return decl.initializer.text;
        }
    }
    return null;
}

/**
 * The password-based encryption policy, in SECURITY.md and in code.
 *
 * What pkinative opens and what it refuses by name is a security promise of
 * the same kind as the key-operation table: a caller holding a legacy
 * PKCS#12 file reads it to learn whether pkinative will ever open it. The
 * table is held to `HMAC_OIDS`, `AES_CBC_OIDS` and `REFUSED_PBE_SCHEMES` of
 * `src/core/key-oids.ts` in both directions, so a scheme opened in code is
 * documented, and a scheme documented as refused is refused.
 */
const pkcs12PolicyParity: Rule = {
    id: 'pkcs12-policy-parity',
    summary: 'The Password-based encryption table of SECURITY.md lists, by OID and both ways, what src/core/key-oids.ts opens (PBES2, PBKDF2 and its HMAC PRFs, the AES-CBC key sizes, PBMAC1) and every scheme REFUSED_PBE_SCHEMES refuses by name, plus the refused RFC 7292 Appendix B MAC.',
    check(ctx) {
        const security = ctx.read(SECURITY);
        const oidsText = ctx.read(KEY_OIDS_SOURCE);
        if (security === null) return [error(SECURITY, 'missing — it carries the password-based encryption policy')];
        if (oidsText === null) return [error(KEY_OIDS_SOURCE, 'missing — the PBES2, PBMAC1 and refused-scheme tables')];
        const out: Finding[] = [];
        const source = parse(KEY_OIDS_SOURCE, oidsText);

        // What the code opens and refuses: OID → the word a row must name, and its verdict.
        const expected = new Map<string, { readonly needle: string; readonly verdict: 'opens' | 'refuses' }>();
        for (const [constant, needle] of [['OID_PBES2', 'PBES2'], ['OID_PBKDF2', 'PBKDF2'], ['OID_PBMAC1', 'PBMAC1']] as const) {
            const oid = stringConst(source, constant);
            if (oid === null) out.push(error(KEY_OIDS_SOURCE, `${constant} is not a string constant the rule can read`));
            else expected.set(oid, { needle, verdict: 'opens' });
        }
        const tables = [
            ['HMAC_OIDS', (v: string): string => `HMAC-${v}`, 'opens'],
            ['AES_CBC_OIDS', (v: string): string => `AES-${v}-CBC`, 'opens'],
            ['REFUSED_PBE_SCHEMES', (v: string): string => `\`${v}\``, 'refuses'],
        ] as const;
        for (const [constant, needleOf, verdict] of tables) {
            const entries = mapEntries(source, constant);
            if (entries === null || entries.length === 0) {
                out.push(error(KEY_OIDS_SOURCE, `${constant} is not a Map of literal pairs the rule can read`));
                continue;
            }
            for (const [oid, value] of entries) expected.set(oid, { needle: needleOf(value), verdict });
        }

        const heading = PBE_HEADING.exec(security);
        if (heading === null) return [...out, error(SECURITY, 'has no "#### Password-based encryption" subsection under Cryptographic Implementation Scope — it states what pkinative opens and refuses')];
        const start = heading.index + heading[0].length;
        const next = /^#{1,4} /m.exec(security.slice(start));
        const section = security.slice(start, next === null ? undefined : start + next.index);
        const sectionLine = lineOf(security, heading.index);

        const rows = new Map<string, { readonly name: string; readonly verdict: string }>();
        let appendixB: string | null = null;
        for (const m of section.matchAll(/^\|\s*(.+?)\s*\|\s*(?:`([\d.]+)`|—)\s*\|\s*(\w+)\s*\|$/gm)) {
            const [, name = '', oid, verdict = ''] = m;
            if (oid === undefined) {
                if (name.includes(APPENDIX_B_MAC)) appendixB = verdict;
                else out.push(error(SECURITY, `the password-based encryption table row "${name}" has no OID and is not the ${APPENDIX_B_MAC}`, lineContaining(security, name)));
                continue;
            }
            if (rows.has(oid)) out.push(error(SECURITY, `the password-based encryption table lists ${oid} twice`, lineContaining(security, oid)));
            rows.set(oid, { name, verdict });
        }

        for (const [oid, want] of expected) {
            const row = rows.get(oid);
            if (row === undefined) {
                out.push(error(SECURITY, `the password-based encryption table omits ${want.needle} (${oid}), which ${KEY_OIDS_SOURCE} ${want.verdict === 'opens' ? 'opens' : 'refuses by name'}`, sectionLine));
                continue;
            }
            const line = lineContaining(security, `\`${oid}\``);
            if (row.verdict !== want.verdict) out.push(error(SECURITY, `the password-based encryption table says pkinative ${row.verdict} ${oid}; ${KEY_OIDS_SOURCE} says it ${want.verdict}`, line));
            if (!row.name.includes(want.needle)) out.push(error(SECURITY, `the password-based encryption row for ${oid} must name ${want.needle}, as ${KEY_OIDS_SOURCE} does`, line));
        }
        for (const oid of rows.keys()) {
            if (!expected.has(oid)) out.push(error(SECURITY, `the password-based encryption table names ${oid}, which ${KEY_OIDS_SOURCE} neither opens nor refuses by name`, lineContaining(security, `\`${oid}\``)));
        }
        if (appendixB !== 'refuses') out.push(error(SECURITY, `the password-based encryption table must list the ${APPENDIX_B_MAC} as refused — the PKCS#12 MAC pkinative will not compute`, sectionLine));
        return out;
    },
};

export const REGISTRY_RULES: readonly Rule[] = [errorParity, errorCodesFrozen, diagnosticsParity, reasonParity, limitsParity, keyOperationParity, pkcs12PolicyParity];

/** Exported for tests: the codes the registries hold, read the way the rules read them. */
export function registryCodes(ctx: RuleContext): { errors: string[]; diagnostics: string[] } {
    const e = readJson<{ errors?: Array<{ code?: unknown }> }>(ctx, ERRORS_REGISTRY);
    const d = readJson<{ diagnostics?: Array<{ code?: unknown }> }>(ctx, DIAGNOSTICS_REGISTRY);
    const codes = (rows: Array<{ code?: unknown }> | undefined): string[] => (rows ?? []).map((r) => r.code).filter((c): c is string => typeof c === 'string');
    return {
        errors: 'finding' in e ? [] : codes(e.value.errors),
        diagnostics: 'finding' in d ? [] : codes(d.value.diagnostics),
    };
}
