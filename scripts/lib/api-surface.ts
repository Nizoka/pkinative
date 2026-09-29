/**
 * pkinative — the public surface, fingerprinted
 * ==============================================
 * What semantic versioning promises for a TypeScript library is the *type*
 * of every export a caller can name: a caller breaks when code that compiled
 * against the old declaration stops compiling against the new one. This
 * module reduces each export of `src/index.ts` to a canonical text that
 * changes exactly when that type changes, and classifies a change as
 * compatible (semver-minor) or not (semver-major).
 *
 * What is in the fingerprint, and what is deliberately not:
 *
 *   - **Read from the syntax tree of the declaring module**, not from
 *     docs/assets/api.json. The manifest lists the exports (name, kind,
 *     module) and that is all it is trusted for: it reads declarations by
 *     regex, keeps an interface member's type from its first line only,
 *     truncates a signature at 1200 characters and flattens `//` comments
 *     into the text they annotated — four ways for a type change to leave
 *     it unchanged.
 *   - **Comments are removed** (TSDoc is documentation, not contract).
 *   - **Parameter names are removed**, everywhere, including in callback
 *     types and labelled tuples: a call is positional, so renaming a
 *     parameter breaks nobody. A default value becomes `?` — the caller
 *     sees an optional parameter, never the default expression.
 *   - **Union members are sorted and interface members are sorted by name**:
 *     order carries no meaning in either.
 *   - **Inherited interface members are merged in**: a base interface need
 *     not be exported (`GeneralNameBase` is not) for its fields to be
 *     promised through every interface that extends it.
 *   - **A constant is its declared type** (or its literal, whose type it
 *     is), never its value: `DEFAULT_PKI_LIMITS` is `PkiLimits`, and a
 *     default raised in a minor release is behaviour, not surface.
 *   - **A class is its public members** — `private` and `#private` are not
 *     visible to a caller.
 *   - **The three code unions are delegated to their registries**
 *     (`VOCABULARIES`): an error code is frozen by
 *     docs/data/errors.frozen.json, a reason code by the `reasons` list of
 *     the snapshot, and a diagnostic code by nothing — diagnostic codes are
 *     additions-only by their own contract, and a diagnostic is advice.
 *
 * @module scripts/lib/api-surface
 */

import { posix } from 'node:path';
import ts from 'typescript';

/** Repository-relative POSIX path → text, or null when absent. */
export type Reader = (path: string) => string | null;

export const API_JSON = 'docs/assets/api.json';
export const API_FROZEN = 'docs/assets/api.frozen.json';
export const REASONS_JSON = 'docs/data/reasons.json';

/** One export as the snapshot records it. */
export interface FrozenExport {
    readonly name: string;
    readonly kind: string;
    readonly signature: string;
}

/**
 * The string-literal code unions whose members are governed by a registry
 * rather than by the fingerprint. The export itself — its name and kind — is
 * still frozen like any other.
 */
export const VOCABULARIES: ReadonlyArray<{ readonly pattern: RegExp; readonly vocabulary: string }> = [
    { pattern: /^Pki[A-Za-z]*ErrorCode$/, vocabulary: 'errors' },
    { pattern: /^PkiReasonCode$/, vocabulary: 'reasons' },
    { pattern: /^PkiDiagnosticCode$/, vocabulary: 'diagnostics' },
];

// ── Printing ─────────────────────────────────────────────────────────

const PRINTER = ts.createPrinter({ removeComments: true, newLine: ts.NewLineKind.LineFeed });

/** Replace every parameter name by `_` (except `this`), and a default value by `?`. */
function anonymizer(context: ts.TransformationContext): ts.Transformer<ts.Node> {
    const f = context.factory;
    const visit = (node: ts.Node): ts.Node => {
        if (ts.isParameter(node)) {
            const isThis = ts.isIdentifier(node.name) && node.name.text === 'this';
            const optional = node.questionToken ?? (node.initializer !== undefined ? f.createToken(ts.SyntaxKind.QuestionToken) : undefined);
            const type = node.type === undefined ? undefined : ts.visitNode(node.type, visit, ts.isTypeNode);
            return f.updateParameterDeclaration(node, node.modifiers, node.dotDotDotToken, isThis ? node.name : f.createIdentifier('_'), optional, type, undefined);
        }
        if (ts.isNamedTupleMember(node)) {
            return f.updateNamedTupleMember(node, node.dotDotDotToken, f.createIdentifier('_'), node.questionToken, ts.visitNode(node.type, visit, ts.isTypeNode) ?? node.type);
        }
        return ts.visitEachChild(node, visit, context);
    };
    return (node) => ts.visitNode(node, visit) ?? node;
}

const collapse = (text: string): string => text.replace(/\s+/g, ' ').replace(/;\s*$/, '').trim();

/** The canonical text of a node: comment-free, parameter names removed, whitespace collapsed. */
function print(node: ts.Node, sf: ts.SourceFile): string {
    const result = ts.transform(node, [anonymizer]);
    try {
        return collapse(PRINTER.printNode(ts.EmitHint.Unspecified, result.transformed[0] ?? node, sf));
    } finally {
        result.dispose();
    }
}

function parse(path: string, text: string): ts.SourceFile {
    return ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

const typeParams = (tps: ts.NodeArray<ts.TypeParameterDeclaration> | undefined, sf: ts.SourceFile): string =>
    tps === undefined || tps.length === 0 ? '' : `<${tps.map((tp) => print(tp, sf)).join(', ')}>`;

const heritage = (clauses: ts.NodeArray<ts.HeritageClause> | undefined, sf: ts.SourceFile): string =>
    (clauses ?? []).map((c) => ` ${print(c, sf)}`).join('');

const nameText = (name: ts.PropertyName | ts.BindingName, sf: ts.SourceFile): string =>
    ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name) || ts.isPrivateIdentifier(name) ? name.text : print(name, sf);

const hasModifier = (node: ts.Node, kind: ts.SyntaxKind): boolean =>
    ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === kind);

// ── Declarations ─────────────────────────────────────────────────────

type Declaration = ts.FunctionDeclaration | ts.ClassDeclaration | ts.InterfaceDeclaration | ts.TypeAliasDeclaration | ts.EnumDeclaration | ts.VariableDeclaration;

function declarationsOf(sf: ts.SourceFile, name: string): Declaration[] {
    const out: Declaration[] = [];
    for (const statement of sf.statements) {
        if (ts.isVariableStatement(statement)) {
            for (const d of statement.declarationList.declarations) if (ts.isIdentifier(d.name) && d.name.text === name) out.push(d);
        } else if ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement) || ts.isInterfaceDeclaration(statement)
            || ts.isTypeAliasDeclaration(statement) || ts.isEnumDeclaration(statement)) && statement.name?.text === name) {
            out.push(statement);
        }
    }
    return out;
}

/** The interface `name` as seen from `module`: declared there, or imported into it from a relative module. */
function resolveInterface(read: Reader, module: string, name: string, cache: Map<string, ts.SourceFile | null>): { decl: ts.InterfaceDeclaration; sf: ts.SourceFile; module: string } | null {
    const sf = sourceFile(read, module, cache);
    if (sf === null) return null;
    const local = declarationsOf(sf, name).find(ts.isInterfaceDeclaration);
    if (local !== undefined) return { decl: local, sf, module };
    for (const statement of sf.statements) {
        if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
        const bindings = statement.importClause?.namedBindings;
        if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
        const element = bindings.elements.find((e) => e.name.text === name);
        if (element === undefined || !statement.moduleSpecifier.text.startsWith('.')) continue;
        const target = posix.normalize(posix.join(posix.dirname(module), statement.moduleSpecifier.text.replace(/\.js$/, '.ts')));
        return resolveInterface(read, target, (element.propertyName ?? element.name).text, cache);
    }
    return null;
}

function sourceFile(read: Reader, path: string, cache: Map<string, ts.SourceFile | null>): ts.SourceFile | null {
    if (!cache.has(path)) {
        const text = read(path);
        cache.set(path, text === null ? null : parse(path, text));
    }
    return cache.get(path) ?? null;
}

/** Every member of an interface, inherited ones merged in (an own member overrides the one it redeclares), by name. */
function interfaceMembers(read: Reader, module: string, decl: ts.InterfaceDeclaration, sf: ts.SourceFile, cache: Map<string, ts.SourceFile | null>, seen: Set<string>): Map<string, string> {
    const members = new Map<string, string>();
    for (const clause of decl.heritageClauses ?? []) {
        for (const base of clause.types) {
            // A generic base (Omit<…>, Base<T>) is a type computation, not a
            // declaration to merge: the heritage clause in the head records it.
            if (!ts.isIdentifier(base.expression) || base.typeArguments !== undefined) continue;
            const key = `${module}#${base.expression.text}`;
            if (seen.has(key)) continue;
            seen.add(key);
            const resolved = resolveInterface(read, module, base.expression.text, cache);
            if (resolved === null) continue;
            for (const [k, v] of interfaceMembers(read, resolved.module, resolved.decl, resolved.sf, cache, seen)) members.set(k, v);
        }
    }
    for (const member of decl.members) {
        const key = member.name === undefined ? print(member, sf) : nameText(member.name, sf);
        members.set(key, print(member, sf));
    }
    return members;
}

function classMember(member: ts.ClassElement, sf: ts.SourceFile, className: string): string | null {
    if (hasModifier(member, ts.SyntaxKind.PrivateKeyword) || (member.name !== undefined && ts.isPrivateIdentifier(member.name))) return null;
    if (ts.isClassStaticBlockDeclaration(member) || ts.isSemicolonClassElement(member)) return null;
    const mods = ts.canHaveModifiers(member)
        ? (ts.getModifiers(member) ?? []).filter((m) => [ts.SyntaxKind.StaticKeyword, ts.SyntaxKind.ReadonlyKeyword, ts.SyntaxKind.ProtectedKeyword, ts.SyntaxKind.AbstractKeyword].includes(m.kind)).map((m) => `${ts.tokenToString(m.kind) ?? ''} `).join('')
        : '';
    const f = ts.factory;
    if (ts.isConstructorDeclaration(member)) return print(f.createConstructorTypeNode(undefined, undefined, member.parameters, f.createTypeReferenceNode(className)), sf);
    if (ts.isMethodDeclaration(member)) return `${mods}${nameText(member.name, sf)}${member.questionToken ? '?' : ''}${print(f.createFunctionTypeNode(member.typeParameters, member.parameters, member.type ?? f.createTypeReferenceNode('__inferred')), sf)}`;
    if (ts.isPropertyDeclaration(member)) {
        const type = member.type !== undefined ? `: ${print(member.type, sf)}` : member.initializer !== undefined ? ` = ${print(member.initializer, sf)}` : ': __inferred';
        return `${mods}${nameText(member.name, sf)}${member.questionToken ? '?' : ''}${type}`;
    }
    if (ts.isGetAccessorDeclaration(member)) return `${mods}get ${nameText(member.name, sf)}: ${member.type === undefined ? '__inferred' : print(member.type, sf)}`;
    if (ts.isSetAccessorDeclaration(member)) return `${mods}set ${nameText(member.name, sf)}${print(f.createFunctionTypeNode(undefined, member.parameters, f.createKeywordTypeNode(ts.SyntaxKind.VoidKeyword)), sf)}`;
    return print(member, sf);
}

const isLiteral = (node: ts.Expression): boolean =>
    ts.isStringLiteral(node) || ts.isNumericLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isBigIntLiteral(node)
    || node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword
    || (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken && ts.isNumericLiteral(node.operand));

const isStringLiteralUnion = (type: ts.TypeNode): boolean =>
    ts.isUnionTypeNode(type) && type.types.every((t) => ts.isLiteralTypeNode(t) && ts.isStringLiteral(t.literal));

/** The vocabulary a type alias belongs to, or null. */
export function vocabularyOf(name: string, alias: ts.TypeAliasDeclaration): string | null {
    const entry = VOCABULARIES.find((v) => v.pattern.test(name));
    return entry !== undefined && isStringLiteralUnion(alias.type) ? entry.vocabulary : null;
}

/** The canonical signature of `name`, declared in `module`, or the reason there is none. */
export function fingerprint(read: Reader, module: string, name: string, cache: Map<string, ts.SourceFile | null> = new Map()): { readonly signature: string } | { readonly problem: string } {
    const sf = sourceFile(read, module, cache);
    if (sf === null) return { problem: `${module} is missing` };
    const decls = declarationsOf(sf, name);
    const first = decls[0];
    if (first === undefined) return { problem: `${module} declares no ${name}` };
    const f = ts.factory;

    if (ts.isFunctionDeclaration(first)) {
        const functions = decls.filter(ts.isFunctionDeclaration);
        const overloads = functions.filter((d) => d.body === undefined);
        const shown = overloads.length > 0 ? overloads : functions;
        if (shown.some((d) => d.type === undefined)) return { problem: `${name} has no explicit return type — the fingerprint cannot see an inferred one` };
        return { signature: shown.map((d) => print(f.createFunctionTypeNode(d.typeParameters, d.parameters, d.type ?? f.createKeywordTypeNode(ts.SyntaxKind.UnknownKeyword)), sf)).join('; ') };
    }
    if (ts.isVariableDeclaration(first)) {
        const keyword = (first.parent.flags & ts.NodeFlags.Const) !== 0 ? 'const' : 'let';
        if (first.type !== undefined) return { signature: `${keyword}: ${print(first.type, sf)}` };
        if (first.initializer !== undefined && isLiteral(first.initializer)) return { signature: `${keyword} = ${print(first.initializer, sf)}` };
        return { problem: `${name} has no type annotation — the fingerprint cannot see an inferred type; annotate it` };
    }
    if (ts.isClassDeclaration(first)) {
        const members = first.members.map((m) => classMember(m, sf, name)).filter((m): m is string => m !== null).sort();
        return { signature: `class${typeParams(first.typeParameters, sf)}${heritage(first.heritageClauses, sf)} { ${members.join('; ')} }` };
    }
    if (ts.isInterfaceDeclaration(first)) {
        const members = [...interfaceMembers(read, module, first, sf, cache, new Set())].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, text]) => text);
        return { signature: `interface${typeParams(first.typeParameters, sf)}${heritage(first.heritageClauses, sf)} { ${members.join('; ')} }` };
    }
    if (ts.isTypeAliasDeclaration(first)) {
        const vocabulary = vocabularyOf(name, first);
        if (vocabulary !== null) return { signature: `vocabulary ${vocabulary}` };
        const rhs = ts.isUnionTypeNode(first.type) ? first.type.types.map((t) => print(t, sf)).sort().join(' | ') : print(first.type, sf);
        return { signature: `type${typeParams(first.typeParameters, sf)} = ${rhs}` };
    }
    return { signature: print(first, sf).replace(/^export /, '') };
}

// ── The surface ──────────────────────────────────────────────────────

/** Every export of docs/assets/api.json fingerprinted from its module, sorted by name, plus what could not be. */
export function currentSurface(read: Reader): { readonly rows: FrozenExport[]; readonly problems: Array<{ readonly module: string; readonly message: string }> } {
    const text = read(API_JSON);
    if (text === null) return { rows: [], problems: [{ module: API_JSON, message: 'missing — run `npm run docs:api`' }] };
    const api = JSON.parse(text) as { exports?: Array<{ name?: unknown; kind?: unknown; module?: unknown }> };
    const cache = new Map<string, ts.SourceFile | null>();
    const rows: FrozenExport[] = [];
    const problems: Array<{ module: string; message: string }> = [];
    for (const e of api.exports ?? []) {
        if (typeof e.name !== 'string' || typeof e.kind !== 'string' || typeof e.module !== 'string') {
            problems.push({ module: API_JSON, message: 'an export without a name, a kind or a module' });
            continue;
        }
        const fp = fingerprint(read, e.module, e.name, cache);
        if ('problem' in fp) problems.push({ module: e.module, message: fp.problem });
        else rows.push({ name: e.name, kind: e.kind, signature: fp.signature });
    }
    rows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    return { rows, problems };
}

/** The reason codes of docs/data/reasons.json with their `since`, in registry order. */
export function reasonCodes(read: Reader): Array<{ readonly code: string; readonly since: string | null }> {
    const text = read(REASONS_JSON);
    if (text === null) return [];
    const registry = JSON.parse(text) as { reasons?: Array<{ code?: unknown; since?: unknown }> };
    return (registry.reasons ?? [])
        .filter((r): r is { code: string; since?: unknown } => typeof r.code === 'string')
        .map((r) => ({ code: r.code, since: typeof r.since === 'string' ? r.since : null }));
}

// ── Compatibility ────────────────────────────────────────────────────

export type Verdict = 'added' | 'removed' | 'kind' | 'compatible' | 'incompatible';

export interface SurfaceChange {
    readonly name: string;
    readonly verdict: Verdict;
    readonly detail: string;
}

function parseAs(text: string): ts.SourceFile {
    return parse('canonical.ts', text);
}

/** Type names referenced anywhere under a node. */
function referencedNames(node: ts.Node, out: Set<string>): void {
    if (ts.isTypeReferenceNode(node) && ts.isIdentifier(node.typeName)) out.add(node.typeName.text);
    if (ts.isExpressionWithTypeArguments(node) && ts.isIdentifier(node.expression)) out.add(node.expression.text);
    node.forEachChild((child) => { referencedNames(child, out); });
}

/**
 * The types a caller may construct: every type reachable from a parameter of
 * an exported function, through interface members, heritage and aliases. A
 * required member added to one of these breaks a caller's object literal; a
 * required member added to a type the caller only ever receives does not.
 */
export function inputTypes(rows: readonly FrozenExport[]): Set<string> {
    const byName = new Map(rows.map((r) => [r.name, r]));
    const found = new Set<string>();
    for (const row of rows.filter((r) => r.kind === 'function')) {
        const alias = parseAs(`type __ = ${row.signature.split('; ')[0] ?? ''};`).statements[0];
        if (alias === undefined || !ts.isTypeAliasDeclaration(alias) || !ts.isFunctionTypeNode(alias.type)) continue;
        for (const p of alias.type.parameters) if (p.type !== undefined) referencedNames(p.type, found);
    }
    const queue = [...found];
    while (queue.length > 0) {
        const row = byName.get(queue.pop() ?? '');
        if (row === undefined || row.kind !== 'type') continue;
        const more = new Set<string>();
        const text = row.signature.startsWith('interface') ? row.signature.replace(/^interface/, 'interface __') : row.signature.startsWith('type') ? `${row.signature.replace(/^type/, 'type __')};` : '';
        referencedNames(parseAs(text), more);
        for (const n of more) if (!found.has(n)) { found.add(n); queue.push(n); }
    }
    return found;
}

function functionParts(signature: string): { tp: string; params: Array<{ text: string; optional: boolean }>; ret: string } | null {
    if (signature.includes('; ')) return null; // overloads: compared exactly
    const sf = parseAs(`type __ = ${signature};`);
    const alias = sf.statements[0];
    if (alias === undefined || !ts.isTypeAliasDeclaration(alias) || !ts.isFunctionTypeNode(alias.type)) return null;
    const fn = alias.type;
    return {
        tp: typeParams(fn.typeParameters, sf),
        params: fn.parameters.map((p) => ({ text: print(p, sf), optional: p.questionToken !== undefined || p.dotDotDotToken !== undefined })),
        ret: print(fn.type, sf),
    };
}

function interfaceParts(signature: string): { head: string; members: Map<string, { text: string; optional: boolean }> } | null {
    const sf = parseAs(signature.replace(/^interface/, 'interface __'));
    const decl = sf.statements[0];
    if (decl === undefined || !ts.isInterfaceDeclaration(decl)) return null;
    const members = new Map<string, { text: string; optional: boolean }>();
    for (const m of decl.members) {
        const key = m.name === undefined ? print(m, sf) : nameText(m.name, sf);
        members.set(key, { text: print(m, sf), optional: (ts.isPropertySignature(m) || ts.isMethodSignature(m)) && m.questionToken !== undefined });
    }
    return { head: `${typeParams(decl.typeParameters, sf)}${heritage(decl.heritageClauses, sf)}`, members };
}

/** A type alias as its type parameters and its union members — a type that is not a union is a union of one. */
function aliasParts(signature: string): { tp: string; union: string[] } | null {
    const sf = parseAs(`${signature.replace(/^type/, 'type __')};`);
    const decl = sf.statements[0];
    if (decl === undefined || !ts.isTypeAliasDeclaration(decl)) return null;
    return {
        tp: typeParams(decl.typeParameters, sf),
        union: ts.isUnionTypeNode(decl.type) ? decl.type.types.map((t) => print(t, sf)) : [print(decl.type, sf)],
    };
}

/**
 * Whether `next` still accepts every caller `frozen` accepted — decided only
 * where that is provable from the syntax; everything else is incompatible.
 * Conservative on purpose: widening a parameter type or narrowing a return
 * type is compatible too, but proving it takes a type checker, and a false
 * "major" costs a reviewed exception while a false "minor" costs a caller.
 */
export function classify(frozen: FrozenExport, next: FrozenExport, inputs: ReadonlySet<string>): { readonly verdict: 'compatible' | 'incompatible'; readonly detail: string } {
    const no = (detail: string): { verdict: 'incompatible'; detail: string } => ({ verdict: 'incompatible', detail });
    if (frozen.kind === 'function') {
        const [a, b] = [functionParts(frozen.signature), functionParts(next.signature)];
        if (a === null || b === null) return no('its overloads changed');
        if (a.tp !== b.tp) return no(`its type parameters changed from "${a.tp}" to "${b.tp}"`);
        if (a.ret !== b.ret) return no(`its return type changed from ${a.ret} to ${b.ret}`);
        for (let i = 0; i < a.params.length; i++) {
            if (a.params[i]?.text !== b.params[i]?.text) return no(`parameter ${String(i + 1)} changed from ${a.params[i]?.text ?? '∅'} to ${b.params[i]?.text ?? '(removed)'}`);
        }
        const required = b.params.slice(a.params.length).findIndex((p) => !p.optional);
        if (required >= 0) return no(`parameter ${String(a.params.length + required + 1)} is new and required`);
        return { verdict: 'compatible', detail: `${String(b.params.length - a.params.length)} optional parameter(s) appended` };
    }
    if (frozen.signature.startsWith('interface') && next.signature.startsWith('interface')) {
        const [a, b] = [interfaceParts(frozen.signature), interfaceParts(next.signature)];
        if (a === null || b === null) return no('its declaration no longer parses');
        if (a.head !== b.head) return no(`its type parameters or heritage changed from "${a.head}" to "${b.head}"`);
        for (const [key, member] of a.members) {
            const now = b.members.get(key);
            if (now === undefined) return no(`member ${key} was removed`);
            if (now.text !== member.text) return no(`member ${key} changed from "${member.text}" to "${now.text}"`);
        }
        const added = [...b.members].filter(([key]) => !a.members.has(key));
        const required = added.find(([, m]) => !m.optional);
        if (required !== undefined && inputs.has(frozen.name)) return no(`member ${required[0]} is new and required, and ${frozen.name} reaches a parameter of an exported function — a caller's object literal stops compiling`);
        return { verdict: 'compatible', detail: `member(s) added: ${added.map(([key]) => key).join(', ')}` };
    }
    if (frozen.signature.startsWith('type') && next.signature.startsWith('type')) {
        const [a, b] = [aliasParts(frozen.signature), aliasParts(next.signature)];
        if (a === null || b === null) return no('its declaration no longer parses');
        if (a.tp !== b.tp) return no(`its type parameters changed from "${a.tp}" to "${b.tp}"`);
        const gone = a.union.filter((m) => !b.union.includes(m));
        if (gone.length > 0) return no(gone.length === a.union.length ? `it changed from ${a.union.join(' | ')} to ${b.union.join(' | ')}` : `union member(s) removed: ${gone.join(' | ')}`);
        return { verdict: 'compatible', detail: `union widened by ${b.union.filter((m) => !a.union.includes(m)).join(' | ')}` };
    }
    return no(`its declaration changed from "${frozen.signature}" to "${next.signature}"`);
}

/** Every difference between a snapshot and the current surface, frozen rows first, in name order. */
export function diffSurface(frozen: readonly FrozenExport[], current: readonly FrozenExport[]): SurfaceChange[] {
    const now = new Map(current.map((r) => [r.name, r]));
    const before = new Set(frozen.map((r) => r.name));
    const inputs = inputTypes(current);
    const out: SurfaceChange[] = [];
    for (const row of frozen) {
        const next = now.get(row.name);
        if (next === undefined) out.push({ name: row.name, verdict: 'removed', detail: `${row.name} (${row.kind}) is no longer exported` });
        else if (next.kind !== row.kind) out.push({ name: row.name, verdict: 'kind', detail: `${row.name} changed from a ${row.kind} to a ${next.kind}` });
        else if (next.signature !== row.signature) {
            const c = classify(row, next, inputs);
            out.push({ name: row.name, verdict: c.verdict, detail: `${row.name}: ${c.detail}` });
        }
    }
    for (const row of current) if (!before.has(row.name)) out.push({ name: row.name, verdict: 'added', detail: `${row.name} (${row.kind}) is a new export` });
    return out;
}

/**
 * Where an ADR lives, and the one status that sanctions a move of a rehearsal
 * snapshot (`build-api-frozen.ts --rebaseline`); the api-surface-frozen rule
 * holds the snapshot's `rebaselines` log to both.
 */
export const ADR_PATH = /^docs\/adr\/\d{4}-[a-z0-9-]+\.md$/;
export const adrAccepted = (text: string | null): boolean => text !== null && /^status: accepted$/m.test(text);
