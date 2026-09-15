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

import ts from 'typescript';
import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

export const ERRORS_SOURCE = 'src/types/pki-errors.ts';
export const TYPES_SOURCE = 'src/types/pki-types.ts';
export const DIAGNOSTICS_SOURCE = 'src/core/pki-diagnostics.ts';
export const LIMITS_SOURCE = 'src/core/pki-limits.ts';
export const ERRORS_REGISTRY = 'docs/data/errors.json';
export const DIAGNOSTICS_REGISTRY = 'docs/data/diagnostics.json';
export const LIMITS_REGISTRY = 'docs/data/limits.json';
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

const errorParity: Rule = {
    id: 'error-parity',
    summary: 'docs/data/errors.json lists exactly the codes of src/types/pki-errors.ts with their class, since, cause, remedy, standard and CWE, and every throw site message starts with "pkinative: ".',
    check(ctx) {
        const out: Finding[] = [];
        const text = ctx.read(ERRORS_SOURCE);
        if (text === null) return [error(ERRORS_SOURCE, 'missing — the error hierarchy and its code unions')];
        const source = parse(ERRORS_SOURCE, text);
        const unions = stringLiteralUnions(source);
        const classes = new Set(source.statements.filter(ts.isClassDeclaration).map((c) => c.name?.text).filter((n): n is string => n !== undefined));
        const codeClass = new Map<string, string>();
        for (const [alias, codes] of unions) {
            const m = /^Pki(\w+)ErrorCode$/.exec(alias);
            if (!m) continue;
            const cls = m[1] === 'Base' ? 'PkiError' : `Pki${m[1]}Error`;
            if (!classes.has(cls)) out.push(error(ERRORS_SOURCE, `${alias} implies class ${cls}, which the module does not declare`, lineContaining(text, alias)));
            for (const code of codes) {
                if (codeClass.has(code)) out.push(error(ERRORS_SOURCE, `${code} belongs to two code unions`, lineContaining(text, `'${code}'`)));
                codeClass.set(code, cls);
            }
        }
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

        for (const file of ctx.list('src').filter((f) => f.endsWith('.ts'))) {
            out.push(...throwSiteFindings(file, ctx.read(file) ?? ''));
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

export const REGISTRY_RULES: readonly Rule[] = [errorParity, diagnosticsParity, limitsParity];

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
