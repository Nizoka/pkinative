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
 *   - no runtime escape hatch (`eval`, `Function`, `fetch`, `process`, …);
 *   - every Web Crypto key operation — called or declared — is named only by
 *     the modules `KEY_OPERATION_POLICY` allows, and five of them by nobody,
 *     ever; the host object itself has one door.
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
    // crypto imports no x509. Everything a verifier needs is already on the
    // parsed structure as data — tbsDer, signatureAlgorithm, signatureValue,
    // subjectPublicKeyInfo.der — and all of those types live in `types`. The
    // asn1 edge is for reading RSASSA-PSS parameters out of an Asn1Node and
    // for the DER ↔ P1363 signature conversion, both pure encoding work.
    // The invariant to defend: the verifier consumes parsed data, it does
    // not parse. It is why verification never ships the certificate parser.
    crypto: ['types', 'core', 'asn1'],
    // build signs what it encodes, so it reaches crypto; it never reaches
    // x509, because nothing here reads a certificate. It reaches hash since
    // 0.7: a CMS signer commits to a digest of the content in its
    // `messageDigest` attribute and to one of its certificate in
    // `signingCertificateV2`, and both are hashes of public bytes.
    build: ['types', 'core', 'asn1', 'hash', 'crypto'],
    // RFC 5280 section 6 reads already-parsed data and returns a verdict. No
    // asn1: if it needed to decode anything, a layer upstream failed to expose
    // the data. No crypto: signature verdicts arrive precomputed, which keeps
    // the state machine synchronous, pure, and fuzzable without a host.
    path: ['types', 'core', 'x509'],
    // CRL and OCSP parsing: structures x509 does not model, read with the same
    // readers. No crypto: a revocation verdict takes a precomputed signature
    // verdict, exactly as section 6 does, so revocation stays synchronous too.
    revocation: ['types', 'core', 'asn1', 'hash', 'x509', 'build'],
    // RFC 5652 CMS and RFC 3161 timestamps: parsing, and the structural
    // decisions a signer's attributes call for. The same shape revocation has
    // and for the same reason — no crypto, because a signature verdict arrives
    // precomputed, so everything here stays synchronous and fuzzable without a
    // host. x509 for the Name, AlgorithmIdentifier and GeneralName readers the
    // two syntaxes share; build and hash for the one thing that writes, a
    // timestamp request, which carries a digest of what is to be stamped.
    cms: ['types', 'core', 'asn1', 'hash', 'x509', 'build'],
    // PKCS#8 and PKCS#12 under PBES2 (0.8): the one layer besides verify that
    // reaches crypto for something other than a signature, because opening a
    // password-protected key IS a Web Crypto call — derive, then unwrap. No
    // x509: a certificate bag comes out as DER and the caller, or verify,
    // parses it, so reading a key file never ships the certificate parser.
    // No hash: PBKDF2 and the PBMAC1 HMAC run in the host.
    keys: ['types', 'core', 'asn1', 'crypto'],
    // The composition layer, and the only one that reaches both a key and a
    // verdict. Everything below it answers one question and answers it the
    // narrow way: primitives return and throw, and each of section 6, name
    // matching, purpose and revocation is deliberately blind to the others.
    // Someone still has to put them in the right order, verify the signatures
    // in parallel first, and turn the exceptions the primitives throw into
    // reasons — and if that someone is every caller, every caller gets it
    // slightly wrong. So it is here, once, and `verify` is the ONLY module of
    // src/ allowed to catch a PkiError.
    verify: ['types', 'core', 'asn1', 'hash', 'x509', 'crypto', 'path', 'revocation', 'cms', 'keys'],
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

/**
 * Every Web Crypto key operation, and the exact modules of `src/` allowed to
 * name each one — in a call, a property signature or a method signature.
 *
 * **An empty list is a permanent refusal**, not a milestone waiting its turn:
 * pkinative never creates, exports, wraps or derives raw key material, in any
 * version. The three that are allowed are allowed in two files and nowhere
 * else, because the guarantee this table exists to give is not "the library
 * is careful" but "there is one door, and here it is".
 *
 * `src/types/webcrypto.ts` appears beside the implementation because the
 * check fires on declarations too: the boundary cannot declare the shape of
 * the host it calls without naming these.
 *
 * Widening this table is a reviewed commit of its own, and changes the
 * SECURITY.md table in the same diff — the `key-operation-parity` rule of
 * verify-docs fails otherwise.
 */
export const KEY_OPERATION_POLICY: Readonly<Record<string, readonly string[]>> = Object.freeze({
    // ── The Web Crypto boundary (0.3) ────────────────────────────────
    importKey: ['src/types/webcrypto.ts', 'src/crypto/webcrypto.ts'],
    verify: ['src/types/webcrypto.ts', 'src/crypto/webcrypto.ts'],
    sign: ['src/types/webcrypto.ts', 'src/crypto/webcrypto.ts'],

    // ── Never, in any version ────────────────────────────────────────
    // generateKey and exportKey: owning a key's lifetime is the caller's
    //   job, and three lines of their code. `exportKey: []` is why the
    //   certificate builder takes SPKI DER instead of a CryptoKey.
    // deriveBits: hands back an ArrayBuffer of key material nothing can
    //   zeroise. deriveKey (0.8, PBES2) strictly dominates it, and
    //   refusing it turns "we prefer deriveKey" from a review habit into
    //   a gate.
    // encrypt and wrapKey: pkinative reads containers; it writes none.
    generateKey: [],
    exportKey: [],
    deriveBits: [],
    encrypt: [],
    wrapKey: [],

    // ── PKCS#8 and PKCS#12 under PBES2 only (0.8) ────────────────────
    // Each returns a handle or public bytes, never key material. deriveKey
    //   turns a password into a non-extractable AES or HMAC key; unwrapKey
    //   turns an encrypted PKCS#8 into a non-extractable signing key without
    //   its plaintext ever reaching the heap; decrypt opens certificate bags,
    //   which hold no key. RFC 7292 Appendix B is not among them in any form:
    //   its KDF is iterated SHA-1 with byte arithmetic over the password.
    deriveKey: ['src/types/webcrypto.ts', 'src/crypto/webcrypto.ts'],
    unwrapKey: ['src/types/webcrypto.ts', 'src/crypto/webcrypto.ts'],
    decrypt: ['src/types/webcrypto.ts', 'src/crypto/webcrypto.ts'],
});

/**
 * The only modules that may reach the host's Web Crypto object. Without the
 * DOM lib, `globalThis.crypto` is the only way there, so it is a single-sink
 * global exactly as `console` is: one door for digests, one for keys.
 */
export const WEBCRYPTO_HOST_MODULES: ReadonlySet<string> = new Set([
    'src/crypto/webcrypto.ts',
    'src/hash/fingerprint.ts',
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

/** `(globalThis as T).x` and `globalThis!.x` reach the same object as `globalThis.x`. */
function unwrapExpression(node: ts.Expression): ts.Expression {
    let current = node;
    while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isTypeAssertionExpression(current)
        || ts.isNonNullExpression(current) || ts.isSatisfiesExpression(current)) {
        current = current.expression;
    }
    return current;
}

function isGlobalThis(node: ts.Expression): boolean {
    const bare = unwrapExpression(node);
    return ts.isIdentifier(bare) && bare.text === 'globalThis';
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
        const member = ts.isPropertyAccessExpression(node) ? node.name
            : (ts.isPropertySignature(node) || ts.isMethodSignature(node)) && ts.isIdentifier(node.name) ? node.name : undefined;
        // `Object.hasOwn`, not `in`: a property named `toString` or
        // `constructor` satisfies `in` through the prototype chain and then
        // yields a function where a list is expected. The same reason
        // src/ puts decoded names in Maps and never in object keys.
        if (member !== undefined && Object.hasOwn(KEY_OPERATION_POLICY, member.text)) {
            const allowed = KEY_OPERATION_POLICY[member.text] ?? [];
            if (allowed.length === 0) {
                findings.push(finding(path, lineAt(node), `\`${member.text}\` is never allowed in src/ — pkinative creates, exports, wraps and derives no key material, in any version; see SECURITY.md §Cryptographic Implementation Scope`));
            } else if (!allowed.includes(path)) {
                findings.push(finding(path, lineAt(node), `\`${member.text}\` is a key operation, and only ${allowed.join(' and ')} may name it — route it through the Web Crypto boundary rather than reaching for the host here`));
            }
        }
        if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
            imports.push({ specifier: node.moduleSpecifier.text, line: lineAt(node) });
        } else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteral(node.argument.literal)) {
            imports.push({ specifier: node.argument.literal.text, line: lineAt(node) });
        } else if (ts.isImportEqualsDeclaration(node)) {
            findings.push(finding(path, lineAt(node), '`import x = require(…)` is forbidden — use an ES import'));
        } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
            findings.push(finding(path, lineAt(node), 'dynamic `import()` is forbidden in src/ — every dependency is static and relative'));
        } else if (ts.isPropertyAccessExpression(node) && isGlobalThis(node.expression)) {
            // Without the DOM lib, `globalThis.console` is the only way to reach the console,
            // so the single-sink and no-host-global rules apply to it as they do to identifiers.
            const name = node.name.text;
            if (name === 'console' && path !== DIAGNOSTICS_MODULE) {
                findings.push(finding(path, lineAt(node), `\`globalThis.console\` is forbidden outside ${DIAGNOSTICS_MODULE} — emit a diagnostic instead`));
            } else if (name === 'crypto' && !WEBCRYPTO_HOST_MODULES.has(path)) {
                findings.push(finding(path, lineAt(node), `\`globalThis.crypto\` is forbidden outside ${[...WEBCRYPTO_HOST_MODULES].join(' and ')} — the host is reached through one door, so what pkinative asks of it can be read in one place`));
            } else if (FORBIDDEN_GLOBALS.has(name)) {
                findings.push(finding(path, lineAt(node), `\`globalThis.${name}\` is forbidden in src/ — the engine has no dynamic code, no I/O and no host-specific globals`));
            }
        } else if (ts.isElementAccessExpression(node) && isGlobalThis(node.expression)) {
            findings.push(finding(path, lineAt(node), 'computed `globalThis[…]` access is forbidden in src/ — name a global statically so the architecture test can check it'));
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
        // `Object.hasOwn` for the reason above: a directory named
        // `constructor` would otherwise resolve to a function.
        if (from !== 'index' && !Object.hasOwn(LAYERS, from)) {
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
        if (!Object.hasOwn(LAYERS, layer)) out.push(finding(FILE, line, `the diagram names layer "${layer}", which LAYERS does not register`));
    }
    return out;
}
