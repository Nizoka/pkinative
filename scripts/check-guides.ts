#!/usr/bin/env tsx
/**
 * pkinative — the guides' code, compiled
 * =======================================
 * Every ```ts fence of README.md and docs/guides/*.md is a program a reader
 * will paste. This script extracts each one, resolves `pkinative` to
 * `src/index.ts` and type-checks it with `strict` against the ES2020 library
 * plus DOM — the environment of a browser or a Web Crypto runtime, with no
 * `node:` types — so a guide that names an export wrongly, passes an option
 * that does not exist, shadows a DOM global or forgets an `await` fails the
 * gate rather than the reader.
 *
 * Three conventions make prose code compilable without lying:
 *
 *   - **Inputs.** A fence may use the free identifiers of `GUIDE_INPUTS`
 *     (`der`, `leaf`, `roots`, …): the bytes, certificates and keys the prose
 *     around it names. They are declared, with their types, in a prelude every
 *     fence gets, minus the ones the fence declares itself; any other free
 *     identifier is an error. The table is closed on purpose — a new input is
 *     a reviewed line here, not a silent `declare`.
 *   - **Continuations.** A fence without its own `import … from 'pkinative'`
 *     continues the ones before it in the same file: the names those fences
 *     imported are imported for it. A fence that imports is self-contained.
 *   - **A handler.** A fence is a module, top-level `await` included. One
 *     that returns early is the body of the handler a reader writes, and is
 *     compiled inside an `async` function with its imports hoisted above.
 *
 * Each fence becomes `test-output/guides/<file>-<line>.ts` (the line is the
 * fence's opening line in the Markdown), so a failure is one file to open.
 *
 * Usage:
 *   npm run check:guides            # or: npx tsx scripts/check-guides.ts
 *
 * Exit: 0 every fence compiles; 1 otherwise.
 *
 * @module scripts/check-guides
 */

import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const OUT_DIR = 'test-output/guides';

/**
 * The free identifiers a fence may use — what the prose around it hands the reader. Closed list; `P` is the
 * `import type * as P from 'pkinative'` of the prelude.
 */
export const GUIDE_INPUTS: Readonly<Record<string, string>> = {
    // bytes and text
    der: 'Uint8Array',
    pemText: 'string',
    crlDer: 'Uint8Array',
    baseDer: 'Uint8Array',
    newerDer: 'Uint8Array',
    p7s: 'Uint8Array',
    p12Bytes: 'Uint8Array',
    message: 'Uint8Array',
    signedContent: 'Uint8Array',
    password: 'string',
    url: 'string',
    tsaUrl: 'string',
    // parsed structures
    leaf: 'P.Certificate',
    certificate: 'P.Certificate',
    caCertificate: 'P.Certificate',
    issuer: 'P.Certificate',
    signerCertificate: 'P.Certificate',
    responderCertificate: 'P.Certificate',
    chain: 'readonly P.Certificate[]',
    candidates: 'readonly P.Certificate[]',
    whateverTheServerSent: 'readonly P.Certificate[]',
    roots: 'readonly P.Certificate[]',
    yourRoots: 'readonly P.Certificate[]',
    trustAnchors: 'readonly P.Certificate[]',
    signatures: 'readonly P.SignatureResult[]',
    base: 'P.CertificateList',
    newer: 'P.CertificateList',
    response: 'P.OcspResponse',
    nonce: 'Uint8Array',
    // verdicts the prose says were computed
    signatureVerified: 'boolean',
    deltaVerified: 'boolean',
    responderAuthorized: 'boolean',
    // keys
    publicKey: 'CryptoKey',
    signingKey: 'P.SigningKey',
    // the reader's own helpers
    log: '(...args: unknown[]) => void',
};

/** One ```ts fence: where it opens in the Markdown and what it holds. */
export interface Fence {
    readonly file: string;
    readonly line: number;
    readonly code: string;
}

/** Every ```ts fence of a Markdown text, in order. */
export function extractTsFences(file: string, markdown: string): Fence[] {
    const lines = markdown.replace(/\r\n/g, '\n').split('\n');
    const out: Fence[] = [];
    for (let i = 0; i < lines.length; i++) {
        if (lines[i] !== '```ts') continue;
        const start = i;
        const body: string[] = [];
        for (i++; i < lines.length && lines[i] !== '```'; i++) body.push(lines[i] as string);
        out.push({ file, line: start + 1, code: body.join('\n') });
    }
    return out;
}

const IMPORT_LINE = /^import\s+(?:type\s+)?\{[^}]*\}\s+from\s+'pkinative';\s*$/;

/** The names a fence imports from pkinative (`type X` counts as `X`). */
function importedNames(code: string): Set<string> {
    const names = new Set<string>();
    for (const line of code.split('\n')) {
        if (!IMPORT_LINE.test(line)) continue;
        const inner = line.slice(line.indexOf('{') + 1, line.indexOf('}'));
        for (const part of inner.split(',')) {
            const name = part.trim().replace(/^type\s+/, '').split(/\s+as\s+/)[0]?.trim();
            if (name) names.add(name);
        }
    }
    return names;
}

/** Whether the fence declares `name` itself (then the prelude must not). */
const declares = (code: string, name: string): boolean => new RegExp(`\\b(?:const|let|var|function|class)\\s+(?:\\{[^}]*\\b${name}\\b[^}]*\\}|\\[[^\\]]*\\b${name}\\b[^\\]]*\\]|${name}\\b)`).test(code);

/**
 * The compilable program of a fence: the prelude (inputs it does not declare, continued imports), the fence's
 * own imports hoisted, then its statements inside one async function. Returns the text and the line of the
 * program on which the fence's first statement sits, for mapping diagnostics back.
 */
export function programOf(fence: Fence, imported: ReadonlySet<string>): { readonly text: string; readonly offset: number } {
    const own = importedNames(fence.code);
    const continued = own.size === 0 ? [...imported].sort() : [];
    const lines = fence.code.split('\n');
    const imports = lines.filter((l) => IMPORT_LINE.test(l));
    const body = lines.map((l) => (IMPORT_LINE.test(l) ? '' : l));
    // A fence that returns early is the body of the reader's handler; the others are a module, top-level await included.
    const handler = /\breturn\b/.test(fence.code) && !/^export\b/m.test(fence.code);
    const prelude = [
        "import type * as P from 'pkinative';",
        ...(continued.length > 0 ? [`import { ${continued.join(', ')} } from 'pkinative';`] : []),
        ...imports,
        ...Object.entries(GUIDE_INPUTS).filter(([name]) => !declares(fence.code, name)).map(([name, type]) => `declare const ${name}: ${type};`),
        handler ? `export async function handler() { // ${fence.file}:${String(fence.line)}` : `export {}; // ${fence.file}:${String(fence.line)}`,
    ];
    return { text: `${prelude.join('\n')}\n${body.join('\n')}\n${handler ? '}\n' : ''}`, offset: prelude.length };
}

export interface GuideFinding {
    readonly file: string;
    readonly line: number;
    readonly message: string;
}

/** Type-check every fence; the findings name the Markdown file and line. */
export function checkGuides(root: string, files: readonly string[]): { readonly fences: number; readonly findings: GuideFinding[] } {
    const outDir = join(root, OUT_DIR);
    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(outDir, { recursive: true });
    const generated = new Map<string, { fence: Fence; offset: number }>();
    for (const file of files) {
        const fences = extractTsFences(file, readFileSync(join(root, file), 'utf8'));
        const imported = new Set<string>();
        for (const fence of fences) {
            const program = programOf(fence, imported);
            for (const n of importedNames(fence.code)) imported.add(n);
            const path = join(outDir, `${file.replace(/[\\/]/g, '-').replace(/\.md$/, '')}-${String(fence.line)}.ts`);
            writeFileSync(path, program.text, 'utf8');
            generated.set(resolve(path), { fence, offset: program.offset });
        }
    }
    const options: ts.CompilerOptions = {
        strict: true,
        noEmit: true,
        skipLibCheck: true,
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
        moduleResolution: ts.ModuleResolutionKind.Bundler,
        lib: ['lib.es2020.d.ts', 'lib.dom.d.ts'],
        types: [],
        baseUrl: root,
        paths: { pkinative: ['src/index.ts'] },
    };
    const program = ts.createProgram([...generated.keys()], options);
    const findings: GuideFinding[] = [];
    for (const [path, { fence, offset }] of generated) {
        const source = program.getSourceFile(path);
        if (source === undefined) { findings.push({ file: fence.file, line: fence.line, message: 'the generated program could not be read' }); continue; }
        for (const d of [...program.getSyntacticDiagnostics(source), ...program.getSemanticDiagnostics(source)]) {
            const at = d.start === undefined ? offset : source.getLineAndCharacterOfPosition(d.start).line;
            // Program line `offset` is the fence's first line, which is Markdown line fence.line + 1.
            findings.push({ file: fence.file, line: fence.line + 1 + Math.max(0, at - offset), message: ts.flattenDiagnosticMessageText(d.messageText, ' ') });
        }
    }
    return { fences: generated.size, findings };
}

/** README.md and every guide, in a stable order. */
export function guideFiles(root: string): string[] {
    return ['README.md', ...readdirSync(join(root, 'docs/guides')).filter((f) => f.endsWith('.md')).sort().map((f) => `docs/guides/${f}`)];
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    const { fences, findings } = checkGuides(ROOT, guideFiles(ROOT));
    for (const f of findings) console.error(`${f.file}:${String(f.line)} ${f.message}`);
    console.log(`check-guides: ${String(fences)} TypeScript fence(s) compiled against src/index.ts with lib ES2020 + DOM, ${String(findings.length)} error(s)${findings.length > 0 ? ` — the programs are in ${OUT_DIR}/` : ''}`);
    process.exit(findings.length === 0 ? 0 : 1);
}
