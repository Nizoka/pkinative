import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
    DIAGNOSTICS_MODULE,
    ERRORS_MODULE,
    LAYERS,
    checkArchitecture,
    checkLayerParity,
    layerOf,
    parseLayerDiagram,
} from '../../scripts/lib/architecture.js';

/**
 * AGENTS.md §Architecture and §Conventions, enforced from the syntax tree.
 * The first two tests hold the real repository to the rules; the rest prove
 * each rule fires on the smallest source that breaks it, and stays quiet on
 * the look-alike that does not (a property named `process`, the word
 * `console` inside a string).
 */

const ROOT = resolve(import.meta.dirname, '..', '..');

function sourceTree(): Record<string, string> {
    const out: Record<string, string> = {};
    const walk = (rel: string): void => {
        for (const entry of readdirSync(join(ROOT, rel))) {
            const child = `${rel}/${entry}`;
            if (statSync(join(ROOT, child)).isDirectory()) walk(child);
            else if (child.endsWith('.ts')) out[child] = readFileSync(join(ROOT, child), 'utf8');
        }
    };
    walk('src');
    return out;
}

describe('the repository', () => {
    it('should respect the layer table and the syntactic conventions in src/', () => {
        expect(checkArchitecture(sourceTree())).toEqual([]);
    });

    it('should document exactly the enforced layer table in AGENTS.md', () => {
        expect(checkLayerParity(readFileSync(join(ROOT, 'AGENTS.md'), 'utf8'))).toEqual([]);
    });
});

describe('layerOf', () => {
    it('should name the layer of a source path, the entry point, or nothing', () => {
        expect(layerOf('src/asn1/asn1-decode.ts')).toBe('asn1');
        expect(layerOf('src/index.ts')).toBe('index');
        expect(layerOf('src/loose.ts')).toBeNull();
        expect(layerOf('scripts/gate.ts')).toBeNull();
    });
});

describe('checkArchitecture', () => {
    const base = {
        'src/index.ts': "export * from './x509/x509-certificate.js';\n",
        'src/types/pki-types.ts': 'export type Bytes = Uint8Array;\n',
        'src/core/bytes.ts': "import type { Bytes } from '../types/pki-types.js';\nexport const empty = (): Bytes => new Uint8Array(0);\n",
        'src/asn1/asn1-decode.ts': "import { empty } from '../core/bytes.js';\nexport const decode = (): Uint8Array => empty();\n",
        'src/x509/x509-certificate.ts': "import { decode } from '../asn1/asn1-decode.js';\nexport const parse = (): Uint8Array => decode();\n",
    };
    const messages = (files: Record<string, string>): string[] => checkArchitecture(files).map((f) => `${f.file}: ${f.message}`);

    it('should pass a tree whose every edge LAYERS allows', () => {
        expect(checkArchitecture(base)).toEqual([]);
    });

    it.each([
        ['a Web Crypto signature', "export const s = (k: never, d: Uint8Array): unknown => (globalThis as { crypto: { subtle: { sign: (...a: unknown[]) => unknown } } }).crypto.subtle.sign('ECDSA', k, d);\n"],
        ['a key generation', 'export const g = (subtle: { generateKey(): void }): void => subtle.generateKey();\n'],
        ['a key operation declared in a type', 'export interface Subtle { deriveBits(): void }\n'],
    ])('should refuse %s in src/', (_, source) => {
        const files = { ...base, 'src/core/keys.ts': source };
        expect(messages(files).some((m) => m.startsWith('src/core/keys.ts') && m.includes('is a key operation'))).toBe(true);
    });

    it('should allow a digest, the one Web Crypto operation 0.1 uses', () => {
        const files = { ...base, 'src/core/hash.ts': 'export const d = (s: { digest(a: string, b: Uint8Array): unknown }, b: Uint8Array): unknown => s.digest(\'SHA-256\', b);\n' };
        expect(checkArchitecture(files)).toEqual([]);
    });

    it('should refuse a reverse edge (asn1 → x509) and name both layers', () => {
        const files = { ...base, 'src/asn1/asn1-decode.ts': "import { parse } from '../x509/x509-certificate.js';\nexport const decode = (): Uint8Array => parse();\n" };
        expect(messages(files).some((m) => m.includes('layer "asn1" imports layer "x509"'))).toBe(true);
    });

    it('should refuse an edge that is not reverse but not allowed either (x509 → oid)', () => {
        const files = { ...base, 'src/oid/oid-names.ts': 'export const n = 1;\n', 'src/x509/x509-name.ts': "import { n } from '../oid/oid-names.js';\nexport const m = n;\n" };
        expect(messages(files)).toEqual([expect.stringContaining('layer "x509" imports layer "oid"')]);
    });

    it('should report an import cycle once', () => {
        const files = {
            ...base,
            'src/core/a.ts': "import { b } from './b.js';\nexport const a = (): number => b();\n",
            'src/core/b.ts': "import { a } from './a.js';\nexport const b = (): number => a();\n",
        };
        expect(messages(files).filter((m) => m.includes('import cycle'))).toHaveLength(1);
    });

    it('should refuse node built-ins, bare specifiers, missing extensions, unresolved files and the entry point', () => {
        const files = {
            ...base,
            'src/core/io.ts': [
                "import { readFileSync } from 'node:fs';",
                "import forge from 'node-forge';",
                "import { empty } from './bytes';",
                "import { gone } from './gone.js';",
                "import * as api from '../index.js';",
                'export const x = [readFileSync, forge, empty, gone, api];',
            ].join('\n'),
        };
        const found = messages(files).join('\n');
        expect(found).toContain('"node:fs"');
        expect(found).toContain('"node-forge" — a bare specifier');
        expect(found).toContain('without the .js extension');
        expect(found).toContain('does not exist');
        expect(found).toContain('nothing inside the library imports the public entry point');
    });

    it('should refuse a class outside the error module and allow it inside', () => {
        expect(messages({ ...base, 'src/core/reader.ts': 'export class Reader {}\n' })).toEqual([expect.stringContaining('`class` is forbidden')]);
        expect(messages({ ...base, 'src/core/reader.ts': 'export const Reader = class {};\n' })).toEqual([expect.stringContaining('`class` is forbidden')]);
        expect(checkArchitecture({ ...base, [ERRORS_MODULE]: 'export class PkiError extends Error {}\n' })).toEqual([]);
    });

    it('should refuse console outside the diagnostics module, and ignore the word in a string or a property name', () => {
        expect(messages({ ...base, 'src/core/log.ts': "export const log = (): void => console.warn('x');\n" })).toEqual([expect.stringContaining('`console` is forbidden')]);
        expect(checkArchitecture({ ...base, [DIAGNOSTICS_MODULE]: "export const warn = (m: string): void => console.warn(m);\n" })).toEqual([]);
        expect(checkArchitecture({ ...base, 'src/core/log.ts': "export const label = 'console';\nexport const o = { console: 1 };\nexport const v = o.console;\n" })).toEqual([]);
    });

    it('should refuse runtime escape hatches and dynamic imports, and ignore same-named properties', () => {
        const found = messages({
            ...base,
            'src/core/escape.ts': [
                "export const a = (): unknown => eval('1');",
                "export const b = (): unknown => new Function('return 1');",
                'export const c = (): unknown => process.env;',
                "export const d = (): unknown => import('./bytes.js');",
                "export const e = (): unknown => fetch('https://example.com');",
            ].join('\n'),
        }).join('\n');
        for (const what of ['`eval`', '`Function`', '`process`', 'dynamic `import()`', '`fetch`']) expect(found).toContain(what);
        expect(checkArchitecture({ ...base, 'src/core/props.ts': 'export const o = { process: 1, fetch: 2 };\nexport const v = o.process + o.fetch;\n' })).toEqual([]);
    });

    it('should apply the console and host-global rules to globalThis property access, through casts', () => {
        const found = messages({
            ...base,
            'src/core/sneaky.ts': [
                "export const a = (): void => (globalThis as { console?: { warn(m: string): void } }).console?.warn('x');",
                'export const b = (): unknown => (globalThis as { process?: unknown }).process;',
                "export const c = (): unknown => (globalThis as Record<string, unknown>)['fetch'];",
            ].join('\n'),
        }).join('\n');
        expect(found).toContain('`globalThis.console` is forbidden');
        expect(found).toContain('`globalThis.process` is forbidden');
        expect(found).toContain('computed `globalThis[…]` access is forbidden');
        const allowed = "export const w = (): void => (globalThis as { console?: { warn(m: string): void } }).console?.warn('x');\n";
        expect(checkArchitecture({ ...base, [DIAGNOSTICS_MODULE]: allowed })).toEqual([]);
        expect(checkArchitecture({ ...base, 'src/core/crypto.ts': 'export const s = (): unknown => (globalThis as { crypto?: unknown }).crypto;\n' })).toEqual([]);
    });

    it('should refuse a file outside every layer and an unregistered layer', () => {
        expect(messages({ ...base, 'src/loose.ts': 'export const x = 1;\n' })).toEqual([expect.stringContaining('outside every layer')]);
        expect(messages({ ...base, 'src/crypto/rsa.ts': 'export const x = 1;\n' })).toEqual([expect.stringContaining('layer "crypto" is not registered')]);
    });
});

describe('parseLayerDiagram and checkLayerParity', () => {
    const diagram = (body: string): string => `# AGENTS.md\n\n## Architecture\n\n\`\`\`\n${body}\n\`\`\`\n\n## Next\n`;
    const exact = Object.entries(LAYERS).map(([layer, deps]) => `${layer.padEnd(6)} → ${deps.join(', ') || '(nothing)'}`).join('\n');

    it('should parse the fenced diagram of the Architecture section', () => {
        expect(parseLayerDiagram(diagram('types  → (nothing)\nx509   → types, core, asn1\nindex  → all'))).toEqual({ types: [], x509: ['types', 'core', 'asn1'] });
        expect(parseLayerDiagram('# no section')).toBeNull();
    });

    it('should pass the exact table and fail an omitted layer, a wrong edge and an unknown layer', () => {
        expect(checkLayerParity(diagram(exact))).toEqual([]);
        expect(checkLayerParity(diagram(exact.replace(/^oid.*$/m, '')))).toEqual([expect.objectContaining({ message: expect.stringContaining('omits layer "oid"') })]);
        expect(checkLayerParity(diagram(exact.replace(/^x509.*$/m, 'x509   → types, core, asn1, oid')))).toEqual([expect.objectContaining({ message: expect.stringContaining('x509 →') })]);
        expect(checkLayerParity(diagram(`${exact}\ncrypto → core`))).toEqual([expect.objectContaining({ message: expect.stringContaining('"crypto"') })]);
        expect(checkLayerParity(null)[0].message).toContain('missing');
        expect(checkLayerParity('# nothing')[0].message).toContain('Architecture');
    });
});
