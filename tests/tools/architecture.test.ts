import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
    BARE_CATCH_PROBES,
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

    it('should test bytes with isBytes, never with a realm-bound instanceof', () => {
        // `x instanceof Uint8Array` is false for a Uint8Array another realm made
        // (a vm context, an iframe, a worker), and refused a token, a nonce or a
        // password that was exactly what the caller meant. `isBytes` in
        // core/bytes.ts reads the view and its brand instead, and is the one
        // place the word may appear.
        const offenders = Object.entries(sourceTree())
            .filter(([path, source]) => path !== 'src/core/bytes.ts' && /instanceof Uint8Array/.test(source))
            .map(([path]) => path);
        expect(offenders).toEqual([]);
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

    /** A call that names the operation once: the parameter type does not repeat it. */
    const calls = (operation: string): string => `type Any = Record<string, () => void>;\nexport const f = (subtle: Any): void => subtle.${operation}();\n`;
    /** A declaration that names it once, and calls nothing. */
    const declares = (operation: string): string => `export interface Subtle { ${operation}(): void }\n`;

    it.each([
        ['a signature, called', calls('sign')],
        ['a key import, called', calls('importKey')],
        ['a verification, called', calls('verify')],
        ['a verification, merely declared', declares('verify')],
    ])('should refuse %s outside the Web Crypto boundary, and name the boundary', (_, source) => {
        const files = { ...base, 'src/core/keys.ts': source };
        expect(messages(files)).toEqual([expect.stringContaining('src/crypto/webcrypto.ts may name it')]);
    });

    it.each([
        ['key generation', calls('generateKey')],
        ['key export', calls('exportKey')],
        ['raw bit derivation', declares('deriveBits')],
        ['encryption', calls('encrypt')],
        ['key wrapping', calls('wrapKey')],
    ])('should refuse %s everywhere, including inside the boundary itself', (_, source) => {
        // Inside the boundary is the case that matters: the permanent tier
        // must not become reachable by moving code into the allowed file.
        const files = { ...base, 'src/crypto/webcrypto.ts': source };
        expect(messages(files)).toEqual([expect.stringContaining('is never allowed in src/')]);
    });

    it.each([
        ['a password derivation', calls('deriveKey')],
        ['a key unwrap', calls('unwrapKey')],
        ['a decryption', calls('decrypt')],
    ])('should refuse %s outside the Web Crypto boundary, where 0.8 opened it', (_, source) => {
        // The keys layer that uses them must go through the door like
        // everyone else: opening an operation is per module, not per layer.
        const files = { ...base, 'src/keys/pkcs12.ts': source, 'src/core/keys.ts': source };
        expect(messages(files).filter((m) => m.startsWith('src/core/keys.ts'))).toEqual([expect.stringContaining('src/crypto/webcrypto.ts may name it')]);
    });

    it('should refuse a key operation in a sibling of the boundary — the policy is per module, not per layer', () => {
        const files = { ...base, 'src/crypto/x509-verify.ts': calls('sign') };
        expect(messages(files)).toEqual([expect.stringContaining('may name it')]);
    });

    it('should allow the boundary to call and declare what it is allowed to', () => {
        const files = {
            ...base,
            'src/types/webcrypto.ts': 'export interface Subtle { importKey(): void; verify(): void; sign(): void; deriveKey(): void; unwrapKey(): void; decrypt(): void }\n',
            'src/crypto/webcrypto.ts': "import type { Subtle } from '../types/webcrypto.js';\nexport const v = (s: Subtle): void => { s.importKey(); s.verify(); s.sign(); s.deriveKey(); s.unwrapKey(); s.decrypt(); };\n",
        };
        expect(checkArchitecture(files)).toEqual([]);
    });

    it('should allow a digest anywhere — it reads public data and names no key', () => {
        const files = { ...base, 'src/core/hash.ts': 'export const d = (s: { digest(a: string, b: Uint8Array): unknown }, b: Uint8Array): unknown => s.digest(\'SHA-256\', b);\n' };
        expect(checkArchitecture(files)).toEqual([]);
    });

    it('should not mistake an inherited property name for a key operation', () => {
        // `'toString' in KEY_OPERATION_POLICY` is true through the prototype
        // chain, and the value is a function — which threw a TypeError from
        // inside the checker rather than reporting anything. Same hazard the
        // engine's "no object keys from input" rule exists for.
        const files = { ...base, 'src/core/proto.ts': 'export const t = (o: { toString(): string; constructor: unknown }): string => o.toString();\n' };
        expect(checkArchitecture(files)).toEqual([]);
    });

    it('should let only the two declared modules reach globalThis.crypto', () => {
        const reach = 'export const s = (): unknown => (globalThis as { crypto?: unknown }).crypto;\n';
        expect(messages({ ...base, 'src/core/crypto.ts': reach })).toEqual([expect.stringContaining('`globalThis.crypto` is forbidden outside')]);
        expect(checkArchitecture({ ...base, 'src/crypto/webcrypto.ts': reach })).toEqual([]);
        expect(checkArchitecture({ ...base, 'src/hash/fingerprint.ts': reach })).toEqual([]);
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

    it('should refuse a bare catch outside BARE_CATCH_PROBES, and require the probe comment inside it', () => {
        // A catch that binds nothing cannot rethrow a TypeError: outside a
        // capability probe it would swallow a bug as a fact about the input.
        const bare = 'export const f = (g: () => void): boolean => { try { g(); return true; } catch { return false; } };\n';
        const probe = 'export const f = (g: () => void): boolean => { try { g(); return true; } catch {\n    // capability probe: every error means unavailable.\n    return false;\n} };\n';
        const bound = "import { _pkiError } from './guard.js';\nexport const f = (g: () => void): boolean => { try { g(); return true; } catch (error) { _pkiError(error); return false; } };\n";
        expect(messages({ ...base, 'src/core/probe.ts': probe })).toEqual([expect.stringContaining('a bare `catch {}` is allowed only in the capability probes of BARE_CATCH_PROBES')]);
        expect(checkArchitecture({ ...base, 'src/hash/fingerprint.ts': probe })).toEqual([]);
        expect(messages({ ...base, 'src/hash/fingerprint.ts': bare })).toEqual([expect.stringContaining('opens with a `// capability probe: …` comment')]);
        expect(checkArchitecture({ ...base, 'src/core/guard.ts': 'export const _pkiError = (e: unknown): unknown => e;\n', 'src/core/probe.ts': bound })).toEqual([]);
    });

    it('should list only files that exist, each with its reason', () => {
        for (const [path, reason] of BARE_CATCH_PROBES) {
            expect(statSync(join(ROOT, path)).isFile()).toBe(true);
            expect(reason.length).toBeGreaterThan(20);
        }
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
    });

    it('should refuse a file outside every layer and an unregistered layer', () => {
        expect(messages({ ...base, 'src/loose.ts': 'export const x = 1;\n' })).toEqual([expect.stringContaining('outside every layer')]);
        // A layer that will never exist: pkinative talks to no hardware
        // token. `crypto` served here until 0.3 registered it, at which
        // point the test would have passed for the wrong reason.
        expect(messages({ ...base, 'src/pkcs11/token.ts': 'export const x = 1;\n' })).toEqual([expect.stringContaining('layer "pkcs11" is not registered')]);
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
        expect(checkLayerParity(diagram(`${exact}\npkcs11 → core`))).toEqual([expect.objectContaining({ message: expect.stringContaining('"pkcs11"') })]);
        expect(checkLayerParity(null)[0].message).toContain('missing');
        expect(checkLayerParity('# nothing')[0].message).toContain('Architecture');
    });
});
