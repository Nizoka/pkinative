import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GUIDE_INPUTS, checkGuides, extractTsFences, guideFiles, programOf, type Fence } from '../../scripts/check-guides.js';

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const fence = (code: string, line = 10): Fence => ({ file: 'docs/guides/x.md', line, code });

describe('extractTsFences', () => {
    it('should take every ```ts fence with its opening line, and nothing fenced otherwise', () => {
        const md = ['# T', '', '```ts', 'const a = 1;', '```', '', '```bash', 'npm i', '```', '', '```ts', 'const b = 2;', 'const c = 3;', '```', ''].join('\n');
        expect(extractTsFences('f.md', md)).toEqual([
            { file: 'f.md', line: 3, code: 'const a = 1;' },
            { file: 'f.md', line: 11, code: 'const b = 2;\nconst c = 3;' },
        ]);
        expect(extractTsFences('f.md', md.replace(/\n/g, '\r\n'))).toHaveLength(2);
    });
});

describe('programOf', () => {
    it('should declare every input the fence does not declare itself, and none it does', () => {
        const { text } = programOf(fence("import { parseCertificate } from 'pkinative';\nconst der = new Uint8Array();\nparseCertificate(der);"), new Set());
        expect(text).not.toContain('declare const der:');
        expect(text).toContain('declare const leaf: P.Certificate;');
        expect(text).toContain("import type * as P from 'pkinative';");
        expect(Object.keys(GUIDE_INPUTS)).toContain('der');
    });

    it('should continue the imports of the fences before it when the fence imports nothing, and never when it imports', () => {
        const continued = programOf(fence('parseCertificate(der);'), new Set(['parseCertificate', 'decodePem']));
        expect(continued.text).toContain("import { decodePem, parseCertificate } from 'pkinative';");
        const own = programOf(fence("import { decodePem } from 'pkinative';\ndecodePem(pemText);"), new Set(['parseCertificate']));
        expect(own.text).not.toContain('parseCertificate');
    });

    it('should compile a fence that returns early as the body of an async handler, with its imports hoisted, and a fence with exports as a module', () => {
        const handler = programOf(fence("import { parseCertificate } from 'pkinative';\nif (der.length === 0) return 'empty';\nparseCertificate(der);"), new Set());
        expect(handler.text).toMatch(/import \{ parseCertificate \} from 'pkinative';\n(declare const [^\n]+\n)+export async function handler\(\) \{/);
        expect(handler.text.trimEnd().endsWith('}')).toBe(true);
        const lines = handler.text.split('\n');
        expect(lines[handler.offset]).toBe('');
        expect(lines[handler.offset + 1]).toBe("if (der.length === 0) return 'empty';");
        const mod = programOf(fence('export function f(): number { return 1; }'), new Set());
        expect(mod.text).toContain('export {}; // docs/guides/x.md:10');
        expect(mod.text).not.toContain('async function handler');
    });
});

describe('checkGuides', () => {
    it('should compile every fence of the README and the guides against src/index.ts with lib ES2020 + DOM, with no error', () => {
        const { fences, findings } = checkGuides(ROOT, guideFiles(ROOT));
        expect(fences).toBeGreaterThan(20);
        expect(findings).toEqual([]);
    }, 60_000);
});
