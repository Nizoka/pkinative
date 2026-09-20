import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { FOREIGN_MARKERS, probeBundle, probeDistFiles, type DistFile } from '../../scripts/lib/bundle-probe.ts';

// The forensic probe of what dist/ ships. Two halves: the predicates are fed
// synthetic bundles here, so each one is proved to fire, and the real dist/ is
// probed when a build is present — the gate builds before the suites, so
// GATE_REQUIRE_ARTIFACTS turns a missing dist/ there into a failure rather
// than a silent skip.

const ROOT = process.cwd();
const CLEAN = 'export function decodeAsn1(){ return globalThis.console && 1; }\n';

describe('probeBundle', () => {
    it('should accept a bundle that breaks no rule', () => {
        expect(probeBundle('clean.js', CLEAN)).toEqual([]);
    });

    it.each([
        ['a node: specifier', `import { readFileSync } from 'node:fs';${CLEAN}`, 'node:fs'],
        ['a require of a package', `${CLEAN}const x = require("lodash");`, 'no runtime dependency'],
        ['a bare import', `import { x } from 'lodash';${CLEAN}`, 'no runtime dependency'],
        ['a write to stdout', `${CLEAN}console.log("hi");`, 'never writes to stdout'],
        ['a second console reference', `${CLEAN}console.warn("hi");`, 'exactly once'],
        ['embedded binary data', `${CLEAN}const b = "${'A'.repeat(512)}";`, 'base64 run'],
        ['an embedded certificate', `${CLEAN}const p = "-----BEGIN CERTIFICATE-----";`, 'embedded PEM block'],
        ['dynamic evaluation', `${CLEAN}const f = new Function("return 1");`, 'unsafe-eval'],
    ])('should refuse %s', (_what, code, expected) => {
        const findings = probeBundle('probe.js', code);
        expect(findings.length, `no finding for ${_what}`).toBeGreaterThan(0);
        expect(findings.join('\n')).toContain(expected);
    });

    it.each(FOREIGN_MARKERS)('should refuse the foreign marker %s', (marker) => {
        expect(probeBundle('probe.js', `${CLEAN}// ${marker}\n`).join('\n')).toContain(JSON.stringify(marker));
    });
});

describe('probeDistFiles', () => {
    const budgets = { 'dist/index.d.ts': { maxBytes: 1000 } };
    const declaration = (body: string): DistFile => ({ path: 'dist/index.d.ts', text: body, bytes: body.length });

    it('should accept declarations that name every export', () => {
        const file = declaration('declare function decodeAsn1(): void;\ninterface Asn1Node {}\nexport { decodeAsn1, type Asn1Node };\n');
        expect(probeDistFiles([file], ['decodeAsn1', 'Asn1Node'], budgets)).toEqual([]);
    });

    it('should refuse a declaration file that drops a type export', () => {
        // The gap smoke:install cannot see: it loads runtime values only.
        const file = declaration('declare function decodeAsn1(): void;\nexport { decodeAsn1 };\n');
        expect(probeDistFiles([file], ['decodeAsn1', 'Asn1Node'], budgets).join('\n')).toContain('Asn1Node');
    });

    it('should refuse a file over its declared budget', () => {
        const file = declaration(`declare function f(): void;\nexport { f };\n// ${'x'.repeat(1000)}`);
        expect(probeDistFiles([file], ['f'], budgets).join('\n')).toContain('over the declared budget');
    });

    it('should refuse a shipped file that no budget covers', () => {
        const file: DistFile = { path: 'dist/extra.js', text: '', bytes: 0 };
        expect(probeDistFiles([file], [], {}).join('\n')).toContain('no entry of declared.bundle budgets it');
    });

    it('should refuse a budget for a file that is not there', () => {
        expect(probeDistFiles([], [], budgets).join('\n')).toContain('not present in dist/');
    });
});

const haveDist = existsSync(join(ROOT, 'dist', 'index.js'));
if (!haveDist && process.env['GATE_REQUIRE_ARTIFACTS'] === '1') {
    throw new Error('dist/index.js is missing but GATE_REQUIRE_ARTIFACTS=1: the gate builds before the suites, so this can only mean the build did not produce it — run `npm run build`');
}

describe.skipIf(!haveDist)('the bundles this repository ships', () => {
    const files: DistFile[] = readdirSync(join(ROOT, 'dist')).map((name) => {
        const path = `dist/${name}`;
        return { path, text: readFileSync(join(ROOT, path), 'utf8'), bytes: statSync(join(ROOT, path)).size };
    });
    const api = JSON.parse(readFileSync(join(ROOT, 'docs/assets/api.json'), 'utf8')) as { exports: Array<{ name: string }> };

    it.each(files.filter((f) => f.path.endsWith('.js') || f.path.endsWith('.cjs')))('$path breaks no bundle rule', (file) => {
        expect(probeBundle(file.path, file.text)).toEqual([]);
    });

    it('should declare every public export in both declaration files, types included', () => {
        const declarations = files.filter((f) => f.path.endsWith('.d.ts') || f.path.endsWith('.d.cts'));
        expect(declarations.length, 'dist/ carries no declaration file').toBe(2);
        expect(probeDistFiles(declarations, api.exports.map((e) => e.name), {})
            .filter((f) => f.includes('public exports'))).toEqual([]);
    });
});
