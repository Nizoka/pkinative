import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
    PACKAGE_FILES_MANIFEST,
    compareEntries,
    forbiddenReason,
    listFindings,
    manifestEntries,
    manifestShapeFindings,
    roleOf,
    type PackageFile,
    type PackageFilesManifest,
} from '../../scripts/lib/package-files.js';

// ── The tarball, file by file ────────────────────────────────────────
//
// scripts/package-files.ts runs these rules over a real `npm pack --dry-run`
// inside the check:package gate step; the package-files-parity rule of
// verify-docs runs them over the committed manifest. Both halves are only as
// good as the rules, so the rules are proven here on synthetic lists.

const ROOT = process.cwd();
const FILES = ['dist', 'LICENSE', 'README.md', 'CHANGELOG.md', 'SECURITY.md', 'THIRD-PARTY-NOTICES.md'];
const BUDGETED = ['dist/index.js', 'dist/index.js.map'];
const SHIPPED = ['CHANGELOG.md', 'LICENSE', 'README.md', 'SECURITY.md', 'THIRD-PARTY-NOTICES.md', 'dist/index.js', 'dist/index.js.map', 'package.json'];

describe('forbiddenReason', () => {
    it.each([
        'src/index.ts', 'tests/fixtures/certs/isrg-root-x1.der', 'dist/.env', '.npmrc', 'scripts/gate.ts',
        'dist/key.pem', 'pkinative-1.0.0.tgz', 'dist/index.test.js', 'dist/tsconfig.tsbuildinfo', 'coverage/lcov.info',
    ])('should refuse %s', (path) => {
        expect(forbiddenReason(path)).not.toBeNull();
    });

    it.each(SHIPPED)('should allow %s', (path) => {
        expect(forbiddenReason(path)).toBeNull();
    });
});

describe('listFindings', () => {
    it('should accept a list that matches package.json files and the budgets', () => {
        expect(listFindings(SHIPPED, FILES, BUDGETED)).toEqual([]);
    });

    it('should refuse a source map outside the budgeted list', () => {
        expect(listFindings([...SHIPPED, 'dist/index.cjs.map'], FILES, BUDGETED)).toEqual([
            'dist/index.cjs.map ships without a byte budget in docs/assets/ecosystem.json declared.bundle',
        ]);
    });

    it('should refuse a budget for a file that does not ship', () => {
        expect(listFindings(SHIPPED.filter((p) => p !== 'dist/index.js.map'), FILES, BUDGETED)).toEqual([
            'declared.bundle budgets dist/index.js.map, which does not ship',
        ]);
    });

    it('should refuse a file package.json does not declare, and a declaration that ships nothing', () => {
        expect(listFindings([...SHIPPED, 'NOTES.md'], FILES, BUDGETED)).toEqual(['NOTES.md ships but package.json "files" does not declare it']);
        expect(listFindings(SHIPPED, [...FILES, 'types'], BUDGETED)).toEqual(['package.json "files" declares types, which ships nothing']);
    });

    it('should refuse a test fixture even when package.json declares it', () => {
        const findings = listFindings([...SHIPPED, 'tests/fixtures/certs/isrg-root-x1.der'], [...FILES, 'tests'], BUDGETED);
        expect(findings[0]).toMatch(/^tests\/fixtures\/certs\/isrg-root-x1\.der must never ship/);
    });
});

describe('compareEntries', () => {
    const pinned: PackageFile[] = manifestEntries(SHIPPED.map((path) => ({ path, mode: 420 })), (p) => `text of ${p}`);

    it('should hash the legal texts and those only', () => {
        expect(pinned.filter((f) => f.sha256 !== undefined).map((f) => f.path)).toEqual(['LICENSE', 'THIRD-PARTY-NOTICES.md']);
        expect(manifestShapeFindings(pinned)).toEqual([]);
    });

    it('should report a file added, removed, made executable or a legal text changed', () => {
        const actual = manifestEntries(
            [...SHIPPED.filter((p) => p !== 'SECURITY.md'), 'dist/extra.js'].map((path) => ({ path, mode: path === 'dist/index.js' ? 493 : 420 })),
            (p) => (p === 'LICENSE' ? 'another licence' : `text of ${p}`),
        );
        const diff = compareEntries(pinned, actual);
        expect(diff).toContain('added: dist/extra.js');
        expect(diff).toContain('removed: SECURITY.md');
        expect(diff).toContain('mode changed: dist/index.js 420 → 493');
        expect(diff.some((l) => l.startsWith('content changed: LICENSE'))).toBe(true);
        expect(diff).toHaveLength(4);
    });
});

describe('manifestShapeFindings', () => {
    it('should refuse an unsorted list, a hand-written role and a hash outside the legal texts', () => {
        const findings = manifestShapeFindings([
            { path: 'dist/index.js', mode: 420, role: 'doc' },
            { path: 'README.md', mode: 420, role: 'doc', sha256: '0'.repeat(64) },
        ]);
        expect(findings).toEqual([
            'the files are not sorted by path',
            'dist/index.js has role doc, derived role is build',
            'README.md: a sha256 is pinned for the legal files and for them only',
        ]);
        expect(roleOf('package.json')).toBe('manifest');
    });
});

describe(PACKAGE_FILES_MANIFEST, () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, PACKAGE_FILES_MANIFEST), 'utf8')) as PackageFilesManifest;

    it('should pin exactly the twelve files 1.0 ships, source maps and .d.cts included', () => {
        // The source maps are budgeted on purpose (declared.bundle.$comment) and
        // the .d.cts is what `exports.require.types` names: both are intended.
        expect(manifest.files.map((f) => f.path)).toEqual([
            'CHANGELOG.md', 'LICENSE', 'README.md', 'SECURITY.md', 'THIRD-PARTY-NOTICES.md',
            'dist/index.cjs', 'dist/index.cjs.map', 'dist/index.d.cts', 'dist/index.d.ts', 'dist/index.js', 'dist/index.js.map',
            'package.json',
        ]);
        expect(manifest.files.every((f) => f.mode === 420)).toBe(true);
    });
});
