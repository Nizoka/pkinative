import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { consumerSource, floorVersion, FLOOR_CONFIGS } from '../../scripts/check-ts-floor.ts';

// The TypeScript consumer floor of ADR 0017. The compile itself needs the
// registry, so it runs in the publish profile; these are the parts a hermetic
// run can hold: the floor comes from the manifest, the consumer names every
// export, and the configurations are the ones the ADR and SECURITY.md promise.

const ROOT = process.cwd();
const manifest = JSON.parse(readFileSync(join(ROOT, 'docs', 'assets', 'ecosystem.json'), 'utf8')) as { contracts?: { support?: { typescript?: unknown } } };

describe('floorVersion', () => {
    it('should read the floor from contracts.support.typescript, the same value contracts-shape holds to SECURITY.md', () => {
        expect(floorVersion([], manifest)).toBe(manifest.contracts?.support?.typescript);
        expect(floorVersion([], manifest)).toMatch(/^5\.0\.\d+$/);
    });

    it('should prefer an explicit --typescript release, and refuse anything that is not one', () => {
        expect(floorVersion(['--typescript', '5.4.5'], manifest)).toBe('5.4.5');
        expect(floorVersion(['--typescript', 'latest'], manifest)).toBeNull();
        expect(floorVersion([], {})).toBeNull();
        expect(floorVersion([], { contracts: { support: { typescript: 5 } } })).toBeNull();
    });
});

describe('consumerSource', () => {
    it('should import every type as a type and every value as a value, so the floor compiler reads the whole surface', () => {
        const source = consumerSource([
            { name: 'parseCertificate', kind: 'function' },
            { name: 'Certificate', kind: 'type' },
            { name: 'PkiError', kind: 'class' },
            { name: 'DEFAULT_PKI_LIMITS', kind: 'const' },
        ]);
        expect(source).toContain("import type { Certificate } from 'pkinative';");
        expect(source).toContain("import { DEFAULT_PKI_LIMITS, PkiError, parseCertificate } from 'pkinative';");
        expect(source).toContain('export type Everything = [Certificate];');
        expect(source).toContain('export const everything = [DEFAULT_PKI_LIMITS, PkiError, parseCertificate] as const;');
    });

    it('should cover the real surface of docs/assets/api.json', () => {
        const api = JSON.parse(readFileSync(join(ROOT, 'docs', 'assets', 'api.json'), 'utf8')) as { exports: Array<{ name: string; kind: string }> };
        const source = consumerSource(api.exports);
        for (const e of api.exports) expect(source, e.name).toMatch(new RegExp(`[{ ,]${e.name}[,} ]`));
    });
});

describe('FLOOR_CONFIGS', () => {
    it('should compile under every moduleResolution ADR 0017 promises, and once without the DOM library', () => {
        expect(FLOOR_CONFIGS.map((c) => c.compilerOptions['moduleResolution'])).toEqual(['node16', 'bundler', 'node', 'node16']);
        const nodom = FLOOR_CONFIGS.find((c) => c.name === 'nodom');
        expect(nodom?.compilerOptions['lib']).toEqual(['es2020']);
        expect(nodom?.compilerOptions['exactOptionalPropertyTypes']).toBe(true);
    });
});
