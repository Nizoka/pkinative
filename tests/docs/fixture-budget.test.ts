import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

// Committed fixtures are foreign-provenance binaries (testing.instructions.md):
// each is listed with its SHA-256 in tests/fixtures/PROVENANCE.md, and the
// tree has a byte budget so hostile inputs keep being generated, not committed.

const ROOT = join(process.cwd(), 'tests', 'fixtures');
const BUDGET_BYTES = 512 * 1024;

function files(dir: string, prefix = ''): string[] {
    return readdirSync(dir).flatMap((entry) => {
        const path = join(dir, entry);
        const rel = prefix === '' ? entry : `${prefix}/${entry}`;
        return statSync(path).isDirectory() ? files(path, rel) : [rel];
    });
}

const provenance = readFileSync(join(ROOT, 'PROVENANCE.md'), 'utf8');
const rows = new Map([...provenance.matchAll(/^\| `([^`]+)` \|.*\| `([0-9a-f]{64})` \|/gm)].map((m) => [m[1] ?? '', m[2] ?? '']));
const binaries = files(ROOT).filter((f) => f !== 'PROVENANCE.md');

describe('tests/fixtures', () => {
    it('should stay under its byte budget', () => {
        const total = binaries.reduce((sum, f) => sum + statSync(join(ROOT, f)).size, 0);
        expect(total).toBeLessThanOrEqual(BUDGET_BYTES);
    });

    it('should list every committed file in PROVENANCE.md, and nothing that is not committed', () => {
        expect([...rows.keys()].sort()).toEqual([...binaries].sort());
    });

    it.each(binaries)('should hold %s with the SHA-256 PROVENANCE.md records', (file) => {
        expect(createHash('sha256').update(readFileSync(join(ROOT, file))).digest('hex')).toBe(rows.get(file));
    });
});
