import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The raster half of the social-image contract.
//
// verify-docs cannot make these assertions: scripts/verify-docs/context.ts
// excludes png from the in-memory tree (BINARY_EXTENSIONS), so a rule that
// read one would fail the perturbation suite's baseline, where no PNG exists.
// The text half — the SHA-256 that proves the PNG is not stale, and the meta
// tags that advertise it — is the `social-images` rule of npm run verify:docs.

const ROOT = process.cwd();
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
/**
 * 358 KB and 406 KB today — a diagonal gradient and a radial glow over a
 * dark ground, the same construction as the two sibling projects, whose own
 * cards weigh 360 KB and 400 KB. 600 KB is the point at which a card starts
 * costing the reader, and the headroom is deliberately thin: a second glow
 * or a noise texture would not fit, and should not be added without
 * measuring.
 */
const BUDGET_BYTES = 600 * 1024;

interface SocialImage {
    readonly svg: string;
    readonly png: string;
    readonly width: number;
    readonly height: number;
}

const manifest = JSON.parse(readFileSync(join(ROOT, 'docs', 'assets', 'ecosystem.json'), 'utf8')) as {
    declared: { socialImages: SocialImage[] };
};

describe('social images', () => {
    it('should declare at least the Open Graph card and the GitHub social preview', () => {
        expect(manifest.declared.socialImages.map((i) => i.png)).toEqual([
            'docs/assets/og-image.png',
            'docs/assets/social-preview.png',
        ]);
    });

    it.each(manifest.declared.socialImages)('should commit $png as a PNG of exactly $width×$height', (image) => {
        const bytes = readFileSync(join(ROOT, image.png));
        expect(bytes.subarray(0, 8), `${image.png} is not a PNG`).toEqual(PNG_SIGNATURE);
        // IHDR is the first chunk: width and height are big-endian at 16 and 20.
        // Reading them here keeps this zero-dependency, as the library is.
        expect(bytes.readUInt32BE(16), `${image.png} width`).toBe(image.width);
        expect(bytes.readUInt32BE(20), `${image.png} height`).toBe(image.height);
        expect(bytes.length, `${image.png} is over the ${BUDGET_BYTES} byte budget`).toBeLessThan(BUDGET_BYTES);
    });

    it.each(manifest.declared.socialImages)('should record in $svg the command that rasterises it', (image) => {
        const source = readFileSync(join(ROOT, image.svg), 'utf8');
        // ++ stands in for the double dash, so nothing in the file reads as a flag.
        expect(source, `${image.svg} has no header comment naming the raster command`)
            .toMatch(new RegExp(`\\+\\+window-size=${image.width},${image.height}`));
        expect(source).toContain('++screenshot=');
    });
});
