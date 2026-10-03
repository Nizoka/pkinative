import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AXE_INTEGRITY, AXE_TAGS, AXE_URL, AXE_VERSION, SCHEMES, harnessPage, sitePages, summarise, type Violation } from '../../scripts/a11y-check.js';

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));

describe('sitePages', () => {
    it('should list every HTML page of docs/ as a URL path, the landing page first, in a stable order', () => {
        const pages = sitePages(ROOT);
        expect(pages).toContain('/index.html');
        expect(pages).toContain('/guides/quickstart.html');
        expect(pages).toContain('/playground/index.html');
        expect(pages.every((p) => p.startsWith('/') && p.endsWith('.html'))).toBe(true);
        expect(pages).toEqual([...pages].sort());
        expect(pages.length).toBeGreaterThanOrEqual(12);
    });
});

describe('harnessPage', () => {
    it('should load axe-core from jsDelivr pinned by version and SRI, with crossorigin, and run the WCAG 2.2 A/AA tags in both palettes', () => {
        const html = harnessPage(['/index.html']);
        expect(AXE_URL).toBe(`https://cdn.jsdelivr.net/npm/axe-core@${AXE_VERSION}/axe.min.js`);
        expect(AXE_INTEGRITY).toMatch(/^sha384-[A-Za-z0-9+/]{64}$/);
        expect(html).toContain(`<script src="${AXE_URL}" integrity="${AXE_INTEGRITY}" crossorigin="anonymous"></script>`);
        expect(html).toContain(JSON.stringify(SCHEMES));
        expect(html).toContain(JSON.stringify(AXE_TAGS));
        expect(AXE_TAGS).toEqual(expect.arrayContaining(['wcag2a', 'wcag2aa', 'wcag22aa']));
        expect(html).toContain("setAttribute('data-theme', scheme)");
    });
});

describe('summarise', () => {
    const pages = ['/index.html', '/guides/x.html'];

    it('should pass only when every page rendered in every palette with no violation', () => {
        const { lines, exitCode } = summarise({ ok: true, agent: 'Chromium', pages: 4, violations: [] }, pages);
        expect(exitCode).toBe(0);
        expect(lines.filter((l) => l.startsWith('ok - '))).toHaveLength(4);
        expect(lines.at(-1)).toMatch(/^a11y: 2 page\(s\) × 2 palette\(s\) under axe-core 4\.13\.0 .* 0 violation\(s\) on Chromium$/);
    });

    it('should fail on one violation, naming the page, the palette, the rule and the first target', () => {
        const v: Violation = { page: '/guides/x.html', scheme: 'dark', id: 'color-contrast', impact: 'serious', help: 'Elements must meet minimum color contrast ratio thresholds', nodes: 3, target: '.hero p' };
        const { lines, exitCode } = summarise({ ok: true, agent: 'Chromium', pages: 4, violations: [v] }, pages);
        expect(exitCode).toBe(1);
        expect(lines).toContain('not ok - /guides/x.html (dark): 1 violation(s)');
        expect(lines.some((l) => l.includes('serious color-contrast') && l.includes('3 node(s), first .hero p'))).toBe(true);
        expect(lines).toContain('ok - /guides/x.html (light)');
    });

    it('should fail when the harness rendered fewer pages than expected, or did not report', () => {
        expect(summarise({ ok: true, agent: 'Chromium', pages: 3, violations: [] }, pages).exitCode).toBe(1);
        const failed = summarise({ ok: false, error: 'axe did not load' }, pages);
        expect(failed.exitCode).toBe(1);
        expect(failed.lines).toEqual(['not ok - browser: axe did not load']);
    });
});
