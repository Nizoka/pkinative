import { describe, it, expect } from 'vitest';
import { architectureDescription, countWord, nearestDependencies, renderArchitectureSvg, renderGuidePage, renderMarkdown, type Reader } from '../../scripts/build-guides.js';
import { renderSitemap } from '../../scripts/build-sitemap.js';
import { LAYERS } from '../../scripts/lib/architecture.js';

/**
 * The site generators reproduce what they are given. Two defects of the 1.0
 * audit were the renderer rewriting its input — every code block re-indented
 * by six spaces, and an inline SVG with blank lines cut into an escaped code
 * block — and neither is visible to a byte-for-byte sync rule, which compares
 * the generator with itself.
 */

const FENCE = '```';

describe('renderMarkdown', () => {
    it('should keep an inline SVG with blank lines raw, byte for byte', () => {
        const svg = '<svg viewBox="0 0 10 10" role="img" class="guide-figure">\n  <g>\n    <rect x="1" y="1" width="2" height="2"/>\n\n    <text x="5" y="5">label</text>\n  </g>\n\n  <path d="M0 0H1"/>\n</svg>';
        const html = renderMarkdown(`# Title\n\nBefore.\n\n${svg}\n\nAfter.\n`);
        expect(html).toContain(svg);
        expect(html).not.toContain('&lt;rect');
        expect(html).not.toContain('<pre>');
        expect(html).toContain('<p>After.</p>');
    });

    it('should leave a fenced block exactly as the Markdown wrote it', () => {
        const code = 'const a = 1;\nif (a) {\n    console.log(a);\n}';
        const page = renderGuidePage(((path: string) => (path.endsWith('.md') ? `# T\n\n> Lede of the page.\n\n${FENCE}ts\n${code}\n${FENCE}\n` : null)) as Reader, 'quickstart');
        expect(page).toContain(`<pre><code class="language-ts">${code}\n</code></pre>`);
    });
});

describe('renderGuidePage', () => {
    it('should carry a BreadcrumbList that mirrors the visible breadcrumb, and a TechArticle without dateModified', () => {
        const page = renderGuidePage(((path: string) => (path.endsWith('.md') ? '# Errors\n\n> What every code means and what to do about it.\n' : null)) as Reader, 'errors');
        const ld = JSON.parse(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(page)?.[1] ?? '{}') as { '@graph': Array<Record<string, unknown>> };
        const crumbs = ld['@graph'].find((n) => n['@type'] === 'BreadcrumbList') as { itemListElement: Array<{ name: string; item: string }> };
        expect(crumbs.itemListElement.map((c) => c.name)).toEqual(['Home', 'Guides', 'Errors']);
        expect(crumbs.itemListElement[2]?.item).toBe('https://pkinative.dev/guides/errors.html');
        const article = ld['@graph'].find((n) => n['@type'] === 'TechArticle');
        expect(article).toMatchObject({ headline: 'Errors', inLanguage: 'en' });
        expect(article).not.toHaveProperty('dateModified');
    });
});

describe('architecture diagram', () => {
    it('should draw every layer of LAYERS and describe every permitted import', () => {
        const svg = renderArchitectureSvg();
        for (const layer of Object.keys(LAYERS)) expect(svg).toContain(`>${layer}</text>`);
        const description = architectureDescription();
        expect(description).toContain(`The ${countWord(Object.keys(LAYERS).length)} pkinative layers.`);
        expect(description).toContain('x509 imports types, core and asn1.');
        expect(description).toContain('x509 never imports oid');
    });

    it('should draw only the nearest dependencies, so an import reached through another is not a second arrow', () => {
        expect(nearestDependencies('build')).toEqual(['hash', 'crypto']);
        expect(nearestDependencies('index')).toEqual(['pem', 'oid', 'verify']);
        expect(nearestDependencies('types')).toEqual([]);
    });
});

describe('renderSitemap', () => {
    it('should stamp every URL with the audit date', () => {
        const pages = new Map([
            ['docs/index.html', '<link rel="canonical" href="https://pkinative.dev/">'],
            ['docs/playground/asn1.html', '<link rel="canonical" href="https://pkinative.dev/playground/asn1.html">'],
            ['docs/orphan.html', '<p>no canonical</p>'],
        ]);
        const { xml, missing } = renderSitemap(pages, '2026-09-29');
        expect(xml).toContain('<url><loc>https://pkinative.dev/</loc><lastmod>2026-09-29</lastmod></url>');
        expect(xml.match(/<lastmod>2026-09-29<\/lastmod>/g)).toHaveLength(2);
        expect(missing).toEqual(['docs/orphan.html']);
    });
});
