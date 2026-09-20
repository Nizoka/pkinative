/**
 * pkinative — sitemap (`npm run docs:sitemap`)
 * ============================================
 * Writes docs/sitemap.xml from the canonical URL every page under docs/
 * already declares. The file is pure derivation: `sitemap-parity` has always
 * computed the expected content, so leaving it hand-written reduced that rule
 * to a reminder for an edit it could have made itself.
 *
 * Nothing is invented here. A page that declares no `<link rel="canonical">`
 * is omitted and named on stderr, because `seo-head` already fails on it and
 * guessing its URL would hide that failure behind a plausible line.
 *
 * Run it after `docs:guides` (which creates the pages this reads) and before
 * `docs:llms` (which measures everything else). Inverted, `llms-index-sync`
 * and `sitemap-parity` contend for the same commit.
 *
 * @module scripts/build-sitemap
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GUIDES, SITE } from './build-guides.js';

/** Repository-relative POSIX paths of every `.html` file under `docs/`, sorted. */
export function htmlPagesOf(root: string): string[] {
    const out: string[] = [];
    const walk = (dir: string): void => {
        for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
            const full = join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.html')) out.push(relative(root, full).split(sep).join(posix.sep));
        }
    };
    walk(join(root, 'docs'));
    return out;
}

/**
 * Reading order, not alphabetical: the landing page, the guides index, the
 * guides in navigation order, then everything else. The `sitemap-parity` rule
 * sorts both sides before comparing, so this ordering is for the human who
 * opens the file — and it is the same order the nav presents.
 */
function rank(url: string): [number, string] {
    const path = url.slice(SITE.length);
    if (path === '/') return [0, ''];
    if (path === '/guides/') return [1, ''];
    const guide = /^\/guides\/([a-z-]+)\.html$/.exec(path)?.[1];
    if (guide !== undefined) {
        const at = GUIDES.indexOf(guide);
        return at >= 0 ? [2, String(at).padStart(3, '0')] : [3, path];
    }
    return [4, path];
}

/** The sitemap for a set of `path → html` pages. */
export function renderSitemap(pages: ReadonlyMap<string, string>): { xml: string; missing: readonly string[] } {
    const urls: string[] = [];
    const missing: string[] = [];
    for (const [path, html] of pages) {
        const canonical = /<link rel="canonical" href="([^"]+)">/.exec(html)?.[1];
        if (canonical === undefined) missing.push(path);
        else urls.push(canonical);
    }
    urls.sort((a, b) => {
        const [ra, sa] = rank(a);
        const [rb, sb] = rank(b);
        return ra - rb || sa.localeCompare(sb) || a.localeCompare(b);
    });
    const body = urls.map((url) => `  <url><loc>${url}</loc></url>`).join('\n');
    return { xml: `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${body}\n</urlset>\n`, missing };
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
    const root = join(dirname(fileURLToPath(import.meta.url)), '..');
    const pages = new Map(htmlPagesOf(root).map((path) => [path, readFileSync(join(root, path), 'utf8')]));
    const { xml, missing } = renderSitemap(pages);
    for (const path of missing) console.error(`build-sitemap: ${path} declares no canonical URL and is not listed`);
    const target = join(root, 'docs/sitemap.xml');
    const changed = readFileSync(target, 'utf8') !== xml;
    if (changed) writeFileSync(target, xml);
    console.error(`build-sitemap: ${String(pages.size - missing.length)} URL(s), ${changed ? 'written' : 'unchanged'}`);
}
