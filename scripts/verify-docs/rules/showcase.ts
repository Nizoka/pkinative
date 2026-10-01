/**
 * pkinative — showcase rules
 * ==========================
 * What the landing page and the playgrounds say about the library, held to
 * the source that knows: the architecture diagram to LAYERS
 * (`architecture-diagram`), the comparison table to the released version
 * (`comparison-current`), and every page's structured data to the page
 * itself (`structured-data`).
 *
 * @module scripts/verify-docs/rules/showcase
 */

import { architectureDescription, countWord, escapeHtml, renderArchitectureSvg } from '../../build-guides.js';
import { LAYERS } from '../../lib/architecture.js';
import { error, lineContaining, readJson, type Finding, type Rule } from '../context.js';

const lf = (text: string): string => text.replace(/\r\n/g, '\n');

const structuredData: Rule = {
    id: 'structured-data',
    summary: 'Every page under docs/ carries schema.org JSON-LD that parses, and a page with a visible breadcrumb carries a BreadcrumbList naming the same crumbs in the same order, its last item at the page\'s canonical URL.',
    check(ctx) {
        const out: Finding[] = [];
        for (const path of ctx.list('docs').filter((p) => p.endsWith('.html'))) {
            const html = lf(ctx.read(path) ?? '');
            const blocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map((m) => m[1] ?? '');
            if (blocks.length === 0) { out.push(error(path, 'carries no JSON-LD (<script type="application/ld+json">)')); continue; }
            const nodes: Array<Record<string, unknown>> = [];
            for (const block of blocks) {
                try {
                    const parsed = JSON.parse(block) as Record<string, unknown>;
                    if (parsed['@context'] !== 'https://schema.org') out.push(error(path, 'JSON-LD does not declare "@context": "https://schema.org"', lineContaining(html, 'ld+json')));
                    const graph = parsed['@graph'];
                    nodes.push(...(Array.isArray(graph) ? graph as Array<Record<string, unknown>> : [parsed]));
                } catch (err) {
                    out.push(error(path, `JSON-LD is not valid JSON — ${(err as Error).message}`, lineContaining(html, 'ld+json')));
                }
            }
            const crumbHtml = /<p class="guide-breadcrumb">([\s\S]*?)<\/p>/.exec(html)?.[1];
            if (crumbHtml === undefined) continue;
            const visible = crumbHtml.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').split('›').map((s) => s.trim());
            const list = nodes.find((n) => n['@type'] === 'BreadcrumbList');
            const items = (Array.isArray(list?.['itemListElement']) ? list['itemListElement'] as Array<{ name?: unknown; item?: unknown }> : []);
            const names = items.map((i) => String(i.name));
            if (names.join(' › ') !== visible.join(' › ')) {
                out.push(error(path, `its BreadcrumbList names ${names.length === 0 ? 'nothing' : names.join(' › ')}; the visible breadcrumb is ${visible.join(' › ')}`, lineContaining(html, 'guide-breadcrumb')));
            }
            const canonical = /<link rel="canonical" href="([^"]+)">/.exec(html)?.[1];
            const last = items[items.length - 1]?.item;
            if (items.length > 0 && last !== canonical) out.push(error(path, `its BreadcrumbList ends at ${String(last)}, not at the canonical URL ${String(canonical)}`));
        }
        return out;
    },
};

const architectureDiagram: Rule = {
    id: 'architecture-diagram',
    summary: 'docs/assets/architecture.svg is what scripts/build-guides.ts draws from LAYERS, the landing page\'s <img> of it carries the same description as its alt text, and the section subtitle states the layer count of LAYERS.',
    check(ctx) {
        const out: Finding[] = [];
        const svg = 'docs/assets/architecture.svg';
        if (lf(ctx.read(svg) ?? '') !== renderArchitectureSvg()) out.push(error(svg, 'stale or missing — run `npm run docs:guides`; it is drawn from LAYERS (scripts/lib/architecture.ts) and never edited by hand'));
        const html = lf(ctx.read('docs/index.html') ?? '');
        const img = /<img src="assets\/architecture\.svg"[^>]*>/.exec(html)?.[0];
        if (img === undefined) out.push(error('docs/index.html', 'does not show assets/architecture.svg'));
        else if (!img.includes(` alt="${escapeHtml(architectureDescription())}"`)) {
            out.push(error('docs/index.html', 'the architecture <img> alt is not architectureDescription() of scripts/build-guides.ts — paste the generated text, which describes LAYERS', lineContaining(html, 'assets/architecture.svg')));
        }
        const section = /<section[^>]*id="architecture"[\s\S]*?<\/section>/.exec(html)?.[0] ?? '';
        const count = Object.keys(LAYERS).length;
        if (!new RegExp(`\\b${countWord(count)} layers\\b`, 'i').test(section)) out.push(error('docs/index.html', `the architecture section does not say "${countWord(count)} layers"; LAYERS has ${String(count)}`, lineContaining(html, 'id="architecture"')));
        return out;
    },
};

/** `a.b.c` → [a, b, c]; missing parts count as zero. */
const parts = (version: string): number[] => version.split('.').map((p) => Number(p) || 0);
const atMost = (a: string, b: string): boolean => {
    const [x, y] = [parts(a), parts(b)];
    for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0);
    return true;
};

const comparisonCurrent: Rule = {
    id: 'comparison-current',
    summary: 'No cell of pkinative\'s own column in the landing page\'s comparison table quotes a version at or below the one package.json declares — "0.3" there means "not yet", which is false once 0.3 has shipped.',
    check(ctx) {
        const pkg = readJson<{ version?: string }>(ctx, 'package.json');
        if ('finding' in pkg) return [pkg.finding];
        const current = pkg.value.version ?? '0.0.0';
        const html = lf(ctx.read('docs/index.html') ?? '');
        const table = /<table class="cmp-table">[\s\S]*?<\/table>/.exec(html)?.[0];
        if (table === undefined) return [error('docs/index.html', 'has no comparison table (table.cmp-table)')];
        const column = (/<thead>[\s\S]*?<tr>([\s\S]*?)<\/tr>/.exec(table)?.[1] ?? '').match(/<th>[^<]*<\/th>/g)?.findIndex((th) => th === '<th>pkinative</th>') ?? -1;
        if (column < 0) return [error('docs/index.html', 'the comparison table has no pkinative column')];
        const out: Finding[] = [];
        for (const row of (/<tbody>([\s\S]*?)<\/tbody>/.exec(table)?.[1] ?? '').match(/<tr>[\s\S]*?<\/tr>/g) ?? []) {
            const cell = (row.match(/<td[^>]*>[\s\S]*?<\/td>/g) ?? [])[column] ?? '';
            const text = cell.replace(/<[^>]+>/g, '').trim();
            if (/^\d+\.\d+(\.\d+)?$/.test(text) && atMost(text, current)) {
                const feature = (row.match(/<td[^>]*>([\s\S]*?)<\/td>/)?.[1] ?? '').trim();
                out.push(error('docs/index.html', `the comparison says pkinative gets "${feature}" in ${text}, but package.json is at ${current} — it has shipped; say so`, lineContaining(html, row.slice(0, 60))));
            }
        }
        return out;
    },
};

export const SHOWCASE_RULES: readonly Rule[] = [structuredData, architectureDiagram, comparisonCurrent];
