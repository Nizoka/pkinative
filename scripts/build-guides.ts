/**
 * pkinative — guide pages (`npm run docs:guides`)
 * ===============================================
 * Renders every docs/guides/<name>.md into a complete, static
 * docs/guides/<name>.html page, plus docs/guides/index.html, and draws
 * docs/assets/architecture.svg from LAYERS. The pages are prerendered — no
 * client-side Markdown — and load two things besides the site stylesheets:
 * the first-party guides/guide.js (copy buttons, heading anchors) and Prism
 * from jsDelivr, pinned by SRI (`prismTags`, held by the `cdn-sri` rule).
 *
 * The Markdown is reproduced, not re-indented: the article body is written
 * at column 0, so a fenced block reaches the page — and the Copy button —
 * byte for byte, and an inline `<svg>` block passes through raw even when it
 * holds blank lines (`renderMarkdown`). Each page also carries schema.org
 * JSON-LD — a BreadcrumbList mirroring the visible breadcrumb, and a
 * TechArticle — as pdfnative's guides do, and like them without
 * dateModified: the only honest per-page date is not available here.
 *
 * Rendering is deterministic — marked@12.0.2 pinned as an EXACT
 * devDependency (zipnative's choice), LF endings, a GitHub-style slugger
 * shared with build-llms-full.ts — and pure: `guideOutputs(read)` returns
 * every page for a `Reader`, so the verify-docs rule `guide-render-sync`
 * rebuilds them in memory and compares byte for byte. Guide content is
 * first-party Markdown reviewed in the repository; no sanitiser runs.
 *
 * @module scripts/build-guides
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Marked } from 'marked';
import { LAYERS } from './lib/architecture.js';

/** Repository-relative POSIX path → text, or null when absent. */
export type Reader = (path: string) => string | null;

export const SITE = 'https://pkinative.dev';
export const REPOSITORY = 'https://github.com/Nizoka/pkinative';
export const NPM = 'https://www.npmjs.com/package/pkinative';

/** The guides, in navigation order. */
export const GUIDES: readonly string[] = ['quickstart', 'use-cases', 'security', 'conformance', 'errors', 'choose'];

const markdown = new Marked({ gfm: true, breaks: false });

const lf = (text: string): string => text.replace(/\r\n/g, '\n');

export function escapeHtml(text: string): string {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function decodeEntities(text: string): string {
    return text.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}

/** GitHub-style heading slugs: punctuation dropped, every whitespace character a hyphen. */
export function slugify(text: string): string {
    return decodeEntities(text.replace(/<[^>]+>/g, ''))
        .trim()
        .toLowerCase()
        .replace(/`/g, '')
        .replace(/[^\p{L}\p{N}\s_-]/gu, '')
        .replace(/\s/g, '-');
}

/** The H1 of a guide, without Markdown code marks. */
export function guideTitle(md: string): string {
    return (/^# (.+)$/m.exec(md)?.[1] ?? '').replace(/`/g, '').trim();
}

/** The lede: the blockquote right under the H1, as plain text. */
export function guideSummary(md: string): string {
    const lines = lf(md).split('\n');
    const h1 = lines.findIndex((l) => l.startsWith('# '));
    const lede: string[] = [];
    for (let i = h1 + 1; i < lines.length; i++) {
        const line = lines[i] ?? '';
        if (line.trim() === '' && lede.length === 0) continue;
        if (!line.startsWith('> ')) break;
        lede.push(line.slice(2).trim());
    }
    return lede.join(' ')
        .replace(/\*\*/g, '')
        .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
        .replace(/`/g, '')
        .trim();
}

/** `## ` and `### ` headings as slugs, in order — the anchors a link may target. */
export function guideAnchors(md: string): string[] {
    return lf(md).split('\n').filter((l) => /^#{2,3} /.test(l)).map((l) => slugify(l.replace(/^#{2,3} /, '')));
}

function addHeadingAnchors(html: string): string {
    const seen = new Map<string, number>();
    return html.replace(/<h([1-4])>([\s\S]*?)<\/h\1>/g, (_m, level: string, inner: string) => {
        let slug = slugify(inner) || 'section';
        const n = seen.get(slug) ?? 0;
        seen.set(slug, n + 1);
        if (n > 0) slug = `${slug}-${n}`;
        const anchor = level === '1' ? '' : ` <a class="heading-anchor" href="#${slug}" aria-label="Link to this section">#</a>`;
        return `<h${level} id="${slug}">${inner}${anchor}</h${level}>`;
    });
}

/** Guide-to-guide links point at the pages; repository files point at GitHub. */
function rewriteLinks(html: string): string {
    return html
        .replace(/href="([a-z-]+)\.md(#[^"]*)?"/g, (_m, name: string, hash: string | undefined) => `href="${name}.html${hash ?? ''}"`)
        .replace(/href="\.\.\/\.\.\/([^"]*)"/g, (_m, path: string) => `href="${REPOSITORY}/${path.endsWith('/') || path === '' ? 'tree' : 'blob'}/main/${path}"`)
        // Family parity with zipnative's externaliseLinks: an outbound link
        // from a guide opens in its own tab, and never with window.opener.
        .replace(/<a href="(https?:\/\/[^"]+)">/g, '<a href="$1" target="_blank" rel="noopener">');
}

/** Which section of the site a page belongs to, for `aria-current`. */
export type NavSection = 'guides' | 'playgrounds' | null;

/**
 * The chrome every page carries, generated here and only here.
 *
 * `prefix` is `''` for docs/index.html and `'../'` for anything one level
 * down. The hand-written pages paste the output of these functions verbatim,
 * and the `chrome-parity` rule proves they still match — which is what lets
 * the landing page stay hand-written without the nav drifting from the
 * generated guides.
 *
 * @internal Exported for `chrome-parity`, not for general use.
 */
export function navHtml(prefix: string, current: NavSection): string {
    const mark = (section: NavSection): string => (section === current ? ' aria-current="page"' : '');
    return `  <nav class="nav" aria-label="Main">
    <div class="nav-inner">
      <a class="nav-brand" href="${prefix === '' ? './' : prefix}"><img src="${prefix}assets/logo.svg" alt="" width="28" height="28">pkinative</a>
      <button class="nav-hamburger" aria-label="Toggle menu" aria-expanded="false">☰</button>
      <ul class="nav-links" role="list">
        <li><a href="${prefix}#features">Features</a></li>
        <li><a href="${prefix}#examples">Examples</a></li>
        <li><a href="${prefix}#comparison">Compare</a></li>
        <li><a href="${prefix}#benchmarks">Benchmarks</a></li>
        <li><a href="${prefix}#architecture">Architecture</a></li>
        <li><a href="${prefix}guides/"${mark('guides')}>Guides</a></li>
        <li><a href="${prefix}playground/"${mark('playgrounds')}>Playground</a></li>
        <li><a href="${prefix}llms.txt">llms.txt</a></li>
        <li><a href="${REPOSITORY}" target="_blank" rel="noopener">GitHub</a></li>
        <li><button class="theme-toggle" aria-label="Toggle theme" aria-pressed="false">🌙</button></li>
      </ul>
    </div>
  </nav>`;
}

/**
 * @param extra Appended inside the meta line. The landing page carries the
 *   audit date there (`verified-on-parity` requires it and
 *   `release-prepare.ts` rewrites it); the guides carry nothing.
 * @internal Exported for `chrome-parity`.
 */
export function footerHtml(prefix: string, extra = ''): string {
    return `  <footer class="footer">
    <div class="footer-inner">
      <div class="footer-cols">
        <div class="footer-col">
          <h2 class="footer-title">Project</h2>
          <ul>
            <li><a href="${REPOSITORY}" target="_blank" rel="noopener">GitHub</a></li>
            <li><a href="${NPM}" target="_blank" rel="noopener">npm</a></li>
            <li><a href="${REPOSITORY}/blob/main/SECURITY.md" target="_blank" rel="noopener">Security policy</a></li>
            <li><a href="${REPOSITORY}/blob/main/ROADMAP.md" target="_blank" rel="noopener">Roadmap</a></li>
            <li><a href="${REPOSITORY}/blob/main/CHANGELOG.md" target="_blank" rel="noopener">Changelog</a></li>
            <li><a href="${REPOSITORY}/blob/main/docs/adr/README.md" target="_blank" rel="noopener">Decision records</a></li>
            <li><a href="https://pdfnative.dev" target="_blank" rel="noopener">Sibling: pdfnative</a></li>
            <li><a href="https://zipnative.dev" target="_blank" rel="noopener">Sibling: zipnative</a></li>
          </ul>
        </div>
        <div class="footer-col">
          <h2 class="footer-title">Guides</h2>
          <ul>
${GUIDES.map((name) => `            <li><a href="${prefix}guides/${name}.html">${escapeHtml(guideNavLabel(name))}</a></li>`).join('\n')}
          </ul>
        </div>
        <div class="footer-col">
          <h2 class="footer-title">For agents</h2>
          <ul>
            <li><a href="${prefix}llms.txt">llms.txt</a></li>
            <li><a href="${prefix}llms-full.txt">llms-full.txt</a></li>
            <li><a href="${prefix}agent-brief.md">Agent brief</a></li>
            <li><a href="${prefix}assets/api.json">api.json</a></li>
          </ul>
        </div>
      </div>
      <div class="footer-meta">
        <span>MIT License · © 2026 Nizoka${extra}</span>
        <ul class="footer-links" role="list">
          <li><a href="${prefix}sitemap.xml">Sitemap</a></li>
          <li><a href="${prefix}guides/">All guides</a></li>
        </ul>
      </div>
    </div>
  </footer>`;
}

/**
 * Prism, pinned by SRI.
 *
 * The guides fence only `ts` and `bash`, so these three files are the whole
 * set; a new language means a new tag and a new hash, computed with
 * `curl -sL <url> | openssl dgst -sha384 -binary | openssl base64 -A` —
 * never guessed. The `cdn-sri` rule fails on any remote load without
 * `integrity` and `crossorigin`.
 *
 * @internal Exported for `chrome-parity`.
 */
export function prismTags(): { head: string; tail: string } {
    return {
        head: '  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism-tomorrow.min.css" integrity="sha384-wFjoQjtV1y5jVHbt0p35Ui8aV8GVpEZkyF99OXWqP/eNJDU93D3Ugxkoyh6Y2I4A" crossorigin="anonymous">',
        tail: [
            '  <script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js" integrity="sha384-BGaNxfftg+9+TtC098wxawPFVEUpKYvaiCgbB0iqAMjK/4jDdmUY+oGxrPNvnXEf" crossorigin="anonymous" defer></script>',
            '  <script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-typescript.min.js" integrity="sha384-PeOqKNW/piETaCg8rqKFy+Pm6KEk7e36/5YZE5XO/OaFdO+/Aw3O8qZ9qDPKVUgx" crossorigin="anonymous" defer></script>',
            '  <script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-bash.min.js" integrity="sha384-9WmlN8ABpoFSSHvBGGjhvB3E/D8UkNB9HpLJjBQFC2VSQsM1odiQDv4NbEo+7l15" crossorigin="anonymous" defer></script>',
        ].join('\n'),
    };
}

/** The label a guide carries in the nav, the footer and the index. */
function guideNavLabel(name: string): string {
    return name === 'quickstart' ? 'Quick start' : `${name[0]?.toUpperCase() ?? ''}${name.slice(1).replace(/-/g, ' ')}`;
}

/** One `ListItem` of a schema.org BreadcrumbList: the visible label and its URL. */
export interface Crumb {
    readonly name: string;
    readonly url: string;
}

/** The schema.org BreadcrumbList that mirrors a visible breadcrumb, crumb for crumb. */
export function breadcrumbList(crumbs: readonly Crumb[]): Record<string, unknown> {
    return {
        '@type': 'BreadcrumbList',
        itemListElement: crumbs.map((crumb, i) => ({ '@type': 'ListItem', position: i + 1, name: crumb.name, item: crumb.url })),
    };
}

/** The publisher every page names: the project, with its logo. */
const PUBLISHER = {
    '@type': 'Organization',
    name: 'pkinative',
    url: `${SITE}/`,
    logo: { '@type': 'ImageObject', url: `${SITE}/assets/logo.svg` },
};

/**
 * A `<script type="application/ld+json">` block for a schema.org @graph.
 * `<` is escaped so no string in the graph can close the script element.
 *
 * @internal Exported for the hand-written playground pages' generator check.
 */
export function jsonLdBlock(graph: ReadonlyArray<Record<string, unknown>>): string {
    const json = JSON.stringify({ '@context': 'https://schema.org', '@graph': graph }, null, 2).replace(/</g, '\\u003c');
    return `  <script type="application/ld+json">\n${json.split('\n').map((l) => `  ${l}`).join('\n')}\n  </script>`;
}

function page(options: { title: string; description: string; path: string; body: string; current: string }): string {
    const url = `${SITE}/${options.path}`;
    const prism = prismTags();
    const isIndex = options.current === 'index';
    const heading = options.title.replace(/ — pkinative$/, '');
    const breadcrumb = isIndex
        ? `<a href="../">Home</a> › Guides`
        : `<a href="../">Home</a> › <a href="./">Guides</a> › ${escapeHtml(heading)}`;
    const crumbs: Crumb[] = [{ name: 'Home', url: `${SITE}/` }, { name: 'Guides', url: `${SITE}/guides/` }];
    if (!isIndex) crumbs.push({ name: heading, url });
    const ld = jsonLdBlock([
        breadcrumbList(crumbs),
        isIndex
            ? { '@type': 'CollectionPage', '@id': url, url, name: heading, description: options.description, inLanguage: 'en', isPartOf: { '@type': 'WebSite', name: 'pkinative', url: `${SITE}/` } }
            : {
                '@type': 'TechArticle',
                headline: heading,
                description: options.description,
                inLanguage: 'en',
                author: { '@type': 'Organization', name: 'Nizoka', url: 'https://github.com/Nizoka' },
                publisher: PUBLISHER,
                image: `${SITE}/assets/og-image.png`,
                mainEntityOfPage: { '@type': 'WebPage', '@id': url },
                isPartOf: { '@type': 'WebSite', name: 'pkinative', url: `${SITE}/` },
            },
    ]);
    const markdownAlternate = isIndex ? '' : `\n  <link rel="alternate" type="text/markdown" href="${options.current}.md" title="Markdown source">`;
    const articleAttrs = isIndex ? '' : ` data-md="${options.current}.md" data-prerendered="true"`;
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(options.title)}</title>
  <meta name="description" content="${escapeHtml(options.description)}">
  <meta name="robots" content="index, follow">
  <meta name="theme-color" content="#2563eb">
  <meta property="og:type" content="article">
  <meta property="og:site_name" content="pkinative">
  <meta property="og:locale" content="en_US">
  <meta property="og:url" content="${url}">
  <meta property="og:title" content="${escapeHtml(options.title)}">
  <meta property="og:description" content="${escapeHtml(options.description)}">
  <meta property="og:image" content="${SITE}/assets/og-image.png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${escapeHtml(options.title)}">
  <meta name="twitter:description" content="${escapeHtml(options.description)}">
  <meta name="twitter:image" content="${SITE}/assets/og-image.png">
  <link rel="canonical" href="${url}">
  <link rel="alternate" hreflang="en" href="${url}">
  <link rel="alternate" hreflang="x-default" href="${url}">${markdownAlternate}
  <link rel="alternate" type="text/plain" href="../llms.txt" title="llms.txt">
  <link rel="icon" type="image/svg+xml" href="../favicon.svg">
  <link rel="stylesheet" href="../style.css">
  <link rel="stylesheet" href="guide.css">
${prism.head}
${ld}
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to content</a>
${navHtml('../', 'guides')}
  <main class="guide-shell" id="main-content" tabindex="-1">
    <p class="guide-breadcrumb">${breadcrumb}</p>
    <article id="guide-content" class="guide-content"${articleAttrs}>
${options.body}    </article>
  </main>
${footerHtml('../')}
${prism.tail}
  <script src="guide.js" defer></script>
</body>
</html>
`;
}

/**
 * Markdown to HTML, with every inline `<svg>…</svg>` block kept raw.
 *
 * CommonMark ends an HTML block at the first blank line, so an SVG laid out
 * with blank lines between its groups would otherwise be cut in two and its
 * indented remainder rendered as an escaped code block. Each block that
 * starts a line with `<svg` and ends one with `</svg>` is set aside, replaced
 * by an HTML comment (a block of its own), and put back verbatim afterwards.
 */
export function renderMarkdown(md: string): string {
    const figures: string[] = [];
    const parked = lf(md).replace(/^<svg\b[\s\S]*?^<\/svg>[ \t]*$/gm, (block) => {
        figures.push(block);
        return `<!--pkinative:raw-svg:${figures.length - 1}-->`;
    });
    const html = rewriteLinks(addHeadingAnchors(markdown.parse(parked, { async: false }) as string));
    return html.replace(/<!--pkinative:raw-svg:(\d+)-->/g, (_m, index: string) => figures[Number(index)] ?? '');
}

/** One guide page. */
export function renderGuidePage(read: Reader, name: string): string {
    const md = lf(read(`docs/guides/${name}.md`) ?? '');
    return page({
        title: `${guideTitle(md)} — pkinative`,
        description: guideSummary(md),
        path: `guides/${name}.html`,
        body: `${renderMarkdown(md).trimEnd()}\n`,
        current: name,
    });
}

/** docs/guides/index.html: every guide with its lede. */
export function renderGuidesIndex(read: Reader): string {
    const items = GUIDES.map((name) => {
        const md = lf(read(`docs/guides/${name}.md`) ?? '');
        return `        <li><a href="${name}.html">${escapeHtml(guideTitle(md))}</a>`
            + `<span class="guide-toc-desc">${escapeHtml(guideSummary(md))}</span></li>`;
    }).join('\n');
    return page({
        title: 'Guides — pkinative',
        description: 'The pkinative guides: quick start, security model, conformance, errors and diagnostics, and choosing a PKI library.',
        // The URL, not the output path: under `cleanUrls` (npm run docs:serve,
        // and most static hosts) /guides/index.html is served at /guides, which
        // loses a path segment and 404s every relative stylesheet.
        path: 'guides/',
        body: `      <h1 id="guides">Guides</h1>\n      <p>Each guide is also plain Markdown for agents: replace <code>.html</code> with <code>.md</code>, or read them all in <a href="../llms-full.txt">llms-full.txt</a>.</p>\n      <ul class="guide-toc-list">\n${items}\n      </ul>\n`,
        current: 'index',
    });
}

/** Every generated page, path → content. */
export function guideOutputs(read: Reader): ReadonlyMap<string, string> {
    const out = new Map<string, string>();
    for (const name of GUIDES) out.set(`docs/guides/${name}.html`, renderGuidePage(read, name));
    out.set('docs/guides/index.html', renderGuidesIndex(read));
    return out;
}

// ── Architecture diagram ─────────────────────────────────────────────

/**
 * The imports AGENTS.md §Architecture refuses by name, each a decision rather
 * than an absence. `renderArchitectureSvg` throws if LAYERS ever grants one.
 */
export const REFUSED_IMPORTS: ReadonlyArray<readonly [from: readonly string[], to: string]> = [
    [['x509'], 'oid'],
    [['pem'], 'asn1'],
    [['crypto', 'build'], 'x509'],
    [['path', 'cms'], 'crypto'],
    [['keys'], 'x509'],
];

/**
 * Where each layer sits: a row (0 = the top, src/index.ts) and a column of
 * seven. Hand-placed so that no arrow runs through a box; a layer added to
 * LAYERS without a place here makes the generator throw, which is the point
 * — a new layer is a reviewed change to the picture too.
 */
const ARCHITECTURE_PLACES: Readonly<Record<string, readonly [row: number, column: number]>> = {
    index: [0, 3], oid: [0, 5],
    verify: [1, 3],
    revocation: [2, 2], cms: [2, 4],
    path: [3, 1], build: [3, 3], keys: [3, 6],
    x509: [4, 2], crypto: [4, 4],
    pem: [5, 0], asn1: [5, 3], hash: [5, 5],
    core: [6, 3],
    types: [7, 3],
};

/** A layer's nearest dependencies: LAYERS without the imports another import already reaches. */
export function nearestDependencies(layer: string): string[] {
    const reach = (from: string, seen = new Set<string>()): Set<string> => {
        for (const next of LAYERS[from] ?? []) if (!seen.has(next)) { seen.add(next); reach(next, seen); }
        return seen;
    };
    const direct = layer === 'index' ? Object.keys(LAYERS) : [...(LAYERS[layer] ?? [])];
    return direct.filter((d) => !direct.some((other) => other !== d && reach(other).has(d)));
}

const NUMBER_NAMES = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty'];

/** A count as prose writes it: a word up to twenty, digits beyond. */
export function countWord(n: number): string {
    return NUMBER_NAMES[n] ?? String(n);
}

function listWords(items: readonly string[], joiner = 'and'): string {
    return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} ${joiner} ${items[items.length - 1] ?? ''}`;
}

/**
 * The diagram's long description, derived from LAYERS — also the `alt` of the
 * landing page's `<img>` (`architecture-diagram` holds both to it).
 */
export function architectureDescription(): string {
    const layers = Object.keys(LAYERS);
    const sentences = layers.map((layer) => {
        const deps = LAYERS[layer] ?? [];
        return `${layer} imports ${deps.length === 0 ? 'nothing' : listWords(deps)}.`;
    });
    const refused = REFUSED_IMPORTS.map(([from, to]) => `${listWords(from)} never ${from.length > 1 ? 'import' : 'imports'} ${to}`);
    return `The ${countWord(layers.length)} pkinative layers. src/index.ts imports every layer, and nothing imports it. ${sentences.join(' ')} `
        + `Refused on purpose: ${refused.join('; ')}.`;
}

/** docs/assets/architecture.svg, drawn from LAYERS. */
export function renderArchitectureSvg(): string {
    const layers = Object.keys(LAYERS);
    for (const layer of [...layers, 'index']) {
        if (ARCHITECTURE_PLACES[layer] === undefined) throw new Error(`build-guides: layer "${layer}" has no place in ARCHITECTURE_PLACES — add one, then look at the picture`);
    }
    for (const [from, to] of REFUSED_IMPORTS) {
        for (const layer of from) if ((LAYERS[layer] ?? []).includes(to)) throw new Error(`build-guides: LAYERS lets ${layer} import ${to}, which AGENTS.md refuses`);
    }
    const W = 116, H = 36, STEP = 64, TOP = 32;
    const x = (column: number): number => 90 + column * 130;
    const y = (row: number): number => TOP + row * STEP;
    const at = (layer: string): { cx: number; top: number; bottom: number; row: number } => {
        const [row, column] = ARCHITECTURE_PLACES[layer] ?? [0, 0];
        return { cx: x(column), top: y(row), bottom: y(row) + H, row };
    };
    // Sources that share a row take distinct horizontal lanes in the gap below
    // it, so two buses never run along the same line.
    const lane = new Map<string, number>();
    const byRow = new Map<number, string[]>();
    for (const layer of ['index', ...layers]) {
        const { row } = at(layer);
        byRow.set(row, [...(byRow.get(row) ?? []), layer]);
    }
    for (const group of byRow.values()) group.forEach((layer, i) => lane.set(layer, 8 + ((i * 7) % 21)));

    const edges: string[] = [];
    for (const from of ['index', ...layers]) {
        for (const to of nearestDependencies(from)) {
            const a = at(from), b = at(to);
            if (a.row === b.row) {
                const dir = Math.sign(b.cx - a.cx);
                edges.push(`<path class="edge" d="M${a.cx + dir * W / 2} ${a.top + H / 2}H${b.cx - dir * (W / 2 + 4)}"/>`);
            } else if (a.cx === b.cx) {
                edges.push(`<path class="edge" d="M${a.cx} ${a.bottom}V${b.top - 4}"/>`);
            } else {
                const mid = a.bottom + (lane.get(from) ?? 14);
                edges.push(`<path class="edge" d="M${a.cx} ${a.bottom}V${mid}H${b.cx}V${b.top - 4}"/>`);
            }
        }
    }
    const boxes = ['index', ...layers].map((layer) => {
        const { cx, top } = at(layer);
        const label = layer === 'index' ? 'src/index.ts' : layer;
        const cls = layer === 'index' ? 'top' : layer === 'oid' ? 'box apart' : 'box';
        return `  <rect class="${cls}" x="${cx - W / 2}" y="${top}" width="${W}" height="${H}" rx="8"/>\n`
            + `  <text class="${layer === 'index' ? 'top-label' : 'label'}" x="${cx}" y="${top + 23}">${label}</text>`;
    }).join('\n');
    const height = y(7) + H + 92;
    const refused = REFUSED_IMPORTS.map(([from, to]) => `${from.join(' or ')} to ${to}`).join(' · ');
    const oid = at('oid');
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 ${height}" width="960" height="${height}" role="img" aria-labelledby="architecture-title architecture-desc">
  <!-- Generated by scripts/build-guides.ts from LAYERS (scripts/lib/architecture.ts); run npm run docs:guides, never edit by hand. -->
  <title id="architecture-title">pkinative layers</title>
  <desc id="architecture-desc">${escapeHtml(architectureDescription())}</desc>
  <style>
    .canvas { fill: #ffffff; stroke: #e2e8f0; stroke-width: 1; }
    .box { fill: #eff6ff; stroke: #2563eb; stroke-width: 1.5; }
    .apart { stroke-dasharray: 5 4; }
    .top { fill: #2563eb; stroke: #1d4ed8; stroke-width: 1.5; }
    .label { font: 600 16px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; fill: #0f172a; text-anchor: middle; }
    .top-label { font: 600 16px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; fill: #ffffff; text-anchor: middle; }
    .note { font: 14px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; fill: #475569; }
    .edge { stroke: #64748b; stroke-width: 1.5; fill: none; marker-end: url(#arrow); }
  </style>
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0 0 10 5 0 10Z" fill="#64748b"/>
    </marker>
  </defs>
  <rect class="canvas" x="0.5" y="0.5" width="959" height="${height - 1}" rx="12"/>
${edges.map((e) => `  ${e}`).join('\n')}
${boxes}
  <text class="note" x="${oid.cx + W / 2 + 12}" y="${oid.top + 15}">imports nothing; only</text>
  <text class="note" x="${oid.cx + W / 2 + 12}" y="${oid.top + 33}">getOidName pulls it in</text>
  <text class="note" x="32" y="${height - 56}">Arrows point at each layer's nearest dependencies; AGENTS.md §Architecture lists every permitted import.</text>
  <text class="note" x="32" y="${height - 30}">Imports refused on purpose: ${refused}.</text>
</svg>
`;
}

/** Every generated site asset besides the guide pages, path → content. */
export function siteAssetOutputs(): ReadonlyMap<string, string> {
    return new Map([['docs/assets/architecture.svg', renderArchitectureSvg()]]);
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
    const root = join(dirname(fileURLToPath(import.meta.url)), '..');
    const read: Reader = (path) => (existsSync(join(root, path)) ? readFileSync(join(root, path), 'utf8') : null);
    let changed = 0;
    for (const [path, text] of [...guideOutputs(read), ...siteAssetOutputs()]) {
        if (read(path) !== text) {
            writeFileSync(join(root, path), text);
            changed++;
        }
    }
    console.error(`build-guides: ${changed} page(s) written, ${GUIDES.length + 1} in total`);
}
