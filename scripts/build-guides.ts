/**
 * pkinative — guide pages (`npm run docs:guides`)
 * ===============================================
 * Renders every docs/guides/<name>.md into a complete, static
 * docs/guides/<name>.html page, plus docs/guides/index.html. The pages are
 * prerendered: no client-side Markdown, no JavaScript and no third-party
 * load at all, so there is nothing to pin with SRI and nothing a CSP must
 * allow.
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

/** Repository-relative POSIX path → text, or null when absent. */
export type Reader = (path: string) => string | null;

export const SITE = 'https://pkinative.dev';
export const REPOSITORY = 'https://github.com/Nizoka/pkinative';

/** The guides, in navigation order. */
export const GUIDES: readonly string[] = ['quickstart', 'security', 'conformance', 'errors', 'choose'];

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
          <h4>Project</h4>
          <ul>
            <li><a href="${REPOSITORY}" target="_blank" rel="noopener">GitHub</a></li>
            <li><a href="${REPOSITORY}/blob/main/SECURITY.md" target="_blank" rel="noopener">Security policy</a></li>
            <li><a href="${REPOSITORY}/blob/main/ROADMAP.md" target="_blank" rel="noopener">Roadmap</a></li>
            <li><a href="${REPOSITORY}/blob/main/CHANGELOG.md" target="_blank" rel="noopener">Changelog</a></li>
          </ul>
        </div>
        <div class="footer-col">
          <h4>Guides</h4>
          <ul>
${GUIDES.map((name) => `            <li><a href="${prefix}guides/${name}.html">${escapeHtml(guideNavLabel(name))}</a></li>`).join('\n')}
          </ul>
        </div>
        <div class="footer-col">
          <h4>For agents</h4>
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

function page(options: { title: string; description: string; path: string; body: string; current: string }): string {
    const url = `${SITE}/${options.path}`;
    const prism = prismTags();
    const isIndex = options.current === 'index';
    const breadcrumb = isIndex
        ? `<a href="../">Home</a> › Guides`
        : `<a href="../">Home</a> › <a href="./">Guides</a> › ${escapeHtml(options.title.replace(/ — pkinative$/, ''))}`;
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

/** One guide page. */
export function renderGuidePage(read: Reader, name: string): string {
    const md = lf(read(`docs/guides/${name}.md`) ?? '');
    const body = rewriteLinks(addHeadingAnchors(markdown.parse(md, { async: false }) as string)).trimEnd();
    return page({
        title: `${guideTitle(md)} — pkinative`,
        description: guideSummary(md),
        path: `guides/${name}.html`,
        body: `${body.split('\n').map((l) => (l === '' ? '' : `      ${l}`)).join('\n')}\n`,
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

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
    const root = join(dirname(fileURLToPath(import.meta.url)), '..');
    const read: Reader = (path) => (existsSync(join(root, path)) ? readFileSync(join(root, path), 'utf8') : null);
    let changed = 0;
    for (const [path, text] of guideOutputs(read)) {
        if (read(path) !== text) {
            writeFileSync(join(root, path), text);
            changed++;
        }
    }
    console.error(`build-guides: ${changed} page(s) written, ${GUIDES.length + 1} in total`);
}
