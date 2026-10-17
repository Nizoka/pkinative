/**
 * pkinative — documentation and site rules
 * ========================================
 * Generated files stay generated (`guide-render-sync`, `llms-sync`,
 * `llms-index-sync`) and read well (`llms-index-quality`); links and anchors
 * resolve (`internal-links`, `anchor-parity`); every page carries its search
 * and social metadata (`seo-head`, `sitemap-parity`, `jsonld-version`,
 * `verified-on-parity`); the docs name
 * only real exports (`api-exists`) and quote only real numbers
 * (`count-tokens`); release notes have their mandatory sections
 * (`release-notes`).
 *
 * @module scripts/verify-docs/rules/site
 */

import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import ts from 'typescript';
import { ENGINE_SOURCE_SLOT, footerHtml, GUIDES, guideAnchors, guideOutputs, isRedirectStub, navHtml, PLAYGROUNDS, SITE, switcherHtml, type NavSection, type Reader } from '../../build-guides.js';
import { llmsOutputs } from '../../build-llms-full.js';
import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

const reader = (ctx: RuleContext): Reader => (path) => ctx.read(path);

const MANIFEST = 'docs/assets/ecosystem.json';

function generatedSync(id: string, summary: string, outputs: (read: Reader) => ReadonlyMap<string, string>, only: (path: string) => boolean, command: string): Rule {
    return {
        id,
        summary,
        check(ctx) {
            const out: Finding[] = [];
            for (const [path, text] of outputs(reader(ctx))) {
                if (!only(path)) continue;
                if (ctx.read(path) !== text) out.push(error(path, `stale or missing — run \`${command}\` and commit the result`));
            }
            return out;
        },
    };
}

const guideRenderSync = generatedSync('guide-render-sync',
    'Every docs/guides/*.html page equals, byte for byte, what scripts/build-guides.ts renders from its Markdown.',
    guideOutputs, () => true, 'npm run docs:guides');

const llmsSync = generatedSync('llms-sync',
    'docs/llms.txt, docs/llms-full.txt and docs/llms-recipes.txt equal what scripts/build-llms-full.ts produces from llms.txt, the README, the guides and the recipes.',
    llmsOutputs, (p) => p !== 'docs/llms-index.json', 'npm run docs:llms');

const llmsIndexSync = generatedSync('llms-index-sync',
    'docs/llms-index.json equals what scripts/build-llms-full.ts produces, sizes and anchors included.',
    llmsOutputs, (p) => p === 'docs/llms-index.json', 'npm run docs:llms');

const llmsIndexQuality: Rule = {
    id: 'llms-index-quality',
    summary: 'Every guide in docs/llms-index.json has a plain-text summary of at most 400 characters and unique, non-empty anchors — a generator bug passes the sync rule forever, so the content is read too.',
    check(ctx) {
        const parsed = readJson<{ guides?: Array<{ title: string; summary: string; anchors: string[] }> }>(ctx, 'docs/llms-index.json');
        if ('finding' in parsed) return [parsed.finding];
        const out: Finding[] = [];
        for (const guide of parsed.value.guides ?? []) {
            const where = `guide "${guide.title}"`;
            if (guide.summary.trim().length < 40 || guide.summary.length > 400) out.push(error('docs/llms-index.json', `${where}: summary must be 40 to 400 characters, found ${guide.summary.length}`));
            if (/\*\*|\]\(|^#/.test(guide.summary)) out.push(error('docs/llms-index.json', `${where}: summary still carries Markdown`));
            if (guide.anchors.some((a) => a === '') || new Set(guide.anchors).size !== guide.anchors.length) out.push(error('docs/llms-index.json', `${where}: anchors must be unique and non-empty`));
        }
        return out;
    },
};

// ── Links ────────────────────────────────────────────────────────────

const LINK_SOURCES = (ctx: RuleContext): string[] => [
    'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'THIRD-PARTY-NOTICES.md', 'tests/fixtures/PROVENANCE.md',
    ...ctx.list('docs').filter((p) => p.endsWith('.md') || p.endsWith('.html')),
    // The committed pull-request bodies. A shipped release note is frozen
    // history and is never rewritten; a PR draft is live prose that links
    // into the repository, so a link that rots there rots in the record.
    ...ctx.list('release-notes/draft').filter((p) => p.endsWith('.md')),
];

function linksOf(path: string, text: string): Array<{ target: string; line: number }> {
    const pattern = path.endsWith('.html') ? /(?:href|src)="([^"]+)"/g : /\]\(([^)\s]+)\)/g;
    const out: Array<{ target: string; line: number }> = [];
    let inFence = false;
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? '';
        if (line.trimStart().startsWith('```')) inFence = !inFence;
        if (inFence) continue;
        for (const m of line.matchAll(pattern)) out.push({ target: m[1] ?? '', line: i + 1 });
    }
    return out;
}

const isExternal = (target: string): boolean => /^(https?:|mailto:|data:)/.test(target) || target.startsWith('#');

const internalLinks: Rule = {
    id: 'internal-links',
    summary: 'Every relative link and image in the README, the policy files and docs/ points at a file that exists in the repository.',
    check(ctx) {
        const out: Finding[] = [];
        for (const path of LINK_SOURCES(ctx)) {
            const text = ctx.read(path);
            if (text === null) continue;
            for (const { target, line } of linksOf(path, text)) {
                if (isExternal(target)) continue;
                const file = target.split('#')[0]?.split('?')[0] ?? '';
                if (file === '' || file === './') continue;
                const resolved = posix.normalize(posix.join(posix.dirname(path), file)).replace(/\/$/, '');
                if (!ctx.exists(resolved)) out.push(error(path, `links to ${target}, which resolves to ${resolved}, a path that does not exist`, line));
            }
        }
        return out;
    },
};

const anchorParity: Rule = {
    id: 'anchor-parity',
    summary: 'Every link into a guide with a #fragment names a heading that guide actually has.',
    check(ctx) {
        const out: Finding[] = [];
        for (const path of LINK_SOURCES(ctx)) {
            const text = ctx.read(path);
            if (text === null) continue;
            for (const { target, line } of linksOf(path, text)) {
                const m = /^([^#]*?)([a-z-]+)\.(md|html)#(.+)$/.exec(target);
                if (m === null || isExternal(target)) continue;
                const guide = posix.normalize(posix.join(posix.dirname(path), `${m[1] ?? ''}${m[2] ?? ''}.md`));
                const md = ctx.read(guide);
                if (md === null || !guide.startsWith('docs/guides/')) continue;
                if (!guideAnchors(md).includes(m[4] ?? '')) out.push(error(path, `links to #${m[4] ?? ''} in ${guide}, which has no such heading`, line));
            }
        }
        return out;
    },
};

// ── Site metadata ────────────────────────────────────────────────────

const htmlPages = (ctx: RuleContext): string[] => ctx.list('docs').filter((p) => p.endsWith('.html'));
/** The pages of the site: every HTML file under docs/ but the noindex redirect stubs (`redirect-stubs` holds those). */
const sitePages = (ctx: RuleContext): string[] => htmlPages(ctx).filter((p) => !isRedirectStub(ctx.read(p) ?? ''));
const canonicalOf = (html: string): string | undefined => /<link rel="canonical" href="([^"]+)">/.exec(html)?.[1];

const seoHead: Rule = {
    id: 'seo-head',
    summary: 'Every page under docs/ but a noindex redirect stub declares its language, viewport, title, description, canonical URL on pkinative.dev, Open Graph title, description and image, and a favicon.',
    check(ctx) {
        const out: Finding[] = [];
        const required: Array<[string, RegExp]> = [
            ['<html lang="en">', /<html lang="en">/],
            ['viewport', /<meta name="viewport" content="width=device-width, initial-scale=1\.0">/],
            ['a non-empty <title>', /<title>[^<]{10,}<\/title>/],
            ['a meta description of 50 to 300 characters', /<meta name="description" content="[^"]{50,300}">/],
            ['a canonical URL on pkinative.dev', new RegExp(`<link rel="canonical" href="${SITE.replace(/\./g, '\\.')}/`)],
            ['og:title', /<meta property="og:title" content="[^"]+">/],
            ['og:description', /<meta property="og:description" content="[^"]+">/],
            ['og:image', /<meta property="og:image" content="https:\/\/[^"]+">/],
            ['a favicon', /<link rel="icon" [^>]*href="[^"]+">/],
        ];
        for (const path of sitePages(ctx)) {
            const html = ctx.read(path) ?? '';
            for (const [what, pattern] of required) if (!pattern.test(html)) out.push(error(path, `lacks ${what}`));
        }
        return out;
    },
};

const sitemapParity: Rule = {
    id: 'sitemap-parity',
    summary: 'docs/sitemap.xml lists exactly the canonical URL of every page under docs/ but the noindex redirect stubs, each with a <lastmod> equal to verifiedOn of docs/assets/ecosystem.json — the date of the last documentation audit, never a guessed modification date.',
    check(ctx) {
        const sitemap = ctx.read('docs/sitemap.xml');
        if (sitemap === null) return [error('docs/sitemap.xml', 'missing')];
        const manifest = readJson<{ verifiedOn?: unknown }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const out: Finding[] = [];
        const listed = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1] ?? '').sort();
        const canonical = sitePages(ctx).map((p) => canonicalOf(ctx.read(p) ?? '') ?? `(no canonical in ${p})`).sort();
        if (listed.join('\n') !== canonical.join('\n')) out.push(error('docs/sitemap.xml', `lists ${listed.join(', ')}; the pages declare ${canonical.join(', ')}`));
        const verifiedOn = String(manifest.value.verifiedOn ?? '');
        for (const m of sitemap.matchAll(/<url>([\s\S]*?)<\/url>/g)) {
            const entry = m[1] ?? '';
            const lastmod = /<lastmod>([^<]*)<\/lastmod>/.exec(entry)?.[1];
            if (lastmod !== verifiedOn) {
                const loc = /<loc>([^<]+)<\/loc>/.exec(entry)?.[1] ?? '?';
                out.push(error('docs/sitemap.xml', `${loc} has lastmod ${String(lastmod)}; verifiedOn is ${verifiedOn} — run \`npm run docs:sitemap\``, lineContaining(sitemap, loc)));
            }
        }
        return out;
    },
};

const cleanUrlSafe: Rule = {
    id: 'clean-url-safe',
    summary: 'No page under docs/ links to a directory index as `…/index.html`, and no canonical URL or sitemap entry ends in `/index.html` — `npm run docs:serve` and most static hosts rewrite that away, which re-bases every relative URL on the page and 404s its stylesheets.',
    check(ctx) {
        const out: Finding[] = [];
        for (const path of LINK_SOURCES(ctx).filter((p) => p.startsWith('docs/'))) {
            const text = ctx.read(path);
            if (text === null) continue;
            for (const { target, line } of linksOf(path, text)) {
                if (isExternal(target) || !/(^|\/)index\.html($|[#?])/.test(target)) continue;
                out.push(error(path, `links to ${target}: under cleanUrls that URL is served one path segment higher, so every relative link on the page it reaches resolves against the wrong directory — link the directory instead (${target.replace(/index\.html/, '')})`, line));
            }
        }
        for (const path of htmlPages(ctx)) {
            const canonical = canonicalOf(ctx.read(path) ?? '');
            if (canonical !== undefined && canonical.endsWith('/index.html')) {
                out.push(error(path, `declares the canonical URL ${canonical}; a host with cleanUrls serves that page at ${canonical.slice(0, -'index.html'.length)}, so the canonical points at a URL that redirects`));
            }
        }
        const sitemap = ctx.read('docs/sitemap.xml');
        for (const m of (sitemap ?? '').matchAll(/<loc>([^<]*\/index\.html)<\/loc>/g)) {
            out.push(error('docs/sitemap.xml', `lists ${m[1] ?? ''}, which a host with cleanUrls redirects away from`, lineContaining(sitemap ?? '', m[1] ?? '')));
        }
        return out;
    },
};

/** One entry of `declared.socialImages` in docs/assets/ecosystem.json. */
interface SocialImage {
    readonly svg?: unknown;
    readonly png?: unknown;
    readonly width?: unknown;
    readonly height?: unknown;
    readonly svgSha256?: unknown;
}

const socialImages: Rule = {
    id: 'social-images',
    summary: 'Every Open Graph and Twitter image under docs/ is a raster listed in declared.socialImages of docs/assets/ecosystem.json, declares that entry\'s width and height, and the recorded SHA-256 of each SVG source matches the file — which is what proves the committed PNG is not stale.',
    check(ctx) {
        const out: Finding[] = [];
        const manifest = readJson<{ declared?: { socialImages?: unknown } }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const declared = manifest.value.declared?.socialImages;
        if (!Array.isArray(declared) || declared.length === 0) {
            return [error(MANIFEST, 'declared.socialImages must list every social image, as { svg, png, width, height, svgSha256 }')];
        }

        const byPng = new Map<string, { width: number; height: number }>();
        for (const raw of declared as SocialImage[]) {
            const { svg, png, width, height, svgSha256 } = raw;
            if (typeof svg !== 'string' || typeof png !== 'string' || typeof width !== 'number' || typeof height !== 'number' || typeof svgSha256 !== 'string') {
                out.push(error(MANIFEST, `a socialImages entry is not { svg, png, width, height, svgSha256 }: ${JSON.stringify(raw)}`));
                continue;
            }
            byPng.set(png, { width, height });
            if (/\.svg$/.test(png)) out.push(error(MANIFEST, `${png} is an SVG: no social platform renders SVG, so the image a page advertises must be a raster`));
            const source = ctx.read(svg);
            if (source === null) { out.push(error(MANIFEST, `${svg} does not exist`)); continue; }
            const actual = createHash('sha256').update(source.replace(/\r\n/g, '\n'), 'utf8').digest('hex');
            if (actual !== svgSha256) {
                out.push(error(svg, `has changed since ${png} was rasterised (SHA-256 ${actual}, ecosystem.json records ${svgSha256}) — re-run the command in this file's header comment and record the new hash`));
            }
            const declaredSize = `width="${width}" height="${height}"`;
            if (!source.includes(declaredSize)) {
                out.push(error(svg, `does not declare ${declaredSize}, the size ecosystem.json says ${png} was rasterised at`));
            }
        }

        for (const path of htmlPages(ctx)) {
            const html = ctx.read(path) ?? '';
            for (const m of html.matchAll(/<meta (?:property|name)="(og:image|twitter:image|og:image:secure_url)" content="([^"]+)">/g)) {
                const [, key = '', url = ''] = m;
                const file = `docs/${url.startsWith(`${SITE}/`) ? url.slice(SITE.length + 1) : url}`;
                if (!byPng.has(file)) {
                    out.push(error(path, `${key} points at ${url}, which declared.socialImages does not list${/\.svg$/.test(url) ? ' — and it is an SVG, which no social platform renders' : ''}`, lineContaining(html, url)));
                    continue;
                }
                if (key !== 'og:image') continue;
                const size = byPng.get(file);
                for (const [dimension, value] of [['width', size?.width], ['height', size?.height]] as const) {
                    const tag = `<meta property="og:image:${dimension}" content="${String(value)}">`;
                    if (!html.includes(tag)) out.push(error(path, `declares ${key} but not ${tag}; a card without declared dimensions is re-cropped by every platform that reads it`, lineContaining(html, url)));
                }
            }
        }
        return out;
    },
};

const cdnSri: Rule = {
    id: 'cdn-sri',
    summary: 'Every third-party script and stylesheet a page under docs/ loads carries both `integrity` and `crossorigin` — a CDN that is ever compromised must not be able to execute in a reader\'s browser. Self-referencing links (canonical, hreflang, alternate) are not loads and are out of scope, and so is the playgrounds\' dynamic `import()` of the published package, which no browser can pin by hash: ADR 0023 records why, and `cdn-pin` holds it to an exact version.',
    check(ctx) {
        const out: Finding[] = [];
        for (const path of htmlPages(ctx)) {
            const html = ctx.read(path) ?? '';
            const remote = [
                ...html.matchAll(/<script[^>]*\bsrc="(https?:\/\/[^"]+)"[^>]*>/g),
                ...html.matchAll(/<link[^>]*rel="stylesheet"[^>]*\bhref="(https?:\/\/[^"]+)"[^>]*>/g),
                ...html.matchAll(/<link[^>]*\bhref="(https?:\/\/[^"]+)"[^>]*rel="stylesheet"[^>]*>/g),
            ];
            for (const m of remote) {
                const tag = m[0];
                if (/\bintegrity="sha(256|384|512)-/.test(tag) && /\bcrossorigin[=>\s]/.test(tag)) continue;
                out.push(error(path, `loads ${m[1] ?? ''} without both integrity and crossorigin — pin it with a subresource hash, or serve it first-party`, lineContaining(html, m[1] ?? '')));
            }
        }
        return out;
    },
};

/**
 * The pages whose chrome is written by hand, with the arguments
 * `navHtml`/`footerHtml` must be called with to reproduce them.
 */
const HAND_WRITTEN_PAGES: ReadonlyArray<readonly [path: string, prefix: string, current: NavSection]> = [
    ['docs/index.html', '', null],
    ['docs/playgrounds/index.html', '../', 'playgrounds'],
    ['docs/playgrounds/certificate.html', '../', 'playgrounds'],
    ['docs/playgrounds/asn1.html', '../', 'playgrounds'],
    ['docs/playgrounds/toolkit.html', '../', 'playgrounds'],
    ['docs/playgrounds/cli.html', '../', 'playgrounds'],
    ['docs/playgrounds/mcp.html', '../', 'playgrounds'],
];

const chromeParity: Rule = {
    id: 'chrome-parity',
    summary: 'Every hand-written page under docs/ carries, byte for byte, the nav and footer that scripts/build-guides.ts renders into the generated guides, and every playground the switcher it renders from PLAYGROUNDS — which is what lets the landing page stay hand-written without the site half-adopting a redesign the guides already have.',
    check(ctx) {
        const manifest = readJson<{ verifiedOn?: unknown }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const verifiedOn = String(manifest.value.verifiedOn ?? '');
        // The landing page alone carries the audit date in its meta line;
        // taking it from the manifest here means this rule also proves the
        // footer quotes the date the manifest declares.
        // A playground names, in the same line, the CDN build it ran.
        const isPlayground = (path: string): boolean => path.startsWith('docs/playgrounds/') && !path.endsWith('/index.html');
        const extraFor = (path: string): string => (path === 'docs/index.html'
            ? ` · verified <time id="verified-on" datetime="${verifiedOn}">${verifiedOn}</time>`
            : isPlayground(path) ? ENGINE_SOURCE_SLOT : '');

        const out: Finding[] = [];
        for (const [path, prefix, current] of HAND_WRITTEN_PAGES) {
            const html = ctx.read(path);
            if (html === null) { out.push(error(path, 'missing')); continue; }
            const expected: ReadonlyArray<readonly [string, string]> = [
                ['nav', navHtml(prefix, current)],
                ['footer', footerHtml(prefix, extraFor(path))],
                ...(isPlayground(path) ? [['playground switcher', switcherHtml(posix.basename(path))] as const] : []),
            ];
            for (const [what, block] of expected) {
                if (!html.replace(/\r\n/g, '\n').includes(block)) {
                    out.push(error(path, `its ${what} is not the one scripts/build-guides.ts renders — the site would be half-redesigned; paste the generator's output rather than editing this by hand`));
                }
            }
        }
        return out;
    },
};

const jsonLdVersion: Rule = {
    id: 'jsonld-version',
    summary: 'Every schema.org node under docs/ that declares a softwareVersion — the library, pkinative-cli, pkinative-mcp, on any page and at any depth (about, mainEntity) — names a package of docs/assets/ecosystem.json and declares that package\'s version; the landing page declares the library\'s.',
    check(ctx) {
        const ecosystem = readJson<{ packages?: Record<string, { version?: string }> }>(ctx, MANIFEST);
        if ('finding' in ecosystem) return [ecosystem.finding];
        const packages = ecosystem.value.packages ?? {};
        const out: Finding[] = [];
        let libraryOnLanding = false;
        for (const path of sitePages(ctx)) {
            const html = ctx.read(path) ?? '';
            for (const m of html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)) {
                let root: unknown;
                try {
                    root = JSON.parse(m[1] ?? '');
                } catch (err) {
                    out.push(error(path, `JSON-LD is not valid JSON — ${(err as Error).message}`, lineContaining(html, 'ld+json')));
                    continue;
                }
                const walk = (node: unknown): void => {
                    if (Array.isArray(node)) { node.forEach(walk); return; }
                    if (typeof node !== 'object' || node === null) return;
                    const record = node as Record<string, unknown>;
                    if (typeof record['softwareVersion'] === 'string') {
                        const name = String(record['name']);
                        const want = packages[name]?.version;
                        if (want === undefined) out.push(error(path, `JSON-LD declares softwareVersion for "${name}", which is not a package of ${MANIFEST}`, lineContaining(html, `"name": "${name}"`)));
                        else if (record['softwareVersion'] !== want) out.push(error(path, `JSON-LD says ${name} is ${String(record['softwareVersion'])}; ${MANIFEST} says ${want}`, lineContaining(html, 'softwareVersion')));
                        if (path === 'docs/index.html' && name === 'pkinative' && record['softwareVersion'] === want) libraryOnLanding = true;
                    }
                    for (const value of Object.values(record)) walk(value);
                };
                walk(root);
            }
        }
        if (!libraryOnLanding) out.push(error('docs/index.html', `its JSON-LD declares no softwareVersion for pkinative equal to ${String(packages['pkinative']?.version)}`));
        return out;
    },
};

const verifiedOnParity: Rule = {
    id: 'verified-on-parity',
    summary: 'The "verified on" date of the site footer equals verifiedOn in docs/assets/ecosystem.json.',
    check(ctx) {
        const html = ctx.read('docs/index.html') ?? '';
        const shown = /<time id="verified-on" datetime="([^"]+)">\1<\/time>/.exec(html)?.[1];
        const ecosystem = readJson<{ verifiedOn?: string }>(ctx, 'docs/assets/ecosystem.json');
        if ('finding' in ecosystem) return [ecosystem.finding];
        return shown === ecosystem.value.verifiedOn ? [] : [error('docs/index.html', `shows verified on ${String(shown)}; ecosystem.json says ${String(ecosystem.value.verifiedOn)}`, lineContaining(html, 'verified-on'))];
    },
};

// ── Names and numbers the docs quote ─────────────────────────────────

export const PROSE_SOURCES = (ctx: RuleContext): string[] => ['README.md', 'llms.txt', 'CHANGELOG.md', ...ctx.list('docs').filter((p) => p.endsWith('.md') || p === 'docs/index.html' || /^docs\/playgrounds\/[^/]+\.html$/.test(p))];

const apiExists: Rule = {
    id: 'api-exists',
    summary: 'Every name imported from pkinative, and every `function(` quoted, in the README, the docs and the recipes is a public export listed in docs/assets/api.json.',
    check(ctx) {
        const api = readJson<{ exports?: Array<{ name: string }> }>(ctx, 'docs/assets/api.json');
        if ('finding' in api) return [api.finding];
        const exported = new Set((api.value.exports ?? []).map((e) => e.name));
        const out: Finding[] = [];
        const sources = [...PROSE_SOURCES(ctx).filter((p) => p !== 'CHANGELOG.md'), ...ctx.list('recipes').filter((p) => p.endsWith('.ts'))];
        for (const path of sources) {
            const text = ctx.read(path) ?? '';
            const names = new Set<string>();
            for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*'pkinative'/g)) {
                for (const piece of (m[1] ?? '').split(',')) {
                    const name = piece.trim().replace(/^type\s+/, '').split(/\s+as\s+/)[0]?.trim() ?? '';
                    if (name !== '') names.add(name);
                }
            }
            if (!path.endsWith('.ts')) for (const m of text.matchAll(/`([a-z][A-Za-z0-9]+)\(/g)) names.add(m[1] ?? '');
            for (const name of names) {
                if (!exported.has(name)) out.push(error(path, `names ${name}, which is not a public export (docs/assets/api.json)`, lineContaining(text, name)));
            }
        }
        return out;
    },
};

const NUMBER_WORDS: readonly string[] = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty'];
/** The tens a compound number word starts with — `twenty-one` is how prose writes 21. */
const TENS_WORDS: readonly string[] = ['twenty', 'thirty', 'forty', 'fifty', 'sixty', 'seventy', 'eighty', 'ninety'];
const COMPOUND = `(?:${TENS_WORDS.join('|')})-(?:${NUMBER_WORDS.slice(1, 10).join('|')})`;
// The compound form comes first: otherwise `Twenty-one` is read as `one`.
export const NUMBER = `(\\d{1,3}(?:[ \\u00a0,]\\d{3})*|\\d+|${COMPOUND}|${NUMBER_WORDS.join('|')}|${TENS_WORDS.join('|')})`;

/**
 * The changelog is history: an entry for a released version records what that
 * version shipped, and holding "six executable recipes" in the 0.1.0 entry to
 * today's eight would force a lie into the record. Only the entry at the top,
 * the one still being written, is held to the current counts.
 */
export function topEntryOnly(path: string, text: string): string {
    if (path !== 'CHANGELOG.md') return text;
    const entries = [...text.matchAll(/^## \[/gm)];
    return entries.length < 2 ? text : text.slice(0, entries[1]?.index);
}

export function quotedValue(token: string): number {
    const [head = '', unit] = token.toLowerCase().split('-');
    const tens = TENS_WORDS.indexOf(head);
    if (tens >= 0) return 20 + tens * 10 + (unit === undefined ? 0 : NUMBER_WORDS.indexOf(unit));
    const word = NUMBER_WORDS.indexOf(head);
    return word >= 0 ? word : Number(token.replace(/[ \u00a0,]/g, ''));
}

const countTokens: Rule = {
    id: 'count-tokens',
    summary: 'Every count quoted in the README, the changelog and the docs \u2014 in digits or in words \u2014 equals its source: the corpus canaries of docs/assets/ecosystem.json, the export count of docs/assets/api.json, the limits of docs/data/limits.json, the error codes of docs/data/errors.json, the guides and the recipes.',
    check(ctx) {
        const ecosystem = readJson<{ declared?: Record<string, Record<string, number | string>> }>(ctx, 'docs/assets/ecosystem.json');
        const api = readJson<{ exportCount?: number }>(ctx, 'docs/assets/api.json');
        const limits = readJson<Record<string, unknown>>(ctx, 'docs/data/limits.json');
        const recipes = readJson<{ recipes?: unknown[] }>(ctx, 'recipes/index.json');
        const errors = readJson<{ errors?: unknown[] }>(ctx, 'docs/data/errors.json');
        for (const parsed of [ecosystem, api, limits, recipes, errors]) if ('finding' in parsed) return [parsed.finding];
        if ('finding' in ecosystem || 'finding' in api || 'finding' in limits || 'finding' in recipes || 'finding' in errors) return [];
        const limbo = ecosystem.value.declared?.['x509-limbo'] ?? {};
        const limitList = Object.values(limits.value).find(Array.isArray);
        const phrases: ReadonlyArray<readonly [string, unknown]> = [
            ['unique x509-limbo certificates', limbo['certificates']],
            ['x509-limbo test cases', limbo['testcases']],
            ['certificates refused', limbo['refused']],
            ['Wycheproof ECDSA vectors', ecosystem.value.declared?.['wycheproof']?.['tests']],
            ['public exports', api.value.exportCount],
            ['(?:named, CWE-tagged |named |CWE-tagged )?limits', limitList?.length],
            ['guides', GUIDES.length],
            ['executable recipes', recipes.value.recipes?.length],
            ['error codes', errors.value.errors?.length],
        ];
        const out: Finding[] = [];
        for (const path of PROSE_SOURCES(ctx)) {
            const text = topEntryOnly(path, ctx.read(path) ?? '');
            for (const [phrase, value] of phrases) {
                for (const m of text.matchAll(new RegExp(`\\b${NUMBER}\\s+${phrase}\\b`, 'gi'))) {
                    if (quotedValue(m[1] ?? '') !== value) out.push(error(path, `quotes "${m[0]}"; the source says ${String(value)}`, lineContaining(text, m[0])));
                }
            }
        }
        return out;
    },
};

// ── Playgrounds ──────────────────────────────────────────────────────

const LOADER = 'docs/playgrounds/load-engine.js';

/**
 * The playgrounds run the published package, never a local copy (ADR 0023):
 * the loader imports `pkinative@VERSION` from esm.sh and then jsDelivr, and
 * VERSION is the version of the manifest — the one npm serves. A playground
 * that imported anything else would demonstrate a library nobody can install.
 */
const cdnPin: Rule = {
    id: 'cdn-pin',
    summary: 'docs/playgrounds/load-engine.js imports pkinative from esm.sh and then jsDelivr, pinned to packages.pkinative.version of docs/assets/ecosystem.json; no playground script imports a local engine copy or any other remote module, and no committed bundle or declared.playgroundBundle survives.',
    check(ctx) {
        const manifest = readJson<{ packages?: { pkinative?: { version?: string } }; declared?: Record<string, unknown> }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const version = manifest.value.packages?.pkinative?.version ?? '';
        const out: Finding[] = [];
        const loader = ctx.read(LOADER);
        if (loader === null) return [error(LOADER, 'missing — the playgrounds load the published package through it')];
        const pinned = /^const VERSION = '([^']+)';$/m.exec(loader)?.[1];
        if (pinned !== version) out.push(error(LOADER, `pins pkinative@${String(pinned)}; ecosystem.json says ${version} — the playgrounds must run the version npm serves`, lineContaining(loader, 'const VERSION')));
        for (const url of ['https://esm.sh/pkinative@${VERSION}', 'https://cdn.jsdelivr.net/npm/pkinative@${VERSION}/+esm']) {
            if (!loader.includes(`\`${url}\``)) out.push(error(LOADER, `does not try ${url} — the loader tries esm.sh, then jsDelivr, both at VERSION`));
        }
        for (const path of ctx.list('docs/playgrounds').filter((p) => p.endsWith('.js') && p !== LOADER)) {
            const text = ctx.read(path) ?? '';
            for (const m of text.matchAll(/(?:from\s+|import\s*\(\s*)'([^']+)'/g)) {
                const target = m[1] ?? '';
                if (/^https?:/.test(target) || /pkinative(\.min)?\.js$/.test(target)) {
                    out.push(error(path, `imports ${target} — a playground gets the engine from loadEngine() in load-engine.js, and nothing else from a third party`, lineContaining(text, target)));
                }
            }
        }
        for (const stale of ['docs/playgrounds/pkinative.js', 'docs/playground/pkinative.js']) {
            if (ctx.exists(stale)) out.push(error(stale, 'a committed engine bundle — the playgrounds import the published package (ADR 0023); delete it'));
        }
        if (manifest.value.declared?.['playgroundBundle'] !== undefined) out.push(error(MANIFEST, 'declared.playgroundBundle describes a bundle the site no longer ships; remove it'));
        return out;
    },
};

/**
 * The site's own JavaScript — the playgrounds, the landing page, the versions
 * widget — is hand-written, ESLint ignores docs/, and a syntax error in it
 * fails only in a reader's browser. zipnative's `playground-syntax`, parsed
 * from the text so the in-memory perturbation can break it.
 */
const siteScriptSyntax: Rule = {
    id: 'site-script-syntax',
    summary: 'Every JavaScript file under docs/ — the playground scripts, app.js, assets/versions.js — parses as an ES module (ESLint does not lint docs/, so this is the net under 4 000 lines a reader\'s browser runs).',
    check(ctx) {
        const out: Finding[] = [];
        for (const path of ctx.list('docs').filter((p) => p.endsWith('.js'))) {
            const { diagnostics = [] } = ts.transpileModule(ctx.read(path) ?? '', { reportDiagnostics: true, fileName: path, compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, allowJs: true } });
            for (const d of diagnostics.filter((x) => x.category === ts.DiagnosticCategory.Error)) {
                const line = d.file !== undefined && d.start !== undefined ? d.file.getLineAndCharacterOfPosition(d.start).line + 1 : 1;
                out.push(error(path, `does not parse: ${ts.flattenDiagnosticMessageText(d.messageText, ' ')}`, line));
            }
        }
        return out;
    },
};

const PLAYGROUNDS_MANIFEST = 'docs/data/playgrounds.json';
const HUB = 'docs/playgrounds/index.html';
const GUIDES_INDEX = 'docs/guides/index.html';

interface PlaygroundEntry {
    readonly id?: string;
    readonly file?: string;
    readonly url?: string;
    readonly title?: string;
    readonly surface?: string;
    readonly controls?: ReadonlyArray<{ readonly id?: string }>;
    readonly exercises?: readonly string[];
}

/**
 * docs/data/playgrounds.json is how an agent learns a playground exists, what
 * it drives and through which controls (pdfnative's convention). It, the
 * switcher (PLAYGROUNDS of build-guides.ts), the hub's cards and the hub's
 * ItemList are four views of one list; this rule keeps them one.
 */
const playgroundsManifest: Rule = {
    id: 'playgrounds-manifest',
    summary: 'docs/data/playgrounds.json lists exactly the playgrounds of PLAYGROUNDS (scripts/build-guides.ts), in that order, each at its URL with a title, a surface, controls that are real ids of its page and what it exercises — a library page only real exports; the hub shows one card per playground in that order, titled alike, mirrored by its JSON-LD ItemList; and the guides index lists them all, in that order, under Interactive playgrounds.',
    check(ctx) {
        const parsed = readJson<{ playgrounds?: PlaygroundEntry[] }>(ctx, PLAYGROUNDS_MANIFEST);
        if ('finding' in parsed) return [parsed.finding];
        const api = readJson<{ exports?: Array<{ name: string }> }>(ctx, 'docs/assets/api.json');
        if ('finding' in api) return [api.finding];
        const exported = new Set((api.value.exports ?? []).map((e) => e.name));
        const out: Finding[] = [];
        const entries = parsed.value.playgrounds ?? [];
        const files = PLAYGROUNDS.map(([file]) => file);
        if (entries.map((e) => e.file).join(' ') !== files.join(' ')) out.push(error(PLAYGROUNDS_MANIFEST, `lists ${entries.map((e) => String(e.file)).join(', ')}; the switcher lists ${files.join(', ')} — one list, one order`));
        for (const entry of entries) {
            const where = `"${String(entry.id)}"`;
            const page = ctx.read(`docs/playgrounds/${String(entry.file)}`);
            if (page === null) { out.push(error(PLAYGROUNDS_MANIFEST, `${where} names ${String(entry.file)}, which does not exist`)); continue; }
            if (entry.url !== `${SITE}/playgrounds/${String(entry.file)}`) out.push(error(PLAYGROUNDS_MANIFEST, `${where} has the url ${String(entry.url)}`));
            if (!['library', 'cli', 'mcp'].includes(String(entry.surface))) out.push(error(PLAYGROUNDS_MANIFEST, `${where} has the surface ${String(entry.surface)}; it is library, cli or mcp`));
            const ids = new Set([...page.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
            for (const control of entry.controls ?? []) if (!ids.has(control.id ?? '')) out.push(error(PLAYGROUNDS_MANIFEST, `${where} names the control #${String(control.id)}, which ${String(entry.file)} does not contain`));
            if ((entry.exercises ?? []).length === 0) out.push(error(PLAYGROUNDS_MANIFEST, `${where} lists nothing under exercises`));
            if (entry.surface === 'library') for (const name of entry.exercises ?? []) if (!exported.has(name)) out.push(error(PLAYGROUNDS_MANIFEST, `${where} exercises ${name}, which is not a public export`));
        }
        const hub = ctx.read(HUB) ?? '';
        const cards = [...hub.matchAll(/<a class="pg-card" href="([^"]+)">[\s\S]*?<h2>([^<]+)<\/h2>/g)].map((m) => [m[1] ?? '', m[2] ?? ''] as const);
        if (cards.map(([href]) => href).join(' ') !== files.join(' ')) out.push(error(HUB, `its cards link ${cards.map(([href]) => href).join(', ')}; the playgrounds are ${files.join(', ')}`));
        for (const [href, title] of cards) {
            const entry = entries.find((e) => e.file === href);
            if (entry !== undefined && entry.title !== title) out.push(error(HUB, `the ${href} card is titled "${title}"; playgrounds.json says "${String(entry.title)}"`, lineContaining(hub, `href="${href}"`)));
        }
        const block = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(hub)?.[1] ?? '{}';
        let list: { numberOfItems?: unknown; itemListElement?: Array<{ position?: unknown; name?: unknown; url?: unknown }> } | undefined;
        try {
            const graph = (JSON.parse(block) as { '@graph'?: Array<Record<string, unknown>> })['@graph'] ?? [];
            list = graph.map((n) => n['mainEntity']).find((m): m is NonNullable<typeof list> => typeof m === 'object' && m !== null && (m as Record<string, unknown>)['@type'] === 'ItemList');
        } catch { /* structured-data reports the JSON */ }
        const items = list?.itemListElement ?? [];
        const expected = cards.map(([href, title], i) => `${String(i + 1)} ${title} ${SITE}/playgrounds/${href}`);
        const actual = items.map((item) => `${String(item.position)} ${String(item.name)} ${String(item.url)}`);
        if (list === undefined || list.numberOfItems !== cards.length || actual.join('\n') !== expected.join('\n')) out.push(error(HUB, 'its JSON-LD ItemList is not its cards — same order, positions from 1, each card\'s title and URL, numberOfItems the card count', lineContaining(hub, 'ItemList')));
        // The guides index's "Interactive playgrounds" section, pdfnative's: a fourth view of the list.
        const index = ctx.read(GUIDES_INDEX) ?? '';
        const section = /<h2 id="playgrounds">[\s\S]*?<\/ul>/.exec(index)?.[0] ?? '';
        const listed = [...section.matchAll(/<a href="\.\.\/playgrounds\/([^"]+)">([^<]+) →<\/a>/g)].map((m) => `${m[1] ?? ''} ${m[2] ?? ''}`);
        const wanted = entries.map((e) => `${String(e.file)} ${String(e.title)}`);
        if (listed.join('\n') !== wanted.join('\n')) out.push(error(GUIDES_INDEX, `its Interactive playgrounds section lists ${listed.length === 0 ? 'nothing' : listed.join(', ')}; the inventory is ${wanted.join(', ')}`, lineContaining(index, 'id="playgrounds"')));
        return out;
    },
};

/**
 * The URLs the site retired stay served: each is a noindex stub that
 * refreshes to its replacement and names it as canonical, so a link anyone
 * kept still lands — and no live page links the stub, or the retirement
 * never finishes.
 */
const redirectStubs: Rule = {
    id: 'redirect-stubs',
    summary: 'Every noindex page under docs/ is a redirect stub: it refreshes at once to a page that exists, declares that page\'s URL as canonical and links to it, and any script that keeps the query and fragment goes to the same page; and no other page or guide links to a stub.',
    check(ctx) {
        const out: Finding[] = [];
        const stubs = htmlPages(ctx).filter((p) => isRedirectStub(ctx.read(p) ?? ''));
        for (const path of stubs) {
            const html = ctx.read(path) ?? '';
            const target = /<meta http-equiv="refresh" content="0; url=([^"]+)">/.exec(html)?.[1];
            if (target === undefined) { out.push(error(path, 'is noindex but does not refresh at once (<meta http-equiv="refresh" content="0; url=…">) to its replacement')); continue; }
            const resolved = posix.normalize(posix.join(posix.dirname(path), target)).replace(/\/$/, '');
            const file = target.endsWith('/') ? `${resolved}/index.html` : resolved;
            if (!ctx.exists(file)) out.push(error(path, `refreshes to ${target}, which resolves to ${file}, a page that does not exist`));
            const url = `${SITE}/${resolved.replace(/^docs\//, '')}${target.endsWith('/') ? '/' : ''}`;
            if (canonicalOf(html) !== url) out.push(error(path, `declares the canonical URL ${String(canonicalOf(html))}; a stub names its replacement, ${url}`));
            if (!html.includes(`href="${target}"`)) out.push(error(path, `does not link ${target}; a reader whose browser ignores the refresh must still find the page`));
            // The script that keeps an old deep link's query and fragment must go where the refresh goes.
            for (const m of html.matchAll(/location\.replace\('([^']+)'/g)) {
                if (m[1] !== target) out.push(error(path, `its script redirects to ${m[1] ?? ''}; the refresh goes to ${target}`, lineContaining(html, 'location.replace')));
            }
        }
        for (const path of LINK_SOURCES(ctx)) {
            const text = ctx.read(path);
            if (text === null || stubs.includes(path)) continue;
            for (const { target, line } of linksOf(path, text)) {
                if (isExternal(target)) continue;
                const file = target.split('#')[0]?.split('?')[0] ?? '';
                if (file === '') continue;
                const resolved = posix.normalize(posix.join(posix.dirname(path), file)).replace(/\/$/, '');
                if (stubs.includes(resolved) || stubs.includes(`${resolved}/index.html`)) out.push(error(path, `links ${target}, a retired URL kept as a redirect stub — link its replacement`, line));
            }
        }
        return out;
    },
};

/**
 * The committed pull-request bodies — the record of what each release
 * claimed and what was actually run.
 *
 * A release note says what shipped; a PR body says *how anyone knows*. The
 * distinction only survives if the archive is complete, so this rule
 * requires one body per release note, with the sections the release audit
 * reads by name and the checkbox that forbids a figure typed from memory.
 * Without it the convention lasts exactly as long as whoever remembers it.
 */
const releasePrDrafts: Rule = {
    id: 'release-pr-drafts',
    summary: 'Every release note has a committed release-notes/draft/PR-vX.Y.Z.md carrying the sections the release audit reads by name — Independent audit, Validation, the maintainer steps and the self-review checklist — and no draft carries a Co-Authored-By trailer.',
    check(ctx) {
        const out: Finding[] = [];
        const notes = ctx.list('release-notes').filter((p) => /\/v\d+\.\d+\.\d+\.md$/.test(p));
        const drafts = new Set(ctx.list('release-notes/draft').filter((p) => p.endsWith('.md')));

        for (const note of notes) {
            const version = /v(\d+\.\d+\.\d+)\.md$/.exec(note)?.[1] ?? '';
            const draft = `release-notes/draft/PR-v${version}.md`;
            if (!drafts.has(draft)) {
                out.push(error(draft, `missing — ${note} shipped, so the body of its pull request is part of the record. Scaffold it with \`npx tsx scripts/release-prepare.ts --version ${version}\``));
                continue;
            }
            const text = ctx.read(draft) ?? '';
            if (!new RegExp(`^# release: v${version.replace(/\./g, '\\.')} — .+`, 'm').test(text)) {
                out.push(error(draft, `must start with "# release: v${version} — <headline>", the title the pull request carries`));
            }
            for (const section of ['Independent audit', 'Validation', 'Human-in-the-loop — steps for the maintainer', 'Self-review checklist']) {
                if (!new RegExp(`^## ${section.replace(/[—]/g, '—')}`, 'm').test(text)) {
                    out.push(error(draft, `lacks the "## ${section}" section (release-notes/PR_TEMPLATE.md); the release audit reads it by name`));
                }
            }
            if (!text.includes('not typed from memory')) {
                out.push(error(draft, 'lacks the self-review line "Every count above was produced by a command on this branch, not typed from memory" — the one instruction this template exists to carry'));
            }
            // An actual trailer starts its line. The checklist item that
            // forbids one necessarily names it, and flagging that would make
            // the rule refuse the very sentence it exists to enforce.
            if (/^Co-Authored-By:/im.test(text)) {
                out.push(error(draft, 'carries a Co-Authored-By trailer; `attribution.commit` is empty on purpose and the record must match', lineContaining(text, 'Co-Authored-By:')));
            }
        }

        for (const draft of drafts) {
            const version = /PR-v(\d+\.\d+\.\d+)\.md$/.exec(draft)?.[1];
            if (version === undefined) out.push(error(draft, 'is not named PR-vX.Y.Z.md — the directory holds one body per release and nothing else'));
        }
        return out;
    },
};

const releaseNotes: Rule = {
    id: 'release-notes',
    summary: 'Every release-notes/vX.Y.Z.md is titled "pkinative vX.Y.Z" and carries Highlights, Known limitations, Install, Upgrade, Downstream integration notes and Links.',
    check(ctx) {
        const out: Finding[] = [];
        for (const path of ctx.list('release-notes').filter((p) => /\/v\d+\.\d+\.\d+\.md$/.test(p))) {
            const text = ctx.read(path) ?? '';
            const version = /v(\d+\.\d+\.\d+)\.md$/.exec(path)?.[1] ?? '';
            if (!text.startsWith(`# pkinative v${version}\n`)) out.push(error(path, `must start with "# pkinative v${version}"`));
            for (const section of ['Highlights', 'Known limitations', 'Install', 'Upgrade', 'Downstream integration notes', 'Links']) {
                if (!new RegExp(`^## ${section}$`, 'm').test(text)) out.push(error(path, `lacks the "## ${section}" section (release-notes/TEMPLATE.md)`));
            }
        }
        return out;
    },
};

export const SITE_RULES: readonly Rule[] = [
    guideRenderSync, llmsSync, llmsIndexSync, llmsIndexQuality, internalLinks, anchorParity,
    seoHead, sitemapParity, cleanUrlSafe, socialImages, cdnSri, chromeParity, jsonLdVersion, verifiedOnParity, apiExists, countTokens, cdnPin, redirectStubs, playgroundsManifest, siteScriptSyntax, releaseNotes, releasePrDrafts,
];
