/**
 * pkinative — documentation and site rules
 * ========================================
 * Generated files stay generated (`guide-render-sync`, `llms-sync`,
 * `llms-index-sync`) and read well (`llms-index-quality`); links and anchors
 * resolve (`internal-links`, `anchor-parity`); every page carries its search
 * and social metadata (`seo-head`, `sitemap-parity`, `jsonld-version`,
 * `verified-on-parity`); the palette is readable (`contrast`); the docs name
 * only real exports (`api-exists`) and quote only real numbers
 * (`count-tokens`); release notes have their mandatory sections
 * (`release-notes`).
 *
 * @module scripts/verify-docs/rules/site
 */

import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import { GUIDES, guideAnchors, guideOutputs, SITE, type Reader } from '../../build-guides.js';
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
const canonicalOf = (html: string): string | undefined => /<link rel="canonical" href="([^"]+)">/.exec(html)?.[1];

const seoHead: Rule = {
    id: 'seo-head',
    summary: 'Every page under docs/ declares its language, viewport, title, description, canonical URL on pkinative.dev, Open Graph title, description and image, and a favicon.',
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
        for (const path of htmlPages(ctx)) {
            const html = ctx.read(path) ?? '';
            for (const [what, pattern] of required) if (!pattern.test(html)) out.push(error(path, `lacks ${what}`));
        }
        return out;
    },
};

const sitemapParity: Rule = {
    id: 'sitemap-parity',
    summary: 'docs/sitemap.xml lists exactly the canonical URL of every page under docs/.',
    check(ctx) {
        const sitemap = ctx.read('docs/sitemap.xml');
        if (sitemap === null) return [error('docs/sitemap.xml', 'missing')];
        const listed = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1] ?? '').sort();
        const canonical = htmlPages(ctx).map((p) => canonicalOf(ctx.read(p) ?? '') ?? `(no canonical in ${p})`).sort();
        return listed.join('\n') === canonical.join('\n') ? [] : [error('docs/sitemap.xml', `lists ${listed.join(', ')}; the pages declare ${canonical.join(', ')}`)];
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

const jsonLdVersion: Rule = {
    id: 'jsonld-version',
    summary: 'The JSON-LD of docs/index.html parses and declares the softwareVersion of docs/assets/ecosystem.json.',
    check(ctx) {
        const html = ctx.read('docs/index.html') ?? '';
        const block = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(html)?.[1];
        const ecosystem = readJson<{ packages?: { pkinative?: { version?: string } } }>(ctx, 'docs/assets/ecosystem.json');
        if ('finding' in ecosystem) return [ecosystem.finding];
        if (block === undefined) return [error('docs/index.html', 'has no JSON-LD block')];
        let declared: string | undefined;
        try {
            const graph = (JSON.parse(block) as { '@graph'?: Array<{ softwareVersion?: string }> })['@graph'] ?? [];
            declared = graph.find((node) => node.softwareVersion !== undefined)?.softwareVersion;
        } catch (err) {
            return [error('docs/index.html', `JSON-LD is not valid JSON — ${(err as Error).message}`, lineContaining(html, 'ld+json'))];
        }
        const version = ecosystem.value.packages?.pkinative?.version;
        return declared === version ? [] : [error('docs/index.html', `JSON-LD softwareVersion is ${String(declared)}; ecosystem.json says ${String(version)}`, lineContaining(html, 'softwareVersion'))];
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

// ── Contrast (WCAG 2.2 AA, 4.5:1 for text) ───────────────────────────

function luminance(hex: string): number {
    const channel = (i: number): number => {
        const c = parseInt(hex.slice(i, i + 2), 16) / 255;
        return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

export function contrastRatio(a: string, b: string): number {
    const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
    return (light + 0.05) / (dark + 0.05);
}

const TEXT_PAIRS: ReadonlyArray<readonly [string, string]> = [
    ['--c-text', '--c-bg'], ['--c-text-dim', '--c-bg'], ['--c-text-muted', '--c-bg-alt'], ['--c-text-muted', '--c-surface'],
    ['--c-primary', '--c-bg'], ['--c-primary', '--c-bg-alt'], ['--c-primary-fg', '--c-primary'], ['--c-code-text', '--c-code-bg'],
];

const contrast: Rule = {
    id: 'contrast',
    summary: 'Every text/background token pair of docs/style.css reaches the WCAG 2.2 AA ratio of 4.5:1, in the light and in the dark palette.',
    check(ctx) {
        const css = ctx.read('docs/style.css') ?? '';
        const out: Finding[] = [];
        const palettes: Array<[string, string | undefined]> = [
            ['light', /:root \{([^}]*)\}/.exec(css)?.[1]],
            ['dark', /\[data-theme="dark"\] \{([^}]*)\}/.exec(css)?.[1]],
        ];
        const light = new Map([...(palettes[0]?.[1] ?? '').matchAll(/(--c-[\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1] ?? '', m[2] ?? '']));
        for (const [name, block] of palettes) {
            if (block === undefined) {
                out.push(error('docs/style.css', `has no ${name} palette block`));
                continue;
            }
            const tokens = new Map([...light, ...[...block.matchAll(/(--c-[\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1] ?? '', m[2] ?? ''] as const)]);
            for (const [fg, bg] of TEXT_PAIRS) {
                const a = tokens.get(fg);
                const b = tokens.get(bg);
                if (a === undefined || b === undefined) {
                    out.push(error('docs/style.css', `${name} palette lacks ${a === undefined ? fg : bg}`));
                    continue;
                }
                const ratio = contrastRatio(a, b);
                if (ratio < 4.5) out.push(error('docs/style.css', `${name}: ${fg} on ${bg} is ${ratio.toFixed(2)}:1, below 4.5:1`, lineContaining(css, fg)));
            }
        }
        return out;
    },
};

// ── Names and numbers the docs quote ─────────────────────────────────

const PROSE_SOURCES = (ctx: RuleContext): string[] => ['README.md', 'llms.txt', 'CHANGELOG.md', ...ctx.list('docs').filter((p) => p.endsWith('.md') || p === 'docs/index.html')];

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
const NUMBER = `(\\d{1,3}(?:[ \\u00a0,]\\d{3})*|\\d+|${NUMBER_WORDS.join('|')})`;

/**
 * The changelog is history: an entry for a released version records what that
 * version shipped, and holding "six executable recipes" in the 0.1.0 entry to
 * today's eight would force a lie into the record. Only the entry at the top,
 * the one still being written, is held to the current counts.
 */
function topEntryOnly(path: string, text: string): string {
    if (path !== 'CHANGELOG.md') return text;
    const entries = [...text.matchAll(/^## \[/gm)];
    return entries.length < 2 ? text : text.slice(0, entries[1]?.index);
}

function quotedValue(token: string): number {
    const word = NUMBER_WORDS.indexOf(token.toLowerCase());
    return word >= 0 ? word : Number(token.replace(/[ \u00a0,]/g, ''));
}

const countTokens: Rule = {
    id: 'count-tokens',
    summary: 'Every count quoted in the README, the changelog and the docs \u2014 in digits or in words \u2014 equals its source: the corpus canaries of docs/assets/ecosystem.json, the export count of docs/assets/api.json, the limits of docs/data/limits.json, the guides and the recipes.',
    check(ctx) {
        const ecosystem = readJson<{ declared?: Record<string, Record<string, number | string>> }>(ctx, 'docs/assets/ecosystem.json');
        const api = readJson<{ exportCount?: number }>(ctx, 'docs/assets/api.json');
        const limits = readJson<Record<string, unknown>>(ctx, 'docs/data/limits.json');
        const recipes = readJson<{ recipes?: unknown[] }>(ctx, 'recipes/index.json');
        for (const parsed of [ecosystem, api, limits, recipes]) if ('finding' in parsed) return [parsed.finding];
        if ('finding' in ecosystem || 'finding' in api || 'finding' in limits || 'finding' in recipes) return [];
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
    seoHead, sitemapParity, cleanUrlSafe, socialImages, jsonLdVersion, verifiedOnParity, contrast, apiExists, countTokens, releaseNotes,
];
