/**
 * pkinative — design and accessibility rules
 * ==========================================
 * The site is a port of the native family's charter, and these rules are
 * what keep "port" true: `design-tokens-parity` holds docs/style.css and
 * docs/guides/guide.css to the pdfnative tokens captured in
 * docs/data/design-tokens.json, `contrast` checks every text/background
 * pair that file lists in all three palettes, and `a11y-structure` checks
 * the page structure a screen reader and a phone rely on.
 *
 * @module scripts/verify-docs/rules/design
 */

import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

const TOKENS = 'docs/data/design-tokens.json';
const STYLE = 'docs/style.css';
const GUIDE_CSS = 'docs/guides/guide.css';

interface TextPair { readonly text: string; readonly on: string; readonly where?: string }
interface RefusedPair { readonly text: string; readonly on: string; readonly guards: ReadonlyArray<{ readonly file: string; readonly selector: string }> }
interface DesignTokens {
    readonly palettes?: { readonly light?: Record<string, string>; readonly dark?: Record<string, string> };
    readonly exception?: { readonly palette?: string; readonly tokens?: Record<string, { readonly value?: string }> };
    readonly fonts?: readonly string[];
    readonly breakpoints?: readonly string[];
    readonly guideShell?: { readonly maxWidth?: string; readonly padding?: string };
    readonly textPairs?: readonly TextPair[];
    readonly refusedPairs?: readonly RefusedPair[];
}

const lf = (text: string): string => text.replace(/\r\n/g, '\n');
const squash = (value: string): string => value.trim().replace(/\s+/g, ' ').replace(/:\s*/g, ':').toLowerCase();

/** The custom properties of one declaration block. */
function tokensOf(block: string): Map<string, string> {
    return new Map([...block.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((m) => [m[1] ?? '', (m[2] ?? '').trim().replace(/\s+/g, ' ')]));
}

/** The three palette blocks of docs/style.css: light, the toggled dark, and the OS-preference dark. */
export function paletteBlocks(css: string): Record<'light' | 'dark' | 'dark-media', Map<string, string> | undefined> {
    const at = (pattern: RegExp): Map<string, string> | undefined => {
        const block = pattern.exec(css)?.[1];
        return block === undefined ? undefined : tokensOf(block);
    };
    return {
        'light': at(/^:root \{([^}]*)\}/m),
        'dark': at(/^\[data-theme="dark"\] \{([^}]*)\}/m),
        'dark-media': at(/@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\) \{([^}]*)\}/),
    };
}

/** Every `selector { declarations }` rule of a stylesheet, at-rule preludes stripped. */
function rulesOf(css: string): Array<{ selector: string; body: string }> {
    const out: Array<{ selector: string; body: string }> = [];
    const clean = css.replace(/\/\*[\s\S]*?\*\//g, '');
    for (const m of clean.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        out.push({ selector: (m[1] ?? '').trim().replace(/\s+/g, ' '), body: m[2] ?? '' });
    }
    return out;
}

const textTokenOf = (body: string): string | undefined => /(?:^|[;\s{])color:\s*var\((--c-[\w-]+)\)/.exec(body)?.[1];
const backgroundTokenOf = (body: string): string | undefined => /background(?:-color)?:\s*var\((--c-[\w-]+)\)/.exec(body)?.[1];

function luminance(hex: string): number {
    const channel = (i: number): number => {
        const c = parseInt(hex.slice(i, i + 2), 16) / 255;
        return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

/** WCAG 2.2 contrast ratio of two `#rrggbb` colours. */
export function contrastRatio(a: string, b: string): number {
    const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
    return (light + 0.05) / (dark + 0.05);
}

function loadTokens(ctx: RuleContext): { tokens: DesignTokens } | { finding: Finding } {
    const parsed = readJson<DesignTokens>(ctx, TOKENS);
    return 'finding' in parsed ? parsed : { tokens: parsed.value };
}

// ── contrast ─────────────────────────────────────────────────────────

const contrast: Rule = {
    id: 'contrast',
    summary: 'Every text/background token pair docs/data/design-tokens.json lists reaches the WCAG 2.2 AA ratio of 4.5:1 in all three palettes of docs/style.css (light, [data-theme="dark"], and the prefers-color-scheme dark block, which must equal it); the list is complete — every token docs/style.css or docs/guides/guide.css uses as a text colour, and every colour/background pair one rule declares, is in it — and every refused pair keeps the CSS rule that guards against it.',
    check(ctx) {
        const loaded = loadTokens(ctx);
        if ('finding' in loaded) return [loaded.finding];
        const pairs = loaded.tokens.textPairs ?? [];
        const css = lf(ctx.read(STYLE) ?? '');
        const out: Finding[] = [];
        if (pairs.length === 0) return [error(TOKENS, 'textPairs is empty — the contrast rule would check nothing')];

        const palettes = paletteBlocks(css);
        const light = palettes.light;
        for (const [name, block] of Object.entries(palettes)) {
            if (block === undefined || light === undefined) {
                out.push(error(STYLE, `has no ${name} palette block`));
                continue;
            }
            const tokens = new Map([...light, ...block]);
            for (const { text, on } of pairs) {
                const a = tokens.get(text);
                const b = tokens.get(on);
                if (a === undefined || b === undefined || !/^#[0-9a-f]{6}$/i.test(a) || !/^#[0-9a-f]{6}$/i.test(b)) {
                    out.push(error(STYLE, `${name} palette has no #rrggbb value for ${a === undefined ? text : on}`));
                    continue;
                }
                const ratio = contrastRatio(a, b);
                if (ratio < 4.5) out.push(error(STYLE, `${name}: ${text} on ${on} is ${ratio.toFixed(2)}:1, below 4.5:1`, lineContaining(css, text)));
            }
        }
        const dark = palettes.dark, media = palettes['dark-media'];
        if (dark !== undefined && media !== undefined) {
            for (const key of new Set([...dark.keys(), ...media.keys()])) {
                if (dark.get(key) !== media.get(key)) {
                    out.push(error(STYLE, `the prefers-color-scheme dark block sets ${key} to ${String(media.get(key))}, [data-theme="dark"] to ${String(dark.get(key))} — a reader on a dark OS without JavaScript sees another palette`, lineContaining(css, ':root:not([data-theme="light"])')));
                }
            }
        }

        // Completeness: the list is only as good as what it leaves out.
        const listed = new Set(pairs.map((p) => `${p.text} ${p.on}`));
        const texts = new Set(pairs.map((p) => p.text));
        for (const file of [STYLE, GUIDE_CSS]) {
            const text = lf(ctx.read(file) ?? '');
            for (const { selector, body } of rulesOf(text)) {
                const fg = textTokenOf(body);
                if (fg === undefined) continue;
                if (!texts.has(fg)) out.push(error(file, `${selector} uses ${fg} as a text colour, and textPairs in ${TOKENS} places it on no background`, lineContaining(text, selector)));
                const bg = backgroundTokenOf(body);
                if (bg !== undefined && !listed.has(`${fg} ${bg}`)) out.push(error(file, `${selector} puts ${fg} on ${bg}, a pair textPairs in ${TOKENS} does not list`, lineContaining(text, selector)));
            }
        }
        for (const refused of loaded.tokens.refusedPairs ?? []) {
            if (listed.has(`${refused.text} ${refused.on}`)) out.push(error(TOKENS, `${refused.text} on ${refused.on} is both listed and refused`));
            for (const guard of refused.guards) {
                const text = lf(ctx.read(guard.file) ?? '');
                if (!rulesOf(text).some((r) => r.selector.split(',').map((s) => s.trim()).includes(guard.selector))) {
                    out.push(error(guard.file, `lacks the rule ${guard.selector}, which keeps ${refused.text} off ${refused.on} (refusedPairs in ${TOKENS})`));
                }
            }
        }
        return out;
    },
};

// ── design-tokens-parity ─────────────────────────────────────────────

const designTokensParity: Rule = {
    id: 'design-tokens-parity',
    summary: 'docs/style.css carries the native-family charter captured in docs/data/design-tokens.json — every custom property of the light and both dark palette blocks, with the charter\'s value except the one declared exception — and docs/style.css and docs/guides/guide.css use only the charter\'s font stacks and width breakpoints, guide.css defines no token of its own, and .guide-shell keeps the charter\'s column.',
    check(ctx) {
        const loaded = loadTokens(ctx);
        if ('finding' in loaded) return [loaded.finding];
        const { palettes: charter, exception, fonts = [], breakpoints = [], guideShell } = loaded.tokens;
        const css = lf(ctx.read(STYLE) ?? '');
        const guide = lf(ctx.read(GUIDE_CSS) ?? '');
        const out: Finding[] = [];
        const blocks = paletteBlocks(css);
        const excepted = exception?.palette === 'dark' ? exception.tokens ?? {} : {};
        const expected: Record<'light' | 'dark' | 'dark-media', Map<string, string>> = {
            'light': new Map(Object.entries(charter?.light ?? {})),
            'dark': new Map(Object.entries(charter?.dark ?? {})),
            'dark-media': new Map(Object.entries(charter?.dark ?? {})),
        };
        for (const name of ['dark', 'dark-media'] as const) {
            for (const [token, { value }] of Object.entries(excepted)) if (value !== undefined) expected[name].set(token, value);
        }
        for (const name of ['light', 'dark', 'dark-media'] as const) {
            const actual = blocks[name];
            if (actual === undefined) { out.push(error(STYLE, `has no ${name} palette block`)); continue; }
            for (const [token, value] of expected[name]) {
                const got = actual.get(token);
                if (got === undefined) out.push(error(STYLE, `${name} palette lacks the charter token ${token}`));
                else if (squash(got) !== squash(value)) out.push(error(STYLE, `${name} palette sets ${token} to ${got}; the charter says ${value}${Object.hasOwn(excepted, token) ? ' (the declared exception)' : ' — a divergence needs a reasoned entry under exception in ' + TOKENS}`, lineContaining(css, token)));
            }
            for (const token of actual.keys()) {
                if (!expected[name].has(token)) out.push(error(STYLE, `${name} palette declares ${token}, which neither the charter nor its exception has`, lineContaining(css, token)));
            }
        }
        if (/--[\w-]+\s*:/.test(guide.replace(/\/\*[\s\S]*?\*\//g, ''))) out.push(error(GUIDE_CSS, 'declares a custom property; guide.css inherits every token from style.css and defines none'));

        const allowedFonts = new Set(fonts.map(squash));
        const allowedQueries = new Set(breakpoints.map(squash));
        for (const [file, text] of [[STYLE, css], [GUIDE_CSS, guide]] as const) {
            for (const m of text.matchAll(/font-family:\s*([^;}]+)[;}]/g)) {
                if (!allowedFonts.has(squash(m[1] ?? ''))) out.push(error(file, `uses the font stack ${(m[1] ?? '').trim()}, which is not one of the charter's (fonts in ${TOKENS})`, lineContaining(text, m[0])));
            }
            for (const m of text.matchAll(/@media ([^{]+)\{/g)) {
                const query = (m[1] ?? '').trim();
                if (/width/.test(query) && !allowedQueries.has(squash(query))) out.push(error(file, `uses the breakpoint ${query}, which is not one of the charter's (breakpoints in ${TOKENS})`, lineContaining(text, m[0])));
            }
        }
        const shell = rulesOf(guide).find((r) => r.selector === '.guide-shell')?.body ?? '';
        if (guideShell?.maxWidth !== undefined && !new RegExp(`max-width:\\s*${guideShell.maxWidth}\\s*;`).test(shell)) out.push(error(GUIDE_CSS, `.guide-shell is not the charter's ${guideShell.maxWidth} column`));
        if (guideShell?.padding !== undefined && !new RegExp(`padding:\\s*${guideShell.padding}\\s*;`).test(shell)) out.push(error(GUIDE_CSS, `.guide-shell does not keep the charter's padding ${guideShell.padding}`));
        return out;
    },
};

// ── a11y-structure ───────────────────────────────────────────────────

const htmlPages = (ctx: RuleContext): string[] => ctx.list('docs').filter((p) => p.endsWith('.html'));

/** Visible text of an HTML fragment, tags and entities aside. */
const textOf = (html: string): string => html.replace(/<[^>]+>/g, '').replace(/&[a-z#0-9]+;/gi, 'x').trim();

/** The markup a page parses into, without script and style bodies or comments. */
const markupOf = (html: string): string => lf(html).replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/g, '<$1></$1>');

const a11yStructure: Rule = {
    id: 'a11y-structure',
    summary: 'Every page under docs/ (whose language seo-head holds) opens with a skip link to an element that exists, has one <main> and exactly one <h1>, never skips a heading level, gives every <img> an alt attribute and every <button> an accessible name, and holds no escaped markup inside an inline <svg>; and docs/guides/guide.css lets inline code wrap, so a long identifier cannot widen a phone screen (WCAG 2.2 SC 1.3.1, 1.4.10, 2.4.1, 4.1.2).',
    check(ctx) {
        const out: Finding[] = [];
        for (const path of htmlPages(ctx)) {
            const raw = lf(ctx.read(path) ?? '');
            const html = markupOf(raw);
            const at = (needle: string): number => lineContaining(raw, needle);
            const skip = /<body[^>]*>\s*<a class="skip-link" href="#([\w-]+)">/.exec(html)?.[1];
            if (skip === undefined) out.push(error(path, 'does not open its <body> with a skip link (SC 2.4.1)'));
            else if (!new RegExp(`\\bid="${skip}"`).test(html)) out.push(error(path, `has a skip link to #${skip}, which no element carries`));
            const mains = html.match(/<main\b/g)?.length ?? 0;
            if (mains !== 1) out.push(error(path, `has ${mains} <main> elements; a page has exactly one`));
            const levels = [...html.matchAll(/<h([1-6])\b/g)].map((m) => Number(m[1]));
            const h1s = levels.filter((l) => l === 1).length;
            if (h1s !== 1) out.push(error(path, `has ${h1s} <h1> elements; a page has exactly one`));
            for (let i = 1; i < levels.length; i++) {
                const [before = 1, now = 1] = [levels[i - 1], levels[i]];
                if (now > before + 1) out.push(error(path, `jumps from <h${before}> to <h${now}>, skipping a heading level (SC 1.3.1)`, at(`<h${now}`)));
            }
            for (const m of html.matchAll(/<img\b[^>]*>/g)) {
                if (!/\balt="/.test(m[0])) out.push(error(path, `has an <img> without alt: ${m[0].slice(0, 80)}`, at(m[0].slice(0, 40))));
            }
            for (const m of html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)) {
                if (!/\baria-label="[^"]+"/.test(m[1] ?? '') && textOf(m[2] ?? '') === '') out.push(error(path, `has a <button> without an accessible name: ${m[0].slice(0, 80)}`, at(m[0].slice(0, 40))));
            }
            for (const m of html.matchAll(/<svg\b[\s\S]*?<\/svg>/g)) {
                if (/<(pre|p|code)\b|&lt;/.test(m[0])) out.push(error(path, 'has an inline <svg> holding escaped markup or paragraphs — the Markdown renderer split it, so the figure shows as source code', at(m[0].slice(0, 40))));
            }
        }
        const guide = lf(ctx.read(GUIDE_CSS) ?? '');
        if (!rulesOf(guide).some((r) => r.selector === '.guide-content :not(pre) > code' && /overflow-wrap:\s*anywhere/.test(r.body))) {
            out.push(error(GUIDE_CSS, 'lacks `.guide-content :not(pre) > code { overflow-wrap: anywhere }` — an unbreakable identifier then widens the page on a phone (SC 1.4.10 Reflow)'));
        }
        return out;
    },
};

export const DESIGN_RULES: readonly Rule[] = [designTokensParity, contrast, a11yStructure];
