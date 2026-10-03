#!/usr/bin/env tsx
/**
 * pkinative — the site under axe, light and dark
 * ===============================================
 * `a11y-structure` (verify-docs) reads the HTML of every page under docs/
 * for what a parser can see: one `<main>`, one `<h1>`, heading levels, `alt`
 * attributes, button names, a skip link. What it cannot see is the rendered
 * page — contrast under both palettes, focus order, ARIA that resolves, a
 * label that the browser actually associates. This script serves docs/ on
 * 127.0.0.1, opens one harness page in headless Chromium, and has that page
 * load every HTML page of the site in turn, in the light palette and then in
 * the dark one (`data-theme` on the root element, as the site's toggle does),
 * inject axe-core into it and run the WCAG 2.2 A and AA rules. One violation
 * on one page in one palette is a failure.
 *
 * axe-core is loaded by the harness from jsDelivr, pinned by version and by
 * SRI hash (`AXE_URL`, `AXE_INTEGRITY`), the way the site itself pins Prism:
 * no npm package is added for a check that only a browser runs, and a byte of
 * the library that differs from the hash does not run. The hash is computed
 * with `curl -sL <url> | openssl dgst -sha384 -binary | openssl base64 -A`,
 * never guessed. The browser is `$CHROME_BIN`, else `google-chrome`, which
 * the GitHub-hosted Ubuntu image ships.
 *
 * Run by the `a11y` job of .github/workflows/docs.yml on every change to the
 * site. Not a gate step: the hermetic profiles have no browser and no
 * network; the result is in the job, in the open.
 *
 * Usage:
 *   npm run check:a11y            # or: npx tsx scripts/a11y-check.ts
 *
 * Exit: 0 every page passes in both palettes; 1 a violation, a page that did
 * not load, or no browser.
 *
 * @module scripts/a11y-check
 */

import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const SITE = 'docs';
const TIMEOUT_MS = 240_000;

/** axe-core, pinned by version and by SRI hash (580 491 bytes at 4.13.0). */
export const AXE_VERSION = '4.13.0';
export const AXE_URL = `https://cdn.jsdelivr.net/npm/axe-core@${AXE_VERSION}/axe.min.js`;
export const AXE_INTEGRITY = 'sha384-jzJDdyy7z7+/I7TeoAg0Gc8k9hD8b1xRN0W18hMptWJ0cdoiebywhPpCyP9eBOgn';

/** The two palettes the site renders (docs/style.css: `[data-theme="dark"]`, else light). */
export const SCHEMES = ['light', 'dark'] as const;

/** WCAG 2.2 A and AA, plus axe's best practices for the ARIA that the structural rule cannot resolve. */
export const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] as const;

const CONTENT_TYPES: Readonly<Record<string, string>> = {
    '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png',
    '.webp': 'image/webp', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml', '.woff2': 'font/woff2',
};

/** Every HTML page of the site, as URL paths (`/`, `/guides/quickstart.html`, …), in a stable order. */
export function sitePages(root: string): string[] {
    const out: string[] = [];
    const walk = (dir: string): void => {
        for (const entry of readdirSync(join(root, SITE, dir)).sort()) {
            const rel = dir === '' ? entry : `${dir}/${entry}`;
            if (entry === 'node_modules' || entry.startsWith('.')) continue;
            if (statSync(join(root, SITE, rel)).isDirectory()) walk(rel);
            else if (entry.endsWith('.html')) out.push(`/${rel}`);
        }
    };
    walk('');
    return out;
}

/** One violation axe reported, reduced to what a reader needs to find it. */
export interface Violation {
    readonly page: string;
    readonly scheme: string;
    readonly id: string;
    readonly impact: string;
    readonly help: string;
    readonly nodes: number;
    readonly target: string;
}

/** What the harness POSTs back. */
export interface HarnessResult {
    readonly ok: boolean;
    readonly agent?: string;
    readonly error?: string;
    readonly pages?: number;
    readonly violations?: readonly Violation[];
}

/** The lines of the report and the exit code, from the harness result. */
export function summarise(result: HarnessResult, pages: readonly string[]): { readonly lines: string[]; readonly exitCode: number } {
    if (!result.ok) return { lines: [`not ok - ${result.agent ?? 'browser'}: ${result.error ?? 'unknown failure'}`], exitCode: 1 };
    const violations = result.violations ?? [];
    const lines: string[] = [];
    for (const page of pages) {
        for (const scheme of SCHEMES) {
            const here = violations.filter((v) => v.page === page && v.scheme === scheme);
            lines.push(here.length === 0 ? `ok - ${page} (${scheme})` : `not ok - ${page} (${scheme}): ${String(here.length)} violation(s)`);
            for (const v of here) lines.push(`    ${v.impact} ${v.id}: ${v.help} — ${String(v.nodes)} node(s), first ${v.target}`);
        }
    }
    const expected = pages.length * SCHEMES.length;
    if ((result.pages ?? 0) !== expected) lines.push(`not ok - the harness ran ${String(result.pages ?? 0)} page renders, expected ${String(expected)}`);
    lines.push(`a11y: ${String(pages.length)} page(s) × ${String(SCHEMES.length)} palette(s) under axe-core ${AXE_VERSION} (${AXE_TAGS.join(', ')}), ${String(violations.length)} violation(s) on ${result.agent ?? 'browser'}`);
    return { lines, exitCode: violations.length === 0 && (result.pages ?? 0) === expected ? 0 : 1 };
}

/** The harness page: loads axe once (SRI), then every page in an iframe, in each palette, and POSTs the violations. */
export function harnessPage(pages: readonly string[]): string {
    return `<!doctype html><meta charset="utf-8"><title>pkinative a11y harness</title>
<script src="${AXE_URL}" integrity="${AXE_INTEGRITY}" crossorigin="anonymous"></script>
<iframe id="f" width="1280" height="900" title="page under test"></iframe>
<script type="module">
const report = (body) => fetch('/result', { method: 'POST', body: JSON.stringify(body) });
const pages = ${JSON.stringify(pages)};
const schemes = ${JSON.stringify(SCHEMES)};
const frame = document.getElementById('f');
const load = (src) => new Promise((ok, ko) => {
    const t = setTimeout(() => ko(new Error('timeout loading ' + src)), 30000);
    frame.onload = () => { clearTimeout(t); ok(); };
    frame.src = src;
});
const inject = (doc) => new Promise((ok, ko) => {
    const s = doc.createElement('script');
    s.src = ${JSON.stringify(AXE_URL)}; s.integrity = ${JSON.stringify(AXE_INTEGRITY)}; s.crossOrigin = 'anonymous';
    s.onload = ok; s.onerror = () => ko(new Error('axe did not load in the frame'));
    doc.head.appendChild(s);
});
try {
    if (typeof axe === 'undefined') throw new Error('axe-core did not load in the harness (SRI or network)');
    const violations = [];
    let runs = 0;
    for (const page of pages) {
        for (const scheme of schemes) {
            await load(page + '?scheme=' + scheme);
            const win = frame.contentWindow, doc = win.document;
            doc.documentElement.setAttribute('data-theme', scheme);
            await inject(doc);
            await new Promise((r) => setTimeout(r, 150));
            const results = await win.axe.run(doc, { runOnly: { type: 'tag', values: ${JSON.stringify(AXE_TAGS)} }, resultTypes: ['violations'] });
            runs++;
            for (const v of results.violations) {
                violations.push({ page, scheme, id: v.id, impact: v.impact ?? 'unknown', help: v.help, nodes: v.nodes.length, target: String(v.nodes[0]?.target?.[0] ?? '?') });
            }
        }
    }
    await report({ ok: true, agent: navigator.userAgent, pages: runs, violations });
} catch (err) {
    await report({ ok: false, error: String(err && err.stack || err), agent: navigator.userAgent });
}
</script>`;
}

function serveFile(urlPath: string): { body: Buffer; type: string } | undefined {
    const clean = decodeURIComponent(urlPath.split('?')[0] ?? '/');
    const rel = normalize(clean.endsWith('/') ? `${clean}index.html` : clean).replace(/^[\\/]+/, '');
    if (rel.split(sep).includes('..')) return undefined;
    const path = join(ROOT, SITE, rel);
    if (!existsSync(path) || statSync(path).isDirectory()) return undefined;
    return { body: readFileSync(path), type: CONTENT_TYPES[extname(path)] ?? 'application/octet-stream' };
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    const pages = sitePages(ROOT);
    let settle: (r: HarnessResult) => void = () => undefined;
    const done = new Promise<HarnessResult>((r) => { settle = r; });
    const server = createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/result') {
            let body = '';
            req.on('data', (chunk: Buffer | string) => { body += String(chunk); });
            req.on('end', () => { res.end('ok'); settle(JSON.parse(body) as HarnessResult); });
            return;
        }
        if ((req.url ?? '/').split('?')[0] === '/__a11y') {
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
            res.end(harnessPage(pages));
            return;
        }
        const file = serveFile(req.url ?? '/');
        if (file === undefined) { res.writeHead(404); res.end(); return; }
        res.writeHead(200, { 'content-type': file.type });
        res.end(file.body);
    });
    server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        const port = typeof address === 'object' && address !== null ? address.port : 0;
        const profile = mkdtempSync(join(tmpdir(), 'pkinative-a11y-'));
        const flags = [
            '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--window-size=1280,900',
            `--user-data-dir=${profile}`,
            ...(process.platform === 'linux' ? ['--no-sandbox'] : []),
            `http://127.0.0.1:${String(port)}/__a11y`,
        ];
        const browser = spawn(process.env['CHROME_BIN'] ?? 'google-chrome', flags, { stdio: 'ignore' });
        browser.on('error', (err) => settle({ ok: false, error: `could not start the browser: ${err.message}` }));
        const timer = setTimeout(() => settle({ ok: false, error: `no result within ${String(TIMEOUT_MS / 1000)} s` }), TIMEOUT_MS);
        void done.then((result) => {
            clearTimeout(timer);
            browser.kill();
            server.close();
            try { rmSync(profile, { recursive: true, force: true }); } catch { /* the browser may still hold it */ }
            const { lines, exitCode } = summarise(result, pages);
            for (const line of lines) (exitCode === 0 ? console.log : console.error)(line);
            process.exit(exitCode);
        });
    });
}
