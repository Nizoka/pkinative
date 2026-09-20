/**
 * pkinative — forensic bundle probe
 * =================================
 * What `dist/` must be true of, asserted on the artefact rather than on the
 * source. The architecture test decides these questions from the syntax tree
 * of `src/`; this decides them from the bytes that ship, which is what a
 * consumer actually receives — a bundler plugin, a stray import or a
 * misconfigured `tsup` can put something in the output that never appeared in
 * the input (pdfnative-cli 1.5.0 doctrine).
 *
 * Every check is a pure predicate over the text of one bundle, so the tests
 * can feed it synthetic bundles and prove each one fires. The checks that
 * need the filesystem — declaration parity and the byte budgets — live in
 * `probeDistFiles`.
 *
 * It deliberately does NOT re-assert the export list: `npm run smoke:install`
 * already proves, from a packed tarball installed into an empty project, that
 * both ESM and CJS expose every runtime export. That is strictly stronger
 * than reading dist/.
 *
 * @module scripts/lib/bundle-probe
 */

/** Strings only a test, a fixture, a debugger session or an agent leaves behind. */
export const FOREIGN_MARKERS: readonly string[] = [
    'Co-Authored-By',
    'letsencrypt-org-leaf',
    'isrg-root-x1',
    'tests/fixtures',
    'describe(',
    'expect(',
    'debugger',
    'FIXME',
];

/**
 * Every assertion that can be made from the text of one bundle.
 *
 * @param name - How to name the file in a finding, e.g. `dist/index.js`.
 * @param code - The bundle's source text.
 * @returns One message per violation; empty when the bundle is clean.
 */
export function probeBundle(name: string, code: string): readonly string[] {
    const fail: string[] = [];

    // Portability. A `node:` specifier is what stops a bundle running
    // unchanged in a browser, in Deno's web target, in Bun or in a Worker —
    // the claim the README makes and nothing else checks on the artefact.
    for (const m of code.matchAll(/["']node:[a-z/]+["']/g)) {
        fail.push(`${name}: imports ${m[0]} — the bundle must run unchanged on Node, browsers, Deno, Bun and Workers`);
    }

    // Zero runtime dependency, proven on the output rather than on package.json.
    for (const m of code.matchAll(/\brequire\((["'][^"']+["'])\)/g)) {
        fail.push(`${name}: require(${m[1] ?? ''}) — pkinative declares no runtime dependency`);
    }
    for (const m of code.matchAll(/(?:^|[^.\w])from\s*["']([^.][^"']*)["']/gm)) {
        fail.push(`${name}: imports "${m[1] ?? ''}" — pkinative declares no runtime dependency`);
    }

    // The console rule of AGENTS.md: only src/core/pki-diagnostics.ts may
    // reach the sink, and it does so once, through globalThis.console.
    if (code.includes('console.log(')) fail.push(`${name}: console.log( — a library never writes to stdout`);
    const consoleHits = [...code.matchAll(/\bconsole\b/g)].length;
    if (consoleHits > 1) {
        fail.push(`${name}: ${String(consoleHits)} references to console — only the diagnostics sink may reach globalThis.console, exactly once`);
    }

    // Nothing foreign, and nothing that a Content-Security-Policy without
    // 'unsafe-eval' would refuse to load.
    for (const marker of FOREIGN_MARKERS) {
        if (code.includes(marker)) fail.push(`${name}: ${JSON.stringify(marker)} found — a test, a fixture or an agent left it behind`);
    }
    if (/[A-Za-z0-9+/]{512,}/.test(code)) fail.push(`${name}: a base64 run of 512+ characters — embedded binary data`);
    if (/-----BEGIN [A-Z ]+-----/.test(code)) fail.push(`${name}: an embedded PEM block — certificates belong in tests/fixtures, not in the bundle`);
    if (/\beval\(|new Function\(/.test(code)) fail.push(`${name}: dynamic code evaluation — a CSP with no 'unsafe-eval' must be able to load this`);

    return fail;
}

/** What `probeDistFiles` needs from the filesystem, so the caller owns the I/O. */
export interface DistFile {
    /** The path, as a finding should name it, e.g. `dist/index.js`. */
    readonly path: string;
    /** Its contents, for a text file. */
    readonly text: string;
    /** Its size in bytes. */
    readonly bytes: number;
}

/** One entry of `declared.bundle` in docs/assets/ecosystem.json. */
export interface BundleBudget {
    readonly maxBytes: number;
}

/**
 * The assertions that span files: the declarations must name exactly the
 * public exports (types included, which `smoke:install` cannot see, because
 * it only loads values), and every shipped file must be inside its budget.
 *
 * @param files - Every file of dist/, already read.
 * @param exportNames - Every export name of docs/assets/api.json.
 * @param budgets - `declared.bundle` of docs/assets/ecosystem.json.
 * @returns One message per violation; empty when dist/ is within contract.
 */
export function probeDistFiles(
    files: readonly DistFile[],
    exportNames: readonly string[],
    budgets: Readonly<Record<string, BundleBudget>>,
): readonly string[] {
    const fail: string[] = [];

    for (const file of files.filter((f) => f.path.endsWith('.d.ts') || f.path.endsWith('.d.cts'))) {
        const declared = new Set<string>();
        for (const m of file.text.matchAll(/^(?:export\s+)?declare\s+(?:function|const|class)\s+([A-Za-z0-9_$]+)/gm)) declared.add(m[1] ?? '');
        for (const m of file.text.matchAll(/^(?:export\s+)?(?:declare\s+)?(?:interface|type)\s+([A-Za-z0-9_$]+)/gm)) declared.add(m[1] ?? '');
        for (const m of file.text.matchAll(/^export\s*\{([^}]*)\}/gm)) {
            for (const piece of (m[1] ?? '').split(',')) {
                const alias = piece.trim().replace(/^type\s+/, '').split(/\s+as\s+/);
                const name = (alias.length > 1 ? alias[1] : alias[0])?.trim() ?? '';
                if (name !== '') declared.add(name);
            }
        }
        const missing = exportNames.filter((name) => !declared.has(name));
        if (missing.length > 0) {
            fail.push(`${file.path}: declares ${String(exportNames.length - missing.length)} of the ${String(exportNames.length)} public exports; missing ${missing.slice(0, 8).join(', ')}${missing.length > 8 ? ', …' : ''} — smoke:install loads values only, so a dropped type export ships unnoticed`);
        }
    }

    for (const [path, budget] of Object.entries(budgets)) {
        const file = files.find((f) => f.path === path);
        if (file === undefined) { fail.push(`${path}: declared in the bundle budget and not present in dist/`); continue; }
        if (file.bytes > budget.maxBytes) {
            fail.push(`${path}: ${String(file.bytes)} bytes, over the declared budget of ${String(budget.maxBytes)} — raising it is a reviewed decision, so change docs/assets/ecosystem.json in the same commit`);
        }
    }
    for (const file of files) {
        if (!(file.path in budgets)) fail.push(`${file.path} ships and no entry of declared.bundle budgets it`);
    }

    return fail;
}
