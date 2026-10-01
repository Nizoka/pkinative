/**
 * pkinative — external link rules
 * ===============================
 * `external-links`: every external link a reader can follow from the
 * documentation is served over HTTPS, and — with `--online`, which the
 * weekly `npm-drift` job of `.github/workflows/docs.yml` passes — still
 * resolves.
 *
 * Internal links are `internal-links` and `anchor-parity`; this is the half
 * the hermetic gate cannot see. Offline, the rule refuses a plain `http://`
 * link (a reader sent over a downgradable connection). Online, it probes each
 * distinct URL once and reports only what is certainly broken: a 404 or 410,
 * or a host that no longer resolves. A 401, 403, 429 or 5xx is a server
 * declining an anonymous probe or having a bad day, not a dead link, and is
 * not reported — a weekly job that went red on every bot wall would be
 * ignored by the second week.
 *
 * What is read: the README, SECURITY.md, CONTRIBUTING.md, SUPPORT.md,
 * llms.txt and every Markdown and HTML page under docs/, decision records
 * included. Code is not prose: fenced Markdown blocks and inline code, `<pre>`,
 * `<code>` and `<script>` elements and `xmlns` attributes are skipped, and so are the hosts RFC 2606
 * and RFC 6761 reserve (example.com, .test, .invalid, .example, localhost).
 * Release notes and the CHANGELOG are history and keep the links of their day.
 *
 * @module scripts/verify-docs/rules/links
 */

import { error, lineOf, type Finding, type Rule, type RuleContext } from '../context.js';

/** One external link, where it was found. */
export interface ExternalLink {
    readonly url: string;
    readonly file: string;
    readonly line: number;
}

/** What one probe answered: an HTTP status, or the network error code. */
export type ProbeResult = { readonly status: number } | { readonly failure: string };

/** Probes one URL. Injected so the rule's verdicts are tested without a network. */
export type Probe = (url: string) => Promise<ProbeResult>;

const RESERVED_HOST = /^(?:localhost|127\.0\.0\.1|\[::1\]|(?:[\w-]+\.)*example(?:\.(?:com|org|net))?|(?:[\w-]+\.)+(?:test|invalid|example|localhost))$/i;

/** The documents whose links a reader follows. */
export function linkSources(ctx: RuleContext): string[] {
    return [
        'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'SUPPORT.md', 'llms.txt',
        ...ctx.list('docs').filter((p) => p.endsWith('.md') || p.endsWith('.html')),
    ].filter((p) => ctx.exists(p));
}

/** Blank out what is code rather than prose, keeping every line where it was. */
function proseOnly(path: string, text: string): string {
    const blank = (m: string): string => m.replace(/[^\n]/g, ' ');
    if (path.endsWith('.html')) {
        return text
            .replace(/<pre\b[\s\S]*?<\/pre>/gi, blank)
            .replace(/<code\b[\s\S]*?<\/code>/gi, blank)
            .replace(/<script\b[\s\S]*?<\/script>/gi, blank)
            .replace(/\sxmlns(?::\w+)?="[^"]*"/gi, blank);
    }
    return text.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[ \t]*$/gm, blank).replace(/`[^`\n]*`/g, blank);
}

/** Every external link of one document, in order, with its line. */
export function externalLinks(path: string, text: string): ExternalLink[] {
    const prose = proseOnly(path, text);
    const out: ExternalLink[] = [];
    // A Markdown target, an autolink, an href or src attribute, or a bare URL.
    const pattern = /\]\((https?:\/\/[^)\s]+)\)|<(https?:\/\/[^>\s]+)>|(?:href|src)="(https?:\/\/[^"]+)"|(?<![("=<])\b(https?:\/\/[^\s<>()"'`\]]+)/g;
    for (const m of prose.matchAll(pattern)) {
        const raw = (m[1] ?? m[2] ?? m[3] ?? m[4] ?? '').replace(/[.,;:!?]+$/, '');
        let host: string;
        try {
            host = new URL(raw).hostname;
        } catch {
            continue;
        }
        if (RESERVED_HOST.test(host)) continue;
        out.push({ url: raw, file: path, line: lineOf(text, m.index) });
    }
    return out;
}

/** The verdict on one probe: a message when the link is certainly broken, else null. */
export function brokenBecause(result: ProbeResult): string | null {
    if ('failure' in result) return /ENOTFOUND|EAI_NONAME/.test(result.failure) ? `its host no longer resolves (${result.failure})` : null;
    return result.status === 404 || result.status === 410 ? `answers ${String(result.status)}` : null;
}

/** Probe each distinct URL once, a few at a time, and report the certainly broken ones where they first appear. */
export async function judgeLinks(links: readonly ExternalLink[], probe: Probe, concurrency = 6): Promise<Finding[]> {
    const first = new Map<string, ExternalLink>();
    for (const link of links) if (!first.has(link.url)) first.set(link.url, link);
    const queue = [...first.values()];
    const out: Finding[] = [];
    const worker = async (): Promise<void> => {
        for (let link = queue.shift(); link !== undefined; link = queue.shift()) {
            const reason = brokenBecause(await probe(link.url));
            if (reason !== null) out.push(error(link.file, `links ${link.url}, which ${reason} — fix the link, point it at an archived copy, or remove it`, link.line));
        }
    };
    await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
    return out.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

/** HEAD, then GET when the server will not answer HEAD usefully; redirects followed. */
export const fetchProbe: Probe = async (url) => {
    const ask = async (method: 'HEAD' | 'GET'): Promise<ProbeResult> => {
        try {
            const response = await fetch(url, {
                method,
                redirect: 'follow',
                signal: AbortSignal.timeout(15_000),
                headers: { 'user-agent': 'pkinative-link-check (+https://github.com/Nizoka/pkinative)' },
            });
            await response.body?.cancel();
            return { status: response.status };
        } catch (err) {
            const cause = (err as { cause?: { code?: unknown } }).cause;
            return { failure: typeof cause?.code === 'string' ? cause.code : (err as Error).name };
        }
    };
    const head = await ask('HEAD');
    return 'status' in head && head.status < 400 ? head : ask('GET');
};

const externalLinksRule: Rule = {
    id: 'external-links',
    summary: 'Every external link of the README, SECURITY.md, CONTRIBUTING.md, SUPPORT.md, llms.txt and docs/ is HTTPS; with --online, none answers 404 or 410 and every host still resolves.',
    async check(ctx) {
        const links = linkSources(ctx).flatMap((path) => externalLinks(path, ctx.read(path) ?? ''));
        const insecure = links
            .filter((link) => link.url.startsWith('http://'))
            .map((link) => error(link.file, `links ${link.url} over plain HTTP — a reader is sent over a connection anyone on the path can rewrite; use https://`, link.line));
        if (!ctx.online) return insecure;
        return [...insecure, ...await judgeLinks(links.filter((link) => link.url.startsWith('https://')), fetchProbe)];
    },
};

export const LINK_RULES: readonly Rule[] = [externalLinksRule];
