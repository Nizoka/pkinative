/**
 * pkinative — LLM documentation files (`npm run docs:llms`)
 * =========================================================
 * Emits, from the committed sources:
 *   docs/llms.txt         — a copy of the root llms.txt (the site serves docs/)
 *   docs/llms-full.txt    — llms.txt + README + every guide, in navigation order
 *   docs/llms-recipes.txt — every recipe of recipes/index.json, fenced as ts
 *   docs/llms-index.json  — the artefacts and guides with sizes and anchors
 *
 * Deterministic (LF, fixed order) and pure: `llmsOutputs(read)` returns every
 * file, so the verify-docs rules `llms-sync` and `llms-index-sync` rebuild
 * them in memory and compare byte for byte (zipnative doctrine).
 *
 * @module scripts/build-llms-full
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GUIDES, SITE, guideAnchors, guideSummary, guideTitle, type Reader } from './build-guides.js';

export const SUMMARY_MAX = 400;

const lf = (text: string): string => text.replace(/\r\n/g, '\n');
const bytes = (text: string): number => Buffer.byteLength(text, 'utf8');

function required(read: Reader, path: string): string {
    return lf(read(path) ?? '');
}

export function buildLlmsFull(read: Reader): string {
    const parts = [required(read, 'llms.txt').trim()];
    const sources = ['README.md', ...GUIDES.map((name) => `docs/guides/${name}.md`)];
    for (const source of sources) parts.push(`\n\n---\n<!-- source: ${source} -->\n\n${required(read, source).trim()}`);
    return `${parts.join('')}\n`;
}

export function buildLlmsRecipes(read: Reader): string {
    const index = JSON.parse(required(read, 'recipes/index.json') || '{"recipes":[]}') as { recipes: Array<{ file: string; task: string }> };
    const parts = [
        '# pkinative — executable recipes\n\n'
        + 'Each recipe below runs on every test run (tests/docs/recipes.test.ts) and its\n'
        + 'expectations in recipes/index.json are asserted, so these samples cannot rot.\n'
        + 'They read the public certificates of tests/fixtures/ through recipes/_fixtures.ts.\n',
    ];
    for (const file of ['_fixtures.ts', ...index.recipes.map((r) => r.file)]) {
        parts.push(`\n---\n<!-- source: recipes/${file} -->\n\n\`\`\`ts\n${required(read, `recipes/${file}`).trim()}\n\`\`\`\n`);
    }
    return parts.join('');
}

function truncate(text: string): string {
    if (text.length <= SUMMARY_MAX) return text;
    const window = text.slice(0, SUMMARY_MAX);
    const sentence = window.lastIndexOf('. ');
    return sentence > SUMMARY_MAX * 0.6 ? window.slice(0, sentence + 1) : `${window.slice(0, window.lastIndexOf(' '))}…`;
}

export function buildLlmsIndex(read: Reader, generated: ReadonlyMap<string, string>): string {
    const text = (path: string): string => generated.get(path) ?? required(read, path);
    const ecosystem = JSON.parse(required(read, 'docs/assets/ecosystem.json') || '{}') as { verifiedOn?: string };
    const artefacts: Array<[string, string, string]> = [
        ['llms.txt', 'docs/llms.txt', 'The machine-readable documentation index — the entry point.'],
        ['agent-brief.md', 'docs/agent-brief.md', 'A compact brief for AI coding agents: what to import, what to catch, what not to write.'],
        ['llms-full.txt', 'docs/llms-full.txt', 'llms.txt, the README and every guide in one text.'],
        ['llms-recipes.txt', 'docs/llms-recipes.txt', 'Every executable recipe, fenced as TypeScript.'],
        ['assets/api.json', 'docs/assets/api.json', 'The public surface: every export with module, signature, summary and thrown error classes.'],
        ['data/errors.json', 'docs/data/errors.json', 'Every error code with its class, cause, remedy, standard and CWE.'],
        ['data/diagnostics.json', 'docs/data/diagnostics.json', 'Every diagnostic code with its severity, cause, remedy and standard.'],
        ['data/limits.json', 'docs/data/limits.json', 'The named resource limits with their defaults and CWE.'],
        ['data/surfaces.json', 'docs/data/surfaces.json', 'What pkinative does, the exports that do it, and since which version.'],
        ['assets/ecosystem.json', 'docs/assets/ecosystem.json', 'Versions, milestones, contracts, corpus pins and counts — the single source of truth.'],
    ];
    const index = {
        $comment: 'Index of pkinative’s machine-readable files and guides, with LF-normalised sizes. Regenerate with `npm run docs:llms`; the verify-docs rule llms-index-sync enforces freshness. approxTokens = bytes / 4.',
        site: SITE,
        verifiedOn: ecosystem.verifiedOn ?? null,
        artefacts: artefacts.map(([url, path, description]) => {
            const size = bytes(text(path));
            return { url, description, bytes: size, approxTokens: Math.round(size / 4) };
        }),
        guides: GUIDES.map((name) => {
            const md = required(read, `docs/guides/${name}.md`);
            const size = bytes(md);
            return {
                title: guideTitle(md),
                summary: truncate(guideSummary(md)),
                html: `guides/${name}.html`,
                markdown: `guides/${name}.md`,
                anchors: guideAnchors(md),
                bytes: size,
                approxTokens: Math.round(size / 4),
            };
        }),
    };
    return `${JSON.stringify(index, null, 2)}\n`;
}

/** Every generated file, path → content, the index last (it measures the others). */
export function llmsOutputs(read: Reader): ReadonlyMap<string, string> {
    const out = new Map<string, string>();
    out.set('docs/llms.txt', required(read, 'llms.txt'));
    out.set('docs/llms-full.txt', buildLlmsFull(read));
    out.set('docs/llms-recipes.txt', buildLlmsRecipes(read));
    out.set('docs/llms-index.json', buildLlmsIndex(read, out));
    return out;
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
    const root = join(dirname(fileURLToPath(import.meta.url)), '..');
    const read: Reader = (path) => (existsSync(join(root, path)) ? readFileSync(join(root, path), 'utf8') : null);
    for (const [path, text] of llmsOutputs(read)) writeFileSync(join(root, path), text);
    console.error('docs/llms.txt, llms-full.txt, llms-recipes.txt and llms-index.json written');
}
