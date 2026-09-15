/**
 * pkinative — prose rules
 * ========================
 * Everything the project writes is English (AGENTS.md §Mission and
 * constraints). The detector is scripts/lib/prose-language.ts; this rule
 * decides which files it reads.
 *
 * @module scripts/verify-docs/rules/prose
 */

import { findNonEnglishProse } from '../../lib/prose-language.js';
import { error, type Rule } from '../context.js';

/** Markdown anywhere, plus the executable documentation (recipes). Generated bulk files are skipped. */
function isProse(path: string): boolean {
    if (path === 'docs/llms-full.txt') return false;
    return path.endsWith('.md') || /^recipes\/.+\.ts$/.test(path) || path === 'llms.txt' || path === 'docs/llms.txt';
}

const proseLanguage: Rule = {
    id: 'prose-language',
    summary: 'Documentation, governance files, release notes and recipes are written in English (demo-language: marks demonstrated content).',
    check(ctx) {
        return ctx.list('')
            .filter(isProse)
            .flatMap((file) => findNonEnglishProse(ctx.read(file) ?? '', file, { suppress: 'verify-docs:allow prose-language' })
                .map((f) => error(file, `${f.reason}: "${f.snippet}" — write it in English, or mark demonstrated content with demo-language: <tag> (reason)`, f.line)));
    },
};

export const PROSE_RULES: readonly Rule[] = [proseLanguage];
