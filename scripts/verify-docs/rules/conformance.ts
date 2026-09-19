/**
 * pkinative — conformance rules
 * =============================
 * `corpus-pin-parity`: the pinned corpora of scripts/lib/corpora.ts, their
 * checksum files, their credit in THIRD-PARTY-NOTICES.md and their canaries
 * in docs/assets/ecosystem.json name the same commits. A re-pin that updates
 * one of them and not the others fails here, before the conformance job
 * downloads the wrong bytes or credits the wrong source.
 *
 * @module scripts/verify-docs/rules/conformance
 */

import { CORPORA, checksumPath, parseChecksums } from '../../lib/corpora.js';
import { error, readJson, type Finding, type Rule } from '../context.js';

const NOTICES = 'THIRD-PARTY-NOTICES.md';
const ECOSYSTEM = 'docs/assets/ecosystem.json';

const corpusPinParity: Rule = {
    id: 'corpus-pin-parity',
    summary: 'Every corpus pinned in scripts/lib/corpora.ts has a checksum file listing exactly its files, is credited with its commit and licence in THIRD-PARTY-NOTICES.md, and is declared with the same commit in docs/assets/ecosystem.json; no stray checksum file exists.',
    check(ctx) {
        const out: Finding[] = [];
        const notices = ctx.read(NOTICES) ?? '';
        const ecosystem = readJson<{ declared?: Record<string, { commit?: string }> }>(ctx, ECOSYSTEM);
        if ('finding' in ecosystem) return [ecosystem.finding];
        const expected = new Set<string>();
        for (const corpus of CORPORA) {
            const path = checksumPath(corpus);
            expected.add(path);
            const text = ctx.read(path);
            if (text === null) {
                out.push(error(path, `missing — ${corpus.id} is pinned at ${corpus.commit} in scripts/lib/corpora.ts`));
            } else {
                const listed = [...parseChecksums(text).keys()].sort();
                const wanted = corpus.files.map((f) => f.name).sort();
                if (listed.join('\n') !== wanted.join('\n')) out.push(error(path, `lists ${listed.join(', ') || 'nothing'}; scripts/lib/corpora.ts pins ${wanted.join(', ')}`));
            }
            if (!notices.includes(corpus.repository) || !notices.includes(corpus.commit) || !notices.includes(corpus.licence)) {
                out.push(error(NOTICES, `does not credit ${corpus.title} (${corpus.repository}) at commit ${corpus.commit} under ${corpus.licence}`));
            }
            const declared = ecosystem.value.declared?.[corpus.id]?.commit;
            if (declared !== corpus.commit) out.push(error(ECOSYSTEM, `declared.${corpus.id}.commit is ${String(declared)}; scripts/lib/corpora.ts pins ${corpus.commit}`));
        }
        for (const path of ctx.list('.github/checksums')) {
            if (!expected.has(path)) out.push(error(path, 'is not the checksum file of any corpus in scripts/lib/corpora.ts — delete it or pin its corpus'));
        }
        return out;
    },
};

export const CONFORMANCE_RULES: readonly Rule[] = [corpusPinParity];
