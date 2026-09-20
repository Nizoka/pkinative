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

const GUIDE = 'docs/guides/conformance.md';
const DISAGREEMENTS = 'scripts/data/validator-disagreements.json';

const validatorRecordParity: Rule = {
    id: 'validator-record-parity',
    summary: 'The L4 record contract is the one the conformance guide documents: every field scripts/lib/validators.ts can compare is described in the guide, the guide invents none, every validator names its implementation lineage in THIRD-PARTY-NOTICES.md, and every reviewed disagreement carries a reason rather than a TODO.',
    check(ctx) {
        const out: Finding[] = [];
        const guide = ctx.read(GUIDE);
        if (guide === null) return [error(GUIDE, 'missing')];
        // Read from the source, so the rule cannot drift from the contract it
        // is checking: a field added in code but not documented is exactly
        // the gap a reader of the guide would fall into.
        const source = ctx.read('scripts/lib/validators.ts') ?? '';
        const fields = [...source.matchAll(/^ {4}([A-Za-z0-9]+): '/gm)].map((m) => m[1] ?? '');
        if (fields.length === 0) return [error('scripts/lib/validators.ts', 'declares no comparable field — FIELDS is what L4 compares')];
        for (const field of fields) {
            if (!guide.includes(`\`${field}\``)) out.push(error(GUIDE, `does not document the L4 field \`${field}\`, which scripts/lib/validators.ts compares`));
        }
        for (const m of guide.matchAll(/`([a-z][A-Za-z0-9]*Fp256)`/g)) {
            if (!fields.includes(m[1] ?? '')) out.push(error(GUIDE, `documents the L4 field \`${m[1] ?? ''}\`, which scripts/lib/validators.ts does not compare`));
        }

        const notices = ctx.read(NOTICES) ?? '';
        for (const m of source.matchAll(/^ {8}lineage: '([^']+)'/gm)) {
            const lineage = (m[1] ?? '').split(',')[0] ?? '';
            if (!notices.includes(lineage)) out.push(error(NOTICES, `credits no "${lineage}", which the L4 validator matrix runs — every toolchain it uses is named, with the fact that none is downloaded, vendored or pinned`));
        }

        const reviewed = readJson<{ schema?: unknown; reviewed?: Record<string, unknown> }>(ctx, DISAGREEMENTS);
        if ('finding' in reviewed) return [...out, reviewed.finding];
        for (const [key, reason] of Object.entries(reviewed.value.reviewed ?? {})) {
            if (typeof reason !== 'string' || reason.trim() === '' || /^TODO\b/i.test(reason)) {
                out.push(error(DISAGREEMENTS, `the disagreement ${key} carries no reason — an entry without one silences a difference instead of recording it`));
            }
            if (!/^[a-z0-9-]+:[0-9a-f]{64}:[A-Za-z0-9]+@[a-z0-9]+$/.test(key)) {
                out.push(error(DISAGREEMENTS, `the key ${JSON.stringify(key)} is not <validator>:<sha256>:<field>@<platform>`));
            }
        }
        return out;
    },
};

export const CONFORMANCE_RULES: readonly Rule[] = [corpusPinParity, validatorRecordParity];
