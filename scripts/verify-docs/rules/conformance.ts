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

import { CLAUSES } from '../../lib/clauses.js';
import { CORPORA, checksumPath, parseChecksums } from '../../lib/corpora.js';
import { error, readJson, type Finding, type Rule } from '../context.js';

const NOTICES = 'THIRD-PARTY-NOTICES.md';
const ECOSYSTEM = 'docs/assets/ecosystem.json';
const DIAGNOSTICS = 'docs/data/diagnostics.json';
const CLAUSE_TABLE = 'scripts/lib/clauses.ts';

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

/**
 * The clause table cannot quietly stop meaning anything.
 *
 * Three ways it could, each closed: a clause naming a diagnostic code that
 * does not exist (so it can never fire, and the runner's "silent miss" check
 * becomes vacuous); a clause with neither a diagnostic nor a written waiver
 * (a sentence nobody enforces, kept for the look of the table); and a
 * documented level count that no longer matches the levels the runner has.
 */
const clauseTableComplete: Rule = {
    id: 'clause-table-complete',
    summary: 'Every L5 clause cites a real section, quotes a normative sentence, and names either a diagnostic code that exists in docs/data/diagnostics.json or a written waiver; the conformance guide documents L5.',
    check(ctx) {
        const out: Finding[] = [];
        const registry = readJson<{ diagnostics: Array<{ code: string }> }>(ctx, DIAGNOSTICS);
        if ('finding' in registry) return [registry.finding];
        const known = new Set(registry.value.diagnostics.map((d) => d.code));

        for (const clause of CLAUSES) {
            if (clause.diagnostic === null) {
                if ((clause.waiver ?? '').trim().length < 20) {
                    out.push(error(CLAUSE_TABLE, `${clause.id} names no diagnostic and no waiver — a clause the product does not report is a sentence nobody enforces`));
                }
            } else if (!known.has(clause.diagnostic)) {
                out.push(error(CLAUSE_TABLE, `${clause.id} names ${clause.diagnostic}, which is not in ${DIAGNOSTICS} — a clause pointing at a code that cannot fire makes the runner's silent-miss check vacuous`));
            }
            if (!/\b(MUST|SHOULD|shall|MAY)\b/.test(clause.quote)) {
                out.push(error(CLAUSE_TABLE, `${clause.id} quotes no normative keyword — "${clause.quote.slice(0, 60)}…" reads as a paraphrase, and a clause nobody can find in the RFC is a clause somebody invented`));
            }
            if (clause.unexercisedBy !== undefined && clause.unexercisedBy.reason.trim().length < 40) {
                out.push(error(CLAUSE_TABLE, `${clause.id} waives corpus coverage without saying why the corpus cannot reach it`));
            }
        }

        // The guide names the levels; L5 exists and must be described there,
        // or the conformance claim lives only in a script nobody reads.
        const guide = ctx.read(GUIDE) ?? '';
        if (!guide.includes('L5')) out.push(error(GUIDE, 'does not describe conformance level L5 — the clause checker is the difference between a regression detector and an authority, and it is not documented'));
        return out;
    },
};

export const CONFORMANCE_RULES: readonly Rule[] = [corpusPinParity, validatorRecordParity, clauseTableComplete];
