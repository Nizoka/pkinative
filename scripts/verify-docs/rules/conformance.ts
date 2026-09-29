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
import { IMPLEMENTED_TOOLS, KEY_CONTAINER_CASES, PENDING_TOOLS } from '../../lib/interop.js';
import { error, readJson, type Finding, type Rule } from '../context.js';

const NOTICES = 'THIRD-PARTY-NOTICES.md';
const ECOSYSTEM = 'docs/assets/ecosystem.json';
const DIAGNOSTICS = 'docs/data/diagnostics.json';
const CLAUSE_TABLE = 'scripts/lib/clauses.ts';
const INTEROP = 'scripts/lib/interop.ts';
const ROADMAP = 'ROADMAP.md';
const CONFORMANCE_WORKFLOW = '.github/workflows/conformance.yml';

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
                if (corpus.archive !== undefined) {
                    // An archive is pinned **twice**, and the two pins answer
                    // different questions. `commit` is the archive's own SHA-256
                    // and already fixes every byte inside it, so which files it
                    // holds is not a choice made in the pin table — listing them
                    // there would be transcribing the archive. What this list
                    // defends against is the other thing: a bug in
                    // scripts/lib/zip.ts that extracted the wrong bytes from the
                    // right archive. So the demand here is only that the second
                    // pin exists and names files the archive could hold.
                    if (listed.length === 0) {
                        out.push(error(path, `lists nothing — ${corpus.id} is an archive corpus, and this file is the pin that holds its extraction to the bytes reviewed`));
                    }
                    const stray = listed.filter((name) => !corpus.archive?.include.some((prefix) => name.startsWith(prefix)));
                    if (stray.length > 0) {
                        out.push(error(path, `lists ${stray.slice(0, 3).join(', ')} and ${String(stray.length)} file(s) outside ${corpus.archive.include.join(', ')} — the extraction kept more than the pin table asks for`));
                    }
                } else {
                    const wanted = corpus.files.map((f) => f.name).sort();
                    if (listed.join('\n') !== wanted.join('\n')) out.push(error(path, `lists ${listed.join(', ') || 'nothing'}; scripts/lib/corpora.ts pins ${wanted.join(', ')}`));
                }
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

/**
 * A gap written down is a gap someone can close; a gap only the code knows
 * about is a matrix that looks complete and is not.
 *
 * ROADMAP.md promises six tools in both directions. This rule holds that
 * promise to `scripts/lib/interop.ts`: every tool named in the roadmap line
 * is either implemented or listed as pending with a reason, and every pending
 * tool carries one long enough to act on. It also refuses a pending list that
 * has emptied without `--require-all` being turned on in the workflow, which
 * is the one moment the matrix stops being partly aspirational. And it holds
 * the key-container cases — the read direction — to the conformance guide in
 * both directions.
 */
const interopMatrixDeclared: Rule = {
    id: 'interop-matrix-declared',
    summary: 'Every interoperability tool is implemented or listed as pending with a reason; ROADMAP.md names them all; every key-container case belongs to an implemented tool and is described in the conformance guide, which describes no other; and when nothing is pending the conformance workflow runs the matrix with --require-all.',
    check(ctx) {
        const out: Finding[] = [];
        const declared = new Set([...IMPLEMENTED_TOOLS, ...PENDING_TOOLS.map((t) => t.id)]);
        if (IMPLEMENTED_TOOLS.length === 0) out.push(error(INTEROP, 'implements no tool at all — a write-direction matrix with no reader proves nothing'));

        for (const tool of PENDING_TOOLS) {
            if (tool.why.trim().length < 40) out.push(error(INTEROP, `${tool.id} is pending without a reason anyone could act on`));
            if (IMPLEMENTED_TOOLS.includes(tool.id)) out.push(error(INTEROP, `${tool.id} is listed as both implemented and pending`));
        }

        const roadmap = ctx.read(ROADMAP) ?? '';
        const line = /^- \[[ x]\] A foreign-tool interop matrix[^\n]*$/m.exec(roadmap)?.[0];
        if (line === undefined) {
            out.push(error(ROADMAP, 'no longer carries the interop-matrix line the 0.4.0 band promises'));
        } else {
            // The roadmap names tools in prose (`OpenSSL`, `certtool`, …); the
            // check is that every declared id is recognisable in it, so a tool
            // cannot be added to the code and quietly left out of the promise,
            // nor promised and never declared.
            for (const id of declared) {
                const word = (id.split('-').pop() ?? id).toLowerCase();
                if (!line.toLowerCase().includes(word)) {
                    out.push(error(ROADMAP, `the interop-matrix line does not mention ${id} (looked for "${word}") — the roadmap and scripts/lib/interop.ts must promise the same matrix`));
                }
            }
        }

        // The read direction for key containers: every case the runner may
        // evaluate belongs to an implemented tool and is described in the
        // conformance guide, and the guide describes no case the runner does
        // not run — a case documented and never run is a claim nobody checks.
        const guide = ctx.read(GUIDE) ?? '';
        const cases = new Set(KEY_CONTAINER_CASES.map((c) => c.id));
        if (cases.size !== KEY_CONTAINER_CASES.length) out.push(error(INTEROP, 'declares a key-container case twice'));
        for (const c of KEY_CONTAINER_CASES) {
            if (!IMPLEMENTED_TOOLS.includes(c.tool) || !c.id.startsWith(`${c.tool}:`)) {
                out.push(error(INTEROP, `the key-container case ${c.id} names ${c.tool}, which is not an implemented tool or not its prefix`));
            }
            if (!guide.includes(`\`${c.id}\``)) out.push(error(GUIDE, `does not describe the key-container case \`${c.id}\`, which npm run interop runs`));
        }
        for (const m of guide.matchAll(/`([a-z0-9-]+:(?:pkcs8|pkcs12|pfx)-[a-z0-9-]+)`/g)) {
            if (!cases.has(m[1] ?? '')) out.push(error(GUIDE, `describes the key-container case \`${m[1] ?? ''}\`, which scripts/lib/interop.ts does not declare`));
        }

        const workflow = ctx.read(CONFORMANCE_WORKFLOW) ?? '';
        const runsMatrix = /run:\s*npm run interop/.test(workflow);
        if (!runsMatrix) {
            out.push(error(CONFORMANCE_WORKFLOW, 'does not run the interoperability matrix — its three contexts are already required, so this is where the write direction becomes blocking on Linux, Windows and macOS'));
        } else if (PENDING_TOOLS.length === 0 && !/npm run interop[^\n]*--require-all/.test(workflow)) {
            out.push(error(CONFORMANCE_WORKFLOW, 'nothing is pending any more, so the matrix must run with --require-all — a tool missing from a runner has to go red, not skip'));
        }
        return out;
    },
};

export const CONFORMANCE_RULES: readonly Rule[] = [corpusPinParity, validatorRecordParity, clauseTableComplete, interopMatrixDeclared];
