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
import { IMPLEMENTED_TOOLS, KEY_CONTAINER_CASES, PENDING_TOOLS, READ_CASES, REQUIRED_TOOLS, TOOL_LIMITATIONS } from '../../lib/interop.js';
import { RFC_INVENTORIES, titleInSource, type RfcInventorySpec } from '../../lib/rfc-requirements.js';
import { error, readJson, type Finding, type Rule, type RuleContext } from '../context.js';

const NOTICES = 'THIRD-PARTY-NOTICES.md';
const ECOSYSTEM = 'docs/assets/ecosystem.json';
const DIAGNOSTICS = 'docs/data/diagnostics.json';
const CLAUSE_TABLE = 'scripts/lib/clauses.ts';
const INTEROP = 'scripts/lib/interop.ts';
const ROADMAP = 'ROADMAP.md';
const CONFORMANCE_WORKFLOW = '.github/workflows/conformance.yml';
const GATE = 'scripts/gate.ts';

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
    summary: 'The L4 record contract is the one the conformance guide documents: every field scripts/lib/validators.ts can compare is described in the guide, the guide invents none, the guide names every validator, every validator names its implementation lineage in THIRD-PARTY-NOTICES.md, and every reviewed disagreement carries a reason rather than a TODO.',
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

        // Every validator the registry runs is named in the guide, so the
        // page says which lineages L4 confronts and where — the claim it
        // once made in general terms while one Windows-only validator ran.
        for (const m of source.matchAll(/^ {8}id: '([^']+)'/gm)) {
            if (!guide.includes(`\`${m[1] ?? ''}\``)) out.push(error(GUIDE, `does not name the L4 validator \`${m[1] ?? ''}\`, which scripts/lib/validators.ts runs`));
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
    summary: 'Every L5 clause cites a real section, quotes a normative sentence, and names either a diagnostic code that exists in docs/data/diagnostics.json or a written waiver; the conformance guide documents L5; the counts of every RFC requirement inventory (scripts/data/rfc<NNNN>-requirements.json) match declared.rfc<NNNN> in ecosystem.json and the conformance guide, and every `test` entry names a test file holding a case of that title.',
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

        // The requirement inventories: their counts are ecosystem.json
        // canaries, and the guide quotes them, so the three must say the same
        // thing. A `test` entry claims that a named case exercises its
        // sentence; a renamed or deleted case would leave the claim standing
        // with nothing behind it, so the file must still hold that title.
        const ecosystem = readJson<{ declared?: Record<string, Record<string, unknown> | undefined> }>(ctx, ECOSYSTEM);
        if ('finding' in ecosystem) return [...out, ecosystem.finding];
        for (const spec of RFC_INVENTORIES) out.push(...inventoryFindings(ctx, spec, guide, ecosystem.value.declared?.[spec.declared]));
        return out;
    },
};

/**
 * One inventory against its three witnesses: its declared counts in
 * ecosystem.json, the sentence of the conformance guide that quotes them —
 * RFC 5280's in the wording of its own paragraph, every other RFC's as
 * `RFC NNNN <scope>: **N sentences**, **N held by a test**, **N excluded**`
 * followed by its exclusions by reason — and, for each `test` entry, the
 * test file that must still hold a case of that title.
 */
function inventoryFindings(ctx: RuleContext, spec: RfcInventorySpec, guide: string, declared: Record<string, unknown> | undefined): Finding[] {
    const out: Finding[] = [];
    const inventory = readJson<{ requirements?: Record<string, { status?: string; reason?: string; file?: string; test?: string }> }>(ctx, spec.data);
    if ('finding' in inventory) return [inventory.finding];
    const entries = Object.entries(inventory.value.requirements ?? {});
    const counts = {
        requirements: entries.length,
        clauses: entries.filter(([, e]) => e.status === 'clause').length,
        tests: entries.filter(([, e]) => e.status === 'test').length,
        excluded: entries.filter(([, e]) => e.status === 'excluded').length,
    };
    for (const [key, value] of Object.entries(counts)) {
        if (declared?.[key] !== value) out.push(error(ECOSYSTEM, `declared.${spec.declared}.${key} is ${String(declared?.[key])}; ${spec.data} holds ${String(value)}`));
    }
    for (const [id, entry] of entries) {
        if (entry.status !== 'test') continue;
        const source = ctx.read(entry.file ?? '');
        if (source === null || !titleInSource(source, entry.test ?? '')) {
            out.push(error(spec.data, `${id} is held by "${String(entry.test)}" in ${String(entry.file)}, which holds no it, test or describe of that title — the test was renamed or removed`));
        }
    }
    if (spec.declared === 'rfc5280') {
        for (const phrase of [`**${String(counts.requirements)} sentences**`, `**${String(counts.clauses)} are held by a clause**`, `**${String(counts.excluded)} are excluded**`]) {
            if (!guide.includes(phrase)) out.push(error(GUIDE, `does not say ${phrase} — the L5 completeness counts in the guide drifted from ${spec.data}`));
        }
        return out;
    }
    const phrase = `${spec.rfc} ${spec.scope}: **${String(counts.requirements)} sentences**, **${String(counts.tests)} held by a test**, **${String(counts.excluded)} excluded**`;
    const at = guide.indexOf(phrase);
    if (at < 0) return [...out, error(GUIDE, `does not say ${phrase} — the L5 completeness counts in the guide drifted from ${spec.data}`)];
    const sentence = guide.slice(at + phrase.length, guide.indexOf('\n', at) < 0 ? undefined : guide.indexOf('\n', at)).split(/\.(\s|$)/)[0] ?? '';
    const reasons = new Map<string, number>();
    for (const [, e] of entries) if (e.status === 'excluded' && e.reason !== undefined) reasons.set(e.reason, (reasons.get(e.reason) ?? 0) + 1);
    for (const [reason, n] of reasons) {
        if (!sentence.includes(`${String(n)} \`${reason}\``)) out.push(error(GUIDE, `does not say ${String(n)} \`${reason}\` in its ${spec.rfc} sentence — the exclusions by reason drifted from ${spec.data}`));
    }
    return out;
}

/**
 * A gap written down is a gap someone can close; a gap only the code knows
 * about is a matrix that looks complete and is not.
 *
 * This rule holds the matrix's declarations (scripts/lib/interop.ts) to every
 * place that promises it: ROADMAP.md names every tool, implemented or pending;
 * THIRD-PARTY-NOTICES.md credits every tool the matrix runs; the conformance
 * guide describes every read-direction case and no other; each platform's
 * required tools are implemented, and the Linux ones are installed by the
 * conformance workflow, which runs the matrix with --require-all — as the
 * release gate does — so a missing tool goes red instead of skipping; and
 * every reviewed tool limitation names an implemented tool, a pattern, a
 * reason and the proof that the limitation is the tool's.
 */
const INSTALLED_BY_WORKFLOW: Readonly<Record<string, string>> = {
    'gnutls-certtool': 'gnutls-bin',
    'go-x509': 'actions/setup-go@',
    zlint: 'github.com/zmap/zlint/v3/cmd/zlint@v',
    'python-cryptography': '--require-hashes',
    pkilint: '--require-hashes',
};

const interopMatrixDeclared: Rule = {
    id: 'interop-matrix-declared',
    summary: 'Every interoperability tool is implemented or pending with a reason; ROADMAP.md names them all and THIRD-PARTY-NOTICES.md credits the implemented ones; every required tool is implemented and, on Linux, installed by the conformance workflow, which runs the matrix with --require-all as the release gate does; every tool limitation is reasoned and proved; every key-container and read case belongs to an implemented tool and is described in the conformance guide, which describes no other.',
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

        const notices = ctx.read(NOTICES) ?? '';
        for (const id of IMPLEMENTED_TOOLS) {
            if (!notices.includes(`\`${id}\``)) out.push(error(NOTICES, `does not credit \`${id}\`, which npm run interop runs — every foreign tool the matrix invokes is named, with the fact that it is run and never vendored`));
        }

        // Which platform must have which tool, and how Linux gets them.
        const workflow = ctx.read(CONFORMANCE_WORKFLOW) ?? '';
        for (const [platform, tools] of Object.entries(REQUIRED_TOOLS)) {
            if (tools.length === 0) out.push(error(INTEROP, `REQUIRED_TOOLS.${platform} is empty — a platform the workflow runs on must be held to something`));
            for (const id of tools) if (!IMPLEMENTED_TOOLS.includes(id)) out.push(error(INTEROP, `REQUIRED_TOOLS.${platform} requires ${id}, which is not implemented`));
        }
        for (const id of REQUIRED_TOOLS.linux) {
            const marker = INSTALLED_BY_WORKFLOW[id];
            if (marker !== undefined && !workflow.includes(marker)) out.push(error(CONFORMANCE_WORKFLOW, `does not install ${id} (looked for "${marker}"), which REQUIRED_TOOLS.linux requires — under --require-all the Linux run would go red for a tool nobody installed`));
        }

        // Reviewed limitations: a tool's, with a reason and a proof.
        for (const l of TOOL_LIMITATIONS) {
            if (!IMPLEMENTED_TOOLS.includes(l.tool)) out.push(error(INTEROP, `a tool limitation names ${l.tool}, which is not implemented`));
            if (l.reason.trim().length < 60) out.push(error(INTEROP, `the ${l.tool} limitation "${l.match.join(', ')}" gives no reason anyone could check`));
            if (l.proof.trim().length < 30) out.push(error(INTEROP, `the ${l.tool} limitation "${l.match.join(', ')}" records no proof that the limitation is the tool's and not pkinative's`));
            if (l.match.length === 0) out.push(error(INTEROP, `a ${l.tool} limitation matches nothing`));
            for (const m of l.match) {
                if (!/^(?:[a-z.*]+|lint:[A-Za-z0-9_.*-]+)@[a-z0-9*-]+\/[a-z0-9*-]+$/.test(m)) out.push(error(INTEROP, `the ${l.tool} limitation pattern ${JSON.stringify(m)} is not <check>@<profile>/<artefact> or lint:<id>@<profile>/<artefact>`));
            }
        }

        // The read direction: every case the runner may evaluate belongs to an
        // implemented tool and is described in the conformance guide, and the
        // guide describes no case the runner does not run — a case documented
        // and never run is a claim nobody checks.
        const guide = ctx.read(GUIDE) ?? '';
        const tables = [
            { table: 'KEY_CONTAINER_CASES', kind: 'key-container', list: KEY_CONTAINER_CASES, shape: /`([a-z0-9-]+:(?:pkcs8|pkcs12|pfx)-[a-z0-9-]+)`/g },
            { table: 'READ_CASES', kind: 'read', list: READ_CASES, shape: /`([a-z0-9-]+:(?:cms|tsp|ocsp|crl|csr)(?:-[a-z0-9-]+)?)`/g },
        ];
        for (const { table, kind, list, shape } of tables) {
            const cases = new Set(list.map((c) => c.id));
            if (cases.size !== list.length) out.push(error(INTEROP, `${table} declares a case twice`));
            for (const c of list) {
                if (!IMPLEMENTED_TOOLS.includes(c.tool) || !c.id.startsWith(`${c.tool}:`)) {
                    out.push(error(INTEROP, `the ${table} case ${c.id} names ${c.tool}, which is not an implemented tool or not its prefix`));
                }
                if (!guide.includes(`\`${c.id}\``)) out.push(error(GUIDE, `does not describe the ${kind} case \`${c.id}\`, which npm run interop runs`));
            }
            for (const m of guide.matchAll(shape)) {
                if (!cases.has(m[1] ?? '')) out.push(error(GUIDE, `describes the ${kind} case \`${m[1] ?? ''}\`, which scripts/lib/interop.ts does not declare`));
            }
        }

        const runsMatrix = /run:\s*npm run interop/.test(workflow);
        if (!runsMatrix) {
            out.push(error(CONFORMANCE_WORKFLOW, 'does not run the interoperability matrix — its three contexts are already required, so this is where the write direction becomes blocking on Linux, Windows and macOS'));
        } else if (!/npm run interop[^\n]*--require-all/.test(workflow)) {
            out.push(error(CONFORMANCE_WORKFLOW, 'runs the matrix without --require-all — a tool REQUIRED_TOOLS names for a runner has to go red when it is missing, not skip'));
        }
        if (!(ctx.read(GATE) ?? '').includes('PKINATIVE_INTEROP_REQUIRE_ALL')) {
            out.push(error(GATE, 'the interop step does not pass PKINATIVE_INTEROP_REQUIRE_ALL — the release gate would accept a run that skipped a required tool'));
        }
        return out;
    },
};

const WAIVERS = 'scripts/data/lint-waivers.json';
const LINTERS = ['zlint', 'pkilint'];

/**
 * A lint finding accepted on what pkinative creates is a decision, and a
 * decision without its reason is a silenced finding. The runner already
 * refuses a warning nobody reviewed and a waiver nothing matches; this rule
 * holds the shape where a run is not needed: a known linter, a lint id, the
 * artefacts it applies to, a reason someone wrote. An error result is never
 * waived — the runner does not consult this file for one — so a waiver of a
 * zlint lint named as an error (`e_`, `f_`) must say why that lint answered
 * WARNING: zlint's e_signature_algorithm_not_supported does, by design, for
 * RSASSA-PSS.
 */
const lintWaiverReviewed: Rule = {
    id: 'lint-waiver-reviewed',
    summary: 'Every waiver in scripts/data/lint-waivers.json names an implemented linter, a lint id, the artefacts it applies to and a written reason; one of a zlint lint named as an error (e_, f_) says why it answered WARNING; none appears twice.',
    check(ctx) {
        const out: Finding[] = [];
        const file = readJson<{ schema?: unknown; waivers?: unknown }>(ctx, WAIVERS);
        if ('finding' in file) return [file.finding];
        if (file.value.schema !== 1) out.push(error(WAIVERS, `declares schema ${String(file.value.schema)}; the runner reads 1`));
        if (!Array.isArray(file.value.waivers)) return [...out, error(WAIVERS, 'has no `waivers` array')];
        const seen = new Set<string>();
        for (const [i, raw] of (file.value.waivers as unknown[]).entries()) {
            const w = (raw ?? {}) as { tool?: unknown; lint?: unknown; artefacts?: unknown; reason?: unknown };
            const where = `waiver ${String(i)}`;
            if (typeof w.tool !== 'string' || !LINTERS.includes(w.tool) || !IMPLEMENTED_TOOLS.includes(w.tool)) out.push(error(WAIVERS, `${where} names ${JSON.stringify(w.tool)}, which is not an implemented linter (${LINTERS.join(', ')})`));
            if (typeof w.lint !== 'string' || !/^[a-z][a-z0-9_.-]+$/.test(w.lint)) out.push(error(WAIVERS, `${where} names no lint id`));
            else if (w.tool === 'zlint' && /^[ef]_/.test(w.lint) && !(typeof w.reason === 'string' && w.reason.includes('WARNING'))) out.push(error(WAIVERS, `${where} waives ${w.lint}, a zlint lint named as an error, without saying why it answered WARNING — an error is fixed, or the linter proved wrong in TOOL_LIMITATIONS, never waived`));
            if (!Array.isArray(w.artefacts) || w.artefacts.length === 0 || !w.artefacts.every((a) => typeof a === 'string' && /^[a-z0-9*-]+\/[a-z0-9*-]+$/.test(a))) out.push(error(WAIVERS, `${where} does not say which artefacts it applies to (<profile>/<name>, * allowed)`));
            if (typeof w.reason !== 'string' || w.reason.trim().length < 60 || /^TODO\b/i.test(w.reason)) out.push(error(WAIVERS, `${where} (${String(w.lint)}) carries no reason — a waiver without one silences a finding instead of recording it`));
            const key = `${String(w.tool)}:${String(w.lint)}`;
            if (seen.has(key)) out.push(error(WAIVERS, `${key} is waived twice`));
            seen.add(key);
        }
        return out;
    },
};

export const CONFORMANCE_RULES: readonly Rule[] = [corpusPinParity, validatorRecordParity, clauseTableComplete, interopMatrixDeclared, lintWaiverReviewed];
