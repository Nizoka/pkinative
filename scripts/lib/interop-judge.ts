/**
 * pkinative — the interoperability matrix: deciding
 * =================================================
 * What a foreign tool's answers mean, decided in one place and with no I/O,
 * so every rule below is proved to fire by `tests/tools/interop.test.ts`.
 *
 * - **A refusal of pkinative's bytes is a failure.** The artefact is ours.
 *   Three exceptions, each written down: a reviewed tool limitation
 *   (`TOOL_LIMITATIONS`), a tool that says it cannot do this for a reason a
 *   self-declared limitation allows, and a tool that is not the reference
 *   build (OpenSSL before 3.0, LibreSSL), whose refusals are reported as not
 *   applicable, exactly as conformance level L3 treats them.
 * - **A fact that disagrees is a failure,** whoever is not the reference.
 * - **An answer this runner cannot read is a failure of the runner,** never
 *   evidence about the artefact.
 * - **A lint error is a failure; a lint warning must be reviewed** in
 *   `scripts/data/lint-waivers.json` with its reason; a lint info is noted.
 * - **Nothing reviewed may go stale.** A limitation whose check now passes,
 *   or matches nothing, and a waiver that matched nothing in a run of its
 *   tool, fail the run: a review nobody needs any more is where the next real
 *   failure hides.
 * - **A tool that compared nothing fails as vacuous.**
 *
 * @module scripts/lib/interop-judge
 */

import type { Artefact, Facts } from './interop-artefacts.js';
import type { ToolLimitation } from './interop.js';
import type { CheckResult } from './interop-tools.js';

/** A reviewed lint warning: `lint` of `tool` is accepted on the artefacts `artefacts` matches, for `reason`. */
export interface LintWaiver {
    readonly tool: string;
    readonly lint: string;
    readonly artefacts: readonly string[];
    readonly reason: string;
}

export interface Judgement {
    readonly failures: string[];
    readonly notApplicable: string[];
    /** Checks that succeeded and fields that were compared: the anti-vacuity count. */
    readonly agreed: number;
    readonly compared: number;
}

/** `*` matches any run of characters; everything else is literal. */
export function glob(pattern: string, text: string): boolean {
    const re = new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
    return re.test(text);
}

const INTEGER_FIELDS = new Set(['serial', 'signerSerial']);

/** One spelling per fact: integers in lowercase hex without leading zeros — a TimeStampReq nonce is an INTEGER too. */
export function canonical(field: string, value: string, kind: Artefact['kind']): string {
    const integer = INTEGER_FIELDS.has(field) || (field === 'nonce' && kind === 'tsq');
    if (!integer || value === '') return value;
    try { return BigInt(`0x${value}`).toString(16); } catch { return value; }
}

/** The fields a reading and pkinative's own facts share, and those that disagree. */
export function compareFacts(expect: Facts, got: Facts, kind: Artefact['kind']): { compared: number; differences: string[] } {
    let compared = 0;
    const differences: string[] = [];
    for (const [field, value] of Object.entries(got)) {
        const wanted = expect[field];
        if (wanted === undefined) continue;
        compared += 1;
        if (canonical(field, value, kind) !== canonical(field, wanted, kind)) differences.push(`${field} ${JSON.stringify(value)}, pkinative wrote ${JSON.stringify(wanted)}`);
    }
    return { compared, differences };
}

/**
 * Judge every answer one tool gave.
 *
 * @param reference Whether the tool is the reference build; refusals of a non-reference build are not applicable.
 */
export function judge(
    tool: string,
    results: readonly CheckResult[],
    artefacts: readonly Artefact[],
    reference: boolean,
    limitations: readonly ToolLimitation[],
    waivers: readonly LintWaiver[],
): Judgement {
    const failures: string[] = [];
    const notApplicable: string[] = [];
    const byId = new Map(artefacts.map((a) => [a.id, a]));
    const mine = limitations.filter((l) => l.tool === tool);
    const usedLimitation = new Set<ToolLimitation>();
    const matchedLimitation = new Set<ToolLimitation>();
    const usedWaiver = new Set<LintWaiver>();
    let agreed = 0;
    let compared = 0;
    const limitationFor = (key: string): ToolLimitation | undefined => {
        const found = mine.find((l) => l.match.some((m) => glob(m, key)));
        if (found !== undefined) matchedLimitation.add(found);
        return found;
    };

    for (const r of results) {
        const key = `${r.check}@${r.artefact}`;
        const artefact = byId.get(r.artefact);
        if (r.unreadable === true) {
            failures.push(`${tool} answered ${key} and run-interop could not read the answer (${r.error ?? ''}) — a defect in this runner, not in the artefact`);
            continue;
        }
        if (artefact === undefined) { failures.push(`${tool} answered about ${r.artefact}, which the set does not contain`); continue; }

        if (r.findings !== undefined) {
            agreed += 1;
            for (const finding of r.findings) {
                if (finding.severity === 'info') continue;
                const lintKey = `lint:${finding.lint}@${r.artefact}`;
                if (finding.severity === 'error') {
                    const limitation = limitationFor(lintKey);
                    if (limitation?.when === 'always') { usedLimitation.add(limitation); notApplicable.push(`${tool} ${lintKey}: a reviewed limitation of ${tool} — ${limitation.reason}`); continue; }
                    failures.push(`${tool} reports ${finding.lint} as an ERROR on ${r.artefact}, which pkinative wrote — a lint error is never waived; fix the encoder, or prove the linter wrong and record it in TOOL_LIMITATIONS`);
                    continue;
                }
                const waiver = waivers.find((w) => w.tool === tool && w.lint === finding.lint && w.artefacts.some((m) => glob(m, r.artefact)));
                if (waiver === undefined) failures.push(`${tool} reports ${finding.lint} as a warning on ${r.artefact} and scripts/data/lint-waivers.json does not review it — fix it, or record why it is accepted`);
                else usedWaiver.add(waiver);
            }
            continue;
        }

        const limitation = limitationFor(key);
        if (!r.ok) {
            if (limitation !== undefined && (limitation.when === 'always' || r.unsupported !== undefined)) {
                usedLimitation.add(limitation);
                notApplicable.push(`${tool} ${key}: a reviewed limitation of ${tool} — ${limitation.reason}`);
            } else if (r.unsupported !== undefined) {
                failures.push(`${tool} says it cannot do ${key} (${r.unsupported}) and TOOL_LIMITATIONS reviews no such limitation`);
            } else if (!reference) {
                notApplicable.push(`${tool} refused ${key} (${r.error ?? ''}); it is not the reference build, so its acceptance policy is not pkinative's contract`);
            } else {
                failures.push(`${tool} REFUSED ${key} (${r.error ?? 'no reason given'}) — the bytes are pkinative's, so this is pkinative's defect until proven otherwise`);
            }
            continue;
        }
        if (limitation?.when === 'always') {
            usedLimitation.add(limitation);
            failures.push(`${tool} now passes ${key}, which TOOL_LIMITATIONS says it cannot — the limitation is stale; delete it`);
        }
        agreed += 1;
        if (r.facts !== undefined) {
            const { compared: n, differences } = compareFacts(artefact.expect, r.facts, artefact.kind);
            compared += n;
            for (const d of differences) failures.push(`${tool} read ${r.artefact} (${r.check}): ${d}`);
        }
    }

    for (const l of mine) {
        if (l.when === 'always' && !matchedLimitation.has(l)) failures.push(`TOOL_LIMITATIONS: the ${tool} limitation "${l.match.join(', ')}" matched no check of this run — it is stale or misspelt`);
    }
    for (const w of waivers.filter((x) => x.tool === tool)) {
        if (!usedWaiver.has(w)) failures.push(`scripts/data/lint-waivers.json: the ${tool} waiver of ${w.lint} on ${w.artefacts.join(', ')} matched nothing in this run — it is stale; delete it`);
    }
    if (agreed === 0) failures.push(`${tool} agreed on nothing — a tool that reads nothing is not a cross-check`);
    return { failures, notApplicable, agreed, compared };
}
