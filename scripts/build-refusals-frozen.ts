#!/usr/bin/env tsx
/**
 * pkinative — frozen refusal snapshot generator
 * =============================================
 * `docs/data/refusals.frozen.json` is the decision surface of ADR 0014:
 * every x509-limbo certificate pkinative refuses, by SHA-256, with its code.
 * It is written from `scripts/data/limbo-refusals.json`, the baseline that
 * conformance L1 verifies against the corpus, and only in these ways:
 *
 *   (no flag)        While `asOf` is unreleased (package.json below it), the
 *                    band that takes the snapshot may retake it. Once
 *                    package.json reaches `asOf`, a change is refused. Below
 *                    1.0.0 this is also how the rehearsal snapshot is first
 *                    written.
 *   --ratchet        Stable phase only: records the refusals the release at
 *                    package.json ships. A refusal the snapshot does not hold
 *                    yet joins it with that release as its `since`, and the
 *                    `refusal-baseline-frozen` rule then wants it listed in
 *                    that release's note. Refused when a promised refusal was
 *                    lifted or recoded — that is semver-major.
 *                    release-prepare.ts runs it on every release from 1.0.0.
 *   --major X.0.0    Rebases the snapshot at a major release: phase `stable`,
 *                    `frozenAt` and `asOf` X.0.0, the baseline as it stands.
 *                    At 1.0.0 (rehearsal → stable) it is refused unless the
 *                    rehearsal held. release-prepare.ts runs it.
 *   --repin [--adr docs/adr/NNNN-….md]
 *                    After x509-limbo is re-pinned and the baseline
 *                    regenerated: carries every promised refusal the new
 *                    corpus still holds to the new commit, adds the corpus's
 *                    new refusals without a `since` (new certificates, not new
 *                    behaviour), and retires the ones whose certificate the
 *                    corpus dropped — which needs an accepted ADR recording
 *                    the re-pin. Refused when a promised refusal changed code.
 *
 * Usage:
 *   npx tsx scripts/build-refusals-frozen.ts
 *   npx tsx scripts/build-refusals-frozen.ts --ratchet
 *   npx tsx scripts/build-refusals-frozen.ts --major 1.0.0
 *   npx tsx scripts/build-refusals-frozen.ts --repin [--adr docs/adr/NNNN-slug.md]
 *
 * Exit: 0 written or already in sync, 1 refused, 2 bad usage or an
 * unreadable file.
 *
 * @module scripts/build-refusals-frozen
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADR_PATH, adrAccepted } from './lib/api-surface.js';
import {
    diffRefusals, parseRefusalBaseline, parseRefusalsFrozen, renderRefusalsFrozen,
    REFUSAL_BASELINE, REFUSALS_FROZEN, type RefusalsFrozen, type RetiredRefusal,
} from './lib/refusals-frozen.js';
import { compareSemver } from './verify-docs/rules/registries.js';

export type RefusalsMode =
    | { readonly kind: 'default' }
    | { readonly kind: 'ratchet' }
    | { readonly kind: 'major'; readonly version: string }
    | { readonly kind: 'repin'; readonly adr?: string | undefined };

export interface RefusalsPlan {
    readonly action: 'write' | 'unchanged' | 'refuse';
    readonly text: string | null;
    readonly message: string;
}

/** A path → text reader over the working tree (or a release being prepared). */
export type Reader = (path: string) => string | null;

const major = (v: string): number => Number(v.split('.')[0]);

/**
 * The mode release-prepare.ts runs for a bump to `version`: a new major
 * rebases, a stable-phase release ratchets, a rehearsal release writes
 * nothing (the rule, not the bump, is what refuses a change there).
 */
export function releaseRefusalsMode(version: string, snapshot: RefusalsFrozen | null): RefusalsMode | null {
    if (snapshot === null) return null;
    if (major(version) >= 1 && major(version) > major(snapshot.frozenAt) && /^\d+\.0\.0$/.test(version)) return { kind: 'major', version };
    return snapshot.phase === 'stable' ? { kind: 'ratchet' } : null;
}

/** What the generator would do, as a pure function of the tree (`read`), package.json's version and the mode. */
export function planRefusalsFrozen(read: Reader, version: string, mode: RefusalsMode): RefusalsPlan {
    const refuse = (message: string): RefusalsPlan => ({ action: 'refuse', text: null, message });
    const baseline = parseRefusalBaseline(read(REFUSAL_BASELINE));
    if (baseline === null) return refuse(`${REFUSAL_BASELINE} is missing or is not a refusal baseline (corpus, commit, refusals)`);
    const currentText = read(REFUSALS_FROZEN);
    let snapshot: RefusalsFrozen | null = null;
    if (currentText !== null) {
        const parsed = parseRefusalsFrozen(currentText);
        if ('problems' in parsed) return refuse(`${REFUSALS_FROZEN} is malformed — ${parsed.problems.join('; ')}`);
        snapshot = parsed.snapshot;
    }
    const baseRows = (): Array<{ sha256: string; code: string }> => [...baseline.refusals].map(([sha256, code]) => ({ sha256, code }));
    const finish = (next: RefusalsFrozen, what: string): RefusalsPlan => {
        const text = renderRefusalsFrozen(next);
        return text === currentText
            ? { action: 'unchanged', text: null, message: `${REFUSALS_FROZEN} is in sync (${next.phase}, frozenAt ${next.frozenAt}, asOf ${next.asOf}, ${String(next.refusals.length)} refusals).` }
            : { action: 'write', text, message: `${what} (${next.phase}, frozenAt ${next.frozenAt}, asOf ${next.asOf}, ${String(next.refusals.length)} refusals${(next.retired ?? []).length > 0 ? `, ${String((next.retired ?? []).length)} retired` : ''}).` };
    };
    const semverMajor = (drift: ReturnType<typeof diffRefusals>): string => [
        ...drift.lifted.map((r) => `${r.sha256} (${r.code}) is no longer refused`),
        ...drift.recoded.map((r) => `${r.row.sha256} is refused with ${r.now}, promised ${r.row.code}`),
    ].join('; ');

    if (mode.kind === 'major') {
        const v = mode.version;
        if (!/^\d+\.0\.0$/.test(v) || major(v) < 1) return refuse(`--major takes a major release X.0.0 with X ≥ 1, not ${v}`);
        if (v !== version) return refuse(`--major ${v} but package.json is at ${version} — the rebase belongs to the release commit that bumps to ${v}`);
        if (snapshot !== null && major(v) <= major(snapshot.frozenAt)) return refuse(`the snapshot is already frozen at ${snapshot.frozenAt}; ${v} is not a new major`);
        if (snapshot !== null && snapshot.phase === 'rehearsal') {
            const drift = diffRefusals(snapshot, baseline);
            if (snapshot.commit !== baseline.commit || drift.lifted.length + drift.recoded.length + drift.added.length > 0) {
                return refuse(`the rehearsal did not hold — ${String(drift.lifted.length)} lifted, ${String(drift.recoded.length)} recoded, ${String(drift.added.length)} added${snapshot.commit === baseline.commit ? '' : ', and the corpus was re-pinned'} since ${snapshot.frozenAt} (npx tsx scripts/verify-docs.ts --only refusal-baseline-frozen lists them); 1.0.0 is the freeze itself and adds no engine behaviour`);
            }
        }
        return finish({ frozenAt: v, phase: 'stable', asOf: v, corpus: baseline.corpus, commit: baseline.commit, refusals: baseRows() }, `rebased ${REFUSALS_FROZEN} at the ${v} major`);
    }

    if (mode.kind === 'repin') {
        if (snapshot === null) return refuse(`--repin moves an existing snapshot; there is none — write it with \`npx tsx scripts/build-refusals-frozen.ts\``);
        if (baseline.corpus !== snapshot.corpus) return refuse(`the baseline is of ${baseline.corpus}, the snapshot of ${snapshot.corpus}`);
        if (baseline.commit === snapshot.commit) return refuse(`nothing to re-pin: the baseline is at ${baseline.commit}, the commit the snapshot is verified at`);
        const drift = diffRefusals(snapshot, baseline);
        if (drift.recoded.length > 0) return refuse(`refusing to re-pin over a code change, which is semver-major: ${semverMajor({ lifted: [], recoded: drift.recoded, added: [] })}`);
        const retiring: RetiredRefusal[] = drift.lifted.map((r) => ({ sha256: r.sha256, code: r.code, commit: snapshot.commit, adr: mode.adr ?? '' }));
        if (retiring.length > 0) {
            if (mode.adr === undefined) return refuse(`${String(retiring.length)} promised refusal(s) are not in the re-pinned baseline — if the new corpus dropped their certificates, record the re-pin in an accepted ADR and pass it with --adr; if it still holds them, they are lifted, which is semver-major`);
            if (!ADR_PATH.test(mode.adr) || !adrAccepted(read(mode.adr))) return refuse(`${mode.adr} is not an accepted ADR (docs/adr/NNNN-slug.md, "status: accepted") — a promised refusal is retired only on a recorded decision`);
        }
        const kept = snapshot.refusals.filter((r) => baseline.refusals.has(r.sha256));
        return finish({
            ...snapshot,
            commit: baseline.commit,
            refusals: [...kept, ...drift.added],
            retired: [...(snapshot.retired ?? []), ...retiring],
        }, `re-pinned ${REFUSALS_FROZEN} to ${snapshot.corpus}@${baseline.commit.slice(0, 12)}: ${String(kept.length)} carried over, ${String(drift.added.length)} new to the corpus, ${String(retiring.length)} retired`);
    }

    if (mode.kind === 'ratchet') {
        if (snapshot === null || snapshot.phase !== 'stable') return refuse('--ratchet applies to the stable phase only: the rehearsal admits no change to record');
        if (compareSemver(version, snapshot.asOf) < 0) return refuse(`package.json is at ${version}, older than the snapshot's asOf ${snapshot.asOf}`);
        if (baseline.commit !== snapshot.commit) return refuse(`the baseline is at ${baseline.commit} and the snapshot at ${snapshot.commit}: the corpus was re-pinned — run --repin first, in its own commit`);
        const drift = diffRefusals(snapshot, baseline);
        if (drift.lifted.length + drift.recoded.length > 0) return refuse(`refusing to ratchet over semver-major changes: ${semverMajor(drift)}`);
        return finish({
            ...snapshot,
            asOf: version,
            refusals: [...snapshot.refusals, ...drift.added.map((r) => ({ ...r, since: version }))],
        }, `ratcheted ${REFUSALS_FROZEN} to the refusals ${version} ships (${String(drift.added.length)} new — list each under "### Decision surface" in release-notes/v${version}.md)`);
    }

    if (snapshot === null) {
        if (major(version) >= 1) return refuse(`no snapshot, and package.json is at ${version}: a stable snapshot is made by the major release commit (--major X.0.0), never from nothing`);
        return finish({ frozenAt: version, phase: 'rehearsal', asOf: version, corpus: baseline.corpus, commit: baseline.commit, refusals: baseRows() }, `wrote ${REFUSALS_FROZEN}`);
    }
    // A retake keeps the `since` a stable-phase release gave each refusal.
    const since = new Map(snapshot.refusals.flatMap((r) => (r.since === undefined ? [] : [[r.sha256, r.since] as const])));
    const next: RefusalsFrozen = {
        ...snapshot, corpus: baseline.corpus, commit: baseline.commit,
        refusals: baseRows().map((r) => (since.has(r.sha256) ? { ...r, since: since.get(r.sha256) } : r)),
    };
    const plan = finish(next, `rewrote ${REFUSALS_FROZEN} while ${snapshot.asOf} is unreleased`);
    if (plan.action === 'write' && compareSemver(version, snapshot.asOf) >= 0) {
        return refuse(`refusing — package.json is at ${version}, so the refusals recorded at ${snapshot.asOf} are released (${snapshot.phase} phase). `
            + (snapshot.phase === 'rehearsal'
                ? 'The rehearsal admits no change to the decision surface: revert the engine change, or make it after 1.0.0 as a recorded fix.'
                : 'A new refusal is recorded by --ratchet at the release that ships it; a lifted or recoded one waits for the next major (--major X.0.0); a re-pinned corpus is recorded by --repin.'));
    }
    return plan;
}

function parseMode(argv: readonly string[]): RefusalsMode | null {
    const at = argv.indexOf('--major');
    const adr = argv.indexOf('--adr');
    const known = argv.filter((a, i) => a === '--ratchet' || a === '--major' || a === '--repin' || a === '--adr' || (at >= 0 && i === at + 1) || (adr >= 0 && i === adr + 1));
    if (known.length !== argv.length) return null;
    if ([argv.includes('--ratchet'), at >= 0, argv.includes('--repin')].filter(Boolean).length > 1) return null;
    if (adr >= 0 && !argv.includes('--repin')) return null;
    if (argv.includes('--repin')) {
        if (adr >= 0 && argv[adr + 1] === undefined) return null;
        return { kind: 'repin', adr: adr >= 0 ? argv[adr + 1] : undefined };
    }
    if (at >= 0) return argv[at + 1] === undefined ? null : { kind: 'major', version: argv[at + 1] ?? '' };
    return argv.includes('--ratchet') ? { kind: 'ratchet' } : { kind: 'default' };
}

function main(argv: readonly string[]): number {
    const mode = parseMode(argv);
    if (mode === null) {
        console.error('usage: npx tsx scripts/build-refusals-frozen.ts [--ratchet | --major X.0.0 | --repin [--adr docs/adr/NNNN-slug.md]]');
        return 2;
    }
    const root = resolve(import.meta.dirname, '..');
    const read: Reader = (path) => (existsSync(join(root, path)) ? readFileSync(join(root, path), 'utf8') : null);
    let version: string;
    try {
        version = (JSON.parse(read('package.json') ?? '') as { version: string }).version;
    } catch (err) {
        console.error(`build-refusals-frozen: package.json — ${(err as Error).message}`);
        return 2;
    }
    const plan = planRefusalsFrozen(read, version, mode);
    if (plan.action === 'refuse') {
        console.error(`build-refusals-frozen: ${plan.message}`);
        return 1;
    }
    if (plan.action === 'write' && plan.text !== null) writeFileSync(join(root, REFUSALS_FROZEN), plan.text, 'utf8');
    console.log(`build-refusals-frozen: ${plan.message}`);
    return 0;
}

// Run only when invoked directly (keeps the module import-safe for tests and release-prepare.ts).
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    process.exit(main(process.argv.slice(2)));
}
