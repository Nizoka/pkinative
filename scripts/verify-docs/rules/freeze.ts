/**
 * pkinative — the freeze, rehearsed
 * ==================================
 * ROADMAP 0.9: "Zero new exports, zero new codes, zero new engine
 * behaviour." 1.0 turns the rehearsal into a promise; these rules land a
 * band early so that each has been proven on real commits before it counts.
 *
 * `api-surface-frozen`: the public surface against docs/assets/api.frozen.json
 * (scripts/build-api-frozen.ts), with semantics chosen by the snapshot's
 * `phase` and checked for coherence with package.json:
 *
 *   | phase       | versions      | addition | compatible change | removal / incompatible | new error or reason code |
 *   |-------------|---------------|----------|-------------------|------------------------|--------------------------|
 *   | `rehearsal` | 0.8.x – 0.9.x | fails    | fails             | fails                  | fails                    |
 *   | `stable`    | ≥ 1.0.0       | passes   | passes            | fails (semver-major)   | passes, with a newer `since` |
 *
 * Diagnostic codes are outside both columns in every phase: a diagnostic is
 * advice, and the set of things worth advising about grows.
 *
 * `release-era-prose`: the sentences that say pkinative is not on npm. Below
 * 1.0.0 each must be present where the repository states it; from 1.0.0 the
 * ones that describe the current state must be gone — a README still saying
 * "not on npm" beside `npm install pkinative` is the drift this prevents.
 * Bidirectional, so the rule bites today and not only at 1.0.
 *
 * The npm registry itself is deliberately not a rule: verify-docs is offline
 * and deterministic. scripts/check-npm-drift.ts reads it, on a schedule.
 *
 * @module scripts/verify-docs/rules/freeze
 */

import { API_FROZEN, API_JSON, currentSurface, diffSurface, reasonCodes, REASONS_JSON, type FrozenExport, type Reader } from '../../lib/api-surface.js';
import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';
import { compareSemver, ERRORS_REGISTRY, FROZEN_REGISTRY } from './registries.js';

const SEMVER = /^\d+\.\d+\.\d+$/;
const GENERATOR = 'npx tsx scripts/build-api-frozen.ts';
const major = (v: string): number => Number(v.split('.')[0]);

interface Snapshot {
    readonly frozenAt?: unknown;
    readonly phase?: unknown;
    readonly asOf?: unknown;
    readonly reasons?: unknown;
    readonly exports?: unknown;
}

const reader = (ctx: RuleContext): Reader => (path) => ctx.read(path);

function packageVersion(ctx: RuleContext): string | null {
    const pkg = readJson<{ version?: unknown }>(ctx, 'package.json');
    return 'finding' in pkg || typeof pkg.value.version !== 'string' ? null : pkg.value.version;
}

// ── api-surface-frozen ───────────────────────────────────────────────

const apiSurfaceFrozen: Rule = {
    id: 'api-surface-frozen',
    summary: 'The public surface matches docs/assets/api.frozen.json under its phase — "rehearsal" (0.8.x-0.9.x): no export, signature, error code or reason code added, removed or changed; "stable" (from 1.0.0): no removal and no incompatible signature change (semver-major), additions pass — and the phase agrees with package.json.',
    check(ctx) {
        const parsed = readJson<Snapshot>(ctx, API_FROZEN);
        if ('finding' in parsed) return [error(API_FROZEN, `missing or unreadable — generate it with \`${GENERATOR}\``)];
        const snap = parsed.value;
        const snapText = ctx.read(API_FROZEN) ?? '';
        const { frozenAt, phase, asOf } = snap;
        if (typeof frozenAt !== 'string' || !SEMVER.test(frozenAt) || typeof asOf !== 'string' || !SEMVER.test(asOf)) {
            return [error(API_FROZEN, '"frozenAt" and "asOf" must be x.y.z versions')];
        }
        if (phase !== 'rehearsal' && phase !== 'stable') return [error(API_FROZEN, '"phase" must be "rehearsal" or "stable"')];
        if (!Array.isArray(snap.exports) || !Array.isArray(snap.reasons)) return [error(API_FROZEN, '"exports" and "reasons" must be arrays')];
        const frozen = snap.exports as FrozenExport[];
        const frozenReasons = snap.reasons as string[];

        const out: Finding[] = [];
        const version = packageVersion(ctx) ?? '0.0.0';
        // Phase coherence: the snapshot must be the one this version line promises.
        if (phase === 'rehearsal' && major(version) >= 1) {
            out.push(error(API_FROZEN, `package.json is at ${version} and the snapshot is still the ${frozenAt} rehearsal — the release commit of ${String(major(version))}.0.0 rebases it: \`${GENERATOR} --major ${String(major(version))}.0.0\` (scripts/release-prepare.ts runs it)`, lineContaining(snapText, '"phase"')));
            return out;
        }
        if (phase === 'rehearsal' && major(frozenAt) >= 1) out.push(error(API_FROZEN, `a rehearsal snapshot frozen at ${frozenAt} — the rehearsal is the pre-1.0 phase; a 1.x snapshot is "stable"`, lineContaining(snapText, '"phase"')));
        if (phase === 'stable' && (major(frozenAt) < 1 || major(version) !== major(frozenAt))) {
            out.push(error(API_FROZEN, `a stable snapshot frozen at ${frozenAt} with package.json at ${version} — a stable snapshot belongs to its own major line; a new major rebases it with \`${GENERATOR} --major X.0.0\``, lineContaining(snapText, '"phase"')));
            return out;
        }
        if (compareSemver(asOf, frozenAt) < 0) out.push(error(API_FROZEN, `"asOf" ${asOf} is older than "frozenAt" ${frozenAt}`, lineContaining(snapText, '"asOf"')));

        const released = compareSemver(version, asOf) >= 0;
        const remedy = !released
            ? `${asOf} is not released yet: a deliberate change is recorded by regenerating with \`${GENERATOR}\``
            : phase === 'rehearsal'
                ? 'the pre-1.0 rehearsal admits no change (ROADMAP 0.9.x: zero new exports, zero new codes) — revert it, and propose the change for a later major'
                : 'that is semver-major — restore it (a rename keeps the old name beside the new one, deprecated), or make it part of the next major';

        const surface = currentSurface(reader(ctx));
        for (const p of surface.problems) out.push(error(p.module, `cannot fingerprint the public surface: ${p.message}`));
        const rowLine = (name: string): number => lineContaining(snapText, `"name": ${JSON.stringify(name)},`);
        const apiText = ctx.read(API_JSON) ?? '';
        for (const change of diffSurface(frozen, surface.rows)) {
            const where = change.verdict === 'added'
                ? { file: API_JSON, line: lineContaining(apiText, `"name": ${JSON.stringify(change.name)},`) }
                : { file: API_FROZEN, line: rowLine(change.name) };
            if (phase === 'stable' && (change.verdict === 'added' || change.verdict === 'compatible')) continue;
            out.push(error(where.file, `${change.detail} — the surface is frozen at ${frozenAt}: ${remedy}`, where.line));
        }

        // The two frozen vocabularies. Removals of an error code are
        // error-codes-frozen's; what the rehearsal adds is that an addition
        // fails too, whatever its "since".
        const regText = ctx.read(ERRORS_REGISTRY) ?? '';
        const reasonsText = ctx.read(REASONS_JSON) ?? '';
        if (phase === 'rehearsal') {
            const frozenCodes = readJson<{ codes?: Array<{ code?: unknown }> }>(ctx, FROZEN_REGISTRY);
            const errors = readJson<{ errors?: Array<{ code?: unknown; since?: unknown }> }>(ctx, ERRORS_REGISTRY);
            if (!('finding' in frozenCodes) && !('finding' in errors)) {
                const known = new Set((frozenCodes.value.codes ?? []).map((c) => c.code));
                for (const e of errors.value.errors ?? []) {
                    if (typeof e.code !== 'string' || known.has(e.code)) continue;
                    out.push(error(ERRORS_REGISTRY, `${e.code} (since ${String(e.since)}) is a new error code, absent from ${FROZEN_REGISTRY}: ${remedy}`, lineContaining(regText, `"${e.code}"`)));
                }
            }
        }
        const reasons = reasonCodes(reader(ctx));
        const present = new Set(reasons.map((r) => r.code));
        for (const code of frozenReasons) {
            if (!present.has(code)) out.push(error(REASONS_JSON, `${code} was frozen at ${frozenAt} and is gone from the reason registry: ${phase === 'stable' ? 'that is semver-major — a caller branching on it stops matching' : remedy}`, lineContaining(snapText, `"${code}"`)));
        }
        for (const r of reasons) {
            if (frozenReasons.includes(r.code)) continue;
            if (phase === 'stable' && r.since !== null && SEMVER.test(r.since) && compareSemver(r.since, asOf) > 0) continue;
            out.push(error(REASONS_JSON, phase === 'stable'
                ? `${r.code} is not in the ${asOf} snapshot, so it is an addition — give it the "since" of the release that adds it, newer than ${asOf}`
                : `${r.code} (since ${r.since ?? '?'}) is a new reason code: ${remedy}`, lineContaining(reasonsText, `"${r.code}"`)));
        }
        return out;
    },
};

// ── release-era-prose ────────────────────────────────────────────────

/**
 * Where the repository says pkinative is not on npm, and what becomes of
 * each sentence at 1.0.0. `absent`: it describes the current state and turns
 * false at the first npm publication. `kept`: it states the pre-1.0 policy,
 * which stays true of those versions forever, so it must be present in both
 * eras. Generated copies (docs/llms.txt, docs/guides/quickstart.html,
 * docs/llms-full.txt) follow their sources through their own rules.
 */
export const PRE_1_0_PROSE: ReadonlyArray<{ readonly file: string; readonly phrase: string; readonly at1: 'absent' | 'kept'; readonly why: string }> = [
    { file: 'README.md', phrase: 'pre-1.0, not on npm', at1: 'absent', why: 'the status line' },
    { file: 'README.md', phrase: 'is not on npm. Install the tarball attached to the GitHub release', at1: 'absent', why: 'the Installation section' },
    { file: 'docs/guides/quickstart.md', phrase: 'is not on npm: install the tarball attached to the GitHub release', at1: 'absent', why: 'the quick start\'s install step' },
    { file: 'llms.txt', phrase: 'Versions below 1.0 are git tags, not npm releases.', at1: 'absent', why: 'the llms.txt summary an agent reads first' },
    { file: 'docs/agent-brief.md', phrase: 'Do not install pkinative from npm', at1: 'absent', why: 'the agent brief\'s install rule' },
    { file: 'docs/index.html', phrase: 'Pre-1.0 is a git tag, not an npm release.', at1: 'absent', why: 'the landing page hero' },
    { file: 'docs/playground/index.html', phrase: 'it is not on npm before 1.0.0', at1: 'absent', why: 'why the playground commits its engine instead of loading it from a CDN' },
    { file: 'docs/assets/ecosystem.json', phrase: '"npm": "not published;', at1: 'absent', why: 'packages.pkinative.npm' },
    { file: 'docs/assets/og-image.svg', phrase: 'pre-1.0 is a git tag, not an npm release', at1: 'absent', why: 'the social card (re-rasterise it: social-images)' },
    { file: 'docs/assets/social-preview.svg', phrase: 'pre-1.0 is a git tag, not an npm release', at1: 'absent', why: 'the repository social preview (re-rasterise it: social-images)' },
    { file: 'AGENTS.md', phrase: 'Pre-1.0 versions are git tags, never npm releases; `publish.yml` refuses them.', at1: 'kept', why: 'the release policy agents follow' },
    { file: '.github/workflows/publish.yml', phrase: 'pre-1.0 versions are git tags, never npm releases', at1: 'kept', why: 'the refusal step, which still guards a 0.x tag cut from an old branch' },
];

const releaseEraProse: Rule = {
    id: 'release-era-prose',
    summary: 'Below 1.0.0 every sentence of PRE_1_0_PROSE saying pkinative is not on npm is present where the repository states it; from 1.0.0 the ones describing the current state are gone and only the policy statements remain.',
    check(ctx) {
        const version = packageVersion(ctx);
        if (version === null) return [];
        const stable = major(version) >= 1;
        const out: Finding[] = [];
        for (const row of PRE_1_0_PROSE) {
            const text = ctx.read(row.file);
            if (text === null) { out.push(error(row.file, `missing — it carries ${row.why}`)); continue; }
            const has = text.includes(row.phrase);
            if (stable && row.at1 === 'absent' && has) {
                out.push(error(row.file, `still says "${row.phrase}" (${row.why}) with package.json at ${version} — from 1.0.0 pkinative is on npm; rewrite the sentence`, lineContaining(text, row.phrase)));
            } else if ((!stable || row.at1 === 'kept') && !has) {
                out.push(error(row.file, `no longer says "${row.phrase}" (${row.why}) — ${stable ? 'this states the pre-1.0 policy, which stays true of those versions' : `below 1.0.0 (package.json: ${version}) the repository says here that pkinative is not on npm`}; restore it, or change PRE_1_0_PROSE in scripts/verify-docs/rules/freeze.ts in the same commit`));
            }
        }
        return out;
    },
};

export const FREEZE_RULES: readonly Rule[] = [apiSurfaceFrozen, releaseEraProse];
