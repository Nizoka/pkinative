/**
 * pkinative — the compatibility promise, held
 * ============================================
 * ROADMAP 1.0: three promises — the export surface, the error vocabulary and
 * the decision surface — "each held by a rule, not by a sentence".
 *
 * `refusal-baseline-frozen`: the decision surface of ADR 0014. The committed
 * baseline scripts/data/limbo-refusals.json (what the engine refuses, as
 * conformance L1 verifies it against the corpus) against the snapshot
 * docs/data/refusals.frozen.json (what is promised), with semantics chosen by
 * the snapshot's `phase` and checked for coherence with package.json:
 *
 *   | phase       | versions      | refusal lifted | code changed | new refusal |
 *   |-------------|---------------|----------------|--------------|-------------|
 *   | `rehearsal` | 0.9.x         | fails          | fails        | fails       |
 *   | `stable`    | ≥ 1.0.0       | fails (major)  | fails (major)| passes; the release ratchets it in, and its note must list it |
 *
 * Offline and deterministic like every rule here: it compares two committed
 * files. The corpus half — the engine against the certificates — is L1's.
 *
 * `contracts-shape`: docs/assets/ecosystem.json → contracts.compatibility
 * names each leg's snapshot, the rules that hold it and the records that
 * decide it, and SECURITY.md §Compatibility promise names them too. Both
 * ways: a `*-frozen` rule or a `*.frozen.json` snapshot that no leg names
 * fails, because a promise held by a rule nobody lists is one a reader of
 * the machine contract cannot find. The same rule holds the policies that
 * complete the promise (ADR 0016, 0017, 0018) — each with its records, and
 * named in that section — and `contracts.support`, the runtime and compiler
 * floors, to package.json, tsup.config.ts, the CI matrix and SECURITY.md;
 * and it refuses "not frozen" for the grow-only reason vocabulary.
 *
 * `option-defaults-parity`: docs/data/defaults.json (ADR 0018) against the
 * source and the export surface. Every row's evidence is found verbatim in
 * the file it cites, so a default cannot change without a diff of the
 * registry; every type or function a row names is exported and takes the
 * option; and every optional boolean member of an exported `…Options`,
 * `…Input` or `…Description` type has a row.
 *
 * `security-txt-parity`: docs/.well-known/security.txt (RFC 9116) against
 * SECURITY.md and the manifest: the required fields, an expiry within a year
 * of the manifest's `verifiedOn`, the canonical URL on the site, and the same
 * two contact channels as the policy.
 *
 * @module scripts/verify-docs/rules/contracts
 */

import { ADR_PATH, adrAccepted } from '../../lib/api-surface.js';
import {
    decisionSurfaceSection, diffRefusals, DECISION_SURFACE_HEADING, HASH_PREFIX, parseRefusalBaseline, parseRefusalsFrozen,
    REFUSAL_BASELINE, REFUSALS_FROZEN, REFUSALS_GENERATOR, type FrozenRefusal,
} from '../../lib/refusals-frozen.js';
import { error, lineContaining, readJson, type Finding, type Rule, type RuleContext } from '../context.js';
import { compareSemver, ERRORS_REGISTRY, FROZEN_REGISTRY } from './registries.js';

const major = (v: string): number => Number(v.split('.')[0]);
const SEMVER = /^\d+\.\d+\.\d+$/;

function packageVersion(ctx: RuleContext): string | null {
    const pkg = readJson<{ version?: unknown }>(ctx, 'package.json');
    return 'finding' in pkg || typeof pkg.value.version !== 'string' ? null : pkg.value.version;
}

// ── refusal-baseline-frozen ──────────────────────────────────────────

const refusalBaselineFrozen: Rule = {
    id: 'refusal-baseline-frozen',
    summary: 'Every refusal of docs/data/refusals.frozen.json is still in scripts/data/limbo-refusals.json with the same code, at the same corpus commit, with a registered code; "rehearsal" (0.9.x): no refusal added either; "stable" (from 1.0.0): a new refusal passes, and one a release added is listed under "### Decision surface" in its note — and the phase agrees with package.json.',
    check(ctx) {
        const snapText = ctx.read(REFUSALS_FROZEN);
        if (snapText === null) return [error(REFUSALS_FROZEN, `missing — generate it with \`${REFUSALS_GENERATOR}\``)];
        const parsed = parseRefusalsFrozen(snapText);
        if ('problems' in parsed) return parsed.problems.map((p) => error(REFUSALS_FROZEN, p));
        const snap = parsed.snapshot;
        const { frozenAt, phase, asOf } = snap;
        const out: Finding[] = [];
        const at = (needle: string): number => lineContaining(snapText, needle);

        // Phase coherence: the snapshot must be the one this version line promises.
        const version = packageVersion(ctx) ?? '0.0.0';
        if (phase === 'rehearsal' && major(version) >= 1) {
            return [error(REFUSALS_FROZEN, `package.json is at ${version} and the snapshot is still the ${frozenAt} rehearsal — the release commit of ${String(major(version))}.0.0 rebases it: \`${REFUSALS_GENERATOR} --major ${String(major(version))}.0.0\` (scripts/release-prepare.ts runs it)`, at('"phase"'))];
        }
        if (phase === 'rehearsal' && major(frozenAt) >= 1) out.push(error(REFUSALS_FROZEN, `a rehearsal snapshot frozen at ${frozenAt} — the rehearsal is the pre-1.0 phase; a 1.x snapshot is "stable"`, at('"phase"')));
        if (phase === 'stable' && (major(frozenAt) < 1 || major(version) !== major(frozenAt))) {
            return [error(REFUSALS_FROZEN, `a stable snapshot frozen at ${frozenAt} with package.json at ${version} — a stable snapshot belongs to its own major line; a new major rebases it with \`${REFUSALS_GENERATOR} --major X.0.0\``, at('"phase"'))];
        }
        if (compareSemver(asOf, frozenAt) < 0) out.push(error(REFUSALS_FROZEN, `"asOf" ${asOf} is older than "frozenAt" ${frozenAt}`, at('"asOf"')));
        for (const row of snap.refusals) {
            if (row.since !== undefined && (compareSemver(row.since, frozenAt) <= 0 || compareSemver(row.since, asOf) > 0)) {
                out.push(error(REFUSALS_FROZEN, `${row.sha256}: "since" ${row.since} is outside (${frozenAt}, ${asOf}] — only a release after the freeze adds a refusal, and only up to the release the snapshot records`, at(row.sha256)));
            }
        }
        for (const row of snap.retired ?? []) {
            if (!ADR_PATH.test(row.adr) || !adrAccepted(ctx.read(row.adr))) {
                out.push(error(REFUSALS_FROZEN, `${row.sha256} is retired on "${row.adr}", which is not an accepted ADR — a promised refusal leaves verification only on a recorded re-pin (${REFUSALS_GENERATOR} --repin --adr docs/adr/NNNN-slug.md)`, at(row.sha256)));
            }
        }

        // The codes: a refusal is promised with a code the registry defines.
        const registry = readJson<{ errors?: Array<{ code?: unknown }> }>(ctx, ERRORS_REGISTRY);
        if ('finding' in registry) return [...out, registry.finding];
        const codes = new Set((registry.value.errors ?? []).map((e) => e.code));
        for (const row of [...snap.refusals, ...(snap.retired ?? [])]) {
            if (!codes.has(row.code)) out.push(error(REFUSALS_FROZEN, `${row.sha256} is promised with ${row.code}, which ${ERRORS_REGISTRY} does not define`, at(row.sha256)));
        }

        // The baseline, and what moved against it.
        const baselineText = ctx.read(REFUSAL_BASELINE);
        const baseline = parseRefusalBaseline(baselineText);
        if (baselineText === null || baseline === null) return [...out, error(REFUSAL_BASELINE, 'missing or not a refusal baseline (corpus, commit, refusals) — conformance L1 writes it with `npx tsx scripts/validate-certs.ts --update-baseline`')];
        if (baseline.corpus !== snap.corpus) return [...out, error(REFUSAL_BASELINE, `is a baseline of ${baseline.corpus}; the snapshot promises refusals of ${snap.corpus}`)];
        if (baseline.commit !== snap.commit) {
            return [...out, error(REFUSALS_FROZEN, `the refusals were verified at ${snap.corpus}@${snap.commit} and the baseline is at ${baseline.commit}: the corpus was re-pinned — record it with \`${REFUSALS_GENERATOR} --repin\` (and --adr, if the new corpus dropped a promised certificate), in a commit that changes no engine behaviour`, at('"commit"'))];
        }
        const released = compareSemver(version, asOf) >= 0;
        const majorRemedy = phase === 'rehearsal'
            ? (released
                ? 'the rehearsal admits no change to the decision surface (1.0.0 is the freeze itself) — revert the engine change'
                : `${asOf} is not released yet: a deliberate change is recorded by regenerating with \`${REFUSALS_GENERATOR}\``)
            : 'that is semver-major (ADR 0014) — restore the refusal and its code, or make the change part of the next major';
        const bLine = (hash: string): number => lineContaining(baselineText, hash);
        const drift = diffRefusals(snap, baseline);
        for (const row of drift.lifted) {
            out.push(error(REFUSAL_BASELINE, `${row.sha256} was promised refused with ${row.code} and the baseline no longer lists it — the certificate now parses: ${majorRemedy}`, bLine(row.sha256)));
        }
        for (const { row, now } of drift.recoded) {
            out.push(error(REFUSAL_BASELINE, `${row.sha256} was promised refused with ${row.code} and is now refused with ${now} — callers branch on the code: ${majorRemedy}`, bLine(row.sha256)));
        }
        if (phase === 'rehearsal') {
            for (const row of drift.added) {
                out.push(error(REFUSAL_BASELINE, `${row.sha256} is a new refusal (${row.code}), absent from ${REFUSALS_FROZEN}: ${released ? 'the rehearsal admits no new engine behaviour — make it after 1.0.0, where a new refusal is a recorded fix' : majorRemedy}`, bLine(row.sha256)));
            }
        }

        // Stable phase: a refusal a release added is listed in that release's note.
        const bySince = new Map<string, FrozenRefusal[]>();
        for (const row of snap.refusals) if (row.since !== undefined && SEMVER.test(row.since)) bySince.set(row.since, [...(bySince.get(row.since) ?? []), row]);
        for (const [since, rows] of bySince) {
            const notePath = `release-notes/v${since}.md`;
            const note = ctx.read(notePath);
            const section = note === null ? null : decisionSurfaceSection(note);
            if (section === null) {
                out.push(error(notePath, `${note === null ? 'is missing' : `has no "${DECISION_SURFACE_HEADING}" section`} — ${String(rows.length)} refusal(s) of ${REFUSALS_FROZEN} were added by ${since}, and a new refusal is never silent (ADR 0014): list each by the first ${String(HASH_PREFIX)} hex digits of its SHA-256, with its code and why`));
                continue;
            }
            for (const row of rows) {
                if (!section.includes(row.sha256.slice(0, HASH_PREFIX))) out.push(error(notePath, `"${DECISION_SURFACE_HEADING}" does not list ${row.sha256.slice(0, HASH_PREFIX)} (${row.code}), a refusal ${since} added`, lineContaining(note ?? '', DECISION_SURFACE_HEADING)));
            }
        }
        return out;
    },
};

// ── contracts-shape ──────────────────────────────────────────────────

const MANIFEST = 'docs/assets/ecosystem.json';
const SECURITY = 'SECURITY.md';
const GATE_SOURCE = 'scripts/validate-certs.ts';
/** The three legs of ROADMAP 1.0's compatibility promise, in its order. */
export const CONTRACT_LEGS: readonly string[] = ['export-surface', 'error-vocabulary', 'decision-surface'];
/** A rule that holds a snapshot of the promise is named `<subject>-frozen`, and a snapshot `<subject>.frozen.json`. */
const HOLDING_RULE = /-frozen$/;
const SNAPSHOT_FILE = /\.frozen\.json$/;

interface Leg {
    readonly promise?: unknown;
    readonly snapshot?: unknown;
    readonly rules?: unknown;
    readonly adrs?: unknown;
    readonly gate?: unknown;
}

/**
 * The policies that complete the three legs (ADR 0016, 0017, 0018): what the
 * promise says about entry points, option defaults, verdicts, returned
 * unions, report fields, non-default options, the wire form, a re-pinned
 * corpus and the runtimes. Each is a sentence a satellite can quote, decided
 * in an accepted record that SECURITY.md §Compatibility promise cites.
 */
export const CONTRACT_POLICIES: readonly string[] = [
    'entry-points', 'option-defaults', 'returned-verdicts', 'open-unions', 'report-fields',
    'non-default-options', 'wire-form', 'corpus-repin', 'runtime-support',
];

interface Policy {
    readonly promise?: unknown;
    readonly adrs?: unknown;
    readonly rules?: unknown;
    readonly registry?: unknown;
    readonly gate?: unknown;
}

/** `contracts.support`: the runtime and compiler floors of ADR 0017. */
interface Support {
    readonly adr?: unknown;
    readonly node?: unknown;
    readonly nodeLines?: unknown;
    readonly currentLines?: unknown;
    readonly typescript?: unknown;
    readonly esTarget?: unknown;
    readonly tested?: unknown;
    readonly targeted?: unknown;
}

interface Contracts {
    readonly runtime_dependencies?: unknown;
    readonly error_codes_frozen_since?: unknown;
    readonly compatibility?: {
        readonly document?: unknown; readonly section?: unknown; readonly legs?: Record<string, Leg>;
        readonly policies?: Record<string, Policy>; readonly notPromised?: unknown;
    };
    readonly support?: Support;
}

const strings = (v: unknown): v is string[] => Array.isArray(v) && v.length > 0 && v.every((s) => typeof s === 'string' && s !== '');

/** The Markdown section under `## <title>`, up to the next `## `, or null. */
function h2Section(text: string, title: string): string | null {
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    const start = lines.findIndex((l) => l.trim() === `## ${title}`);
    if (start < 0) return null;
    const end = lines.findIndex((l, i) => i > start && /^## /.test(l));
    return lines.slice(start + 1, end < 0 ? undefined : end).join('\n');
}

/** The Markdown section under `### <title>`, up to the next `## ` or `### `, or null. */
function h3Section(text: string, title: string): string | null {
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    const start = lines.findIndex((l) => l.trim() === `### ${title}`);
    if (start < 0) return null;
    const end = lines.findIndex((l, i) => i > start && /^###? /.test(l));
    return lines.slice(start + 1, end < 0 ? undefined : end).join('\n');
}

/** The four-digit number of an ADR path, as prose cites it ("ADR 0018"). */
const adrNumber = (path: string): string => path.slice('docs/adr/'.length, 'docs/adr/'.length + 4);

/** The wording ADR 0018 retired for the grow-only reason vocabulary. */
const REASON_NOT_FROZEN = /(?:reason vocabulary|PkiReasonCode)[^.\n]{0,60}?\bnot (?:\*\*)?frozen|vocabulary does NOT freeze/i;

const SUPPORT_SECTION = 'Supported runtimes and compilers';
const TSUP_CONFIG = 'tsup.config.ts';
const CI_WORKFLOW = '.github/workflows/ci.yml';
const CURRENT_WORKFLOW = '.github/workflows/node-current.yml';

/** `contracts.support` against package.json, the build, the CI matrix, its record and SECURITY.md (ADR 0017). */
function checkSupport(ctx: RuleContext, support: Support | undefined, security: string, mLine: (needle: string) => number): Finding[] {
    const out: Finding[] = [];
    const where = mLine('"support"');
    if (typeof support !== 'object' || support === null) {
        return [error(MANIFEST, 'contracts.support is missing — the Node.js floor, the supported lines, the TypeScript floor and the ECMAScript target of ADR 0017, for a program to read', where)];
    }
    const section = h3Section(security, SUPPORT_SECTION);
    if (section === null) out.push(error(SECURITY, `has no "### ${SUPPORT_SECTION}" section — the runtime and compiler policy of ADR 0017`));
    const named = (what: string, needle: string): void => {
        if (section !== null && !section.includes(needle)) out.push(error(SECURITY, `§${SUPPORT_SECTION} does not name ${what} ${needle} (docs/assets/ecosystem.json → contracts.support)`, lineContaining(security, `### ${SUPPORT_SECTION}`)));
    };

    if (typeof support.adr !== 'string' || !ADR_PATH.test(support.adr) || !adrAccepted(ctx.read(support.adr))) {
        out.push(error(MANIFEST, `contracts.support.adr is ${JSON.stringify(support.adr)}, which is not an accepted ADR — the support policy is decided in one`, where));
    } else {
        named('ADR', adrNumber(support.adr));
    }

    const pkg = readJson<{ engines?: { node?: unknown } }>(ctx, 'package.json');
    const engines = 'finding' in pkg ? undefined : pkg.value.engines?.node;
    if (typeof support.node !== 'string' || support.node !== engines) {
        out.push(error(MANIFEST, `contracts.support.node is ${JSON.stringify(support.node)}; package.json engines.node is ${JSON.stringify(engines)} — they state the same floor`, mLine('"node"')));
    } else {
        named('the Node.js range', `\`${support.node}\``);
    }

    const ci = ctx.read(CI_WORKFLOW) ?? '';
    if (!Array.isArray(support.nodeLines) || support.nodeLines.length === 0 || !support.nodeLines.every((n) => Number.isInteger(n))) {
        out.push(error(MANIFEST, 'contracts.support.nodeLines must list the supported Node.js majors, e.g. [22, 24]', where));
    } else {
        for (const line of support.nodeLines as number[]) {
            if (!new RegExp(`node-version: ${String(line)}\\b`).test(ci)) out.push(error(MANIFEST, `Node.js ${String(line)} is a supported line and ${CI_WORKFLOW} does not test it — a supported runtime is a tested runtime (ADR 0017)`, mLine('"nodeLines"')));
            if (typeof engines === 'string' && !new RegExp(`(?:^|[^\\d.])${String(line)}\\.`).test(engines)) out.push(error(MANIFEST, `Node.js ${String(line)} is a supported line and engines.node "${engines}" gives it no floor`, mLine('"nodeLines"')));
            named('the supported line', `Node.js ${String(line)}`);
        }
    }

    // A Current line is tested in its own advisory workflow and promised by nothing (ADR 0017, amended 2026-10-03).
    const current = ctx.read(CURRENT_WORKFLOW) ?? '';
    if (!Array.isArray(support.currentLines) || !support.currentLines.every((n) => Number.isInteger(n))) {
        out.push(error(MANIFEST, 'contracts.support.currentLines must list the Current Node.js majors tested without being promised, e.g. [26] — empty when none is', where));
    } else {
        for (const line of support.currentLines as number[]) {
            if (Array.isArray(support.nodeLines) && (support.nodeLines as unknown[]).includes(line)) out.push(error(MANIFEST, `Node.js ${String(line)} is in both nodeLines and currentLines — a line is supported or Current, not both`, mLine('"currentLines"')));
            if (!new RegExp(`node-version: ${String(line)}\\b`).test(current)) out.push(error(MANIFEST, `Node.js ${String(line)} is a tested Current line and ${CURRENT_WORKFLOW} does not run it — tested means run (ADR 0017)`, mLine('"currentLines"')));
            named('the Current line', `Node.js ${String(line)}`);
        }
    }

    if (typeof support.typescript !== 'string' || !SEMVER.test(support.typescript)) {
        out.push(error(MANIFEST, `contracts.support.typescript is ${JSON.stringify(support.typescript)}; it is the exact TypeScript release scripts/check-ts-floor.ts compiles against, e.g. "5.0.4"`, mLine('"typescript"')));
    } else {
        named('the TypeScript floor', `TypeScript ${support.typescript.split('.').slice(0, 2).join('.')}`);
    }

    const tsup = ctx.read(TSUP_CONFIG) ?? '';
    if (typeof support.esTarget !== 'string' || !/^es20\d\d$/.test(support.esTarget)) {
        out.push(error(MANIFEST, `contracts.support.esTarget is ${JSON.stringify(support.esTarget)}; write the build target, e.g. "es2020"`, mLine('"esTarget"')));
    } else {
        if (!tsup.includes(`target: '${support.esTarget}'`)) out.push(error(TSUP_CONFIG, `does not build for ${support.esTarget}, the ECMAScript target contracts.support promises for 1.x (ADR 0017)`));
        named('the ECMAScript target', support.esTarget.toUpperCase());
    }
    if (!strings(support.tested)) out.push(error(MANIFEST, 'contracts.support.tested must list the runtimes a gate executes', where));
    if (!strings(support.targeted)) out.push(error(MANIFEST, 'contracts.support.targeted must list the runtimes the build targets without a gate executing it — say which claims are tested and which are not', where));
    return out;
}

const contractsShape: Rule = {
    id: 'contracts-shape',
    summary: 'docs/assets/ecosystem.json → contracts.compatibility names exactly the three legs of the 1.0 promise, each with a snapshot that exists, the verify-docs rules and conformance levels that hold it and the accepted ADRs that decide it, and exactly the policies that complete it (ADR 0016–0018), each with its records; SECURITY.md §Compatibility promise names every one of them and lists what is not promised entry for entry; every "-frozen" rule and "*.frozen.json" snapshot belongs to a leg; contracts.support agrees with package.json engines, tsup.config.ts, the CI matrix and SECURITY.md §Supported runtimes and compilers; no guide calls the grow-only reason vocabulary "not frozen"; and the scalar contracts agree with package.json and errors.frozen.json.',
    async check(ctx) {
        // The rule table imports this module; reading it at check time keeps the cycle harmless.
        const { RULES } = await import('./index.js');
        const manifest = readJson<{ contracts?: Contracts }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const manifestText = ctx.read(MANIFEST) ?? '';
        const mLine = (needle: string): number => lineContaining(manifestText, needle);
        const contracts = manifest.value.contracts;
        if (typeof contracts !== 'object' || contracts === null) return [error(MANIFEST, 'has no "contracts" block — the machine-readable half of SECURITY.md §Compatibility promise')];
        const out: Finding[] = [];

        // The scalar contracts, each held to the file it summarises.
        const pkg = readJson<{ dependencies?: Record<string, unknown> }>(ctx, 'package.json');
        if (!('finding' in pkg)) {
            const deps = Object.keys(pkg.value.dependencies ?? {}).length;
            if (contracts.runtime_dependencies !== deps) out.push(error(MANIFEST, `contracts.runtime_dependencies is ${String(contracts.runtime_dependencies)}; package.json declares ${String(deps)}`, mLine('"runtime_dependencies"')));
        }
        const errorsFrozen = readJson<{ frozenAt?: unknown }>(ctx, FROZEN_REGISTRY);
        if (!('finding' in errorsFrozen) && contracts.error_codes_frozen_since !== errorsFrozen.value.frozenAt) {
            out.push(error(MANIFEST, `contracts.error_codes_frozen_since is ${String(contracts.error_codes_frozen_since)}; ${FROZEN_REGISTRY} is frozen at ${String(errorsFrozen.value.frozenAt)}`, mLine('"error_codes_frozen_since"')));
        }

        const compat = contracts.compatibility;
        if (typeof compat !== 'object' || compat === null || typeof compat.legs !== 'object' || compat.legs === null) {
            return [...out, error(MANIFEST, 'contracts.compatibility.legs is missing — it names the three legs of the 1.0 promise (ADR 0014)')];
        }
        if (compat.document !== SECURITY || compat.section !== 'Compatibility promise') {
            out.push(error(MANIFEST, `contracts.compatibility must point at the prose that states the promise: "document": "${SECURITY}", "section": "Compatibility promise"`, mLine('"compatibility"')));
        }
        if (!strings(compat.notPromised)) out.push(error(MANIFEST, 'contracts.compatibility.notPromised must list what the promise leaves out — a contract that does not say where it stops reads as covering everything', mLine('"compatibility"')));
        const security = ctx.read(SECURITY) ?? '';
        const section = h2Section(security, 'Compatibility promise');
        if (section === null) out.push(error(SECURITY, 'has no "## Compatibility promise" section — the three legs, what is not promised, and what holds each'));
        const gateSource = ctx.read(GATE_SOURCE) ?? '';

        const legs = compat.legs;
        const names = Object.keys(legs);
        for (const name of CONTRACT_LEGS) if (!names.includes(name)) out.push(error(MANIFEST, `contracts.compatibility.legs lacks "${name}" — the promise has three legs (ROADMAP 1.0): ${CONTRACT_LEGS.join(', ')}`, mLine('"legs"')));
        for (const name of names) if (!CONTRACT_LEGS.includes(name)) out.push(error(MANIFEST, `contracts.compatibility.legs names "${name}", which is not a leg of the promise (${CONTRACT_LEGS.join(', ')})`, mLine(`"${name}"`)));

        const ruleIds = new Set(RULES.map((r) => r.id));
        const namedRules = new Set<string>();
        const namedSnapshots = new Set<string>();
        const inSection = (what: string, needle: string, holder: string): void => {
            const of = holder.startsWith('policy ') ? holder : `the ${holder} leg`;
            if (section !== null && !section.includes(needle)) out.push(error(SECURITY, `§Compatibility promise does not name ${what} ${needle}, which holds ${of} (docs/assets/ecosystem.json → contracts.compatibility)`, lineContaining(security, '## Compatibility promise')));
        };
        for (const name of names.filter((n) => CONTRACT_LEGS.includes(n))) {
            const leg = legs[name] ?? {};
            const where = mLine(`"${name}"`);
            if (typeof leg.promise !== 'string' || leg.promise.length < 20) out.push(error(MANIFEST, `leg "${name}" needs a "promise": one sentence a satellite can quote`, where));
            if (typeof leg.snapshot !== 'string' || !SNAPSHOT_FILE.test(leg.snapshot)) {
                out.push(error(MANIFEST, `leg "${name}" needs a "snapshot": the *.frozen.json file that records what is promised`, where));
            } else {
                namedSnapshots.add(leg.snapshot);
                const snap = readJson<{ frozenAt?: unknown }>(ctx, leg.snapshot);
                if ('finding' in snap) out.push(error(MANIFEST, `leg "${name}" names ${leg.snapshot}: ${snap.finding.message}`, where));
                else if (typeof snap.value.frozenAt !== 'string' || !SEMVER.test(snap.value.frozenAt)) out.push(error(leg.snapshot, 'has no "frozenAt" version — it is not a snapshot of a promise'));
                inSection('the snapshot', leg.snapshot, name);
            }
            if (!strings(leg.rules)) out.push(error(MANIFEST, `leg "${name}" needs "rules": the verify-docs rules that hold it — a promise held by no rule is a sentence`, where));
            else for (const id of leg.rules) {
                namedRules.add(id);
                if (!ruleIds.has(id)) out.push(error(MANIFEST, `leg "${name}" is held by "${id}", which is not a verify-docs rule`, mLine(`"${id}"`)));
                inSection('the rule', `\`${id}\``, name);
            }
            if (!strings(leg.adrs)) out.push(error(MANIFEST, `leg "${name}" needs "adrs": the accepted records that decide it`, where));
            else for (const adr of leg.adrs) {
                if (!ADR_PATH.test(adr) || !adrAccepted(ctx.read(adr))) out.push(error(MANIFEST, `leg "${name}" cites ${adr}, which is not an accepted ADR`, mLine(adr)));
                else inSection('ADR', adrNumber(adr), name);
            }
            if (leg.gate !== undefined) {
                if (!strings(leg.gate)) out.push(error(MANIFEST, `leg "${name}": "gate" lists conformance levels, e.g. ["L1", "L2"]`, where));
                else for (const level of leg.gate) {
                    if (!/^L\d$/.test(level) || !new RegExp(`^ \\*   ${level}  `, 'm').test(gateSource)) out.push(error(MANIFEST, `leg "${name}" is verified by conformance ${level}, which ${GATE_SOURCE} does not document`, mLine(`"${level}"`)));
                }
            }
        }

        // The policies that complete the legs, each decided in a record SECURITY.md cites.
        const policies = compat.policies;
        if (typeof policies !== 'object' || policies === null) {
            out.push(error(MANIFEST, `contracts.compatibility.policies is missing — it names what the promise says beyond its snapshots (ADR 0018): ${CONTRACT_POLICIES.join(', ')}`, mLine('"compatibility"')));
        } else {
            const ids = Object.keys(policies);
            for (const id of CONTRACT_POLICIES) if (!ids.includes(id)) out.push(error(MANIFEST, `contracts.compatibility.policies lacks "${id}" — ${CONTRACT_POLICIES.join(', ')}`, mLine('"policies"')));
            for (const id of ids) if (!CONTRACT_POLICIES.includes(id)) out.push(error(MANIFEST, `contracts.compatibility.policies names "${id}", which is not a policy of the promise (${CONTRACT_POLICIES.join(', ')})`, mLine(`"${id}"`)));
            for (const id of ids.filter((n) => CONTRACT_POLICIES.includes(n))) {
                const policy = policies[id] ?? {};
                const where = mLine(`"${id}"`);
                const label = `policy "${id}"`;
                if (typeof policy.promise !== 'string' || policy.promise.length < 20) out.push(error(MANIFEST, `${label} needs a "promise": one sentence a satellite can quote`, where));
                if (!strings(policy.adrs)) out.push(error(MANIFEST, `${label} needs "adrs": the accepted records that decide it`, where));
                else for (const adr of policy.adrs) {
                    if (!ADR_PATH.test(adr) || !adrAccepted(ctx.read(adr))) out.push(error(MANIFEST, `${label} cites ${adr}, which is not an accepted ADR`, mLine(adr)));
                    else inSection('ADR', adrNumber(adr), label);
                }
                if (policy.rules !== undefined) {
                    if (!strings(policy.rules)) out.push(error(MANIFEST, `${label}: "rules" lists verify-docs rule ids`, where));
                    else for (const ruleId of policy.rules) {
                        if (!ruleIds.has(ruleId)) out.push(error(MANIFEST, `${label} is held by "${ruleId}", which is not a verify-docs rule`, mLine(`"${ruleId}"`)));
                        inSection('the rule', `\`${ruleId}\``, label);
                    }
                }
                if (policy.registry !== undefined) {
                    if (typeof policy.registry !== 'string' || ctx.read(policy.registry) === null) out.push(error(MANIFEST, `${label} names the registry ${JSON.stringify(policy.registry)}, which does not exist`, where));
                    else inSection('the registry', policy.registry, label);
                }
                if (policy.gate !== undefined) {
                    if (!strings(policy.gate)) out.push(error(MANIFEST, `${label}: "gate" lists conformance levels, e.g. ["L6"]`, where));
                    else for (const level of policy.gate) {
                        if (!/^L\d$/.test(level) || !new RegExp(`^ \\*   ${level}  `, 'm').test(gateSource)) out.push(error(MANIFEST, `${label} is verified by conformance ${level}, which ${GATE_SOURCE} does not document`, mLine(`"${level}"`)));
                    }
                }
            }
        }

        // What is not promised, entry for entry with the prose.
        const notSection = h3Section(security, 'What is not promised');
        if (notSection === null) {
            out.push(error(SECURITY, 'has no "### What is not promised" section — a contract that does not say where it stops reads as covering everything'));
        } else if (strings(compat.notPromised)) {
            const bullets = notSection.split('\n').filter((l) => /^- /.test(l)).length;
            if (bullets !== compat.notPromised.length) out.push(error(MANIFEST, `contracts.compatibility.notPromised lists ${String(compat.notPromised.length)} entries and SECURITY.md §What is not promised ${String(bullets)} — the two say the same thing, entry for entry`, mLine('"notPromised"')));
        }

        out.push(...checkSupport(ctx, contracts.support, security, mLine));

        // One word for the reason vocabulary: grow-only, never "not frozen" (ADR 0018).
        const proseFiles = [SECURITY, 'README.md', 'docs/agent-brief.md', 'docs/data/reasons.json', ...ctx.list('docs/guides').filter((p) => p.endsWith('.md'))];
        for (const file of proseFiles) {
            const text = ctx.read(file);
            const hit = text === null ? null : REASON_NOT_FROZEN.exec(text);
            if (text !== null && hit !== null) out.push(error(file, `calls the reason vocabulary "${hit[0]}" — it is grow-only: every name is frozen with the export surface, and a new reason is a minor (ADR 0018)`, lineContaining(text, hit[0])));
        }

        // Both ways: nothing that holds a promise goes unlisted.
        for (const rule of RULES) {
            if (HOLDING_RULE.test(rule.id) && !namedRules.has(rule.id)) out.push(error(MANIFEST, `the rule "${rule.id}" holds a frozen snapshot and no leg of contracts.compatibility names it — add it to the leg it holds, or rename it`, mLine('"legs"')));
        }
        for (const path of ctx.list('docs')) {
            if (SNAPSHOT_FILE.test(path) && !namedSnapshots.has(path)) out.push(error(MANIFEST, `${path} is a frozen snapshot no leg of contracts.compatibility names — a promise a satellite cannot find`, mLine('"legs"')));
        }
        return out;
    },
};

// ── option-defaults-parity ───────────────────────────────────────────

export const DEFAULTS_REGISTRY = 'docs/data/defaults.json';
const API_JSON = 'docs/assets/api.json';
/** What a 1.x release may do to a default (ADR 0018). */
export const DEFAULT_SEMVERS: readonly string[] = ['frozen', 'lowerable', 'addable', 'not-promised'];
/** The exported types whose optional members are options a caller sets. */
const OPTION_HOLDER = /(?:Options|Input|Description)$/;

interface ApiExport {
    readonly name: string;
    readonly kind: string;
    readonly module?: string;
    readonly signature?: string;
    readonly params?: ReadonlyArray<{ readonly name?: string }> | null;
    readonly members?: ReadonlyArray<{ readonly name?: string; readonly type?: string; readonly optional?: boolean }> | null;
}

interface DefaultRow {
    readonly option?: unknown;
    readonly in?: unknown;
    readonly default?: unknown;
    readonly semver?: unknown;
    readonly evidence?: unknown;
}

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Whether the export takes the option: a member of an interface, a parameter
 * of a function, or — for a union alias, whose members api.json does not
 * list — a `readonly <option>?` member declared in its module.
 */
function takesOption(ctx: RuleContext, exp: ApiExport, option: string): boolean {
    if (exp.kind === 'function') return (exp.params ?? []).some((p) => p.name === option.split('.')[0]);
    if (Array.isArray(exp.members) && exp.members.length > 0) return exp.members.some((m) => m.name === option);
    const source = exp.module === undefined ? null : ctx.read(exp.module);
    return source !== null && new RegExp(`\\breadonly ${escapeRegExp(option)}\\?:`).test(source);
}

const optionDefaultsParity: Rule = {
    id: 'option-defaults-parity',
    summary: 'docs/data/defaults.json lists every option default with a 1.x semver (frozen, lowerable, addable, not-promised) and the source lines that implement it: every evidence string is found in its file, every type or function named is exported and takes the option, and every optional boolean member of an exported …Options, …Input or …Description type has a row (ADR 0018).',
    check(ctx) {
        const registry = readJson<{ defaults?: unknown }>(ctx, DEFAULTS_REGISTRY);
        if ('finding' in registry) return [registry.finding];
        const text = ctx.read(DEFAULTS_REGISTRY) ?? '';
        const api = readJson<{ exports?: ApiExport[] }>(ctx, API_JSON);
        if ('finding' in api) return [api.finding];
        const exports = new Map((api.value.exports ?? []).map((e) => [e.name, e]));
        const rows = registry.value.defaults;
        if (!Array.isArray(rows) || rows.length === 0) return [error(DEFAULTS_REGISTRY, '"defaults" must list every option default — the registry ADR 0018 holds the defaults to')];

        const out: Finding[] = [];
        const covered = new Set<string>();
        (rows as DefaultRow[]).forEach((row, index) => {
            const option = typeof row.option === 'string' && row.option !== '' ? row.option : null;
            const at = option === null ? 1 : lineContaining(text, `"option": "${option}"`);
            const label = `row ${String(index + 1)} (${option ?? '?'})`;
            if (option === null) out.push(error(DEFAULTS_REGISTRY, `${label} has no "option"`, at));
            if (typeof row.default !== 'string' || row.default === '') out.push(error(DEFAULTS_REGISTRY, `${label} has no "default": say what the library chooses`, at));
            if (typeof row.semver !== 'string' || !DEFAULT_SEMVERS.includes(row.semver)) out.push(error(DEFAULTS_REGISTRY, `${label}: "semver" is ${JSON.stringify(row.semver)}; one of ${DEFAULT_SEMVERS.join(', ')} (ADR 0018)`, at));
            if (!strings(row.in)) {
                out.push(error(DEFAULTS_REGISTRY, `${label} needs "in": the exported types or functions that take the option`, at));
            } else if (option !== null) {
                for (const name of row.in) {
                    const exp = exports.get(name);
                    if (exp === undefined) out.push(error(DEFAULTS_REGISTRY, `${label} names ${name}, which ${API_JSON} does not list as an export`, at));
                    else if (!takesOption(ctx, exp, option)) out.push(error(DEFAULTS_REGISTRY, `${label}: ${name} does not take "${option}"`, at));
                    else covered.add(`${name}.${option}`);
                }
            }
            const evidence = row.evidence;
            if (!Array.isArray(evidence) || evidence.length === 0) {
                out.push(error(DEFAULTS_REGISTRY, `${label} needs "evidence": the source lines that implement the default, as { "file", "text" }`, at));
                return;
            }
            for (const item of evidence as Array<{ file?: unknown; text?: unknown }>) {
                if (typeof item.file !== 'string' || typeof item.text !== 'string' || item.text === '') {
                    out.push(error(DEFAULTS_REGISTRY, `${label}: every evidence item is { "file": "src/…", "text": "…" }`, at));
                    continue;
                }
                const source = ctx.read(item.file);
                if (source === null) out.push(error(DEFAULTS_REGISTRY, `${label} cites ${item.file}, which does not exist`, at));
                else if (!source.includes(item.text)) {
                    out.push(error(DEFAULTS_REGISTRY, `${label}: ${item.file} no longer contains ${JSON.stringify(item.text)} — if the default changed, that is semver-major under ADR 0018 unless its row says otherwise; if only the code moved, update the evidence`, at));
                }
            }
        });

        // Every flag has a default, and the registry must say which.
        for (const exp of exports.values()) {
            if (exp.kind !== 'type' || !OPTION_HOLDER.test(exp.name) || !Array.isArray(exp.members)) continue;
            for (const member of exp.members) {
                if (member.optional !== true || typeof member.name !== 'string' || !/^boolean(?: \| undefined)?$/.test(member.type ?? '')) continue;
                if (!covered.has(`${exp.name}.${member.name}`)) {
                    out.push(error(DEFAULTS_REGISTRY, `${exp.name}.${member.name} is an optional flag with no row — its default is part of the 1.x promise (ADR 0018): add it, with the source line that implements it`));
                }
            }
        }
        return out;
    },
};

// ── security-txt-parity ──────────────────────────────────────────────

export const SECURITY_TXT = 'docs/.well-known/security.txt';
/** The fields RFC 9116 §2.5 defines; anything else is a typo a parser ignores. */
const SECURITY_TXT_FIELDS: ReadonlySet<string> = new Set(['acknowledgments', 'canonical', 'contact', 'encryption', 'expires', 'hiring', 'policy', 'preferred-languages']);
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const DAY = 86_400_000;

const securityTxtParity: Rule = {
    id: 'security-txt-parity',
    summary: 'docs/.well-known/security.txt carries the RFC 9116 fields — Contact, one Expires within a year of the manifest\'s verifiedOn, Canonical on the site, Policy pointing at SECURITY.md, Preferred-Languages — and the same contact channels as SECURITY.md, both ways.',
    check(ctx) {
        const txt = ctx.read(SECURITY_TXT);
        if (txt === null) return [error(SECURITY_TXT, 'missing — RFC 9116 asks every site that takes vulnerability reports to publish one under /.well-known/')];
        const manifest = readJson<{ verifiedOn?: unknown; packages?: { pkinative?: { site?: unknown; repo?: unknown } } }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];
        const site = String(manifest.value.packages?.pkinative?.site ?? '');
        const repo = String(manifest.value.packages?.pkinative?.repo ?? '');
        const security = ctx.read(SECURITY) ?? '';
        const out: Finding[] = [];

        const fields = new Map<string, Array<{ value: string; line: number }>>();
        txt.split('\n').forEach((raw, i) => {
            const line = raw.replace(/\r$/, '');
            if (line.trim() === '' || line.startsWith('#')) return;
            const m = /^([A-Za-z-]+):\s*(.+)$/.exec(line);
            if (m === null) {
                out.push(error(SECURITY_TXT, `line ${String(i + 1)} is neither a comment nor a "Field: value" line`, i + 1));
                return;
            }
            const name = (m[1] ?? '').toLowerCase();
            if (!SECURITY_TXT_FIELDS.has(name)) out.push(error(SECURITY_TXT, `"${m[1] ?? ''}" is not a field RFC 9116 defines`, i + 1));
            fields.set(name, [...(fields.get(name) ?? []), { value: (m[2] ?? '').trim(), line: i + 1 }]);
        });
        const one = (name: string): string | undefined => fields.get(name)?.[0]?.value;

        const contacts = (fields.get('contact') ?? []).map((f) => f.value);
        if (contacts.length === 0) out.push(error(SECURITY_TXT, 'has no Contact — RFC 9116 §2.5.3 requires at least one'));
        for (const contact of contacts) {
            const needle = contact.startsWith('mailto:') ? contact.slice('mailto:'.length) : contact;
            if (!security.includes(needle)) out.push(error(SECURITY_TXT, `Contact ${contact} is not a channel SECURITY.md names — the two must offer the same ways to report`, lineContaining(txt, contact)));
        }
        const advisories = `${repo}/security/advisories/new`;
        if (!contacts.includes(advisories)) out.push(error(SECURITY_TXT, `does not offer ${advisories}, the private vulnerability reporting channel SECURITY.md names first`));
        for (const address of new Set([...security.matchAll(/\bsecurity@[a-z0-9.-]+\.[a-z]+/g)].map((m) => m[0]))) {
            if (!contacts.includes(`mailto:${address}`)) out.push(error(SECURITY_TXT, `does not offer mailto:${address}, which SECURITY.md names as a channel`));
        }

        const expires = fields.get('expires') ?? [];
        if (expires.length !== 1) out.push(error(SECURITY_TXT, `has ${String(expires.length)} Expires fields — RFC 9116 §2.5.5 requires exactly one`));
        const expiry = expires[0];
        if (expiry !== undefined) {
            const when = RFC3339.test(expiry.value) ? Date.parse(expiry.value) : Number.NaN;
            const verified = typeof manifest.value.verifiedOn === 'string' ? Date.parse(`${manifest.value.verifiedOn}T00:00:00Z`) : Number.NaN;
            if (Number.isNaN(when)) out.push(error(SECURITY_TXT, `Expires "${expiry.value}" is not an RFC 3339 date-time`, expiry.line));
            else if (!Number.isNaN(verified) && (when <= verified || when > verified + 366 * DAY)) {
                out.push(error(SECURITY_TXT, `Expires ${expiry.value} is not within a year after the manifest's verifiedOn ${String(manifest.value.verifiedOn)} — RFC 9116 §2.5.5 recommends less than a year ahead; renew it when the documentation is re-verified`, expiry.line));
            }
        }

        const canonical = `${site}/.well-known/security.txt`;
        if (!(fields.get('canonical') ?? []).some((f) => f.value === canonical)) out.push(error(SECURITY_TXT, `has no "Canonical: ${canonical}" — the URL the site serves it at`));
        const policy = one('policy');
        if (policy === undefined || !policy.startsWith(repo) || !policy.endsWith('/SECURITY.md')) out.push(error(SECURITY_TXT, `Policy must point at SECURITY.md in ${repo}`));
        const languages = (one('preferred-languages') ?? '').split(',').map((l) => l.trim());
        if (!languages.includes('en')) out.push(error(SECURITY_TXT, 'Preferred-Languages must include en — the project writes English everywhere'));
        if (!security.includes(SECURITY_TXT.slice('docs/'.length))) out.push(error(SECURITY, `does not mention ${SECURITY_TXT.slice('docs/'.length)}, the machine-readable form of its contact section`));
        return out;
    },
};

export const CONTRACT_RULES: readonly Rule[] = [refusalBaselineFrozen, contractsShape, optionDefaultsParity, securityTxtParity];
