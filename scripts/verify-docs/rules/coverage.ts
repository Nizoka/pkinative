/**
 * pkinative — coverage rules
 * ==========================
 * `coverage-ignore-budget`: every coverage-ignore comment under src/ carries
 * a `--` justification, sits alone on its line, and the total matches
 * `declared.coverageIgnores` in docs/assets/ecosystem.json; the four
 * thresholds are 100 and `coverage.exclude` matches what the manifest
 * declares.
 *
 * At 100 % there are exactly two ways left to leave code unproven: an ignore
 * comment, and an exclude glob. This rule makes each of them a counted,
 * reviewed decision rather than a silent one.
 *
 * @module scripts/verify-docs/rules/coverage
 */

import { error, lineOf, readJson, type Finding, type Rule } from '../context.js';

const MANIFEST = 'docs/assets/ecosystem.json';
const VITEST_CONFIG = 'vitest.config.ts';

/** The directives v8-to-istanbul honours, in both comment forms. */
const IGNORE = /\/[/*]\s*(?:v8|c8|node:coverage)\s+(?:ignore|disable)\b[^\n*]*/g;
/** A justification is `--` followed by prose. */
const JUSTIFIED = /\s--\s+\S/;

const coverageIgnoreBudget: Rule = {
    id: 'coverage-ignore-budget',
    summary: 'Every coverage-ignore comment under src/ carries a `--` justification and sits alone on its line, their total equals declared.coverageIgnores in docs/assets/ecosystem.json, and vitest.config.ts keeps all four thresholds at 100 with exactly the declared exclusions.',
    check(ctx) {
        const out: Finding[] = [];
        const manifest = readJson<{ declared?: { coverageIgnores?: unknown; coverageExcludes?: unknown } }>(ctx, MANIFEST);
        if ('finding' in manifest) return [manifest.finding];

        let total = 0;
        for (const path of ctx.list('src')) {
            if (!path.endsWith('.ts')) continue;
            const text = ctx.read(path) ?? '';
            for (const match of text.matchAll(IGNORE)) {
                total++;
                const line = lineOf(text, match.index);
                if (!JUSTIFIED.test(match[0])) {
                    out.push(error(path, `the coverage-ignore comment ${JSON.stringify(match[0].trim())} carries no justification — write \`/* v8 ignore next -- why no input can reach this branch */\``, line));
                }
                // `v8 ignore next` drops the WHOLE following line from the
                // report, so an ignore sharing a line with reachable code
                // silently removes that code's counts as well.
                if (!/(?:^|\n)[ \t]*$/.test(text.slice(0, match.index))) {
                    out.push(error(path, 'a coverage-ignore comment must be alone on its line: on a line that also holds code it drops that code from the report too', line));
                }
            }
        }

        const declared = manifest.value.declared?.coverageIgnores;
        if (typeof declared !== 'number' || !Number.isInteger(declared) || declared < 0) {
            out.push(error(MANIFEST, 'declared.coverageIgnores must be the number of coverage-ignore comments under src/'));
        } else if (declared !== total) {
            out.push(error(MANIFEST, `declared.coverageIgnores is ${String(declared)}; src/ holds ${String(total)} — every unproven branch is a reviewed decision, so justify the change and update this count in the same commit`));
        }

        const config = ctx.read(VITEST_CONFIG);
        if (config === null) return [...out, error(VITEST_CONFIG, 'missing')];
        for (const axis of ['statements', 'branches', 'functions', 'lines']) {
            if (!new RegExp(`${axis}:\\s*100\\b`).test(config)) {
                out.push(error(VITEST_CONFIG, `does not hold ${axis} coverage at 100 — lowering a threshold hides exactly what the ignore budget is there to count`, lineOf(config, config.indexOf(axis))));
            }
        }
        const excludes = manifest.value.declared?.coverageExcludes;
        if (!Array.isArray(excludes) || excludes.some((e) => typeof e !== 'string')) {
            out.push(error(MANIFEST, 'declared.coverageExcludes must list the paths vitest.config.ts excludes from coverage'));
        } else {
            const actual = /exclude:\s*\[([^\]]*)\]/.exec(config)?.[1] ?? '';
            const listed = [...actual.matchAll(/'([^']+)'/g)].map((m) => m[1] ?? '');
            if (listed.join('|') !== (excludes as string[]).join('|')) {
                out.push(error(VITEST_CONFIG, `excludes ${listed.join(', ') || '(nothing)'} from coverage; declared.coverageExcludes says ${(excludes as string[]).join(', ')} — what is not measured is declared`, lineOf(config, config.indexOf('exclude:'))));
            }
        }
        return out;
    },
};

export const COVERAGE_RULES: readonly Rule[] = [coverageIgnoreBudget];
