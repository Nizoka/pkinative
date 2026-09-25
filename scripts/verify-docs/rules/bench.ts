/**
 * pkinative — benchmark rules
 * ===========================
 * `bench-parity`: the three ways a performance record rots, each closed.
 *
 * A benchmark suite decays differently from a test suite. A test that stops
 * matching the code goes red; a benchmark that stops matching it just keeps
 * producing numbers, and the document quoting them keeps looking authoritative.
 * So the checks here are about *attribution*, not about speed:
 *
 *   1. Two benchmarks may not share a name. Every results table in this
 *      project is keyed by name, and two rows that cannot be told apart make
 *      a whole section unreadable — including in retrospect, which is the
 *      only time anyone reads it.
 *   2. Every dated section of bench/RESULTS.md declares where its numbers
 *      came from, or says in its own words why it could not. `bench/
 *      RESULTS.md` opens with "numbers with no run context are not
 *      evidence"; this is that sentence, enforced.
 *   3. `.github/workflows/bench.yml` actually runs `npm run bench`, and is
 *      never one of the contexts `.github/rulesets/main.json` requires. A
 *      performance budget that blocks a merge on a shared runner — 2-5x
 *      run-to-run variance — teaches people to re-run until green, which is
 *      worse than having no budget at all.
 *
 * @module scripts/verify-docs/rules/bench
 */

import { error, type Finding, type Rule } from '../context.js';

const RESULTS = 'bench/RESULTS.md';
const WORKFLOW = '.github/workflows/bench.yml';
const RULESET = '.github/rulesets/main.json';

/** A dated section must say where the numbers came from. */
const CONTEXT_KEYS = ['Command', 'Runtime', 'Machine'];

const benchParity: Rule = {
    id: 'bench-parity',
    summary: 'Benchmark names are unique, every dated section of bench/RESULTS.md declares its run context (or says why it cannot), and bench.yml runs `npm run bench` without ever being a required status check.',
    check(ctx) {
        const out: Finding[] = [];

        // ── 1. Unique names ──
        const seen = new Map<string, string>();
        const files = ctx.list('bench').filter((p) => p.endsWith('.bench.ts'));
        if (files.length === 0) out.push(error('bench', 'holds no *.bench.ts file, but bench.yml and RESULTS.md both assume one'));
        for (const path of files) {
            for (const m of (ctx.read(path) ?? '').matchAll(/\bbench\(\s*(['"`])([^'"`]+)\1/g)) {
                const name = m[2];
                const first = seen.get(name);
                if (first !== undefined) out.push(error(path, `the benchmark name ${JSON.stringify(name)} is already used in ${first} — results tables are keyed by name, and two rows nobody can tell apart make the record unreadable`));
                else seen.set(name, path);
            }
        }
        if (seen.size === 0 && files.length > 0) out.push(error(files[0], 'declares no bench() — the file would produce an empty results table'));

        // ── 2. Every dated section says where its numbers came from ──
        const results = ctx.read(RESULTS);
        if (results === null) {
            out.push(error(RESULTS, 'missing — a benchmark with no recorded results is a benchmark nobody can compare against'));
        } else {
            // Split rather than match a lookahead: in multiline mode `$`
            // matches at every line end, so a lazy body followed by `\n*$`
            // captures nothing at all and every section silently passes.
            const sections = results.split(/^## /m).slice(1)
                .map((chunk) => [/^(\d{4}-\d{2}-\d{2})/.exec(chunk)?.[1], chunk] as const)
                .filter((pair): pair is readonly [string, string] => pair[0] !== undefined);
            if (sections.length === 0) out.push(error(RESULTS, 'has no "## YYYY-MM-DD — …" section; every measurement is dated or it is not a measurement'));
            for (const [date, body] of sections) {
                const declares = CONTEXT_KEYS.filter((key) => new RegExp(`\\*\\*${key}[^*]*:\\*\\*`).test(body));
                // A section may decline the standard keys, but only in
                // writing: the 2026-09-20 section does exactly that, because
                // `npm run bench` was not the instrument it used. Silence is
                // what is refused, not an unusual method.
                const explains = /\*\*Why the numbers below are not[^*]*:\*\*/.test(body) || /\*\*Runtime \/ machine:\*\*/.test(body);
                if (declares.length < CONTEXT_KEYS.length && !explains) {
                    const missing = CONTEXT_KEYS.filter((key) => !declares.includes(key));
                    out.push(error(RESULTS, `the ${date} section declares no ${missing.join(', ')} — say where the numbers came from, or say in writing why the usual context does not apply`));
                }
            }
        }

        // ── 3. The workflow runs the benchmarks, and blocks nothing ──
        const workflow = ctx.read(WORKFLOW);
        if (workflow === null) {
            out.push(error(WORKFLOW, 'missing — the trend is only a trend if something records it on a schedule'));
        } else {
            if (!/run:\s*npm run bench\b/.test(workflow)) out.push(error(WORKFLOW, 'never runs `npm run bench`, so whatever it archives is not this repository\'s benchmark'));
            if (!/^on:\n(?:[ \t]+[^\n]*\n)*?[ \t]+schedule:/m.test(workflow)) out.push(error(WORKFLOW, 'has no `schedule:` trigger — a trend needs more than one point'));
            if (/^\s*pull_request:/m.test(workflow)) out.push(error(WORKFLOW, 'triggers on pull_request; a shared runner varies 2-5x run to run, so a per-PR benchmark reports noise as news'));
        }

        const ruleset = ctx.read(RULESET);
        if (ruleset !== null && /"context"\s*:\s*"[^"]*bench/i.test(ruleset)) {
            out.push(error(RULESET, 'requires a bench status check — a performance budget enforced on a shared runner is a budget people learn to re-run until it passes'));
        }

        return out;
    },
};

export const BENCH_RULES: readonly Rule[] = [benchParity];
