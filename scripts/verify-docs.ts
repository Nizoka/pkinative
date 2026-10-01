#!/usr/bin/env tsx
/**
 * pkinative — documentation consistency verifier
 * ================================================
 * In pdfnative, versions, counts and inventories hand-copied across dozens of
 * files drifted a full release train apart before anything checked them.
 * This script makes `docs/assets/ecosystem.json` and the source tree the
 * single sources of truth and fails the build when any document, governance
 * file or agent configuration disagrees with them.
 *
 * The engine is here; the rules live one per concern under
 * `scripts/verify-docs/rules/` and read the repository only through a
 * `RuleContext`, which is what lets tests/docs/verify-docs.test.ts prove
 * that every rule fires on its own perturbation.
 *
 * Usage:
 *   npm run verify:docs                              # offline, hermetic — safe in CI
 *   npx tsx scripts/verify-docs.ts --online          # also the rules that reach the network: external-links probes
 *                                                    #   every cited URL (the npm registry is scripts/check-npm-drift.ts)
 *   npx tsx scripts/verify-docs.ts --strict          # warnings fail too
 *   npx tsx scripts/verify-docs.ts --json            # machine-readable
 *   npx tsx scripts/verify-docs.ts --only <rule>     # one rule
 *   npx tsx scripts/verify-docs.ts --list            # the rule table
 *
 * Suppression: `verify-docs:allow <rule>` on the reported line or the line
 * above it silences that rule there, and is itself reviewable in the diff.
 *
 * Exit codes:
 *   0 — every rule passes.
 *   1 — at least one rule failed; each problem is printed as `path:line [rule] message`.
 *   2 — bad usage.
 *
 * The script never writes. It is safe to run against a dirty tree.
 */

import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFsContext, type Rule, type RuleContext } from './verify-docs/context.js';
import { RULES } from './verify-docs/rules/index.js';

export interface Problem {
    readonly file: string;
    readonly line: number;
    readonly rule: string;
    readonly message: string;
    readonly severity: 'error' | 'warn';
}

export const ALLOW_MARKER = 'verify-docs:allow';

function suppressed(ctx: RuleContext, file: string, line: number, rule: string): boolean {
    const text = ctx.read(file);
    if (text === null) return false;
    const lines = text.split('\n');
    const marker = `${ALLOW_MARKER} ${rule}`;
    return [line - 1, line - 2].some((i) => i >= 0 && (lines[i] ?? '').includes(marker));
}

/** Run rules over a context and collect every unsuppressed problem, in rule order. */
export async function runRules(ctx: RuleContext, rules: readonly Rule[] = RULES, only: string | null = null): Promise<Problem[]> {
    const out: Problem[] = [];
    for (const rule of rules) {
        if (only !== null && rule.id !== only) continue;
        let findings;
        try {
            findings = await rule.check(ctx);
        } catch (err) {
            out.push({ file: 'scripts/verify-docs.ts', line: 1, rule: rule.id, severity: 'error', message: `the rule crashed — ${(err as Error).stack ?? String(err)}` });
            continue;
        }
        for (const f of findings) {
            if (suppressed(ctx, f.file, f.line, rule.id)) continue;
            out.push({ file: f.file, line: f.line, rule: rule.id, message: f.message, severity: f.severity });
        }
    }
    return out;
}

async function main(argv: readonly string[]): Promise<number> {
    const online = argv.includes('--online');
    const strict = argv.includes('--strict');
    const json = argv.includes('--json');
    const onlyAt = argv.indexOf('--only');
    const only = onlyAt >= 0 ? argv[onlyAt + 1] ?? '' : null;
    const known = new Set(['--online', '--strict', '--json', '--only', '--list']);
    const unknown = argv.filter((a, i) => !known.has(a) && !(onlyAt >= 0 && i === onlyAt + 1));
    if (unknown.length > 0 || (only !== null && !RULES.some((r) => r.id === only))) {
        process.stderr.write(`verify-docs: ${unknown.length > 0 ? `unknown argument(s) ${unknown.join(' ')}` : `unknown rule "${only}"`}\n`);
        process.stderr.write(`Rules: ${RULES.map((r) => r.id).join(', ')}\n`);
        return 2;
    }
    if (argv.includes('--list')) {
        for (const r of RULES) process.stdout.write(`${r.id.padEnd(24)} ${r.summary}\n`);
        return 0;
    }

    const root = resolve(import.meta.dirname, '..');
    const problems = await runRules(createFsContext(root, online), RULES, only);
    const failing = problems.filter((p) => p.severity === 'error' || strict);
    const ran = only === null ? RULES.length : 1;

    if (json) {
        process.stdout.write(`${JSON.stringify({ ok: failing.length === 0, rules: ran, problems }, null, 2)}\n`);
    } else {
        for (const p of problems) {
            process.stdout.write(`${p.severity === 'warn' ? 'warn  ' : ''}${p.file}:${p.line} [${p.rule}] ${p.message}\n`);
        }
        const errors = problems.filter((p) => p.severity === 'error').length;
        const warns = problems.length - errors;
        process.stdout.write(`verify-docs: ${ran} rule(s), ${errors} error(s), ${warns} warning(s)\n`);
    }
    return failing.length === 0 ? 0 : 1;
}

// Run only when invoked directly (keeps the module import-safe for tests).
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    main(process.argv.slice(2)).then((code) => process.exit(code), (err: unknown) => {
        process.stderr.write(`verify-docs: ${(err as Error).stack ?? String(err)}\n`);
        process.exit(1);
    });
}
