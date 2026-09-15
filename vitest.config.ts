import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

/**
 * The executable-documentation recipes in `recipes/` import from 'pkinative'
 * exactly as a consumer would; the alias points that specifier at the in-repo
 * sources so the recipe suite always exercises the current tree.
 */
const rootUrl = (p: string): string => fileURLToPath(new URL(p, import.meta.url));

/**
 * Reporters are chosen for token-cheap output: `dot` prints one character
 * per test instead of one line per file, and `github-actions` adds inline
 * annotations on CI only. When `scripts/gate.ts` drives the run (GATE=1) a
 * JSON report is written as well, which is where the gate reads the test
 * count from; nothing else needs the file, so it is not produced otherwise.
 */
const reporters: Array<'dot' | 'github-actions' | ['json', { outputFile: string }]> = ['dot'];
if (process.env['GITHUB_ACTIONS']) reporters.push('github-actions');
if (process.env['GATE'] === '1') reporters.push(['json', { outputFile: 'test-output/.gate/vitest.json' }]);

/** The parsers of untrusted bytes carry a higher bar than the rest of the library. */
const PARSER_THRESHOLDS = { statements: 98, branches: 95, functions: 98, lines: 98 } as const;

export default defineConfig({
    resolve: {
        alias: [{ find: /^pkinative$/, replacement: rootUrl('./src/index.ts') }],
    },
    test: {
        include: ['tests/**/*.test.ts'],
        environment: 'node',
        globals: false,
        reporters,
        // Certificate validity is UTC by definition (RFC 5280 §4.1.2.5); pinning
        // the zone keeps any formatted date identical on every machine.
        env: { TZ: 'UTC' },
        // Process isolation: a test that leaks a global or a timer cannot
        // influence the next file's outcome.
        pool: 'forks',
        // Determinism: the same ordering on every machine, so a failure seen
        // in CI reproduces locally without a seed.
        sequence: { shuffle: false },
        // The fuzzing suites run fixed, seeded iteration budgets; under
        // coverage instrumentation they legitimately exceed vitest's 5 s
        // default. 30 s is the ceiling, not a target.
        testTimeout: 30_000,
        hookTimeout: 30_000,
        coverage: {
            provider: 'v8',
            include: ['src/**/*.ts'],
            exclude: ['src/index.ts', 'src/types/**'],
            // `text-summary` is four lines instead of one per source file;
            // `json-summary` is what scripts/gate.ts reads the percentage
            // from; `html` stays for local drill-down.
            reporter: ['text-summary', 'json-summary', 'html'],
            thresholds: {
                statements: 95,
                branches: 90,
                functions: 95,
                lines: 95,
                'src/asn1/**': PARSER_THRESHOLDS,
                'src/pem/**': PARSER_THRESHOLDS,
            },
        },
    },
});
