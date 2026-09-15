import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    eslint.configs.recommended,
    ...tseslint.configs.strict,
    {
        languageOptions: {
            parserOptions: {
                projectService: {
                    // The plain-JS maintenance scripts belong to no tsconfig;
                    // they are linted on demand (`npx eslint scripts/x.mjs`).
                    allowDefaultProject: ['scripts/*.mjs'],
                },
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
            '@typescript-eslint/no-explicit-any': 'error',
            '@typescript-eslint/no-non-null-assertion': 'error',
            '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports', fixStyle: 'inline-type-imports' }],
            'eqeqeq': ['error', 'always'],
            'no-throw-literal': 'error',
            'no-shadow': 'off',
            '@typescript-eslint/no-shadow': 'error',
            'no-var': 'error',
            'prefer-const': 'error',
            'no-eval': 'error',
            'no-implied-eval': 'error',
            'no-new-func': 'error',
            // Only src/core/pki-diagnostics.ts may call console.warn; the
            // architecture test (tests/tools/architecture.test.ts) enforces
            // the single sink, this rule forbids everything else outright.
            'no-console': ['error', { allow: ['warn'] }],
            'no-restricted-globals': ['error', 'process', 'require', 'Buffer', 'fetch', 'WebSocket', 'XMLHttpRequest'],
        },
    },
    {
        ignores: ['dist/**', 'coverage/**', 'test-output/**', 'tests/**', 'bench/**', 'recipes/**', 'scripts/**', 'docs/**', '*.config.*'],
    },
);
