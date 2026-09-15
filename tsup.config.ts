import { defineConfig } from 'tsup';

// One entry, on purpose: a subpath export is a public contract that only a
// major release may remove (AGENTS.md §Decisions). Tree-shaking is proven by
// `npm run verify:bundle`, not promised by extra entry points.
export default defineConfig([
    {
        entry: { index: 'src/index.ts' },
        format: ['esm', 'cjs'],
        dts: true,
        sourcemap: true,
        clean: true,
        splitting: false,
        treeshake: true,
        minify: false,
        target: 'es2020',
        outDir: 'dist',
    },
]);
