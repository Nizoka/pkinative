import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';

// Recipes are executable documentation (zipnative doctrine): every recipe
// runs on every test run and its declared expectations are asserted, so a
// sample cannot silently rot. The README quick start is one of them.

interface RecipeSpec {
    readonly file: string;
    readonly task: string;
    readonly surface: readonly string[];
    readonly since: string;
    readonly expects: readonly string[];
}

const index = JSON.parse(readFileSync('recipes/index.json', 'utf8')) as { recipes: RecipeSpec[] };
const api = JSON.parse(readFileSync('docs/assets/api.json', 'utf8')) as { exports: Array<{ name: string; kind: string }> };
const exported = new Set(api.exports.map((e) => e.name));

describe('recipes', () => {
    it.each(index.recipes)('$file: $task', async (spec) => {
        const recipe = await import(/* @vite-ignore */ `../../recipes/${spec.file}`) as { default: () => Record<string, string> | Promise<Record<string, string>> };
        expect(typeof recipe.default, `${spec.file} must default-export its run function`).toBe('function');
        const result = await recipe.default();
        for (const expectation of spec.expects) {
            const at = expectation.indexOf('=');
            expect(result[expectation.slice(0, at)], `${spec.file} expects ${expectation}`).toBe(expectation.slice(at + 1));
        }
    });

    it('should index every recipe file, and only files that exist', () => {
        const files = readdirSync('recipes').filter((f) => f.endsWith('.ts') && !f.startsWith('_')).sort();
        expect(index.recipes.map((r) => r.file).sort()).toEqual(files);
    });

    it('should declare only a surface the package exports', () => {
        for (const spec of index.recipes) {
            for (const name of spec.surface) expect(exported.has(name), `${spec.file}: ${name}`).toBe(true);
        }
    });

    it('should demonstrate every runtime export in at least one recipe that runs', () => {
        // The reverse of the test above. A name no recipe exercises is a name
        // whose sample nothing proves still works — and, for a caller reading
        // only the docs, a feature that may as well not exist.
        const covered = new Set(index.recipes.flatMap((r) => r.surface));
        const callables = api.exports.filter((e) => e.kind !== 'type').map((e) => e.name);
        expect(callables.filter((name) => !covered.has(name))).toEqual([]);
    });

    // Every code block a reader copies is the marked region of a recipe that
    // runs, byte for byte: identity alone would only prove the sample matches
    // a file, not that the file still works.
    const EMBEDDED: ReadonlyArray<{ doc: string; heading: string; recipe: string; marker: string }> = [
        { doc: 'README.md', heading: '## Quick start', recipe: 'recipes/quick-start.ts', marker: 'quick-start' },
        { doc: 'docs/agent-brief.md', heading: '## Read a certificate', recipe: 'recipes/agent-brief.ts', marker: 'agent-brief' },
    ];

    it.each(EMBEDDED)('should keep the $doc code block identical to $recipe', ({ doc, heading, recipe, marker }) => {
        const source = readFileSync(recipe, 'utf8').replace(/\r\n/g, '\n');
        const block = new RegExp(`// ${marker}:begin\\n([\\s\\S]*?)// ${marker}:end`).exec(source)?.[1];
        const text = readFileSync(doc, 'utf8').replace(/\r\n/g, '\n');
        const code = /```ts\n([\s\S]*?)```/.exec(text.slice(text.indexOf(heading)))?.[1];
        expect(block, `${recipe} has no ${marker}:begin/end region`).toBeDefined();
        expect(code).toBe(block);
    });
});
