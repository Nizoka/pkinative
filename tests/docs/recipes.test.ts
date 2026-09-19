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
const api = JSON.parse(readFileSync('docs/assets/api.json', 'utf8')) as { exports: Array<{ name: string }> };
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

    it('should keep the README quick start identical to the quick-start recipe', () => {
        const recipe = readFileSync('recipes/quick-start.ts', 'utf8').replace(/\r\n/g, '\n');
        const block = /\/\/ quick-start:begin\n([\s\S]*?)\/\/ quick-start:end/.exec(recipe)?.[1];
        const readme = readFileSync('README.md', 'utf8').replace(/\r\n/g, '\n');
        const section = readme.slice(readme.indexOf('## Quick start'));
        const code = /```ts\n([\s\S]*?)```/.exec(section)?.[1];
        expect(block).toBeDefined();
        expect(code).toBe(block);
    });
});
