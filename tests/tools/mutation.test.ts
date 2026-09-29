import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
    applyMutant, buildImportGraph, checkEquivalentsFile, enumerateMutants, matchEquivalents, sampleMutants, scoreOf, selectTests,
    type EquivalentsFile, type Mutant,
} from '../../scripts/lib/mutation.ts';

// scripts/mutate.ts spawns vitest once per mutant, which is far too slow for
// the gate; everything it decides from file contents alone is pinned here.

const pick = (mutants: readonly Mutant[], operator: string): Array<[string, string]> =>
    mutants.filter((m) => m.operator === operator).map((m) => [m.original, m.replacement]);

describe('enumerateMutants', () => {
    const source = [
        'const MAX_DEPTH = 64;',
        'const TABLE = [1, 2, 3];',
        'type T = 0 | 1;',
        'export function f(a: number, b: Uint8Array, c: boolean): boolean {',
        '    if (a < MAX_DEPTH && !c) throw new Error("x");',
        '    if (a >= 2 || a === b[a + 1]) return true;',
        '    const w = b.subarray(0, 4);',
        '    switch (a) { case 48: return c ? w.length > 0 : false; }',
        '    return false;',
        '}',
    ].join('\n');
    const mutants = enumerateMutants('src/x.ts', source);

    it('should flip each relational and equality operator to its neighbour', () => {
        expect(pick(mutants, 'relational')).toEqual([['<', '<='], ['>=', '>'], ['>', '>=']]);
        expect(pick(mutants, 'equality')).toEqual([['===', '!==']]);
    });

    it('should swap && and ||', () => {
        expect(pick(mutants, 'logical')).toEqual([['&&', '||'], ['||', '&&']]);
    });

    it('should remove a negation, keeping the operand parenthesised', () => {
        expect(pick(mutants, 'not-removal')).toEqual([['!c', '(c)']]);
    });

    it('should swap the branches of a conditional expression', () => {
        expect(pick(mutants, 'conditional')).toEqual([['c ? w.length > 0 : false', '(c ? false : w.length > 0)']]);
    });

    it('should force every if true, and call the false mutant of a throwing branch a throw guard', () => {
        expect(pick(mutants, 'if-true')).toEqual([['a < MAX_DEPTH && !c', 'true'], ['a >= 2 || a === b[a + 1]', 'true']]);
        expect(pick(mutants, 'throw-guard')).toEqual([['a < MAX_DEPTH && !c', 'false']]);
        expect(pick(mutants, 'if-false')).toEqual([['a >= 2 || a === b[a + 1]', 'false']]);
    });

    it('should move limits and offsets by one, and leave tables, case labels and types alone', () => {
        expect(pick(mutants, 'number')).toEqual([
            ['64', '65'], ['64', '63'],
            ['2', '3'], ['2', '1'],
            ['1', '2'], ['1', '0'],
            ['0', '1'], ['0', '-1'],
            ['4', '5'], ['4', '3'],
            ['0', '1'], ['0', '-1'],
        ]);
    });

    it('should negate a returned boolean literal', () => {
        expect(pick(mutants, 'return-boolean')).toEqual([['true', 'false'], ['false', 'true']]);
    });

    it('should give every mutant a unique id of file, line, column and operator', () => {
        const ids = mutants.map((m) => m.id);
        expect(new Set(ids).size).toBe(ids.length);
        expect(ids).toContain('src/x.ts:5:11:relational');
        expect(ids).toContain('src/x.ts:1:19:number+1');
    });

    it('should apply exactly one mutant to the source', () => {
        const m = mutants.find((x) => x.id === 'src/x.ts:5:11:relational') as Mutant;
        expect(applyMutant(source, m).split('\n')[4]).toBe('    if (a <= MAX_DEPTH && !c) throw new Error("x");');
    });
});

describe('sampleMutants', () => {
    const mutants = enumerateMutants('src/y.ts', Array.from({ length: 40 }, (_, i) => `export const f${i} = (a: number): boolean => a < ${i} || a > 2 * ${i};`).join('\n'));

    it('should return the same sample for the same seed, in source order', () => {
        const first = sampleMutants(mutants, 25, 7).map((m) => m.id);
        expect(sampleMutants(mutants, 25, 7).map((m) => m.id)).toEqual(first);
        expect(first).toHaveLength(25);
        const starts = sampleMutants(mutants, 25, 7).map((m) => m.start);
        expect(starts).toEqual([...starts].sort((a, b) => a - b));
    });

    it('should draw a different sample for another seed', () => {
        expect(sampleMutants(mutants, 25, 8).map((m) => m.id)).not.toEqual(sampleMutants(mutants, 25, 7).map((m) => m.id));
    });

    it('should return every mutant when the sample is at least as large as the list', () => {
        expect(sampleMutants(mutants, mutants.length, 3)).toEqual(mutants);
    });
});

describe('selectTests', () => {
    const graph = buildImportGraph(new Map([
        ['src/a.ts', ''],
        ['src/b.ts', "import { a } from './a.js';"],
        ['src/index.ts', "export * from './b.js';"],
        ['tests/b.test.ts', "import { b } from '../src/b.js';"],
        ['tests/api.test.ts', "import { b } from 'pkinative';"],
        ['tests/docs/doc.test.ts', "import { b } from 'pkinative';"],
        ['tests/unrelated.test.ts', "import { x } from 'vitest';"],
    ]));

    it('should resolve .js specifiers to .ts files and the pkinative alias to src/index.ts', () => {
        expect(graph.get('src/b.ts')).toEqual(['src/a.ts']);
        expect(graph.get('tests/api.test.ts')).toEqual(['src/index.ts']);
        expect(graph.get('tests/unrelated.test.ts')).toEqual([]);
    });

    it('should fall back to the suites of the nearest importer when no suite names the module', () => {
        expect(selectTests(graph, 'src/a.ts', ['tests/docs/']).direct).toEqual(['tests/b.test.ts']);
    });

    it('should reach every suite that imports the module transitively, minus the excluded prefixes', () => {
        expect(selectTests(graph, 'src/a.ts', ['tests/docs/']).reach).toEqual(['tests/api.test.ts', 'tests/b.test.ts']);
    });
});

describe('the equivalent-mutant table', () => {
    const table = JSON.parse(readFileSync('scripts/data/mutation-equivalents.json', 'utf8')) as EquivalentsFile;

    it('should be well-formed, with a reason for every entry', () => {
        expect(checkEquivalentsFile(table)).toEqual([]);
    });

    it('should name only mutants that still exist, with their original and replacement text', () => {
        const files = [...new Set(table.equivalents.map((e) => e.id.slice(0, e.id.indexOf(':'))))];
        const mutants = files.flatMap((f) => enumerateMutants(f, readFileSync(f, 'utf8')));
        const { matched, stale } = matchEquivalents(table.equivalents, mutants);
        expect(stale.map((e) => e.id)).toEqual([]);
        expect(matched.size).toBe(table.equivalents.length);
    });

    it('should refuse a placeholder reason, a repeated id and a missing field', () => {
        const entry = { id: 'src/a.ts:1:1:if-true', original: 'x', replacement: 'true', reason: 'TODO' };
        expect(checkEquivalentsFile({ schema: 1, equivalents: [entry, entry, { id: 'src/a.ts:2:1:if-true' }] })).toEqual([
            'equivalents[0] (src/a.ts:1:1:if-true) has no reason yet — an equivalent mutant is an argument, not a placeholder',
            'equivalents[1] repeats src/a.ts:1:1:if-true',
            'equivalents[1] (src/a.ts:1:1:if-true) has no reason yet — an equivalent mutant is an argument, not a placeholder',
            'equivalents[2] needs a non-empty "original"',
            'equivalents[2] needs a non-empty "replacement"',
            'equivalents[2] needs a non-empty "reason"',
        ]);
    });

    it('should report an entry whose mutant moved as stale, and ignore files that were not enumerated', () => {
        const mutants = enumerateMutants('src/a.ts', 'export const f = (a: number): boolean => a < 1;');
        const moved = { id: 'src/a.ts:1:44:relational', original: '<=', replacement: '<', reason: 'r' };
        const elsewhere = { id: 'src/z.ts:1:1:if-true', original: 'x', replacement: 'true', reason: 'r' };
        expect(matchEquivalents([moved, elsewhere], mutants).stale).toEqual([moved]);
    });
});

describe('scoreOf', () => {
    it('should count timeouts as detected and leave compile errors and equivalents out of the denominator', () => {
        expect(scoreOf(['killed', 'killed', 'timeout', 'survived', 'compile-error', 'equivalent'])).toEqual({
            total: 6, killed: 2, survived: 1, timeout: 1, compileError: 1, equivalent: 1, score: 75,
        });
    });

    it('should score an empty or all-excluded set as 100', () => {
        expect(scoreOf([]).score).toBe(100);
        expect(scoreOf(['equivalent']).score).toBe(100);
    });
});
