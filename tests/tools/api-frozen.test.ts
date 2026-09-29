import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { classify, diffSurface, fingerprint, inputTypes, type FrozenExport, type Reader } from '../../scripts/lib/api-surface.js';
import { parseApiFrozen, planApiFrozen, releaseModeFor, renderApiFrozen, type ApiFrozen } from '../../scripts/build-api-frozen.js';
import { loadTextTree } from '../../scripts/verify-docs/context.js';

// What semver promises for a TypeScript export, pinned case by case: the
// fingerprint must move when a caller can break and stay put when nobody
// can, and the snapshot must move only in the ways a release may move it.

const ROOT = resolve(import.meta.dirname, '..', '..');
const TREE = loadTextTree(ROOT);
const readerOf = (files: Readonly<Record<string, string>>): Reader => (path) => files[path] ?? null;

const sig = (source: string, name: string): string => {
    const fp = fingerprint(readerOf({ 'm.ts': source }), 'm.ts', name);
    if ('problem' in fp) throw new Error(fp.problem);
    return fp.signature;
};

describe('fingerprint', () => {
    it('should drop comments, parameter names and defaults, and keep optionality', () => {
        const a = sig('/** Doc. */\nexport function f(der: Uint8Array, /* inline */ options: Opts = {}): Result { return x; }', 'f');
        const b = sig('export function f(bytes: Uint8Array, opts?: Opts): Result { return x; }', 'f');
        expect(a).toBe('(_: Uint8Array, _?: Opts) => Result');
        expect(b).toBe(a);
    });

    it('should drop parameter names inside callback types and tuple labels too', () => {
        expect(sig('export interface S { readonly sign: (data: Uint8Array) => Promise<Uint8Array>; readonly h: readonly [name: string, value: string] }', 'S'))
            .toBe('interface { readonly h: readonly [ _: string, _: string ]; readonly sign: (_: Uint8Array) => Promise<Uint8Array> }');
    });

    it('should sort union members and interface members, whose order means nothing', () => {
        expect(sig("export type T = 'b' | 'a';", 'T')).toBe(sig("export type T = 'a' | 'b';", 'T'));
        expect(sig('export interface I { b: number; a: string }', 'I')).toBe(sig('export interface I { a: string; b: number }', 'I'));
    });

    it('should merge the members of a base interface that is not exported, across an import', () => {
        const read = readerOf({
            'base.ts': 'export interface Base { readonly kind: string }\n',
            'm.ts': "import type { Base } from './base.js';\nexport interface Leaf extends Base { readonly kind: 'leaf'; readonly der: Uint8Array }\n",
        });
        const fp = fingerprint(read, 'm.ts', 'Leaf');
        expect(fp).toEqual({ signature: "interface extends Base { readonly der: Uint8Array; readonly kind: 'leaf' }" });
    });

    it('should read a constant as its declared type, or as its literal, never as its value', () => {
        expect(sig('export const LIMITS: Limits = Object.freeze({ max: 1 });', 'LIMITS')).toBe('const: Limits');
        expect(sig("export const OID = '1.2.3';", 'OID')).toBe("const = '1.2.3'");
        expect(fingerprint(readerOf({ 'm.ts': 'export const X = build();' }), 'm.ts', 'X')).toEqual({ problem: expect.stringContaining('no type annotation') });
    });

    it('should keep the public members of a class and drop the private ones', () => {
        expect(sig('export class E extends Error { readonly code: string; private secret = 1; #hidden = 2; constructor(code: string, message: string) { super(message); this.code = code; } }', 'E'))
            .toBe('class extends Error { new (_: string, _: string) => E; readonly code: string }');
    });

    it('should delegate the three code unions to their registries', () => {
        expect(sig("export type PkiLimitErrorCode = | 'PKI_LIMIT_EXCEEDED' // why\n | 'PKI_LIMIT_INVALID';", 'PkiLimitErrorCode')).toBe('vocabulary errors');
        expect(sig("export type PkiReasonCode = 'PKI_REASON_A' | 'PKI_REASON_B';", 'PkiReasonCode')).toBe('vocabulary reasons');
        expect(sig("export type PkiDiagnosticCode = 'PKI_DIAG_A' | 'PKI_DIAG_B';", 'PkiDiagnosticCode')).toBe('vocabulary diagnostics');
        // A union of unions is an ordinary type: its members are type names.
        expect(sig('export type PkiErrorCode = PkiLimitErrorCode | PkiKeyErrorCode;', 'PkiErrorCode')).toBe('type = PkiKeyErrorCode | PkiLimitErrorCode');
    });

    it('should refuse an inferred return type and a missing declaration rather than guess', () => {
        expect(fingerprint(readerOf({ 'm.ts': 'export function f(a: number) { return a; }' }), 'm.ts', 'f')).toEqual({ problem: expect.stringContaining('no explicit return type') });
        expect(fingerprint(readerOf({ 'm.ts': '' }), 'm.ts', 'g')).toEqual({ problem: 'm.ts declares no g' });
    });
});

describe('classify and diffSurface', () => {
    const fn = (name: string, signature: string): FrozenExport => ({ name, kind: 'function', signature });
    const ty = (name: string, signature: string): FrozenExport => ({ name, kind: 'type', signature });

    it('should call a new optional trailing parameter compatible and a new required one incompatible', () => {
        const before = fn('f', '(_: A) => R');
        expect(classify(before, fn('f', '(_: A, _?: B) => R'), new Set()).verdict).toBe('compatible');
        expect(classify(before, fn('f', '(_: A, ..._: B[]) => R'), new Set()).verdict).toBe('compatible');
        expect(classify(before, fn('f', '(_: A, _: B) => R'), new Set())).toEqual({ verdict: 'incompatible', detail: 'parameter 2 is new and required' });
        expect(classify(before, fn('f', '(_: A) => S'), new Set()).verdict).toBe('incompatible');
    });

    it('should allow a required member only on a type no exported function takes', () => {
        const before = ty('Report', 'interface { readonly ok: boolean }');
        const after = ty('Report', 'interface { readonly ok: boolean; readonly why: string }');
        expect(classify(before, after, new Set()).verdict).toBe('compatible');
        expect(classify(before, after, new Set(['Report'])).verdict).toBe('incompatible');
        expect(classify(before, ty('Report', 'interface { readonly ok: boolean; readonly why?: string }'), new Set(['Report'])).verdict).toBe('compatible');
        expect(classify(before, ty('Report', 'interface { readonly ok: number }'), new Set()).verdict).toBe('incompatible');
    });

    it('should call a widened union compatible and a narrowed one incompatible', () => {
        expect(classify(ty('T', "type = 'a' | 'b'"), ty('T', "type = 'a' | 'b' | 'c'"), new Set()).verdict).toBe('compatible');
        expect(classify(ty('T', "type = 'a'"), ty('T', "type = 'a' | 'b'"), new Set()).verdict).toBe('compatible');
        expect(classify(ty('T', "type = 'a' | 'b'"), ty('T', "type = 'a'"), new Set())).toEqual({ verdict: 'incompatible', detail: "union member(s) removed: 'b'" });
    });

    it('should find the types a caller may construct through parameters, members and aliases', () => {
        const rows = [fn('f', '(_: Input) => Output'), ty('Input', 'interface { readonly nested: Nested }'), ty('Nested', "type = 'a' | Deep"), ty('Output', 'interface { readonly x: Leaf }')];
        expect([...inputTypes(rows)].sort()).toEqual(['Deep', 'Input', 'Nested']);
    });

    it('should report removals and kind changes before additions', () => {
        const changes = diffSurface([fn('a', '() => void'), fn('b', '() => void')], [{ name: 'b', kind: 'constant', signature: 'const: X' }, fn('c', '() => void')]);
        expect(changes.map((c) => `${c.name}:${c.verdict}`)).toEqual(['a:removed', 'b:kind', 'c:added']);
    });
});

describe('build-api-frozen', () => {
    // The committed snapshot is the stable 1.0 promise. The rehearsal cases run
    // on the tree it was rebased from, rebuilt here from it: the same surface,
    // reasons and rebaseline log, in the 0.8.0 rehearsal phase.
    const live = parseApiFrozen(TREE['docs/assets/api.frozen.json'] ?? '') as ApiFrozen;
    const snapshot: ApiFrozen = { ...live, frozenAt: '0.8.0', phase: 'rehearsal', asOf: '0.8.0' };
    const REHEARSAL: Record<string, string> = { ...TREE, 'docs/assets/api.frozen.json': renderApiFrozen(snapshot) };

    it('should be in sync with the committed snapshot, which is the 1.0.0 stable promise', () => {
        expect(live).toMatchObject({ frozenAt: '1.0.0', phase: 'stable', asOf: '1.0.0' });
        expect(planApiFrozen(readerOf(TREE), '1.0.0', { kind: 'default' }).action).toBe('unchanged');
        expect(renderApiFrozen(live)).toBe(TREE['docs/assets/api.frozen.json']);
        expect(planApiFrozen(readerOf(REHEARSAL), '0.8.0', { kind: 'default' }).action).toBe('unchanged');
    });

    const changed = (): Record<string, string> => ({
        ...REHEARSAL,
        'src/asn1/asn1-oid.ts': (REHEARSAL['src/asn1/asn1-oid.ts'] ?? '').replace('export function isValidOid(oid: string): boolean {', 'export function isValidOid(oid: string, strict?: boolean): boolean {'),
    });

    it('should refuse to rewrite a released rehearsal, and rewrite an unreleased one', () => {
        expect(planApiFrozen(readerOf(changed()), '0.8.0', { kind: 'default' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('The rehearsal admits no change') });
        expect(planApiFrozen(readerOf(changed()), '0.7.9', { kind: 'default' }).action).toBe('write');
    });

    it('should move a released rehearsal only on an accepted ADR, and log the move', () => {
        const adr = 'docs/adr/0014-a-rename-set.md';
        const accepted = { ...changed(), [adr]: '---\nstatus: accepted\n---\n# A rename set\n' };
        const proposed = { ...changed(), [adr]: '---\nstatus: proposed\n---\n# A rename set\n' };
        expect(planApiFrozen(readerOf(changed()), '0.8.0', { kind: 'rebaseline', adr })).toMatchObject({ action: 'refuse', message: expect.stringContaining('does not exist or is not "status: accepted"') });
        expect(planApiFrozen(readerOf(proposed), '0.8.0', { kind: 'rebaseline', adr })).toMatchObject({ action: 'refuse' });
        expect(planApiFrozen(readerOf(accepted), '0.8.0', { kind: 'rebaseline', adr: 'docs/0014.md' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('docs/adr/NNNN-slug.md') });
        expect(planApiFrozen(readerOf({ ...REHEARSAL, [adr]: accepted[adr] ?? '' }), '0.8.0', { kind: 'rebaseline', adr })).toMatchObject({ action: 'refuse', message: expect.stringContaining('nothing to rebaseline') });
        const moved = planApiFrozen(readerOf(accepted), '0.8.0', { kind: 'rebaseline', adr });
        expect(moved.action).toBe('write');
        // Appended to the log, never replacing a move already recorded (ADR 0013 was the first).
        const before = parseApiFrozen(REHEARSAL['docs/assets/api.frozen.json'] ?? '')?.rebaselines ?? [];
        expect(parseApiFrozen(moved.text ?? '')?.rebaselines).toEqual([...before, { adr, asOf: '0.8.0' }]);
    });

    it('should refuse --rebaseline once the surface is stable', () => {
        const stable = { ...REHEARSAL, 'docs/assets/api.frozen.json': (REHEARSAL['docs/assets/api.frozen.json'] ?? '').replace('"phase": "rehearsal"', '"phase": "stable"') };
        expect(planApiFrozen(readerOf(stable), '0.8.0', { kind: 'rebaseline', adr: 'docs/adr/0001-no-secret-dependent-cryptography.md' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('rehearsal phase only') });
    });

    it('should refuse --ratchet during the rehearsal', () => {
        expect(planApiFrozen(readerOf(REHEARSAL), '0.9.0', { kind: 'ratchet' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('stable phase only') });
    });

    it('should rebase at 1.0.0 only when the rehearsal held, and only on the 1.0.0 release commit', () => {
        const rebased = planApiFrozen(readerOf(REHEARSAL), '1.0.0', { kind: 'major', version: '1.0.0' });
        expect(rebased.action).toBe('write');
        expect(parseApiFrozen(rebased.text ?? '')).toMatchObject({ frozenAt: '1.0.0', phase: 'stable', asOf: '1.0.0' });
        expect(planApiFrozen(readerOf(changed()), '1.0.0', { kind: 'major', version: '1.0.0' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('the rehearsal did not hold') });
        expect(planApiFrozen(readerOf(REHEARSAL), '0.9.0', { kind: 'major', version: '1.0.0' })).toMatchObject({ action: 'refuse' });
        expect(planApiFrozen(readerOf(REHEARSAL), '0.9.0', { kind: 'major', version: '0.9.0' })).toMatchObject({ action: 'refuse' });
    });

    it('should ratchet a stable snapshot over compatible changes and refuse over a removal', () => {
        const stable = planApiFrozen(readerOf(REHEARSAL), '1.0.0', { kind: 'major', version: '1.0.0' }).text ?? '';
        const files: Record<string, string> = { ...changed(), 'docs/assets/api.frozen.json': stable };
        const ratcheted = planApiFrozen(readerOf(files), '1.1.0', { kind: 'ratchet' });
        expect(ratcheted.action).toBe('write');
        expect(parseApiFrozen(ratcheted.text ?? '')?.asOf).toBe('1.1.0');
        const removed = { ...files, 'docs/assets/api.json': (files['docs/assets/api.json'] ?? '').replace(/\{\s*"name": "ANY_EXTENDED_KEY_USAGE",[\s\S]*?"members": null\s*\},/, '') };
        expect(planApiFrozen(readerOf(removed), '1.1.0', { kind: 'ratchet' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('ANY_EXTENDED_KEY_USAGE') });
        expect(planApiFrozen(readerOf(files), '1.1.0', { kind: 'default' })).toMatchObject({ action: 'refuse', message: expect.stringContaining('--ratchet') });
    });

    it('should choose the release mode from the version a bump goes to', () => {
        const rehearsal = snapshot as ApiFrozen;
        const stable: ApiFrozen = { ...rehearsal, frozenAt: '1.0.0', phase: 'stable', asOf: '1.0.0' };
        expect(releaseModeFor('0.9.0', rehearsal)).toBeNull();
        expect(releaseModeFor('1.0.0', rehearsal)).toEqual({ kind: 'major', version: '1.0.0' });
        expect(releaseModeFor('1.2.0', stable)).toEqual({ kind: 'ratchet' });
        expect(releaseModeFor('2.0.0', stable)).toEqual({ kind: 'major', version: '2.0.0' });
        expect(releaseModeFor('1.0.0', null)).toBeNull();
    });
});
