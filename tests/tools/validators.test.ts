import { describe, it, expect } from 'vitest';
import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
    FIELDS,
    SCHEMA,
    VALIDATORS,
    checkFieldMask,
    compareRecord,
    negativeCanaries,
    parseStream,
    writeBlob,
    type CertRecord,
} from '../../scripts/lib/validators.ts';

// The contract of conformance level L4. Every guard is proved to fire here:
// a cross-implementation check that cannot detect a validator which stopped
// halfway, rejects everything or accepts everything is worse than none,
// because it reports agreement it never established.

const header = (over: Record<string, unknown> = {}): string =>
    JSON.stringify({ t: 'header', schema: SCHEMA, tool: 'probe', version: '1', fields: ['subjectFp256'], ...over });
const cert = (i: number, over: Record<string, unknown> = {}): string =>
    JSON.stringify({ t: 'cert', i, ok: true, subjectFp256: 'a'.repeat(64), ...over });
const footer = (count: number): string => JSON.stringify({ t: 'footer', count });
const stream = (...lines: string[]): string => `${lines.join('\n')}\n`;

describe('the blob transport', () => {
    it('should frame every certificate by length, so a DER octet can never be a delimiter', () => {
        const path = join(tmpdir(), `pkinative-blob-${String(process.pid)}.bin`);
        const certs = [Uint8Array.of(0x30, 0x00), new Uint8Array(0), Uint8Array.of(0xff, 0xff, 0xff)];
        writeBlob(path, certs);
        const blob = readFileSync(path);
        rmSync(path, { force: true });
        expect(blob.subarray(0, 8).toString('ascii')).toBe('PKIBLOB1');
        expect(blob.readUInt32BE(8)).toBe(3);
        let at = 12;
        for (const expected of certs) {
            expect(blob.readUInt32BE(at)).toBe(expected.length);
            expect(new Uint8Array(blob.subarray(at + 4, at + 4 + expected.length))).toEqual(expected);
            at += 4 + expected.length;
        }
        expect(at).toBe(blob.length);
    });
});

describe('parseStream', () => {
    it('should accept a well-formed stream', () => {
        const parsed = parseStream(stream(header(), cert(0), cert(1), footer(2)), 2);
        expect('errors' in parsed).toBe(false);
        if ('errors' in parsed) return;
        expect(parsed.certs.map((c) => c.i)).toEqual([0, 1]);
        expect(parsed.header.fields).toEqual(['subjectFp256']);
    });

    it.each([
        ['no header', stream(cert(0), footer(1)), 1, 'does not open with a header'],
        ['another schema', stream(header({ schema: 99 }), cert(0), footer(1)), 1, 'speaks'],
        ['an unknown field', stream(header({ fields: ['whatItFeelsLike'] }), cert(0), footer(1)), 1, 'unknown field'],
        ['an empty field mask', stream(header({ fields: [] }), cert(0), footer(1)), 1, 'non-empty `fields`'],
        // The failure the footer exists for: a validator that stopped halfway
        // and exited 0 is otherwise indistinguishable from a complete one.
        ['no footer', stream(header(), cert(0), cert(1)), 2, 'does not end with a footer'],
        ['a footer that miscounts', stream(header(), cert(0), footer(9)), 1, 'the footer counts 9'],
        ['fewer records than submitted', stream(header(), cert(0), footer(1)), 2, 'the footer counts 1'],
        ['a gap in the indices', stream(header(), cert(0), cert(7), footer(2)), 2, 'with no gap'],
        ['a line that is not JSON', stream(header(), 'nonsense', footer(1)), 1, 'is not JSON'],
        ['a record with no ok', stream(header(), JSON.stringify({ t: 'cert', i: 0 }), footer(1)), 1, 'no boolean'],
    ])('should refuse a stream with %s', (_what, text, expected, message) => {
        const parsed = parseStream(text, expected);
        expect('errors' in parsed, _what).toBe(true);
        if (!('errors' in parsed)) return;
        expect(parsed.errors.join('\n')).toContain(message);
    });
});

describe('compareRecord', () => {
    const expected = { subjectFp256: 'a'.repeat(64), version: 3, keyAlgOid: '1.2.840.10045.2.1' };

    it('should report nothing when every declared field agrees', () => {
        expect(compareRecord(expected, JSON.parse(cert(0)) as CertRecord, ['subjectFp256'])).toEqual([]);
    });

    it('should report a field that differs', () => {
        const record = JSON.parse(cert(0, { subjectFp256: 'b'.repeat(64) })) as CertRecord;
        expect(compareRecord(expected, record, ['subjectFp256']).join('')).toContain('subjectFp256:');
    });

    it('should refuse a field the header declared and the record omits', () => {
        const record = JSON.parse(JSON.stringify({ t: 'cert', i: 0, ok: true })) as CertRecord;
        expect(compareRecord(expected, record, ['subjectFp256']).join('')).toContain('absent, though the header declares it');
    });

    it('should ignore a declared field pkinative has no opinion about', () => {
        expect(compareRecord({ version: 3 }, JSON.parse(cert(0)) as CertRecord, ['subjectFp256'])).toEqual([]);
    });

    it('should compare a number and its text form as equal, since JSON is the only wire', () => {
        const record = JSON.parse(cert(0, { version: '3' })) as CertRecord;
        expect(compareRecord(expected, record, ['version'])).toEqual([]);
    });
});

describe('the negative canaries', () => {
    const real = new Uint8Array(readFileSync(join(process.cwd(), 'tests/fixtures/certs/isrg-root-x1.der')));

    it('should be structurally broken, not merely profile-invalid', () => {
        // A certificate one implementation refuses and another reads is a
        // difference of policy and belongs in the disagreement file. These
        // are bytes no implementation can read, so accepting one is proof
        // the validator is not reading at all.
        const canaries = negativeCanaries(real);
        expect(canaries.length).toBeGreaterThanOrEqual(3);
        for (const canary of canaries) {
            expect(canary.why, 'every canary says what it is').not.toBe('');
            expect(canary.bytes.length).toBeLessThan(real.length);
        }
        expect(canaries.some((c) => c.bytes.length === 0)).toBe(true);
    });

    it('should be derived from the input, never committed', () => {
        const other = negativeCanaries(real.subarray(0, real.length - 2));
        expect(other[0]?.bytes.length).not.toBe(negativeCanaries(real)[0]?.bytes.length);
    });
});

describe('the validator registry', () => {
    it('should give every validator a distinct id and a real platform list', () => {
        expect(new Set(VALIDATORS.map((v) => v.id)).size).toBe(VALIDATORS.length);
        for (const spec of VALIDATORS) {
            expect(spec.platforms.length, spec.id).toBeGreaterThan(0);
            for (const platform of spec.platforms) expect(['win32', 'linux', 'darwin'], spec.id).toContain(platform);
            expect(spec.lineage, `${spec.id} must name the implementation family it speaks for`).not.toBe('');
        }
    });

    it('should describe every field it can compare', () => {
        for (const [name, description] of Object.entries(FIELDS)) {
            expect(description, name).toMatch(/[a-z]/);
        }
    });

    it('should pin the mask of every validator, by count and by name', () => {
        const pinned = Object.fromEntries(VALIDATORS.map((v) => [v.id, v.fields.length]));
        expect(pinned).toEqual({ 'windows-cryptoapi': 5, 'go-x509': 6, 'python-cryptography': 5 });
        for (const spec of VALIDATORS) {
            expect(new Set(spec.fields).size, spec.id).toBe(spec.fields.length);
            for (const field of spec.fields) expect(Object.keys(FIELDS), spec.id).toContain(field);
        }
        expect(VALIDATORS.find((v) => v.id === 'windows-cryptoapi')?.fields).not.toContain('tbsFp256');
        expect(VALIDATORS.find((v) => v.id === 'python-cryptography')?.fields).not.toContain('spkiKeyFp256');
    });

    it('should pin exactly the mask each validator program declares in its header', () => {
        // The emitters are read as text: the pin and the program must move together.
        const root = join(process.cwd(), 'scripts', 'validators');
        const sources: Record<string, string> = {
            'windows-cryptoapi': readFileSync(join(root, 'windows-cryptoapi.ps1'), 'utf8'),
            'go-x509': readFileSync(join(root, 'go-x509', 'main.go'), 'utf8'),
            'python-cryptography': readFileSync(join(root, 'python-cryptography.py'), 'utf8'),
        };
        for (const spec of VALIDATORS) {
            const source = sources[spec.id];
            expect(source, `${spec.id} has no emitter source in this test`).toBeDefined();
            const header = /fields['"]?\s*[:=]?\s*(?:@\(|\[\]string\{|\[)([^)}\]]*)/.exec(source ?? '')?.[1] ?? '';
            const declared = [...header.matchAll(/['"](\w+)['"]/g)].map((m) => m[1]);
            expect(new Set(declared), spec.id).toEqual(new Set(spec.fields));
        }
    });

    it('should fail a validator whose declared mask drifts from its pin, in either direction', () => {
        const spec = { id: 'probe', fields: ['subjectFp256', 'tbsFp256'] };
        expect(checkFieldMask(spec, ['tbsFp256', 'subjectFp256'])).toEqual([]);
        const dropped = checkFieldMask(spec, ['subjectFp256']);
        expect(dropped).toHaveLength(1);
        expect(dropped[0]).toMatch(/no longer declares tbsFp256/);
        const added = checkFieldMask(spec, ['subjectFp256', 'tbsFp256', 'version']);
        expect(added).toHaveLength(1);
        expect(added[0]).toMatch(/declares version, which its registry entry does not pin/);
    });
});
