import { describe, it, expect } from 'vitest';
import { decodePem, encodePem } from '../../src/pem/pem.js';
import type { DecodePemOptions } from '../../src/types/pem-types.js';
import { PkiError } from '../../src/types/pki-errors.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';

const PAYLOAD = Uint8Array.from({ length: 200 }, (_, i) => i);
const PEM = encodePem('CERTIFICATE', PAYLOAD);
const LAX: DecodePemOptions = { mode: 'lax', onDiagnostic: () => undefined };

function failure(fn: () => unknown): PkiError {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiError) return err;
        throw err;
    }
    throw new Error('expected a PkiError');
}

function laxDiagnostics(text: string): PkiDiagnostic[] {
    const seen: PkiDiagnostic[] = [];
    decodePem(text, { mode: 'lax', onDiagnostic: (d) => seen.push(d) });
    return seen;
}

describe('encodePem', () => {
    it('should write the strict RFC 7468 form with LF line endings', () => {
        expect(encodePem('TEST', Uint8Array.of(0x66, 0x6f, 0x6f))).toBe('-----BEGIN TEST-----\nZm9v\n-----END TEST-----\n');
        const lines = PEM.split('\n');
        expect(lines[0]).toBe('-----BEGIN CERTIFICATE-----');
        expect(lines.slice(1, -3).every((l) => l.length === 64)).toBe(true);
        expect(PEM.endsWith('-----END CERTIFICATE-----\n')).toBe(true);
    });

    it('should encode an empty payload as a block without body lines', () => {
        expect(encodePem('EMPTY', new Uint8Array(0))).toBe('-----BEGIN EMPTY-----\n-----END EMPTY-----\n');
    });

    it.each([' CERT', 'CERT ', 'A  B', 'A--B', '-A', 'A-', 'É', 5])('should refuse the label %j', (label) => {
        expect(failure(() => encodePem(label as string, PAYLOAD)).code).toBe('PKI_PEM_LABEL_INVALID');
    });

    it('should refuse a payload that is not bytes', () => {
        expect(failure(() => encodePem('CERTIFICATE', 'abc' as unknown as Uint8Array)).code).toBe('PKI_INVALID_INPUT');
    });
});

describe('decodePem — strict', () => {
    it('should decode what encodePem writes', () => {
        const [block] = decodePem(PEM);
        expect(block?.label).toBe('CERTIFICATE');
        expect([...(block?.bytes ?? [])]).toEqual([...PAYLOAD]);
        expect(block?.headers).toEqual([]);
        expect(block?.offset).toBe(0);
        expect(Object.isFrozen(block)).toBe(true);
    });

    it('should accept CRLF and CR line endings', () => {
        expect(decodePem(PEM.replace(/\n/g, '\r\n'))[0]?.bytes.length).toBe(200);
        expect(decodePem(PEM.replace(/\n/g, '\r'))[0]?.bytes.length).toBe(200);
    });

    it('should ignore explanatory text, and report every block with its offset', () => {
        const text = `Subject: CN=Example\n${PEM}between blocks\n${encodePem('X.509 CERTIFICATE', Uint8Array.of(1))}trailer`;
        const blocks = decodePem(text);
        expect(blocks.map((b) => b.label)).toEqual(['CERTIFICATE', 'X.509 CERTIFICATE']);
        expect(blocks[0]?.offset).toBe(20);
        expect(text.slice(blocks[1]?.offset, (blocks[1]?.offset ?? 0) + 10)).toBe('-----BEGIN');
    });

    it('should accept an empty label and an empty body', () => {
        expect(decodePem('-----BEGIN -----\n-----END -----\n')[0]).toMatchObject({ label: '' });
        expect(decodePem('-----BEGIN -----\n-----END -----\n')[0]?.bytes.length).toBe(0);
    });

    it.each([
        ['a line of 65 characters', PEM.replace(/^(.{64})\n(.)/m, '$1$2\n'), 'PKI_PEM_BASE64_INVALID'],
        ['a short line before the last', PEM.replace(/^(.{63}).\n/m, '$1\n'), 'PKI_PEM_BASE64_INVALID'],
        ['a space inside a line', PEM.replace(/^([A-Za-z0-9+/]{10})[A-Za-z0-9+/]/m, '$1 '), 'PKI_PEM_BASE64_INVALID'],
        ['a blank line in the body', PEM.replace('-----\n', '-----\n\n'), 'PKI_PEM_BASE64_INVALID'],
        ['trailing whitespace on the BEGIN line', PEM.replace('CERTIFICATE-----\n', 'CERTIFICATE----- \n'), 'PKI_PEM_NO_BLOCK'],
        ['non-canonical padding bits', '-----BEGIN X-----\nZh==\n-----END X-----\n', 'PKI_PEM_BASE64_INVALID'],
        ['RFC 1421 headers', '-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\n\nZm9v\n-----END X-----\n', 'PKI_PEM_HEADERS_FORBIDDEN'],
    ])('should refuse %s', (_label, text, code) => {
        expect(failure(() => decodePem(text)).code).toBe(code);
    });
});

describe('decodePem — boundaries and labels', () => {
    it.each([
        ['an empty text', ''],
        ['text without a block', 'hello\nworld'],
        ['an END line alone', '-----END CERTIFICATE-----\n'],
    ])('should refuse %s with PKI_PEM_NO_BLOCK', (_label, text) => {
        expect(failure(() => decodePem(text)).code).toBe('PKI_PEM_NO_BLOCK');
    });

    it('should refuse a missing END line, and a BEGIN line inside a block', () => {
        expect(failure(() => decodePem(PEM.replace('-----END CERTIFICATE-----\n', ''))).code).toBe('PKI_PEM_UNTERMINATED');
        const nested = PEM.replace('-----END CERTIFICATE-----\n', '') + PEM;
        expect(failure(() => decodePem(nested)).code).toBe('PKI_PEM_UNTERMINATED');
    });

    it('should refuse an END label that differs, and a label outside the grammar', () => {
        expect(failure(() => decodePem(PEM.replace('END CERTIFICATE', 'END PRIVATE KEY'))).code).toBe('PKI_PEM_LABEL_MISMATCH');
        expect(failure(() => decodePem('-----BEGIN A  B-----\n-----END A  B-----\n')).code).toBe('PKI_PEM_LABEL_INVALID');
    });

    it('should enforce the label option, and refuse an invalid one', () => {
        expect(decodePem(PEM, { label: 'CERTIFICATE' })).toHaveLength(1);
        const key = encodePem('PRIVATE KEY', Uint8Array.of(1));
        expect(failure(() => decodePem(`${PEM}${key}`, { label: 'CERTIFICATE' })).code).toBe('PKI_PEM_UNEXPECTED_LABEL');
        expect(failure(() => decodePem(PEM, { label: ' BAD' })).code).toBe('PKI_INVALID_OPTION');
    });
});

describe('decodePem — lax', () => {
    it('should accept whitespace inside the base64 text with one diagnostic', () => {
        const spaced = PEM.replace(/^([A-Za-z0-9+/]{10})/m, '$1 \t');
        expect(failure(() => decodePem(spaced)).code).toBe('PKI_PEM_BASE64_INVALID');
        expect(decodePem(spaced, LAX)[0]?.bytes.length).toBe(200);
        expect(laxDiagnostics(spaced)).toEqual([expect.objectContaining({ code: 'PKI_DIAG_PEM_LAX_ACCEPTED', message: expect.stringContaining('whitespace inside') })]);
    });

    it('should accept lines of any length and blank lines with one diagnostic', () => {
        const oneLine = `-----BEGIN X-----\n${PEM.split('\n').slice(1, -2).join('')}\n\n-----END X-----\n`;
        expect(decodePem(oneLine, LAX)[0]?.bytes.length).toBe(200);
        expect(laxDiagnostics(oneLine)[0]?.message).toContain('not 64 characters');
    });

    it('should accept whitespace around the boundary lines', () => {
        const padded = `  ${PEM.replace('CERTIFICATE-----\n', 'CERTIFICATE-----  \n').replace('-----END', '\t-----END')}`;
        expect(decodePem(padded, LAX)[0]?.label).toBe('CERTIFICATE');
        expect(laxDiagnostics(padded)[0]?.message).toContain('boundary line');
    });

    it('should read RFC 1421 headers, continuation lines included', () => {
        const legacy = '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,\n 00112233\n\nZm9v\n-----END RSA PRIVATE KEY-----\n';
        const [block] = decodePem(legacy, LAX);
        expect(block?.headers).toEqual([['Proc-Type', '4,ENCRYPTED'], ['DEK-Info', 'AES-128-CBC, 00112233']]);
        expect([...(block?.bytes ?? [])]).toEqual([0x66, 0x6f, 0x6f]);
        expect(laxDiagnostics(legacy)[0]?.message).toContain('RFC 1421 headers');
    });

    it('should still refuse headers without a blank line, a stray body line in the headers, and non-base64 characters', () => {
        expect(failure(() => decodePem('-----BEGIN X-----\nProc-Type: 4\nZm9v\n-----END X-----\n', LAX)).code).toBe('PKI_PEM_BASE64_INVALID');
        expect(failure(() => decodePem('-----BEGIN X-----\nProc-Type: 4\n-----END X-----\n', LAX)).code).toBe('PKI_PEM_BASE64_INVALID');
        expect(failure(() => decodePem('-----BEGIN X-----\nZm9*\n-----END X-----\n', LAX)).code).toBe('PKI_PEM_BASE64_INVALID');
    });

    it('should escalate a lax deviation under strict: true', () => {
        expect(failure(() => decodePem(PEM.replace(/^([A-Za-z0-9+/]{10})/m, '$1 '), { mode: 'lax', strict: true })).code).toBe('PKI_STRICT_DIAGNOSTIC');
    });
});

describe('decodePem — arguments and limits', () => {
    it.each([
        ['a non-string text', () => decodePem(new Uint8Array(1) as unknown as string), 'PKI_INVALID_INPUT'],
        ['null text', () => decodePem(null as unknown as string), 'PKI_INVALID_INPUT'],
        ['non-object options', () => decodePem(PEM, 'lax' as unknown as DecodePemOptions), 'PKI_INVALID_OPTION'],
        ['an unknown mode', () => decodePem(PEM, { mode: 'loose' as 'lax' }), 'PKI_INVALID_OPTION'],
        ['a non-boolean strict', () => decodePem(PEM, { strict: 'yes' as unknown as boolean }), 'PKI_INVALID_OPTION'],
        ['a non-function onDiagnostic', () => decodePem(PEM, { onDiagnostic: 1 as unknown as () => void }), 'PKI_INVALID_OPTION'],
        ['a text over maxInputBytes', () => decodePem(PEM, { limits: { maxInputBytes: 10 } }), 'PKI_LIMIT_EXCEEDED'],
        ['more blocks than maxPemBlocks', () => decodePem(PEM + PEM, { limits: { maxPemBlocks: 1 } }), 'PKI_LIMIT_EXCEEDED'],
    ])('should refuse %s', (_label, fn, code) => {
        expect(failure(fn).code).toBe(code);
    });
});
