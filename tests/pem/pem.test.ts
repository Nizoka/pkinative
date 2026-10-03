import { describe, it, expect } from 'vitest';
import { decodePem, encodePem } from '../../src/pem/pem.js';
import type { DecodePemOptions } from '../../src/types/pem-types.js';
import { PkiEncodingError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
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

    it('should refuse an END line with whitespace around it in strict mode and accept it in lax mode', () => {
        const spaced = PEM.replace('-----END CERTIFICATE-----', '-----END CERTIFICATE----- ');
        expect(failure(() => decodePem(spaced)).code).toBe('PKI_PEM_UNTERMINATED');
        expect(decodePem(spaced, { mode: 'lax', onDiagnostic: () => undefined })).toHaveLength(1);
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

    it('should report, not refuse, a lax deviation under strict: true — the caller chose lax, and the acceptance is info', () => {
        const seen: string[] = [];
        expect(decodePem(PEM.replace(/^([A-Za-z0-9+/]{10})/m, '$1 '), { mode: 'lax', strict: true, onDiagnostic: (d) => { seen.push(d.code); } })).toHaveLength(1);
        expect(seen).toEqual(['PKI_DIAG_PEM_LAX_ACCEPTED']);
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

// ── Exact boundaries (mutation pins) ──
// Each vector sits at a boundary of the RFC 7468 grammar, or one past it, and
// asserts the bytes, the refusal code with its offset, or the exact
// diagnostics a lax decode emits.

/** The base64 body lines of `encodePem('X', bytes)`. */
function bodyLines(length: number): string[] {
    return encodePem('X', Uint8Array.from({ length }, (_, i) => (i * 7) & 0xff)).split('\n').slice(1, -2);
}

function laxBlock(body: string): string {
    return `-----BEGIN X-----\n${body}\n-----END X-----\n`;
}

function encodingFailure(fn: () => unknown): PkiEncodingError {
    const err = failure(fn);
    expect(err).toBeInstanceOf(PkiEncodingError);
    return err as PkiEncodingError;
}

describe('decodePem — line splitting', () => {
    it('should read a final END line that has no line terminator (RFC 7468 §3: eol is optional after the last boundary)', () => {
        const [block] = decodePem('-----BEGIN X-----\nZm9v\n-----END X-----');
        expect([...(block?.bytes ?? [])]).toEqual([0x66, 0x6f, 0x6f]);
    });
});

describe('decodePem — maxPemBlocks at and past the limit', () => {
    it('should accept exactly maxPemBlocks blocks', () => {
        expect(decodePem(PEM, { limits: { maxPemBlocks: 1 } })).toHaveLength(1);
        expect(decodePem(PEM + PEM, { limits: { maxPemBlocks: 2 } })).toHaveLength(2);
    });

    it('should refuse the block one past maxPemBlocks, naming the limit and the count', () => {
        const err = failure(() => decodePem(PEM + PEM, { limits: { maxPemBlocks: 1 } }));
        expect(err).toBeInstanceOf(PkiLimitError);
        expect(err).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxPemBlocks', configured: 1, observed: 2 });
    });
});

describe('decodePem — strict refusals carry the offending line offset', () => {
    it('should place PKI_PEM_HEADERS_FORBIDDEN on the first header line', () => {
        const err = encodingFailure(() => decodePem('-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\n\nZm9v\n-----END X-----\n'));
        expect(err.code).toBe('PKI_PEM_HEADERS_FORBIDDEN');
        expect(err.offset).toBe(18);
    });

    it('should refuse a body made of one header line as PKI_PEM_HEADERS_FORBIDDEN, not as base64', () => {
        const err = encodingFailure(() => decodePem('-----BEGIN X-----\nProc-Type: 4\n-----END X-----\n'));
        expect(err.code).toBe('PKI_PEM_HEADERS_FORBIDDEN');
        expect(err.offset).toBe(18);
    });

    it('should place a 64-character line holding a space on that line, not on the block', () => {
        const err = encodingFailure(() => decodePem(PEM.replace(/^([A-Za-z0-9+/]{10})[A-Za-z0-9+/]/m, '$1 ')));
        expect(err.code).toBe('PKI_PEM_BASE64_INVALID');
        expect(err.offset).toBe(28);
    });

    it('should place a short line before the last on that line', () => {
        const err = encodingFailure(() => decodePem(PEM.replace(/^(.{63}).\n/m, '$1\n')));
        expect(err.code).toBe('PKI_PEM_BASE64_INVALID');
        expect(err.offset).toBe(28);
    });

    it('should accept a last line of exactly 64 characters and refuse one of 65 on that line', () => {
        const [first, second] = bodyLines(96);
        expect(decodePem(laxBlock(`${first}\n${second}`))[0]?.bytes.length).toBe(96);
        const err = encodingFailure(() => decodePem(laxBlock(`${first}${(second ?? '').slice(0, 1)}`)));
        expect(err.code).toBe('PKI_PEM_BASE64_INVALID');
        expect(err.offset).toBe(18);
    });
});

describe('decodePem — lax headers (RFC 1421 §4.2)', () => {
    it('should read a header value that follows the colon without a space', () => {
        const [block] = decodePem('-----BEGIN X-----\nProc-Type:4,ENCRYPTED\n\nZm9v\n-----END X-----\n', LAX);
        expect(block?.headers).toEqual([['Proc-Type', '4,ENCRYPTED']]);
    });

    it('should end the headers at a whitespace-only line, as at an empty one', () => {
        const [block] = decodePem('-----BEGIN X-----\nProc-Type: 4\n \t\nZm9v\n-----END X-----\n', LAX);
        expect(block?.headers).toEqual([['Proc-Type', '4']]);
        expect([...(block?.bytes ?? [])]).toEqual([0x66, 0x6f, 0x6f]);
    });
});

describe('decodePem — lax diagnostics, exactly', () => {
    const lengthDeviation = [expect.objectContaining({ code: 'PKI_DIAG_PEM_LAX_ACCEPTED', message: expect.stringContaining('not 64 characters') })];

    it('should report nothing for strict text decoded in lax mode', () => {
        expect(laxDiagnostics(PEM)).toEqual([]);
    });

    it('should report nothing for a last line of exactly 64 characters', () => {
        const [first, second] = bodyLines(96);
        expect(laxDiagnostics(laxBlock(`${first}\n${second}`))).toEqual([]);
    });

    it('should report a last line longer than 64 characters once', () => {
        const [first, second, third] = bodyLines(99);
        expect(laxDiagnostics(laxBlock(`${first}\n${second}${third}`))).toEqual(lengthDeviation);
    });

    it('should report a 65-character last line before refusing its base64 length', () => {
        const [first, second] = bodyLines(99);
        const seen: PkiDiagnostic[] = [];
        const err = encodingFailure(() => decodePem(laxBlock(`${first}${(second ?? '').slice(0, 1)}`), { mode: 'lax', onDiagnostic: (d) => seen.push(d) }));
        expect(err.code).toBe('PKI_PEM_BASE64_INVALID');
        expect(seen).toEqual(lengthDeviation);
    });

    it('should report a one-character first line', () => {
        expect(laxDiagnostics(laxBlock('Z\nm9v'))).toEqual(lengthDeviation);
        expect([...(decodePem(laxBlock('Z\nm9v'), LAX)[0]?.bytes ?? [])]).toEqual([0x66, 0x6f, 0x6f]);
    });

    it('should report an empty line in the body when every other length is canonical', () => {
        expect(laxDiagnostics(laxBlock('Zm9v\n'))).toEqual(lengthDeviation);
    });

    it('should report each kind of deviation once, at its first offset', () => {
        const padded = `  ${PEM.replace('CERTIFICATE-----\n', 'CERTIFICATE-----  \n').replace('-----END', '\t-----END')}`;
        expect(laxDiagnostics(padded)).toEqual([expect.objectContaining({ code: 'PKI_DIAG_PEM_LAX_ACCEPTED', offset: 0, message: expect.stringContaining('boundary line') })]);
    });
});
