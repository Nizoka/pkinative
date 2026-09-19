/**
 * pkinative — PEM (RFC 7468)
 * ==========================
 * Textual encoding of PKIX structures: decoding in strict or lax mode, and
 * strict encoding.
 *
 * PEM is an envelope, not a decoder of its content: this module never
 * imports the ASN.1 layer, and hands back the payload bytes for the caller to
 * decode. Text outside the blocks is ignored in both modes, as RFC 7468 §2
 * requires of parsers ("explanatory text" before a certificate is common).
 *
 * Strict mode follows the `stricttextualmsg` grammar: exact boundary lines,
 * base64 lines of exactly 64 characters but the last, no headers, canonical
 * base64. Lax mode follows `laxtextualmsg`: whitespace anywhere in the base64
 * text and around the boundaries, lines of any length, and RFC 1421 headers,
 * each deviation reported once. Both modes refuse a label outside the grammar,
 * an END label that differs from its BEGIN label, a block without an END line,
 * and non-canonical base64 — the ambiguities that let two tools read one file
 * differently.
 *
 * @module pem/pem
 */

import { decodeBase64, encodeBase64 } from '../core/base64.js';
import { assertBytes } from '../core/bytes.js';
import { createDiagnosticEmitter, pemLaxAcceptedDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit, resolveLimits } from '../core/pki-limits.js';
import type { DecodePemOptions, PemBlock } from '../types/pem-types.js';
import { PkiEncodingError, PkiError } from '../types/pki-errors.js';
import type { PkiDiagnosticEmitter } from '../types/pki-types.js';

/** RFC 7468 §3: printable ASCII other than hyphen, joined by single hyphens or spaces. */
const LABEL = /^(?:[\x21-\x2c\x2e-\x7e](?:[- ]?[\x21-\x2c\x2e-\x7e])*)?$/;
const BEGIN = /^-----BEGIN (.*)-----$/;
const END = /^-----END (.*)-----$/;
const BASE64_LINE = /^[A-Za-z0-9+/=]+$/;
/** RFC 1421 §4.2 header field: a name, a colon, a value. Base64 never contains a colon. */
const HEADER = /^([\x21-\x39\x3b-\x7e]+):[ \t]*(.*)$/;
const LAX_WHITESPACE = /[ \t\v\f\r\n]/g;
const TRAILING_WHITESPACE = /[ \t\v\f]+$/;
const LEADING_WHITESPACE = /^[ \t\v\f]+/;

interface Line {
    readonly text: string;
    readonly start: number;
}

function splitLines(text: string): Line[] {
    const lines: Line[] = [];
    let start = 0;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if (c !== 0x0a && c !== 0x0d) continue;
        lines.push({ text: text.slice(start, i), start });
        if (c === 0x0d && text.charCodeAt(i + 1) === 0x0a) i++;
        start = i + 1;
    }
    if (start < text.length) lines.push({ text: text.slice(start), start });
    return lines;
}

function isValidLabel(label: string): boolean {
    return LABEL.test(label);
}

interface Deviation {
    readonly emitter: PkiDiagnosticEmitter;
    readonly reported: Set<string>;
}

function deviate(state: Deviation, what: string, offset: number): void {
    if (state.reported.has(what)) return;
    state.reported.add(what);
    state.emitter.emit(pemLaxAcceptedDiagnostic(what, offset));
}

/**
 * Decode every PEM block of a text.
 *
 * @param text    The PEM text (explanatory text around the blocks is ignored).
 * @param options Mode (strict by default), a required label, limits and diagnostics.
 * @returns The blocks in text order, with their labels, payloads, headers and offsets.
 * @throws {PkiEncodingError} `PKI_PEM_NO_BLOCK`, `PKI_PEM_LABEL_INVALID`, `PKI_PEM_LABEL_MISMATCH`, `PKI_PEM_UNEXPECTED_LABEL`, `PKI_PEM_UNTERMINATED`, `PKI_PEM_BASE64_INVALID` or `PKI_PEM_HEADERS_FORBIDDEN`.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` beyond `maxInputBytes` (characters) or `maxPemBlocks`.
 * @throws {PkiError} `PKI_INVALID_INPUT` for a non-string text; `PKI_INVALID_OPTION` for a malformed option.
 */
export function decodePem(text: string, options?: DecodePemOptions): readonly PemBlock[] {
    if (typeof text !== 'string') {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: decodePem expects PEM text as a string, got ${text === null ? 'null' : typeof text} — for DER bytes, call the DER function directly`);
    }
    if (options !== undefined && (typeof options !== 'object' || options === null)) {
        throw new PkiError('PKI_INVALID_OPTION', 'pkinative: options must be an object — pass { mode, label, limits, strict, onDiagnostic } or omit it');
    }
    const mode = options?.mode ?? 'strict';
    if (mode !== 'strict' && mode !== 'lax') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: mode must be 'strict' or 'lax', got ${String(mode)}`);
    }
    const wanted = options?.label;
    if (wanted !== undefined && (typeof wanted !== 'string' || !isValidLabel(wanted))) {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: label must be an RFC 7468 label such as 'CERTIFICATE', got ${JSON.stringify(wanted)}`);
    }
    if (options?.strict !== undefined && typeof options.strict !== 'boolean') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: strict must be a boolean, got ${typeof options.strict}`);
    }
    if (options?.onDiagnostic !== undefined && typeof options.onDiagnostic !== 'function') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: onDiagnostic must be a function, got ${typeof options.onDiagnostic}`);
    }
    const limits = resolveLimits(options?.limits);
    enforceLimit(limits, 'maxInputBytes', text.length, 'the PEM text length');
    const state: Deviation = { emitter: createDiagnosticEmitter(options?.strict, options?.onDiagnostic), reported: new Set() };
    const lax = mode === 'lax';

    const boundary = (line: Line): string => {
        if (!lax) return line.text;
        const trimmed = line.text.replace(LEADING_WHITESPACE, '').replace(TRAILING_WHITESPACE, '');
        if (trimmed !== line.text && (BEGIN.test(trimmed) || END.test(trimmed))) deviate(state, 'whitespace around a boundary line', line.start);
        return trimmed;
    };

    const lines = splitLines(text);
    const blocks: PemBlock[] = [];
    for (let i = 0; i < lines.length; i++) {
        const beginLine = lines[i] as Line;
        const begin = BEGIN.exec(boundary(beginLine));
        if (begin === null) continue;
        const label = begin[1] ?? '';
        if (!isValidLabel(label)) {
            throw new PkiEncodingError('PKI_PEM_LABEL_INVALID',
                `pkinative: the BEGIN label ${JSON.stringify(label)} at offset ${beginLine.start} is outside the RFC 7468 label grammar — printable ASCII joined by single spaces or hyphens`, beginLine.start);
        }
        enforceLimit(limits, 'maxPemBlocks', blocks.length + 1, 'the number of PEM blocks');

        const body: Line[] = [];
        let endLine: Line | undefined;
        let endLabel = '';
        const bodyStart = i + 1;
        for (i++; i < lines.length; i++) {
            const line = lines[i] as Line;
            const shown = boundary(line);
            const end = END.exec(shown);
            if (end !== null) {
                endLine = line;
                endLabel = end[1] ?? '';
                break;
            }
            if (BEGIN.test(shown)) break;
            body.push(line);
        }
        if (endLine === undefined) {
            if (!lax && lines.slice(bodyStart).some((l) => l.text !== l.text.trim() && END.test(l.text.trim()))) {
                throw new PkiEncodingError('PKI_PEM_UNTERMINATED',
                    `pkinative: the "${label}" block at offset ${beginLine.start} has an END line with whitespace around it, which strict RFC 7468 parsing does not accept as a boundary — decode with mode: 'lax' to accept it`, beginLine.start);
            }
            throw new PkiEncodingError('PKI_PEM_UNTERMINATED',
                `pkinative: the "${label}" block at offset ${beginLine.start} has no matching END line — the text is truncated or spliced`, beginLine.start);
        }
        if (endLabel !== label) {
            throw new PkiEncodingError('PKI_PEM_LABEL_MISMATCH',
                `pkinative: the block that begins as "${label}" at offset ${beginLine.start} ends as "${endLabel}" at offset ${endLine.start} — the text was spliced or corrupted`, endLine.start);
        }
        if (wanted !== undefined && label !== wanted) {
            throw new PkiEncodingError('PKI_PEM_UNEXPECTED_LABEL',
                `pkinative: the block at offset ${beginLine.start} is "${label}", not "${wanted}" — pass the right block, or omit the label option`, beginLine.start);
        }

        const headers: Array<readonly [string, string]> = [];
        let first = 0;
        if (body.length > 0 && HEADER.test((body[0] as Line).text.replace(LEADING_WHITESPACE, ''))) {
            if (!lax) {
                throw new PkiEncodingError('PKI_PEM_HEADERS_FORBIDDEN',
                    `pkinative: the "${label}" block at offset ${beginLine.start} carries RFC 1421 headers, which strict RFC 7468 parsing refuses — decode with mode: 'lax' to read legacy PEM`, (body[0] as Line).start);
            }
            deviate(state, 'RFC 1421 headers', (body[0] as Line).start);
            for (; first < body.length; first++) {
                const raw = (body[first] as Line).text;
                if (raw.trim() === '') break;
                const header = HEADER.exec(raw.replace(LEADING_WHITESPACE, ''));
                const previous = headers[headers.length - 1];
                if (header !== null && !LEADING_WHITESPACE.test(raw)) headers.push([header[1] ?? '', (header[2] ?? '').trim()]);
                else if (previous !== undefined && LEADING_WHITESPACE.test(raw)) headers[headers.length - 1] = [previous[0], `${previous[1]} ${raw.trim()}`];
                else break;
            }
            if (first >= body.length || (body[first] as Line).text.trim() !== '') {
                throw new PkiEncodingError('PKI_PEM_BASE64_INVALID',
                    `pkinative: the headers of the "${label}" block at offset ${beginLine.start} are not followed by a blank line (RFC 1421 §4.4)`, beginLine.start);
            }
            first++;
        }

        let base64 = '';
        const content = body.slice(first);
        if (lax) {
            base64 = content.map((l) => l.text).join('\n');
            const stripped = base64.replace(LAX_WHITESPACE, '');
            const lengths = content.map((l) => l.text.length).filter((n) => n > 0);
            if (stripped !== base64.replace(/\n/g, '')) deviate(state, 'whitespace inside the base64 text', beginLine.start);
            else if (lengths.slice(0, -1).some((n) => n !== 64) || (lengths[lengths.length - 1] ?? 0) > 64 || content.some((l) => l.text.length === 0)) {
                deviate(state, 'base64 lines that are not 64 characters long', beginLine.start);
            }
            base64 = stripped;
        } else {
            for (let k = 0; k < content.length; k++) {
                const line = content[k] as Line;
                const last = k === content.length - 1;
                if (!BASE64_LINE.test(line.text) || line.text.length > 64 || (!last && line.text.length !== 64)) {
                    throw new PkiEncodingError('PKI_PEM_BASE64_INVALID',
                        `pkinative: line ${k + 1} of the "${label}" block at offset ${line.start} is not a strict base64 line (64 characters from the base64 alphabet, the last one shorter) — decode with mode: 'lax' to tolerate whitespace and line lengths`, line.start);
                }
                base64 += line.text;
            }
        }
        const bytes = decodeBase64(base64);
        if (bytes === null) {
            throw new PkiEncodingError('PKI_PEM_BASE64_INVALID',
                `pkinative: the body of the "${label}" block at offset ${beginLine.start} is not canonical base64 (alphabet, padding and zero padding bits, RFC 4648 §3.5)`, beginLine.start);
        }
        blocks.push(Object.freeze({ label, bytes, headers: Object.freeze(headers), offset: beginLine.start }));
    }
    if (blocks.length === 0) {
        if (!lax && lines.some((l) => BEGIN.test(l.text.trim()))) {
            throw new PkiEncodingError('PKI_PEM_NO_BLOCK',
                'pkinative: the text has a -----BEGIN line with whitespace around it, which strict RFC 7468 parsing does not accept as a boundary — decode with mode: \'lax\' to accept it', 0);
        }
        throw new PkiEncodingError('PKI_PEM_NO_BLOCK',
            'pkinative: the text contains no -----BEGIN line — pass the PEM text itself, or call the DER function directly for binary input', 0);
    }
    return Object.freeze(blocks);
}

/**
 * Encode bytes as one strict RFC 7468 block: 64-character lines, LF line endings.
 *
 * @param label The label, e.g. `CERTIFICATE`.
 * @param bytes The binary payload.
 * @returns The PEM text, ending with a line feed.
 * @throws {PkiEncodingError} `PKI_PEM_LABEL_INVALID` for a label outside the RFC 7468 grammar.
 * @throws {PkiError} `PKI_INVALID_INPUT` when the payload is not a Uint8Array.
 */
export function encodePem(label: string, bytes: Uint8Array): string {
    if (typeof label !== 'string' || !isValidLabel(label)) {
        throw new PkiEncodingError('PKI_PEM_LABEL_INVALID',
            `pkinative: ${JSON.stringify(label)} is not an RFC 7468 label — use printable ASCII joined by single spaces or hyphens, such as 'CERTIFICATE'`);
    }
    const base64 = encodeBase64(assertBytes(bytes, 'encodePem bytes'));
    const lines: string[] = [];
    for (let i = 0; i < base64.length; i += 64) lines.push(base64.slice(i, i + 64));
    return `-----BEGIN ${label}-----\n${lines.map((l) => `${l}\n`).join('')}-----END ${label}-----\n`;
}
