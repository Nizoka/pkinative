import { describe, it, expect } from 'vitest';
import { _unknownCriticalEntryExtension, findRevocation, parseCertificateList } from '../../src/revocation/crl-parse.js';
import { parseOcspResponse } from '../../src/revocation/ocsp-response.js';
import { PkiCertificateError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import { universal } from '../helpers/raw-der-builder.js';

// The CRL and OCSP readers walk the root from the raw buffer with the cursor, not through the
// node decoder that enforces maxInputBytes and maxNodes. Until the review of 2026-10-04 they
// consulted neither: a root SEQUENCE of millions of two-octet NULLs was materialised header by
// header (seconds, gigabytes) before the "holds three values" check. Now the input size is the
// first refusal, and every walk is bounded by the field's own arity.

/** A SEQUENCE holding `count` NULL values — a well-formed envelope no CRL or OCSP grammar accepts. */
function nulls(count: number): Uint8Array {
    const content = new Uint8Array(count * 2);
    for (let i = 0; i < count; i++) content[i * 2] = 0x05;
    return universal(16, content, true);
}

function failure(fn: () => unknown): PkiError {
    try {
        fn();
    } catch (err) {
        if (err instanceof PkiError) return err;
        throw err;
    }
    throw new Error('did not throw');
}

const READERS: ReadonlyArray<[string, (der: Uint8Array, options?: { limits?: { maxInputBytes?: number } }) => unknown]> = [
    ['parseCertificateList', (der, o) => parseCertificateList(der, o)],
    ['findRevocation', (der, o) => findRevocation(der, new Uint8Array([1]), o)],
    ['_unknownCriticalEntryExtension', (der, o) => _unknownCriticalEntryExtension(der, o)],
    ['parseOcspResponse', (der, o) => parseOcspResponse(der, o)],
];

describe.each(READERS)('%s', (_name, read) => {
    it('should refuse an input past maxInputBytes before reading a byte, as PKI_LIMIT_EXCEEDED on that limit', () => {
        const der = nulls(100);
        const err = failure(() => read(der, { limits: { maxInputBytes: der.length - 1 } }));
        expect(err).toBeInstanceOf(PkiLimitError);
        expect(err).toMatchObject({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxInputBytes' });
        expect(() => read(der, { limits: { maxInputBytes: der.length } })).toThrow(PkiCertificateError);
    });

    it('should refuse a root SEQUENCE of a hundred thousand values at the field bound, as a structure error, not by walking them all', () => {
        const err = failure(() => read(nulls(100_000)));
        expect(err).toBeInstanceOf(PkiCertificateError);
        expect(err).toMatchObject({ code: 'PKI_X509_STRUCTURE_INVALID' });
        expect(err.message).toMatch(/holds more than \d+ values/);
    });
});
