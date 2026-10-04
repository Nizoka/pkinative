import { describe, it, expect } from 'vitest';
import { _unknownCriticalEntryExtension, findRevocation, parseCertificateList } from '../../src/revocation/crl-parse.js';
import { parseOcspResponse } from '../../src/revocation/ocsp-response.js';
import { PkiCertificateError, PkiError, PkiLimitError } from '../../src/types/pki-errors.js';
import { verifyCertificateChain } from '../../src/verify/verify-chain.js';
import { universal } from '../helpers/raw-der-builder.js';
import { AT, issue, makeRoot } from '../verify/_cms-pki.js';

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

describe('through verifyCertificateChain', () => {
    // The report keyed its "first of each list" set by the hex of every list before any reader
    // saw it: 1.8 GiB of strings for a 32 MiB input (review of 2026-10-04). Lists are now compared
    // byte for byte, same length only, and a list past maxInputBytes reaches the reader's refusal.
    const hostile = nulls(4 * 1024 * 1024); // 8 MiB of NULLs, one well-formed SEQUENCE
    const variant = hostile.slice();
    variant[variant.length - 1] = 0x01; // same length, one octet apart: a different list, kept
    const malformed = (report: { readonly reasons: readonly { code: string; path?: string | undefined; errorCode?: string | undefined }[] }): string[] =>
        report.reasons.filter((r) => r.code === 'PKI_REASON_INPUT_MALFORMED').map((r) => `${r.path ?? ''}:${r.errorCode ?? ''}`).sort();

    it('should report 8 MiB hostile CRLs and an OCSP response as PKI_REASON_INPUT_MALFORMED, the same list once — the time budget is in tests/performance', async () => {
        const root = await makeRoot('Bounded Root');
        const leaf = await issue(root);
        const report = await verifyCertificateChain({
            leaf: leaf.certificate, candidates: [], trustAnchors: [root.certificate], at: AT,
            crls: [hostile, hostile, variant], ocspResponses: [hostile, hostile],
        });
        expect(malformed(report)).toEqual([
            'crls[0]:PKI_X509_STRUCTURE_INVALID', 'crls[2]:PKI_X509_STRUCTURE_INVALID', 'ocspResponses[0]:PKI_X509_STRUCTURE_INVALID',
        ]);
    });

    it('should carry the maxInputBytes refusal of a list into the report as the reason', async () => {
        const root = await makeRoot('Bounded Root');
        const leaf = await issue(root);
        const over = await verifyCertificateChain({
            leaf: leaf.certificate, candidates: [], trustAnchors: [root.certificate], at: AT,
            crls: [hostile], ocspResponses: [hostile], limits: { maxInputBytes: hostile.length - 1 },
        });
        expect(malformed(over)).toEqual(['crls[0]:PKI_LIMIT_EXCEEDED', 'ocspResponses[0]:PKI_LIMIT_EXCEEDED']);
    });
});
