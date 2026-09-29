import { describe, expect, it } from 'vitest';
import { findRevocation, parseCertificateList } from '../../src/revocation/crl-parse.js';
import { ascii, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * RFC 5280 §5 CertificateList parsing.
 *
 * Every CRL here is built with `tests/helpers/raw-der-builder.ts`, which never
 * imports `src/`: a parser tested only against its own encoder is a parser
 * tested against its own assumptions. The list is walked rather than decoded,
 * so the interesting cases are the ones where walking and decoding would
 * differ — a huge list, a truncated entry, an entry that overruns its parent.
 */

const OID_SHA256_RSA = universal(6, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
const ALG = sequence(OID_SHA256_RSA, universal(5, []));
const CN = universal(6, [0x55, 0x04, 0x03]);

const name = (value: string): Uint8Array => sequence(universal(17, sequence(CN, universal(12, ascii(value))), true));
const utc = (text: string): Uint8Array => universal(23, ascii(text));
const int = (...bytes: readonly number[]): Uint8Array => universal(2, bytes);

/**
 * `SEQUENCE { userCertificate, revocationDate, crlEntryExtensions OPTIONAL }`.
 *
 * `crlEntryExtensions` is `Extensions ::= SEQUENCE OF Extension`, so a single
 * extension still has to be wrapped — passing one bare is the first mistake
 * this helper existed to stop making.
 */
const entry = (serial: readonly number[], date = '260601000000Z', ...extensions: readonly Uint8Array[]): Uint8Array =>
    sequence(int(...serial), utc(date), ...(extensions.length === 0 ? [] : [sequence(...extensions)]));

const extension = (oid: readonly number[], value: Uint8Array, critical?: boolean, trailing?: readonly number[]): Uint8Array =>
    sequence(
        universal(6, oid),
        ...(critical === undefined ? [] : [universal(1, [critical ? 0xff : 0x00])]),
        // `trailing` puts octets INSIDE extnValue behind the value, which is
        // the one thing the in-place decoder exists to catch.
        universal(4, trailing === undefined ? value : Uint8Array.from([...value, ...trailing])),
    );

interface CrlParts {
    readonly version?: Uint8Array | null;
    readonly thisUpdate?: Uint8Array;
    readonly nextUpdate?: Uint8Array | null;
    readonly entries?: readonly Uint8Array[] | null;
    /** The whole `revokedCertificates` SEQUENCE, for a list too long to spread. */
    readonly entriesRaw?: Uint8Array;
    readonly crlExtensions?: readonly Uint8Array[] | null;
}

function crl(parts: CrlParts = {}): Uint8Array {
    if (parts.entriesRaw !== undefined) {
        const tbs = sequence(int(1), ALG, name('Example CA'), utc('260101000000Z'), utc('260701000000Z'), parts.entriesRaw);
        return sequence(tbs, ALG, universal(3, [0x00, 0xaa, 0xbb]));
    }
    const entries = parts.entries === undefined ? [entry([0x01]), entry([0x02])] : parts.entries;
    const crlExtensions = parts.crlExtensions === undefined ? null : parts.crlExtensions;
    const tbs = sequence(
        ...(parts.version === null ? [] : [parts.version ?? int(1)]),
        ALG,
        name('Example CA'),
        parts.thisUpdate ?? utc('260101000000Z'),
        ...(parts.nextUpdate === null ? [] : [parts.nextUpdate ?? utc('260701000000Z')]),
        ...(entries === null ? [] : [sequence(...entries)]),
        ...(crlExtensions === null ? [] : [tlv(2, true, 0, sequence(...crlExtensions))]),
    );
    return sequence(tbs, ALG, universal(3, [0x00, 0xaa, 0xbb]));
}

const quiet = { onDiagnostic: (): undefined => undefined };

describe('parseCertificateList', () => {

    it('should refuse an argument that is not bytes as PKI_INVALID_INPUT, never as a TypeError', () => {
        // A caller's type error, not a fact about any encoding: it used to
        // escape as a TypeError, or as a length error about bytes nobody passed.
        for (const value of ['30 03 02 01 01', undefined, null, [0x30, 0x00]]) {
            expect(() => parseCertificateList(value as unknown as Uint8Array)).toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
        }
    });
    it('should read the envelope of a v2 CRL', () => {
        const list = parseCertificateList(crl(), quiet);
        expect(list.version).toBe(2);
        expect(list.issuer.rdns).toHaveLength(1);
        expect(new Date(list.thisUpdate.epochMilliseconds).toISOString()).toBe('2026-01-01T00:00:00.000Z');
        expect(new Date((list.nextUpdate?.epochMilliseconds ?? 0)).toISOString()).toBe('2026-07-01T00:00:00.000Z');
        expect(list.entryCount).toBe(2);
    });

    it('should read a v1 CRL, where the version field is absent', () => {
        const list = parseCertificateList(crl({ version: null }), quiet);
        expect(list.version).toBe(1);
    });

    it('should accept a CRL with no nextUpdate', () => {
        const list = parseCertificateList(crl({ nextUpdate: null }), quiet);
        expect(list.nextUpdate).toBeUndefined();
    });

    it('should accept a CRL with no entries at all', () => {
        // The common case for a CA that has revoked nothing, and the one an
        // implementation that assumed the field was present would crash on.
        const list = parseCertificateList(crl({ entries: null }), quiet);
        expect(list.entryCount).toBe(0);
        expect(findRevocation(crl({ entries: null }), Uint8Array.of(0x01), quiet)).toBeUndefined();
    });

    it('should expose the tbs bytes the signature covers, and the signature', () => {
        const der = crl();
        const list = parseCertificateList(der, quiet);
        // tbsCertList is the first child of the outer SEQUENCE.
        expect(list.tbsDer[0]).toBe(0x30);
        expect(Array.from(list.signatureValue.bytes)).toEqual([0xaa, 0xbb]);
        expect(list.signatureValue.unusedBits).toBe(0);
        expect(list.der.length).toBe(der.length);
    });

    it('should read cRLNumber and notice a delta CRL', () => {
        const withNumber = crl({ crlExtensions: [extension([0x55, 0x1d, 0x14], int(0x2a))] });
        expect(parseCertificateList(withNumber, quiet).crlNumber).toBe(42n);
        expect(parseCertificateList(withNumber, quiet).isDelta).toBe(false);

        const delta = crl({ crlExtensions: [extension([0x55, 0x1d, 0x14], int(0x2b)), extension([0x55, 0x1d, 0x1b], int(0x2a), true)] });
        expect(parseCertificateList(delta, quiet).isDelta).toBe(true);
    });

    it('should carry on when cRLNumber is malformed', () => {
        // A CRL number nobody can read does not change any revocation answer,
        // and refusing the whole list over it would hide every revocation in
        // it — which is the failure mode that matters here.
        const broken = crl({ crlExtensions: [extension([0x55, 0x1d, 0x14], universal(12, ascii('not an integer')))] });
        expect(parseCertificateList(broken, quiet).crlNumber).toBeUndefined();
    });

    it.each([
        { name: 'not a SEQUENCE', der: universal(2, [0x01]) },
        { name: 'two values instead of three', der: sequence(sequence(ALG), ALG) },
        { name: 'a thisUpdate that is not a time', der: sequence(sequence(int(1), ALG, name('CA'), int(5)), ALG, universal(3, [0x00])) },
        { name: 'a version that is neither 0 nor 1', der: crl({ version: int(7) }) },
        { name: 'a signatureValue that is not a BIT STRING', der: sequence(sequence(int(1), ALG, name('CA'), utc('260101000000Z')), ALG, universal(4, [0x00])) },
    ])('should refuse a CertificateList with $name', ({ der }) => {
        expect(() => parseCertificateList(der, quiet)).toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should read a v1 CRL whose version field is present and zero', () => {
        // Two different encodings of v1: the field absent, and the field
        // written as 0. Both are v1, and DER prefers the first — but a CA that
        // writes the second is not producing something to refuse.
        expect(parseCertificateList(crl({ version: int(0) }), quiet).version).toBe(1);
    });

    it('should refuse a tbsCertList that stops before thisUpdate', () => {
        const tbs = sequence(int(1), ALG);
        expect(() => parseCertificateList(sequence(tbs, ALG, universal(3, [0x00])), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should read an empty signature BIT STRING without inventing a padding count', () => {
        const tbs = sequence(int(1), ALG, name('CA'), utc('260101000000Z'));
        const list = parseCertificateList(sequence(tbs, ALG, universal(3, [])), quiet);
        expect(list.signatureValue.unusedBits).toBe(0);
        expect(list.signatureValue.bytes).toHaveLength(0);
    });

    it('should decode an extension it recognises, in place', () => {
        // Every CRL in the wild carries an authorityKeyIdentifier, and this is
        // the first test here to use an extension pkinative actually *decodes*
        // — cRLNumber and the delta marker above are read from their raw value
        // and never reach the decoder table, which is why the defect this locks
        // survived a whole suite.
        //
        // `_decodeExtension` decodes the value in place and refuses trailing
        // octets inside extnValue, so it needs the offset of the value's
        // content and a view that ends where the value ends. Handed the
        // Extension SEQUENCE's own offset and the whole CRL instead, it read
        // the SEQUENCE as the value and saw the rest of the file behind it —
        // which refused **every CRL carrying a recognised extension**.
        const keyIdentifier = tlv(2, false, 0, [0xde, 0xad, 0xbe, 0xef]);
        const aki = crl({ crlExtensions: [extension([0x55, 0x1d, 0x23], sequence(keyIdentifier))] });
        const list = parseCertificateList(aki, quiet);
        expect(list.extensions).toHaveLength(1);
        expect(list.extensions[0]).toMatchObject({ kind: 'authorityKeyIdentifier', oid: '2.5.29.35', critical: false });
        expect(Array.from((list.extensions[0] as { keyIdentifier?: Uint8Array }).keyIdentifier ?? [])).toEqual([0xde, 0xad, 0xbe, 0xef]);
    });

    it('should still refuse an extension value with octets behind it', () => {
        // The check the fix above must not have disabled: an extnValue holding
        // its value *and* something else is two readings of one field.
        const trailing = crl({ crlExtensions: [extension([0x55, 0x1d, 0x23], sequence(tlv(2, false, 0, [0x01])), undefined, [0x05, 0x00])] });
        expect(() => parseCertificateList(trailing, quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_EXTENSION_MALFORMED' }));
    });

    it('should accept an empty crlExtensions field', () => {
        const tbs = sequence(int(1), ALG, name('CA'), utc('260101000000Z'), tlv(2, true, 0, new Uint8Array(0)));
        const list = parseCertificateList(sequence(tbs, ALG, universal(3, [0x00])), quiet);
        expect(list.extensions).toEqual([]);
        expect(list.crlNumber).toBeUndefined();
    });

    it('should refuse an extension with fewer than two fields', () => {
        const broken = crl({ crlExtensions: [sequence(universal(6, [0x55, 0x1d, 0x14]))] });
        expect(() => parseCertificateList(broken, quiet)).toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should refuse a field after crlExtensions', () => {
        const tbs = sequence(int(1), ALG, name('CA'), utc('260101000000Z'), tlv(2, true, 0, sequence()), int(9));
        expect(() => parseCertificateList(sequence(tbs, ALG, universal(3, [0x00])), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should refuse an entry that is not a SEQUENCE', () => {
        expect(() => parseCertificateList(crl({ entries: [int(1)] }), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should stop at maxRevokedCertificates', () => {
        const many = Array.from({ length: 40 }, (_, i) => entry([i + 1]));
        expect(() => parseCertificateList(crl({ entries: many }), { ...quiet, limits: { maxRevokedCertificates: 10 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED', limit: 'maxRevokedCertificates' }));
    });
});

describe('findRevocation', () => {
    const der = crl({ entries: [
        entry([0x01]),
        entry([0x02], '260602000000Z', extension([0x55, 0x1d, 0x15], universal(10, [0x01]))),
        entry([0x00, 0xff]),
    ] });

    it('should find an entry by its content octets', () => {
        const found = findRevocation(der, Uint8Array.of(0x02), quiet);
        expect(found?.serialNumber.hex).toBe('02');
        expect(new Date(found?.revocationDate.epochMilliseconds ?? 0).toISOString()).toBe('2026-06-02T00:00:00.000Z');
    });

    it('should return undefined for a serial that is not listed', () => {
        expect(findRevocation(der, Uint8Array.of(0x09), quiet)).toBeUndefined();
    });

    it('should compare by octets, so a leading zero is a different serial', () => {
        // Two serials that differ only in a leading zero octet are two serials
        // to a CA. Comparing the bigint would make them one, and that is a
        // revocation silently missed.
        expect(findRevocation(der, Uint8Array.of(0x00, 0xff), quiet)?.serialNumber.hex).toBe('00ff');
        expect(findRevocation(der, Uint8Array.of(0xff), quiet)).toBeUndefined();
    });

    it('should read cRLReason from an entry extension', () => {
        expect(findRevocation(der, Uint8Array.of(0x02), quiet)?.reason).toBe('keyCompromise');
        expect(findRevocation(der, Uint8Array.of(0x01), quiet)?.reason).toBeUndefined();
    });

    it('should leave reason undefined for the unassigned code 7', () => {
        // RFC 5280 §5.3.1 skips 7. A CRL asserting it is reporting a reason no
        // standard defines, and inventing a name for it would be worse.
        const odd = crl({ entries: [entry([0x05], '260601000000Z', extension([0x55, 0x1d, 0x15], universal(10, [0x07])))] });
        const found = findRevocation(odd, Uint8Array.of(0x05), quiet);
        expect(found).toBeDefined();
        expect(found?.reason).toBeUndefined();
    });

    it.each([
        { name: 'a reason that is not an ENUMERATED or an INTEGER', value: universal(12, ascii('1')) },
        { name: 'a reason wider than one octet', value: universal(10, [0x00, 0x01]) },
        // Not even a TLV: the extension value is empty, so decoding throws
        // rather than returning something with a wrong tag.
        { name: 'a reason whose value is not DER at all', value: new Uint8Array(0) },
    ])('should leave reason undefined for $name', ({ value }) => {
        // A reason nobody can read must not become a reason invented, and must
        // not hide the revocation either: the entry is still found.
        const odd = crl({ entries: [entry([0x08], '260601000000Z', extension([0x55, 0x1d, 0x15], value))] });
        const found = findRevocation(odd, Uint8Array.of(0x08), quiet);
        expect(found).toBeDefined();
        expect(found?.reason).toBeUndefined();
    });

    it('should read invalidityDate, and survive a malformed one', () => {
        const dated = crl({ entries: [entry([0x06], '260601000000Z', extension([0x55, 0x1d, 0x18], universal(24, ascii('20260401000000Z'))))] });
        expect(findRevocation(dated, Uint8Array.of(0x06), quiet)?.invalidityDate).toBe(Date.UTC(2026, 3, 1));

        const broken = crl({ entries: [entry([0x07], '260601000000Z', extension([0x55, 0x1d, 0x18], int(5)))] });
        expect(findRevocation(broken, Uint8Array.of(0x07), quiet)?.invalidityDate).toBeUndefined();
    });

    it('should refuse an entry with fewer than two fields', () => {
        const short = crl({ entries: [sequence(int(1))] });
        expect(() => findRevocation(short, Uint8Array.of(0x01), quiet))
            .toThrow(expect.objectContaining({ code: 'PKI_X509_STRUCTURE_INVALID' }));
    });

    it('should stop at maxRevokedCertificates while searching', () => {
        const many = Array.from({ length: 40 }, (_, i) => entry([i + 1]));
        expect(() => findRevocation(crl({ entries: many }), Uint8Array.of(0x28), { ...quiet, limits: { maxRevokedCertificates: 10 } }))
            .toThrow(expect.objectContaining({ code: 'PKI_LIMIT_EXCEEDED' }));
    });

    it('should walk a list far larger than maxNodes would allow to be decoded', () => {
        // The point of the whole design. maxNodes is 200 000 and an entry costs
        // three nodes, so a decoded tree refuses this list; the cursor walks it
        // in constant memory. 100 000 entries is still a small CRL by the
        // standards of a large CA.
        //
        // Built by concatenating bytes, not by `sequence(...entries)`: spreading
        // 100 000 arguments into a call overflows the stack, which is a fact
        // about JavaScript rather than about CRLs, and one this test tripped
        // over on its first run.
        const parts: Uint8Array[] = [];
        let total = 0;
        for (let i = 0; i < 100_000; i += 1) {
            const one = entry([(i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff]);
            parts.push(one);
            total += one.length;
        }
        const content = new Uint8Array(total);
        let at = 0;
        for (const part of parts) { content.set(part, at); at += part.length; }
        const big = crl({ entries: [], entriesRaw: universal(16, content, true) });

        expect(parseCertificateList(big, quiet).entryCount).toBe(100_000);
        const last = findRevocation(big, Uint8Array.of(0x01, 0x86, 0x9f), quiet);
        expect(last?.serialNumber.hex).toBe('01869f');
    });
});
