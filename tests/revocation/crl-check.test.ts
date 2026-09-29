import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createCertificate } from '../../src/build/build-certificate.js';
import { encodeBasicConstraints } from '../../src/build/build-structures.js';
import { verifyCrlSignature } from '../../src/crypto/x509-verify.js';
import { checkRevocation } from '../../src/revocation/crl-check.js';
import { parseCertificateList } from '../../src/revocation/crl-parse.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { ascii, sequence, universal } from '../helpers/raw-der-builder.js';

/**
 * The revocation decision, and the four answers it keeps apart.
 *
 * The one that matters most is the difference between **not revoked** and
 * **unknown**. A validator that reported a missing or unsigned list as a clean
 * bill of health would be making the soft-fail decision on the caller's behalf,
 * invisibly — which is the whole failure mode this vocabulary exists to stop.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const AT = Date.UTC(2026, 2, 1);
const DAY = 86_400_000;

const ALG = sequence(universal(6, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), universal(5, []));
const CN_OID = universal(6, [0x55, 0x04, 0x03]);
const nameOf = (value: string): Uint8Array => sequence(universal(17, sequence(CN_OID, universal(12, ascii(value))), true));
const utc = (text: string): Uint8Array => universal(23, ascii(text));
const int = (...bytes: readonly number[]): Uint8Array => universal(2, bytes);
const entry = (serial: readonly number[], date: string): Uint8Array => sequence(int(...serial), utc(date));

interface CrlOptions {
    readonly issuer?: Uint8Array;
    readonly nextUpdate?: Uint8Array | null;
    readonly entries?: readonly Uint8Array[];
}

/** A CRL from `CN=Example CA`, valid to 2026-07-01 unless told otherwise. */
function buildCrl(options: CrlOptions = {}): Uint8Array {
    const tbs = sequence(
        int(0x01),
        ALG,
        options.issuer ?? nameOf('Example CA'),
        utc('260101000000Z'),
        ...(options.nextUpdate === null ? [] : [options.nextUpdate ?? utc('260701000000Z')]),
        sequence(...(options.entries ?? [entry([0x07], '260201000000Z')])),
    );
    return sequence(tbs, ALG, universal(3, [0x00, 0xaa]));
}

/** A certificate issued by `CN=Example CA` with the given serial. */
async function certificateWithSerial(serial: bigint | Uint8Array): Promise<Certificate> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const der = await createCertificate({
        serialNumber: serial,
        issuerDer: nameOf('Example CA'),
        subject: [[{ type: '2.5.4.3', value: 'host.example' }]],
        notBefore: AT - DAY,
        notAfter: AT + DAY,
        subjectPublicKey: spki,
        extensions: [{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) }],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
    return parseCertificate(der, quiet);
}

const LISTED = await certificateWithSerial(7n);
const NOT_LISTED = await certificateWithSerial(9n);

const codes = (reasons: ReadonlyArray<{ code: string }>): string[] => reasons.map((r) => r.code);

const check = (certificate: Certificate, crlDer: Uint8Array, overrides: Partial<Parameters<typeof checkRevocation>[0]> = {}): ReadonlyArray<{ code: string; message: string }> =>
    checkRevocation({
        certificate,
        crl: parseCertificateList(crlDer, quiet),
        crlDer,
        at: AT,
        signatureVerified: true,
        ...quiet,
        ...overrides,
    });

describe('checkRevocation', () => {
    it('should answer nothing at all for a certificate that is not listed', () => {
        expect(check(NOT_LISTED, buildCrl())).toEqual([]);
    });

    it('should report REVOKED with the date for a listed certificate', () => {
        const reasons = check(LISTED, buildCrl());
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOKED']);
        // The date is in the message because a signature made before the
        // revocation instant may still be good.
        expect(reasons[0]?.message).toContain('2026-02-01T00:00:00.000Z');
    });

    it('should tell UNKNOWN apart from not revoked when the signature was never checked', () => {
        // The distinction the whole vocabulary exists for: silence is not a
        // clean bill of health, and a soft-fail policy has to be the caller's.
        const reasons = check(NOT_LISTED, buildCrl(), { signatureVerified: undefined });
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
        expect(reasons[0]?.message).toContain('never checked');
    });

    it('should word UNKNOWN differently when the signature was checked and failed', () => {
        const reasons = check(NOT_LISTED, buildCrl(), { signatureVerified: false });
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
        expect(reasons[0]?.message).toContain('did not verify');
    });

    it('should report WRONG_ISSUER for a list from another CA', () => {
        const other = buildCrl({ issuer: nameOf('Other CA') });
        expect(codes(check(NOT_LISTED, other))).toEqual(['PKI_REASON_REVOCATION_WRONG_ISSUER']);
    });

    it('should compare issuers by encoded name, not by rendering', () => {
        // Two names that print the same and encode differently are two names.
        // `CN=Example CA` as a PrintableString is not the UTF8String above.
        const printable = sequence(universal(17, sequence(CN_OID, universal(19, ascii('Example CA'))), true));
        expect(codes(check(NOT_LISTED, buildCrl({ issuer: printable })))).toContain('PKI_REASON_REVOCATION_WRONG_ISSUER');
    });

    it('should report STALE once nextUpdate has passed', () => {
        const expired = buildCrl({ nextUpdate: utc('260201000000Z') });
        expect(codes(check(NOT_LISTED, expired))).toEqual(['PKI_REASON_REVOCATION_STALE']);
    });

    it('should hold a list current up to and including its nextUpdate instant, and stale one millisecond after', () => {
        // RFC 5280 §5.1.2.5: nextUpdate is the date by which the next list will
        // be issued — the list is still the current one at that instant.
        const crl = buildCrl({ nextUpdate: utc('260701000000Z') });
        const nextUpdate = Date.UTC(2026, 6, 1);
        expect(check(NOT_LISTED, crl, { at: nextUpdate })).toEqual([]);
        expect(codes(check(NOT_LISTED, crl, { at: nextUpdate + 1 }))).toEqual(['PKI_REASON_REVOCATION_STALE']);
        // …and the tolerance moves that boundary by exactly its own length.
        expect(check(NOT_LISTED, crl, { at: nextUpdate + DAY, staleTolerance: DAY })).toEqual([]);
        expect(codes(check(NOT_LISTED, crl, { at: nextUpdate + DAY + 1, staleTolerance: DAY }))).toEqual(['PKI_REASON_REVOCATION_STALE']);
    });

    it('should accept a lapsed list within an explicit tolerance', () => {
        // Soft-fail as an explicit choice, with a number the caller wrote.
        const expired = buildCrl({ nextUpdate: utc('260215000000Z') });
        expect(check(NOT_LISTED, expired, { staleTolerance: 30 * DAY })).toEqual([]);
        expect(codes(check(NOT_LISTED, expired, { staleTolerance: DAY }))).toEqual(['PKI_REASON_REVOCATION_STALE']);
    });

    it('should treat a list with no nextUpdate as stale rather than as current', () => {
        // RFC 5280 §5.1.2.5 makes it optional and tells CAs to include it.
        // Nothing asserts such a list is still current, so it is not believed.
        const reasons = check(NOT_LISTED, buildCrl({ nextUpdate: null }));
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_STALE']);
        expect(reasons[0]?.message).toContain('declares no nextUpdate');
    });

    it('should still report a revocation found on a stale list from the wrong CA', () => {
        // The one direction of error that matters: hiding a revocation behind
        // an earlier failure would be worse than reporting all three.
        const bad = buildCrl({ issuer: nameOf('Other CA'), nextUpdate: utc('260105000000Z') });
        expect(codes(check(LISTED, bad, { signatureVerified: false })).sort()).toEqual([
            'PKI_REASON_REVOCATION_STALE',
            'PKI_REASON_REVOCATION_UNKNOWN',
            'PKI_REASON_REVOCATION_WRONG_ISSUER',
            'PKI_REASON_REVOKED',
        ]);
    });

    it('should compare serials by octets, so a leading zero is a different certificate', async () => {
        const padded = await certificateWithSerial(Uint8Array.of(0x00, 0xff));
        const listed = buildCrl({ entries: [entry([0x00, 0xff], '260201000000Z')] });
        expect(codes(check(padded, listed))).toEqual(['PKI_REASON_REVOKED']);

        const bare = await certificateWithSerial(Uint8Array.of(0x7f));
        expect(check(bare, listed)).toEqual([]);
    });

    it('should never throw for a revocation issue', () => {
        expect(() => check(LISTED, buildCrl({ issuer: nameOf('Other CA'), nextUpdate: null }), { signatureVerified: false })).not.toThrow();
    });
});

describe('verifyCrlSignature', () => {
    const ROOT = parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/isrg-root-x1.der')), quiet);

    it('should refuse anything that is not a parsed CertificateList', async () => {
        await expect(verifyCrlSignature(buildCrl() as never, ROOT))
            .rejects.toThrow(expect.objectContaining({ code: 'PKI_INVALID_INPUT' }));
    });

    it('should return false when the signature does not verify', async () => {
        // The CRL above is signed with 0xaa, which is not an RSA signature by
        // anyone. A verdict, not an exception.
        const crl = parseCertificateList(buildCrl(), quiet);
        expect(await verifyCrlSignature(crl, ROOT)).toBe(false);
    });

    it('should return false when the two algorithm fields disagree', async () => {
        const mismatched = sequence(
            sequence(int(0x01), sequence(universal(6, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])), nameOf('CA'), utc('260101000000Z')),
            ALG,
            universal(3, [0x00, 0xaa]),
        );
        const crl = parseCertificateList(mismatched, quiet);
        expect(await verifyCrlSignature(crl, ROOT)).toBe(false);
    });

    it('should return false for a signature BIT STRING with padding bits', async () => {
        // A signature is a whole number of octets. Anything else is a rewritten
        // structure, not a short signature.
        const padded = sequence(sequence(int(0x01), ALG, nameOf('CA'), utc('260101000000Z')), ALG, universal(3, [0x03, 0xa8]));
        const crl = parseCertificateList(padded, quiet);
        expect(await verifyCrlSignature(crl, ROOT)).toBe(false);
    });

    it('should let a caller waive the algorithm-match check', async () => {
        const mismatched = sequence(
            sequence(int(0x01), sequence(universal(6, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])), nameOf('CA'), utc('260101000000Z')),
            ALG,
            universal(3, [0x00, 0xaa]),
        );
        const crl = parseCertificateList(mismatched, quiet);
        // Still false — the signature is nonsense — but it got past the match.
        expect(await verifyCrlSignature(crl, ROOT, { requireAlgorithmMatch: false })).toBe(false);
    });

    it('should verify a CRL that was really signed, and refuse the same CRL under another key', async () => {
        // Ed25519 is deterministic, so this is reproducible; the CRL is signed
        // here rather than fetched, because no public CRL is small enough to
        // commit and stable enough to pin.
        // Web Crypto types generateKey as CryptoKey | CryptoKeyPair; Ed25519 always
        // returns a pair, and narrowing once beats casting at three call sites.
        const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as webcrypto.CryptoKeyPair;
        const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
        const ED = sequence(universal(6, [0x2b, 0x65, 0x70]));
        const tbs = sequence(int(0x01), ED, nameOf('Signing CA'), utc('260101000000Z'), utc('260701000000Z'));
        const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, tbs));
        const der = sequence(tbs, ED, universal(3, [0x00, ...signature]));

        const caDer = await createCertificate({
            serialNumber: 1n,
            subject: [[{ type: '2.5.4.3', value: 'Signing CA' }]],
            notBefore: AT - DAY,
            notAfter: AT + DAY,
            subjectPublicKey: spki,
            extensions: [{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) }],
        }, { key: pair.privateKey, algorithm: { name: 'Ed25519' } });
        const ca = parseCertificate(caDer, quiet);

        const crl = parseCertificateList(der, quiet);
        expect(await verifyCrlSignature(crl, ca)).toBe(true);
        expect(await verifyCrlSignature(crl, ROOT)).toBe(false);
    });
});
