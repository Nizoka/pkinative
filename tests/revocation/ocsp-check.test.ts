import { describe, expect, it } from 'vitest';
import { sha1 } from '../../src/hash/sha1.js';
import { checkOcspStatus, OCSP_NONCE_OID, type CheckOcspStatusInput } from '../../src/revocation/ocsp-check.js';
import { parseOcspResponse } from '../../src/revocation/ocsp-response.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

/**
 * The OCSP status decision, and RFC 6960 §3.2's four client responsibilities.
 *
 * The cases that matter most here are the substitutions: an answer about
 * another serial, about another CA, a nonce that came back different. Each is a
 * response a client that trusted `responses[0]` would accept as its own, and
 * each is why `PKI_REASON_REVOCATION_MISMATCH` is a separate code — retrying a
 * mismatch against the same responder is the wrong move, and a caller that
 * could not tell it from `UNKNOWN` would do exactly that.
 */

const quiet = { onDiagnostic: (): undefined => undefined };
const AT = Date.UTC(2026, 5, 15);
const MINUTE = 60_000;
const DAY = 86_400_000;

const NAME_HASH = sha1(new TextEncoder().encode('CN=Example CA'));
const KEY_HASH = sha1(new TextEncoder().encode('the CA key bits'));
const SERIAL = Uint8Array.of(0x2a);

const EXPECTED = { issuerNameHash: NAME_HASH, issuerKeyHash: KEY_HASH, serialNumber: SERIAL };

const ALG = sequence(universal(6, [0x2b, 0x65, 0x70]));
const OID_BASIC = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]);
const NONCE_OID = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]);
const SHA1_ALG = sequence(universal(6, [0x2b, 0x0e, 0x03, 0x02, 0x1a]), universal(5, []));
const gen = (at: number): Uint8Array => universal(24, ascii(`${new Date(at).toISOString().replace(/[-:T]/g, '').slice(0, 14)}Z`));

const GOOD = tlv(2, false, 0, new Uint8Array(0));
const UNKNOWN_STATUS = tlv(2, false, 2, new Uint8Array(0));
const revokedStatus = (at: number, reason = 1): Uint8Array =>
    tlv(2, true, 1, concat(gen(at), tlv(2, true, 0, universal(10, [reason]))));

interface CertIdParts {
    readonly nameHash?: Uint8Array;
    readonly keyHash?: Uint8Array;
    readonly serial?: readonly number[];
}

const certId = (parts: CertIdParts = {}): Uint8Array => sequence(
    SHA1_ALG,
    universal(4, [...(parts.nameHash ?? NAME_HASH)]),
    universal(4, [...(parts.keyHash ?? KEY_HASH)]),
    universal(2, [...(parts.serial ?? [0x2a])]),
);

interface SingleParts {
    readonly id?: Uint8Array;
    readonly status?: Uint8Array;
    readonly thisUpdate?: number;
    readonly nextUpdate?: number | null;
}

const single = (parts: SingleParts = {}): Uint8Array => sequence(
    parts.id ?? certId(),
    parts.status ?? GOOD,
    gen(parts.thisUpdate ?? AT - DAY),
    ...(parts.nextUpdate === null || parts.nextUpdate === undefined ? [] : [tlv(2, true, 0, gen(parts.nextUpdate))]),
);

interface ResponseParts {
    readonly statusCode?: number;
    readonly singles?: readonly Uint8Array[];
    readonly nonce?: Uint8Array | null;
}

function build(parts: ResponseParts = {}): Uint8Array {
    if (parts.statusCode !== undefined && parts.statusCode !== 0) {
        return sequence(universal(10, [parts.statusCode]));
    }
    const extensions = parts.nonce === undefined || parts.nonce === null
        ? []
        : [tlv(2, true, 1, sequence(sequence(NONCE_OID, universal(4, [...universal(4, [...parts.nonce])]))))];
    const tbs = sequence(
        tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)])),
        gen(AT - DAY),
        sequence(...(parts.singles ?? [single({ nextUpdate: AT + DAY })])),
        ...extensions,
    );
    const basic = sequence(tbs, ALG, universal(3, [0x00, 0xde]));
    return sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
}

const check = (der: Uint8Array, overrides: Partial<CheckOcspStatusInput> = {}): readonly { code: string; message: string }[] =>
    checkOcspStatus({
        response: parseOcspResponse(der, quiet),
        expected: EXPECTED,
        at: AT,
        signatureVerified: true,
        responderAuthorized: true,
        ...overrides,
    });

const codes = (reasons: readonly { code: string }[]): string[] => reasons.map((r) => r.code).sort();

describe('checkOcspStatus', () => {
    it('should answer nothing at all for a clean good', () => {
        expect(check(build())).toEqual([]);
    });

    it('should report REVOKED with the date and the reason', () => {
        const reasons = check(build({ singles: [single({ status: revokedStatus(Date.UTC(2026, 4, 1)), nextUpdate: AT + DAY })] }));
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOKED']);
        expect(reasons[0]?.message).toContain('2026-05-01T00:00:00.000Z');
        expect(reasons[0]?.message).toContain('keyCompromise');
    });

    it('should keep the responder’s own unknown as unknown, not as good', () => {
        const reasons = check(build({ singles: [single({ status: UNKNOWN_STATUS, nextUpdate: AT + DAY })] }));
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
        expect(reasons[0]?.message).toContain('no record of this certificate');
    });

    it.each([
        { code: 1, status: 'malformedRequest' },
        { code: 3, status: 'tryLater' },
        { code: 6, status: 'unauthorized' },
    ])('should report UNKNOWN naming the declining status $status', ({ code, status }) => {
        // Which one it was decides the next move, so the status is in the
        // message rather than flattened away.
        const reasons = check(build({ statusCode: code }));
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
        expect(reasons[0]?.message).toContain(status);
        expect(reasons).toHaveLength(1);
    });

    it('should report UNKNOWN when the signature was never checked, and word it differently when it failed', () => {
        expect(check(build(), { signatureVerified: undefined })[0]?.message).toContain('never checked');
        expect(check(build(), { signatureVerified: false })[0]?.message).toContain('did not verify');
    });

    it('should report UNKNOWN when nothing says the responder is authorised', () => {
        // A responder nobody authorised is a responder anyone can be. RFC 6960
        // §4.2.2.2 gives three routes and this library decides none of them.
        expect(check(build(), { responderAuthorized: undefined })[0]?.message).toContain('nothing says the signer is authorised');
        expect(check(build(), { responderAuthorized: false })[0]?.message).toContain('not authorised');
    });

    it('should report MISMATCH for an answer about another serial, and name both', () => {
        const other = single({ id: certId({ serial: [0x2b] }), nextUpdate: AT + DAY });
        const reasons = check(build({ singles: [other] }));
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
        expect(reasons[0]?.message).toContain('serial 2b');
        expect(reasons[0]?.message).toContain('2a');
    });

    it('should report MISMATCH for the same serial under another CA name', () => {
        const other = single({ id: certId({ nameHash: sha1(new TextEncoder().encode('CN=Other CA')) }), nextUpdate: AT + DAY });
        expect(check(build({ singles: [other] }))[0]?.message).toContain('issuer name hash does not');
    });

    it('should report MISMATCH for the same serial under another key', () => {
        const other = single({ id: certId({ keyHash: sha1(new TextEncoder().encode('another key')) }), nextUpdate: AT + DAY });
        expect(check(build({ singles: [other] }))[0]?.message).toContain('issuer key hash does not');
    });

    it('should find the right answer among several rather than taking the first', () => {
        // Taking `responses[0]` is how a client reads somebody else's status as
        // its own. The answer asked about is second here on purpose.
        const wrong = single({ id: certId({ serial: [0x99] }), status: revokedStatus(AT - DAY), nextUpdate: AT + DAY });
        const right = single({ nextUpdate: AT + DAY });
        expect(check(build({ singles: [wrong, right] }))).toEqual([]);
    });

    it('should report MISMATCH when the response carries no answers at all', () => {
        const reasons = check(build({ singles: [] }));
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
        expect(reasons[0]?.message).toContain('no answers at all');
    });

    it('should report STALE once nextUpdate has passed, and accept an explicit tolerance', () => {
        const stale = build({ singles: [single({ thisUpdate: AT - 40 * DAY, nextUpdate: AT - 10 * DAY })] });
        expect(codes(check(stale))).toEqual(['PKI_REASON_REVOCATION_STALE']);
        expect(check(stale, { staleTolerance: 20 * DAY })).toEqual([]);
    });

    it('should NOT treat a missing nextUpdate as stale, unlike a CRL', () => {
        // RFC 6960 §4.2.2.1: an absent nextUpdate means newer information is
        // always available — the opposite of the CRL case, where it means
        // nothing promises a successor.
        expect(check(build({ singles: [single({ nextUpdate: null })] }))).toEqual([]);
    });

    it('should refuse a thisUpdate well in the future, within a clock-skew allowance', () => {
        // Clocks disagree by seconds, not hours. A thisUpdate far ahead is a
        // broken clock or a response minted for later.
        expect(check(build({ singles: [single({ thisUpdate: AT + 30 * MINUTE, nextUpdate: AT + DAY })] }))[0]?.code)
            .toBe('PKI_REASON_REVOCATION_STALE');
        expect(check(build({ singles: [single({ thisUpdate: AT + 30_000, nextUpdate: AT + DAY })] }))).toEqual([]);
        expect(check(build({ singles: [single({ thisUpdate: AT + 30 * MINUTE, nextUpdate: AT + DAY })] }), { futureTolerance: DAY })).toEqual([]);
    });
});

describe('checkOcspStatus — the nonce', () => {
    const nonce = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);

    it('should accept an echoed nonce that matches', () => {
        expect(check(build({ nonce }), { nonce })).toEqual([]);
    });

    it('should report MISMATCH for a nonce that came back different', () => {
        // Always wrong, whatever the policy: that response was not produced for
        // this request.
        const reasons = check(build({ nonce: Uint8Array.of(9, 9, 9, 9) }), { nonce });
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
        expect(reasons[0]?.message).toContain('not the one that was sent');
    });

    it('should tolerate a missing echo by default, and refuse it when asked', () => {
        // The CA/Browser Forum discourages nonces so responses stay cacheable,
        // and most public responders omit the echo. Which matters more is the
        // caller's choice, not a default.
        expect(check(build(), { nonce })).toEqual([]);
        expect(codes(check(build(), { nonce, requireNonce: true }))).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
    });

    it('should not look for an echo when no nonce was sent', () => {
        expect(check(build({ nonce }), { requireNonce: true })).toEqual([]);
    });

    it('should report MISMATCH for an echo wrapped at the wrong depth', () => {
        // The nonce sits inside two OCTET STRINGs. Comparing at the wrong layer
        // is a nonce check that passes on everything, so a single-layer echo
        // must fail rather than be unwrapped generously.
        const oneLayer = tlv(2, true, 1, sequence(sequence(NONCE_OID, universal(4, [...nonce]))));
        const tbs = sequence(
            tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)])),
            gen(AT - DAY),
            sequence(single({ nextUpdate: AT + DAY })),
            oneLayer,
        );
        const basic = sequence(tbs, ALG, universal(3, [0x00, 0xde]));
        const der = sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
        expect(codes(check(der, { nonce }))).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
    });

    it('should report MISMATCH for an echo that is not an OCTET STRING at all', () => {
        const notOctets = tlv(2, true, 1, sequence(sequence(NONCE_OID, universal(4, [...universal(2, [0x01])]))));
        const tbs = sequence(
            tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)])),
            gen(AT - DAY),
            sequence(single({ nextUpdate: AT + DAY })),
            notOctets,
        );
        const basic = sequence(tbs, ALG, universal(3, [0x00, 0xde]));
        const der = sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
        expect(codes(check(der, { nonce }))).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
    });

    it('should expose the nonce OID so a caller can find the echo itself', () => {
        expect(OCSP_NONCE_OID).toBe('1.3.6.1.5.5.7.48.1.2');
    });
});

describe('checkOcspStatus — several reasons at once', () => {
    it('should report every applicable reason, not only the first', () => {
        // A caller fixing one problem per round trip is a caller the report
        // failed.
        const stale = build({ singles: [single({ status: revokedStatus(AT - 30 * DAY), thisUpdate: AT - 40 * DAY, nextUpdate: AT - 10 * DAY })] });
        // The revoked answer of a response nobody authenticated is the third
        // UNKNOWN, not REVOKED: this pinned REVOKED until the 1.0 audit, and
        // RFC 6960 §3.2 accepts a response only once its signature is valid
        // and its signer authorised.
        expect(codes(check(stale, { signatureVerified: false, responderAuthorized: false }))).toEqual([
            'PKI_REASON_REVOCATION_STALE',
            'PKI_REASON_REVOCATION_UNKNOWN',
            'PKI_REASON_REVOCATION_UNKNOWN',
            'PKI_REASON_REVOCATION_UNKNOWN',
        ]);
    });

    it('should not report REVOKED on the word of a signer nobody authorised, or of a bad signature', () => {
        // An on-path attacker on plain-HTTP OCSP, or any key at all, could
        // otherwise have a report say "revoked (reason: keyCompromise)".
        const revoked = build({ singles: [single({ status: revokedStatus(AT - 30 * DAY) })] });
        for (const verdicts of [{ signatureVerified: true, responderAuthorized: false }, { signatureVerified: false, responderAuthorized: true }]) {
            const reasons = check(revoked, verdicts);
            expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN', 'PKI_REASON_REVOCATION_UNKNOWN']);
            expect(reasons[1]?.message).toContain('the response says this certificate was revoked on');
            expect(reasons[1]?.message).toContain('but the response is not authenticated');
            expect(reasons[1]?.message).toContain('(reason: keyCompromise)');
        }
    });

    it('should report UNKNOWN for a successful response with no body', () => {
        // `parseOcspResponse` refuses that combination, so this is only
        // reachable from a response object a caller built themselves — which
        // the type permits, so the guard has to be there and has to be tested.
        const reasons = checkOcspStatus({
            response: { der: new Uint8Array(0), status: 'successful', basicResponse: undefined, diagnostics: [] },
            expected: EXPECTED,
            at: AT,
            signatureVerified: true,
            responderAuthorized: true,
        });
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
        expect(reasons[0]?.message).toContain('no body');
    });

    it('should report MISMATCH for a nonce echo whose length is not a short form', () => {
        // A nonce is at most 32 octets (RFC 8954 §2.1), so a long-form length
        // here is not a nonce this code should try to read — and reading it
        // generously is how a nonce check starts passing on everything.
        const nonce = Uint8Array.of(1, 2, 3, 4);
        const longForm = tlv(2, true, 1, sequence(sequence(NONCE_OID, universal(4, [0x04, 0x81, 0x04, 1, 2, 3, 4]))));
        const tbs = sequence(
            tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)])),
            gen(AT - DAY),
            sequence(single({ nextUpdate: AT + DAY })),
            longForm,
        );
        const basic = sequence(tbs, ALG, universal(3, [0x00, 0xde]));
        const der = sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
        expect(codes(check(der, { nonce }))).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
    });

    it('should never throw for a status issue', () => {
        expect(() => check(build({ statusCode: 3 }), { signatureVerified: undefined, responderAuthorized: undefined })).not.toThrow();
    });
});
