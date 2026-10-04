import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDiagnosticEmitter, ocspResponderIdMismatchDiagnostic } from '../../src/core/pki-diagnostics.js';
import { sha1 } from '../../src/hash/sha1.js';
import { checkOcspStatus, OCSP_NONCE_OID, type CheckOcspStatusInput } from '../../src/revocation/ocsp-check.js';
import { parseOcspResponse } from '../../src/revocation/ocsp-response.js';
import type { PkiDiagnostic } from '../../src/types/pki-types.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { ascii, concat, sequence, tlv, universal } from '../helpers/raw-der-builder.js';

afterEach(() => {
    vi.restoreAllMocks();
});

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
    /** The responderID TLV; byKey of twenty 0xcc octets by default. */
    readonly responderId?: Uint8Array;
}

function build(parts: ResponseParts = {}): Uint8Array {
    if (parts.statusCode !== undefined && parts.statusCode !== 0) {
        return sequence(universal(10, [parts.statusCode]));
    }
    const extensions = parts.nonce === undefined || parts.nonce === null
        ? []
        : [tlv(2, true, 1, sequence(sequence(NONCE_OID, universal(4, [...universal(4, [...parts.nonce])]))))];
    const tbs = sequence(
        parts.responderId ?? tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)])),
        gen(AT - DAY),
        sequence(...(parts.singles ?? [single({ nextUpdate: AT + DAY })])),
        ...extensions,
    );
    const basic = sequence(tbs, ALG, universal(3, [0x00, 0xde]));
    return sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
}

const check = (der: Uint8Array, overrides: Partial<CheckOcspStatusInput> = {}): readonly { code: string; message: string; path: string }[] =>
    checkOcspStatus({
        response: parseOcspResponse(der, quiet),
        expected: EXPECTED,
        at: AT,
        signatureVerified: true,
        responderAuthorized: true,
        onDiagnostic: quiet.onDiagnostic,
        ...overrides,
    });

/** `check`, with what the decision says through `onDiagnostic` kept beside its reasons. */
function diagnosed(der: Uint8Array, overrides: Partial<CheckOcspStatusInput> = {}): { readonly reasons: readonly { code: string }[]; readonly diagnostics: readonly PkiDiagnostic[] } {
    const diagnostics: PkiDiagnostic[] = [];
    const reasons = check(der, { onDiagnostic: (d) => { diagnostics.push(d); }, ...overrides });
    return { reasons, diagnostics };
}

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

    it('should treat a missing nextUpdate as stale by default, as a CRL does', () => {
        // RFC 6960 §4.2.2.1: an absent nextUpdate means newer information is
        // available all the time — the answer vouches for thisUpdate and for
        // nothing after it. A good from five years ago is not a good today.
        const ancient = check(build({ singles: [single({ thisUpdate: AT - 5 * 365 * DAY, nextUpdate: null })] }));
        expect(ancient.map((r) => [r.code, r.path])).toEqual([['PKI_REASON_REVOCATION_STALE', 'ocsp']]);
        expect(codes(check(build({ singles: [single({ nextUpdate: null })] })))).toEqual(['PKI_REASON_REVOCATION_STALE']);
    });

    it('should measure the tolerance from thisUpdate when there is no nextUpdate', () => {
        // How a caller holding a response it just fetched accepts it: thisUpdate
        // is a day before AT, so a day of tolerance is exactly enough.
        const fetched = build({ singles: [single({ thisUpdate: AT - DAY, nextUpdate: null })] });
        expect(check(fetched, { staleTolerance: DAY })).toEqual([]);
        expect(codes(check(fetched, { staleTolerance: DAY - 1 }))).toEqual(['PKI_REASON_REVOCATION_STALE']);
        // With a nextUpdate the tolerance is still measured from it.
        expect(check(build({ singles: [single({ thisUpdate: AT - DAY, nextUpdate: AT })] }))).toEqual([]);
    });

    it('should not call a revocation without nextUpdate stale: a published revocation stands', () => {
        const reasons = check(build({ singles: [single({ status: revokedStatus(AT - 30 * DAY), thisUpdate: AT - 5 * 365 * DAY, nextUpdate: null })] }));
        expect(codes(reasons)).toEqual(['PKI_REASON_REVOKED']);
    });

    it('should report UNKNOWN for two answers about this certificate that disagree, in either order', () => {
        // First-wins would let the order of the SEQUENCE decide the verdict.
        const good = single({ nextUpdate: AT + DAY });
        const revoked = single({ status: revokedStatus(AT - DAY), nextUpdate: AT + DAY });
        for (const singles of [[good, revoked], [revoked, good]]) {
            const reasons = check(build({ singles }));
            expect(reasons.map((r) => [r.code, r.path])).toEqual([['PKI_REASON_REVOCATION_UNKNOWN', 'ocsp']]);
            expect(reasons[0]?.message).toContain('disagree');
        }
    });

    it('should accept two answers about this certificate that agree', () => {
        const good = single({ nextUpdate: AT + DAY });
        expect(check(build({ singles: [good, good] }))).toEqual([]);
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

describe('checkOcspStatus — the edges of the nonce echo and of freshness', () => {
    /** A response whose nonce extension carries exactly these octets as its value. */
    const echoing = (value: readonly number[]): Uint8Array => {
        const tbs = sequence(
            tlv(2, true, 2, universal(4, [...new Array<number>(20).fill(0xcc)])),
            gen(AT - DAY),
            sequence(single({ nextUpdate: AT + DAY })),
            tlv(2, true, 1, sequence(sequence(NONCE_OID, universal(4, [...value])))),
        );
        const basic = sequence(tbs, ALG, universal(3, [0x00, 0xde]));
        return sequence(universal(10, [0x00]), tlv(2, true, 0, sequence(OID_BASIC, universal(4, [...basic]))));
    };
    const run = (n: number, from = 1): number[] => Array.from({ length: n }, (_, i) => (from + i) & 0xff);

    it.each([
        // An empty OCTET STRING is an empty echo, and matches an empty nonce.
        { what: 'an empty OCTET STRING, for an empty nonce', value: [0x04, 0x00], sent: [], codes: [] },
        { what: 'a lone tag', value: [0x04], sent: [], codes: ['PKI_REASON_REVOCATION_MISMATCH'] },
        { what: 'another type, empty', value: [0x05, 0x00], sent: [], codes: ['PKI_REASON_REVOCATION_MISMATCH'] },
        { what: 'a long-form length over exactly the nonce', value: [0x04, 0x81, 1, 2, 3], sent: [1, 2, 3], codes: ['PKI_REASON_REVOCATION_MISMATCH'] },
        { what: 'a long-form length that fits', value: [0x04, 0x81, ...run(129)], sent: run(129), codes: ['PKI_REASON_REVOCATION_MISMATCH'] },
        { what: 'the indefinite-length marker', value: [0x04, 0x80, ...run(128)], sent: run(128), codes: ['PKI_REASON_REVOCATION_MISMATCH'] },
        { what: 'the longest short form, 127 octets', value: [0x04, 0x7f, ...run(127)], sent: run(127), codes: [] },
        { what: 'a length past the end', value: [0x04, 0x03, 1, 2], sent: [1, 2], codes: ['PKI_REASON_REVOCATION_MISMATCH'] },
        { what: 'a trailing octet after the OCTET STRING', value: [0x04, 0x02, 1, 2, 9], sent: [1, 2], codes: [] },
    ])('should read $what', ({ value, sent, codes: expected }) => {
        expect(codes(check(echoing(value), { nonce: Uint8Array.from(sent) }))).toEqual(expected);
    });

    it('should allow a thisUpdate a minute ahead, and not a millisecond more', () => {
        expect(check(build({ singles: [single({ thisUpdate: AT + MINUTE, nextUpdate: AT + DAY })] }))).toEqual([]);
        expect(codes(check(build({ singles: [single({ thisUpdate: AT + MINUTE + 1000, nextUpdate: AT + DAY })] }))))
            .toEqual(['PKI_REASON_REVOCATION_STALE']);
        // A minute is sixty thousand milliseconds, not one more.
        expect(codes(check(build({ singles: [single({ thisUpdate: AT + MINUTE, nextUpdate: AT + DAY })] }), { at: AT - 1 })))
            .toEqual(['PKI_REASON_REVOCATION_STALE']);
    });

    it('should hold a response current up to its nextUpdate, inclusive', () => {
        expect(check(build({ singles: [single({ nextUpdate: AT })] }))).toEqual([]);
        expect(check(build({ singles: [single({ nextUpdate: AT - DAY })] }), { staleTolerance: DAY })).toEqual([]);
        expect(codes(check(build({ singles: [single({ nextUpdate: AT - 1000 })] })))).toEqual(['PKI_REASON_REVOCATION_STALE']);
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

describe('checkOcspStatus — what the response says about itself (RFC 6960 §4.2.2.2.1, §4.2.2.3)', () => {
    // A signer as checkOcspStatus reads one: its subject bytes, its public key
    // bits and its extensions. Nothing else of a certificate is consulted.
    const SUBJECT = sequence(universal(17, sequence(universal(6, [0x55, 0x04, 0x03]), universal(12, ascii('Responder'))), true));
    const OTHER_SUBJECT = sequence(universal(17, sequence(universal(6, [0x55, 0x04, 0x03]), universal(12, ascii('Somebody'))), true));
    const KEY_BITS = Uint8Array.from(ascii('the responder key bits'));
    const signerWith = (extensions: readonly object[] = []): Certificate =>
        ({ subject: { der: SUBJECT }, subjectPublicKeyInfo: { publicKey: { bytes: KEY_BITS } }, extensions } as unknown as Certificate);
    const byName = (name: Uint8Array): Uint8Array => tlv(2, true, 1, name);
    const byKey = (hash: Uint8Array): Uint8Array => tlv(2, true, 2, universal(4, [...hash]));
    const NO_CHECK = '1.3.6.1.5.5.7.48.1.5';

    it('should diagnose a responderID that names neither the subject nor the key hash of the signer, and accept one that does (RFC 6960 §4.2.2.3)', () => {
        const signer = signerWith();
        expect(diagnosed(build({ responderId: byName(SUBJECT) }), { signer }).diagnostics).toEqual([]);
        expect(diagnosed(build({ responderId: byKey(sha1(KEY_BITS)) }), { signer }).diagnostics).toEqual([]);

        const name = diagnosed(build({ responderId: byName(OTHER_SUBJECT) }), { signer });
        expect(name.diagnostics.map((d) => [d.code, d.severity, d.path])).toEqual([['PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH', 'warning', 'ocsp.responderID']]);
        expect(name.diagnostics[0]?.message).toContain('names a subject');
        const key = diagnosed(build(), { signer });
        expect(key.diagnostics.map((d) => d.code)).toEqual(['PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH']);
        expect(key.diagnostics[0]?.message).toContain('key hash');
        // The verdict is the signature's, not the claim's.
        expect(name.reasons).toEqual([]);
        expect(key.reasons).toEqual([]);
        // Without the signer there is nothing to compare, and nothing is said.
        expect(diagnosed(build()).diagnostics).toEqual([]);
    });

    it('should diagnose a signer whose id-pkix-ocsp-nocheck is critical, and say nothing of one that is not (RFC 6960 §4.2.2.2.1)', () => {
        const honest = build({ responderId: byName(SUBJECT) });
        const critical = diagnosed(honest, { signer: signerWith([{ kind: 'ocspNoCheck', oid: NO_CHECK, critical: true }]) });
        expect(critical.diagnostics.map((d) => [d.code, d.severity, d.path])).toEqual([['PKI_DIAG_OCSP_NOCHECK_CRITICAL', 'info', 'ocsp.signer.ocspNoCheck']]);
        expect(critical.reasons).toEqual([]);
        expect(diagnosed(honest, { signer: signerWith([{ kind: 'ocspNoCheck', oid: NO_CHECK, critical: false }]) }).diagnostics).toEqual([]);
        expect(diagnosed(honest, { signer: signerWith([{ kind: 'basicConstraints', oid: '2.5.29.19', critical: true }]) }).diagnostics).toEqual([]);
        // Both claims wrong at once: both said, the responderID first.
        expect(diagnosed(build(), { signer: signerWith([{ kind: 'ocspNoCheck', oid: NO_CHECK, critical: true }]) }).diagnostics.map((d) => d.code))
            .toEqual(['PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH', 'PKI_DIAG_OCSP_NOCHECK_CRITICAL']);
    });

    it('should diagnose SingleResponse elements about certificates nobody asked about, beside the answer that was (RFC 6960 §4.2.2.3)', () => {
        const other = (serial: number): Uint8Array => single({ id: certId({ serial: [serial] }), nextUpdate: AT + DAY });
        const right = single({ nextUpdate: AT + DAY });
        const one = diagnosed(build({ singles: [other(0x99), right] }));
        expect(one.reasons).toEqual([]);
        expect(one.diagnostics.map((d) => [d.code, d.severity, d.path])).toEqual([['PKI_DIAG_OCSP_SINGLE_RESPONSE_UNREQUESTED', 'info', 'ocsp.responses']]);
        expect(one.diagnostics[0]?.message).toContain('1 SingleResponse element(s)');
        expect(diagnosed(build({ singles: [other(0x98), right, other(0x99)] })).diagnostics[0]?.message).toContain('2 SingleResponse element(s)');
        // Alone, or twice about the same certificate: nothing unasked for.
        expect(diagnosed(build({ singles: [right] })).diagnostics).toEqual([]);
        expect(diagnosed(build({ singles: [right, right] })).diagnostics).toEqual([]);
        // Without the answer asked about, the response is a mismatch, said once
        // as a reason — not again as a diagnostic.
        const mismatch = diagnosed(build({ singles: [other(0x99)] }));
        expect(codes(mismatch.reasons)).toEqual(['PKI_REASON_REVOCATION_MISMATCH']);
        expect(mismatch.diagnostics).toEqual([]);
    });

    it('should warn once on the console without a handler, as every primitive does, and a strict emitter refuses the warning', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        expect(check(build(), { signer: signerWith(), onDiagnostic: undefined })).toEqual([]);
        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn.mock.calls[0]?.[0]).toContain('[PKI_DIAG_OCSP_RESPONDER_ID_MISMATCH]');
        // checkOcspStatus itself never throws; the severity is what a strict
        // parse would refuse, and the emitter is where that is decided.
        expect(() => createDiagnosticEmitter(true, undefined).emit(ocspResponderIdMismatchDiagnostic('ocsp', 'byKey')))
            .toThrow(expect.objectContaining({ code: 'PKI_STRICT_DIAGNOSTIC' }));
    });
});

describe('the freshness tolerances', () => {
    // A NaN compares false with everything and a negative tolerance moves the window the wrong way:
    // either one silently disables the check it tunes, so both are the caller's mistake, said as such.
    it.each([
        ['futureTolerance', Number.NaN],
        ['futureTolerance', -1],
        ['staleTolerance', Number.POSITIVE_INFINITY],
        ['staleTolerance', -0.5],
    ] as const)('should refuse %s = %s as PKI_INVALID_OPTION', (name, value) => {
        expect(() => check(build(), { [name]: value })).toThrow(expect.objectContaining({ code: 'PKI_INVALID_OPTION', message: expect.stringContaining(name) }));
    });

    it('should accept zero for both — the strictest window', () => {
        expect(() => check(build(), { futureTolerance: 0, staleTolerance: 0 })).not.toThrow();
    });
});
