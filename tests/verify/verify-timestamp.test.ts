import { describe, expect, it } from 'vitest';
import { encodeInteger, encodeSequence, encodeTlv } from '../../src/asn1/asn1-encode.js';
import { encodeDistinguishedName, encodeSubjectAltName } from '../../src/build/build-structures.js';
import { parseSignedData } from '../../src/cms/cms-signed-data.js';
import { createTimeStampRequest } from '../../src/cms/tsp-request.js';
import { PkiCmsError, PkiError } from '../../src/types/pki-errors.js';
import { verifyTimeStampToken, type VerifyTimeStampInput } from '../../src/verify/verify-timestamp.js';
import {
    AT,
    type Authority,
    codes,
    DAY,
    eku,
    flipLastOctetOf,
    type Holder,
    issueTsa,
    makeCrl,
    makeRoot,
    makeToken,
    OID,
    sha,
    signerInfosOf,
    tstInfo,
    withCertificates,
    withSigners,
} from './_cms-pki.js';

/**
 * `verifyTimeStampToken`: RFC 3161 §2.4.2's client checks, one call.
 *
 * Every token is signed here by a TSA whose key the test holds, so each
 * verdict is computed — the signature, the TSA's right to stamp, and what the
 * token stamps are all asked for real.
 */

const DATA = new TextEncoder().encode('the document that was stamped');

/** A TimeStampResp (RFC 3161 §2.4.2): PKIStatusInfo, then the token when there is one. */
const timeStampResp = (status: number, token?: Uint8Array, text?: string, failBit0 = false): Uint8Array => encodeSequence([
    encodeSequence([
        encodeInteger(status),
        ...(text === undefined ? [] : [encodeSequence([encodeTlv('universal', 12, false, new TextEncoder().encode(text))])]),
        ...(failBit0 ? [encodeTlv('universal', 3, false, Uint8Array.of(7, 0x80))] : []),
    ]),
    ...(token === undefined ? [] : [token]),
]);

interface World {
    readonly root: Authority;
    readonly tsa: Holder;
    readonly imprint: Uint8Array;
}

async function world(tsaOptions: Parameters<typeof issueTsa>[1] = {}): Promise<World> {
    const root = await makeRoot();
    return { root, tsa: await issueTsa(root, tsaOptions), imprint: await sha('SHA-256', DATA) };
}

const verify = async (w: World, token: Uint8Array, extra: Partial<VerifyTimeStampInput> = {}): ReturnType<typeof verifyTimeStampToken> =>
    verifyTimeStampToken({ token, data: DATA, trustAnchors: [w.root.certificate], at: AT, ...extra });

describe('verifyTimeStampToken', () => {
    describe('what was stamped', () => {
        it('should refuse to run without a request, the data or the imprint', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            const call = verifyTimeStampToken({ token, trustAnchors: [w.root.certificate] });
            await expect(call).rejects.toBeInstanceOf(PkiError);
            await expect(call).rejects.toMatchObject({ code: 'PKI_API_MISUSE' });
        });

        it('should refuse a call that passes both a token and a response, or neither', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            for (const call of [
                verifyTimeStampToken({ token, response: timeStampResp(0, token), data: DATA, trustAnchors: [w.root.certificate] }),
                verifyTimeStampToken({ data: DATA, trustAnchors: [w.root.certificate] }),
            ]) {
                await expect(call).rejects.toMatchObject({ code: 'PKI_API_MISUSE' });
            }
        });

        it('should refuse a request that is not a TimeStampReq with the CMS error', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            const call = verifyTimeStampToken({ token, request: encodeSequence([]), trustAnchors: [w.root.certificate] });
            await expect(call).rejects.toBeInstanceOf(PkiCmsError);
        });

        it('should accept a token that stamps the data, and fill in what it established', async () => {
            const w = await world();
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint })));
            expect(codes(report)).toEqual([]);
            expect(report.valid).toBe(true);
            expect(report.genTime?.epochMilliseconds).toBe(AT);
            expect(report.earliest).toBe(AT);
            expect(report.latest).toBe(AT);
            expect(report.tsaCertificate?.der).toEqual(w.tsa.certificate.der);
            expect(report.chain?.valid).toBe(true);
            expect(report.token?.tstInfo.serialNumber).toBeDefined();
            // The TSA's signature and the one link above it.
            expect(report.verified).toBe(2);
        });

        it('should accept a token that stamps the imprint the caller holds', async () => {
            const w = await world();
            const report = await verifyTimeStampToken({
                token: await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), imprint: w.imprint, trustAnchors: [w.root.certificate], at: AT,
            });
            expect(codes(report)).toEqual([]);
        });

        it('should accept a token that answers the request: imprint, nonce and policy', async () => {
            const w = await world();
            const request = createTimeStampRequest(w.imprint, { nonce: 42n, policy: OID.policy });
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint, nonce: 42n }));
            expect(codes(await verifyTimeStampToken({ token, request, trustAnchors: [w.root.certificate], at: AT }))).toEqual([]);
        });

        it('should hash the data with the token\'s own imprint algorithm (RFC 8933 §3.5)', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: await sha('SHA-512', DATA), hashOid: OID.sha512 }));
            expect(codes(await verify(w, token))).toEqual([]);
        });

        it('should report a token over other data as TSP_IMPRINT_MISMATCH, and establish no time', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: await sha('SHA-256', new TextEncoder().encode('other')) }));
            const report = await verify(w, token);
            expect(codes(report)).toEqual(['PKI_REASON_TSP_IMPRINT_MISMATCH']);
            expect(report.reasons[0]?.path).toBe('token.tstInfo.messageImprint');
            expect(report.valid).toBe(false);
            expect(report.genTime).toBeUndefined();
            expect(report.earliest).toBeUndefined();
            expect(report.latest).toBeUndefined();
            // The rest was still judged.
            expect(report.tsaCertificate?.der).toEqual(w.tsa.certificate.der);
        });

        it('should report an imprint the caller holds that differs', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            const report = await verifyTimeStampToken({ token, imprint: new Uint8Array(32), trustAnchors: [w.root.certificate], at: AT });
            expect(codes(report)).toEqual(['PKI_REASON_TSP_IMPRINT_MISMATCH']);
        });

        it('should report a request whose imprint names another algorithm, even over the same data', async () => {
            const w = await world();
            const request = createTimeStampRequest(await sha('SHA-384', DATA), { hashAlgorithm: 'SHA-384' });
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            expect(codes(await verifyTimeStampToken({ token, request, trustAnchors: [w.root.certificate], at: AT })))
                .toEqual(['PKI_REASON_TSP_IMPRINT_MISMATCH']);
        });

        it('should report a request whose hash differs under the same algorithm', async () => {
            const w = await world();
            const request = createTimeStampRequest(new Uint8Array(32).fill(7));
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            expect(codes(await verifyTimeStampToken({ token, request, trustAnchors: [w.root.certificate], at: AT })))
                .toEqual(['PKI_REASON_TSP_IMPRINT_MISMATCH']);
        });

        it('should say a mismatch once when the request, the imprint and the data all disagree with the token', async () => {
            const w = await world();
            const request = createTimeStampRequest(new Uint8Array(32).fill(7));
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            const report = await verifyTimeStampToken({
                token, request, imprint: new Uint8Array(32), data: new TextEncoder().encode('other'), trustAnchors: [w.root.certificate], at: AT,
            });
            expect(codes(report)).toEqual(['PKI_REASON_TSP_IMPRINT_MISMATCH']);
        });

        it('should report a token whose imprint digest pkinative does not compute as TSP_TOKEN_INVALID when given the data', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: new Uint8Array(28), hashOid: OID.sha224 }));
            const report = await verify(w, token);
            expect(codes(report)).toEqual(['PKI_REASON_TSP_TOKEN_INVALID']);
            expect(report.reasons[0]?.path).toBe('token.tstInfo.messageImprint');
            // The same token checked against the imprint the caller holds needs no hashing.
            expect(codes(await verifyTimeStampToken({ token, imprint: new Uint8Array(28), trustAnchors: [w.root.certificate], at: AT }))).toEqual([]);
        });

        it.each([
            ['a different nonce', 43n, 'the token echoes 43'],
            ['no nonce', undefined, 'echoes none'],
        ])('should report a token that echoes %s as TSP_REQUEST_MISMATCH — the replay RFC 3161 §2.4.2 guards against', async (_label, echoed, said) => {
            const w = await world();
            const request = createTimeStampRequest(w.imprint, { nonce: 42n });
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint, ...(echoed === undefined ? {} : { nonce: echoed }) }));
            const report = await verifyTimeStampToken({ token, request, trustAnchors: [w.root.certificate], at: AT });
            expect(codes(report)).toEqual(['PKI_REASON_TSP_REQUEST_MISMATCH']);
            expect(report.reasons[0]?.path).toBe('token.tstInfo.nonce');
            expect(report.reasons[0]?.message).toContain(said);
        });

        it('should report a token issued under another policy than the one requested', async () => {
            const w = await world();
            const request = createTimeStampRequest(w.imprint, { policy: '1.3.6.1.4.1.99999.2' });
            const report = await verifyTimeStampToken({ token: await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), request, trustAnchors: [w.root.certificate], at: AT });
            expect(codes(report)).toEqual(['PKI_REASON_TSP_REQUEST_MISMATCH']);
            expect(report.reasons[0]?.path).toBe('token.tstInfo.policy');
        });
    });

    describe('the token itself', () => {
        it('should report bytes that are not a token as INPUT_MALFORMED with the error that would have been thrown', async () => {
            const w = await world();
            const report = await verify(w, Uint8Array.of(0x30, 0x03, 0x02, 0x01));
            expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
            expect(report.reasons[0]?.path).toBe('token');
            expect(report.reasons[0]?.errorCode).toMatch(/^PKI_/);
            expect(report.token).toBeUndefined();
            expect(report.verified).toBe(0);
        });

        it('should take a profile concern in the token for what it is — not a verdict', async () => {
            const w = await world();
            // ordering FALSE written out, where DER omits a DEFAULT (X.690 §11.5): a diagnostic, silenced here.
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint, ordering: false })));
            expect(codes(report)).toEqual([]);
            expect(report.token?.tstInfo.ordering).toBe(false);
        });

        it('should report a signed message that is not over a TSTInfo as INPUT_MALFORMED', async () => {
            const w = await world();
            const message = await makeToken(w.tsa, DATA, { contentType: OID.data });
            const report = await verify(w, message);
            expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
            expect(report.reasons[0]?.errorCode).toBe('PKI_CMS_CONTENT_TYPE_UNEXPECTED');
        });

        it('should report a token with no signer as CMS_NO_SIGNERS', async () => {
            const w = await world();
            const token = withSigners(await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), []);
            const report = await verify(w, token);
            expect(codes(report)).toEqual(['PKI_REASON_CMS_NO_SIGNERS']);
            expect(report.reasons[0]?.path).toBe('token.signerInfos');
            expect(report.token).toBeDefined();
        });

        it('should report a token with a second signer as TSP_TOKEN_INVALID, and still judge the first', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            const [info] = signerInfosOf(token);
            const report = await verify(w, withSigners(token, [info as Uint8Array, info as Uint8Array]));
            expect(codes(report)).toEqual(['PKI_REASON_TSP_TOKEN_INVALID']);
            expect(report.reasons[0]?.path).toBe('token.signerInfos');
            expect(report.tsaCertificate?.der).toEqual(w.tsa.certificate.der);
        });

        it('should report a token whose signature was altered as SIGNATURE_INVALID, without a TSA', async () => {
            const w = await world({ family: 'Ed25519' });
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            const signature = parseSignedData(token).signerInfos[0]?.signature as Uint8Array;
            const report = await verify(w, flipLastOctetOf(token, signature));
            expect(codes(report)).toEqual(['PKI_REASON_SIGNATURE_INVALID']);
            expect(report.tsaCertificate).toBeUndefined();
            expect(report.chain).toBeUndefined();
        });

        it('should require the signing-certificate binding RFC 5816 makes mandatory for a TSA', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }), { signingCertificateV2: false });
            const report = await verify(w, token);
            expect(codes(report)).toEqual(['PKI_REASON_CMS_ATTRIBUTE_INVALID']);
            expect(report.reasons[0]?.path).toBe('token.signerInfos[0].signedAttrs.signingCertificate');
        });
    });

    describe('finding the TSA', () => {
        it('should find a TSA the token does not carry among the certificates passed — certReq FALSE', async () => {
            const w = await world();
            const token = withCertificates(await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), []);
            const missing = await verify(w, token);
            expect(codes(missing)).toEqual(['PKI_REASON_CMS_SIGNER_NOT_FOUND']);
            expect(missing.tsaCertificate).toBeUndefined();
            expect(missing.chain).toBeUndefined();
            expect(codes(await verify(w, token, { certificates: [w.tsa.certificate] }))).toEqual([]);
        });

        it('should skip a certificate in the bag that cannot be read, and say how many when the TSA is not found', async () => {
            const w = await world();
            const junk = encodeSequence([encodeInteger(1)]);
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            // Alongside the TSA's own certificate, the stranger changes nothing.
            expect(codes(await verify(w, withCertificates(token, [w.tsa.certificate.der, junk])))).toEqual([]);

            const report = await verify(w, withCertificates(token, [junk, junk]));
            expect(codes(report)).toEqual(['PKI_REASON_CMS_SIGNER_NOT_FOUND']);
            expect(report.reasons[0]?.message).toContain('2 certificate(s) in the message could not be read');
        });
    });

    describe('whether the TSA may stamp (RFC 3161 §2.3)', () => {
        it.each([
            ['no extKeyUsage', [], undefined],
            ['an extKeyUsage without timestamping', [eku([OID.codeSigning])], undefined],
            ['timestamping among other purposes', [eku([OID.timeStamping, OID.codeSigning])], 'exclusive'],
            ['a non-critical extKeyUsage', [eku([OID.timeStamping], false)], 'critical'],
        ] as const)('should report a TSA certificate with %s as PURPOSE_NOT_PERMITTED, once', async (_label, extensions, _rule) => {
            const w = await world({ extensions: [...extensions] });
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint })));
            // Said by the RFC 3161 check, and not said again by the chain.
            expect(codes(report)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
            expect(report.reasons[0]?.path).toBe('token.tsaCertificate.extKeyUsage');
            expect(report.chain?.valid).toBe(true);
        });

        it('should accept a non-critical timestamping extKeyUsage with allowNonCriticalTimestampingEku', async () => {
            const w = await world({ extensions: [eku([OID.timeStamping], false)] });
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), { allowNonCriticalTimestampingEku: true });
            expect(codes(report)).toEqual([]);
        });

        it('should still refuse timestamping among other purposes with allowNonCriticalTimestampingEku', async () => {
            const w = await world({ extensions: [eku([OID.timeStamping, OID.codeSigning], false)] });
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), { allowNonCriticalTimestampingEku: true });
            expect(codes(report)).toEqual(['PKI_REASON_PURPOSE_NOT_PERMITTED']);
        });

        it.each([
            ['before the TSA certificate was valid', AT - 2 * DAY, 'PKI_REASON_NOT_YET_VALID'],
            ['after the TSA certificate expired', AT + 10 * DAY, 'PKI_REASON_EXPIRED'],
        ])('should report a genTime %s', async (_label, genTime, code) => {
            const w = await world();
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint, genTime })));
            expect(codes(report)).toEqual([code]);
            expect(report.reasons[0]?.path).toBe('token.tsaCertificate');
        });
    });

    describe('the tsa name in the TSTInfo', () => {
        const directoryName = (cn: string): Uint8Array =>
            encodeTlv('context', 4, true, encodeDistinguishedName([[{ type: '2.5.4.3', value: cn }]]));
        const dnsName = (value: string): Uint8Array => encodeSubjectAltName([{ kind: 'dNSName', value }]).subarray(2);

        it('should accept the TSA\'s own subject', async () => {
            const w = await world();
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint, tsa: directoryName('CMS Test TSA') })));
            expect(codes(report)).toEqual([]);
        });

        it('should accept a name among the TSA\'s subjectAltName', async () => {
            const w = await world({ extensions: [eku([OID.timeStamping]), { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'tsa.example' }]) }] });
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint, tsa: dnsName('tsa.example') })));
            expect(codes(report)).toEqual([]);
        });

        it.each([
            ['another directory name', directoryName('Some Other TSA')],
            ['a DNS name, with no subjectAltName to hold it', dnsName('tsa.example')],
        ])('should report %s as TSP_TOKEN_INVALID', async (_label, name) => {
            const w = await world();
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint, tsa: name })));
            expect(codes(report)).toEqual(['PKI_REASON_TSP_TOKEN_INVALID']);
            expect(report.reasons[0]?.path).toBe('token.tstInfo.tsa');
        });
    });

    describe('whether you trust the TSA', () => {
        it('should report a TSA that chains to no anchor you trust, with the token otherwise good', async () => {
            const w = await world();
            // With no anchor at all, the root is nowhere to be found either, so
            // the TSA certificate's own signature goes unchecked too.
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), { trustAnchors: [] });
            expect(codes(report)).toEqual(['PKI_REASON_SIGNATURE_NOT_CHECKED', 'PKI_REASON_NO_TRUST_ANCHOR']);
            expect(report.reasons.every((reason) => reason.path.startsWith('token.tsaChain.'))).toBe(true);
            expect(report.tsaCertificate?.der).toEqual(w.tsa.certificate.der);

            const stranger = await makeRoot('Somebody Else');
            expect(codes(await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), { trustAnchors: [stranger.certificate] })))
                .toEqual(['PKI_REASON_SIGNATURE_NOT_CHECKED', 'PKI_REASON_NO_TRUST_ANCHOR']);
        });

        it('should judge the TSA\'s chain now when `at` is not given', async () => {
            const w = await world();
            // Every certificate here expired in early 2026.
            const report = await verifyTimeStampToken({ token: await makeToken(w.tsa, tstInfo({ imprint: w.imprint })), data: DATA, trustAnchors: [w.root.certificate] });
            expect(codes(report)).toContain('PKI_REASON_EXPIRED');
        });

        it('should report a revoked TSA from a CRL the caller passes, or one the token carries', async () => {
            const w = await world();
            const crl = await makeCrl(w.root, [w.tsa.certificate]);
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            expect(codes(await verify(w, token, { crls: [crl] }))).toEqual(['PKI_REASON_REVOKED']);
            expect(codes(await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint }), { crls: [crl] })))).toEqual(['PKI_REASON_REVOKED']);
        });

        it('should pass requireRevocation, ocsp, allowSha1 and limits on to the TSA\'s chain', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            const options = { ocsp: [], allowSha1: false, limits: { maxInputBytes: 1 << 20 } };
            expect(codes(await verify(w, token, { ...options, requireRevocation: true }))).toEqual(['PKI_REASON_REVOCATION_UNKNOWN']);
            expect(codes(await verify(w, token, { ...options, requireRevocation: true, crls: [await makeCrl(w.root)] }))).toEqual([]);
        });
    });

    describe('the time window', () => {
        it('should widen earliest and latest by the declared accuracy', async () => {
            const w = await world();
            // seconds 1, millis [0] 500, micros [1] 100: 1500.1 ms either way.
            const accuracy = encodeSequence([encodeInteger(1), encodeTlv('context', 0, false, Uint8Array.of(0x01, 0xf4)), encodeTlv('context', 1, false, Uint8Array.of(0x64))]);
            const report = await verify(w, await makeToken(w.tsa, tstInfo({ imprint: w.imprint, accuracy })));
            expect(codes(report)).toEqual([]);
            expect(report.earliest).toBeCloseTo(AT - 1500.1, 6);
            expect(report.latest).toBeCloseTo(AT + 1500.1, 6);
        });
    });

    describe('a whole TimeStampResp', () => {
        it('should verify the token inside a granted response as it verifies the token alone', async () => {
            const w = await world();
            const token = await makeToken(w.tsa, tstInfo({ imprint: w.imprint }));
            const report = await verifyTimeStampToken({ response: timeStampResp(0, token), data: DATA, trustAnchors: [w.root.certificate], at: AT });
            expect(codes(report)).toEqual([]);
            expect(report.valid).toBe(true);
            expect(report.token?.tstInfo.messageImprint.hashedMessage).toEqual(w.imprint);
        });

        it('should report a response that granted nothing as TSP_NOT_GRANTED, not as a malformed input', async () => {
            const w = await world();
            const report = await verifyTimeStampToken({ response: timeStampResp(2, undefined, 'unsupported digest', true), data: DATA, trustAnchors: [w.root.certificate], at: AT });
            expect(codes(report)).toEqual(['PKI_REASON_TSP_NOT_GRANTED']);
            expect(report.reasons[0]?.path).toBe('response.status');
            expect(report.valid).toBe(false);
            expect(report.token).toBeUndefined();
        });

        it('should report a response that is not a TimeStampResp as malformed input, at the response', async () => {
            const w = await world();
            const report = await verifyTimeStampToken({ response: encodeSequence([encodeInteger(1)]), data: DATA, trustAnchors: [w.root.certificate], at: AT });
            expect(codes(report)).toEqual(['PKI_REASON_INPUT_MALFORMED']);
            expect(report.reasons[0]?.path).toBe('response');
        });
    });
});
