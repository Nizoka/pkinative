/**
 * Recipe: prove when a signature existed — ask a timestamp authority
 * (RFC 3161), check its answer, attach it to the signature, and judge the
 * signer at the time the token proves instead of today.
 *
 * A token says that **a hash existed at a time**, and only once three things
 * are established: the hash is the one you care about, a TSA signed it, and
 * that TSA was entitled to. `verifyTimeStampToken` makes every check of
 * RFC 3161 §2.4.2 in one call and never throws for a verdict.
 *
 * There is no network here, so the recipe plays the TSA itself: a TSTInfo
 * built with the public encoders and signed with `createSignedData`, which is
 * all a timestamp token is — a SignedData over a TSTInfo. In production the
 * request is POSTed to the TSA and its answer read with
 * `parseTimeStampResponse`, exactly as below.
 */
import {
    addTimeStampToken,
    canSign,
    createCertificate,
    createSignedData,
    createTimeStampRequest,
    encodeAlgorithmIdentifier,
    encodeBasicConstraints,
    encodeExtendedKeyUsage,
    encodeInteger,
    encodeKeyUsage,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeSequence,
    encodeTime,
    KEY_PURPOSES,
    parseCertificate,
    parseSignedData,
    parseTimeStampResponse,
    parseTimeStampToken,
    parseTstInfo,
    PkiCmsError,
    verifySignedData,
    verifyTimeStampToken,
    type Certificate,
    type CreateTimeStampRequestOptions,
    type SigningKey,
    type TimeStampResponse,
    type TimeStampToken,
    type TstInfo,
    type VerifyTimeStampInput,
    type VerifyTimeStampReport,
} from 'pkinative';

const NOW = Date.UTC(2026, 0, 15);
const DAY = 86_400_000;
const CN = '2.5.4.3';
const SHA256 = '2.16.840.1.101.3.4.2.1';
const ID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const quiet = { onDiagnostic: () => undefined };
const codes = (report: { reasons: readonly { code: string; path: string }[] }): string =>
    report.reasons.map((reason) => `${reason.code}@${reason.path}`).join(' ') || 'none';

async function keyPair(): Promise<{ signer: SigningKey; spki: Uint8Array }> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return {
        signer: { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } },
        spki: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
    };
}

/**
 * The TSA's side, played locally: RFC 3161 §2.4.2's TSTInfo — version,
 * policy, the imprint it was asked to stamp, a serial, genTime, an accuracy
 * of one second, and the request's nonce echoed — signed as a SignedData
 * whose content type is id-ct-TSTInfo, wrapped in a granted TimeStampResp.
 */
async function answer(imprint: Uint8Array, nonce: bigint, genTime: number, tsa: Certificate, key: SigningKey): Promise<Uint8Array> {
    const tstInfo = encodeSequence([
        encodeInteger(1n),
        encodeObjectIdentifier('1.3.6.1.4.1.99999.2'),
        encodeSequence([encodeAlgorithmIdentifier(SHA256), encodeOctetString(imprint)]),
        encodeInteger(20260115n),
        encodeTime(genTime, 'GeneralizedTime'),
        encodeSequence([encodeInteger(1n)]),
        encodeInteger(nonce),
    ]);
    // A token must carry SigningCertificateV2 (RFC 5816), which createSignedData writes by default.
    const token = await createSignedData({ content: tstInfo, contentType: ID_CT_TSTINFO, certificate: tsa }, key);
    return encodeSequence([encodeSequence([encodeInteger(0n)]), token]);   // PKIStatusInfo { granted }, token
}

export default async function run(): Promise<Record<string, string>> {
    if (!canSign()) return { available: 'no' };

    // ── A root, a document signer whose certificate lives one day, and a TSA ──
    const ca = await keyPair();
    const root = parseCertificate(await createCertificate({
        serialNumber: 1n,
        subject: [[{ type: CN, value: 'Example Root' }]],
        notBefore: NOW - 30 * DAY,
        notAfter: NOW + 3650 * DAY,
        subjectPublicKey: ca.spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
        ],
    }, ca.signer), quiet);
    const issue = async (serial: bigint, name: string, spki: Uint8Array, lifetime: number, extension: { oid: string; critical: boolean; value: Uint8Array }): Promise<Certificate> =>
        parseCertificate(await createCertificate({
            serialNumber: serial, issuerDer: root.subject.der, subject: [[{ type: CN, value: name }]],
            notBefore: NOW - DAY, notAfter: NOW + lifetime, subjectPublicKey: spki, extensions: [extension],
        }, ca.signer), quiet);
    const signerKey = await keyPair();
    const signer = await issue(2n, 'Example Signer', signerKey.spki, DAY,
        { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) });
    // RFC 3161 §2.3: the TSA's extKeyUsage is present, critical, and names timeStamping alone.
    const tsaKey = await keyPair();
    const tsa = await issue(3n, 'Example TSA', tsaKey.spki, 30 * DAY,
        { oid: '2.5.29.37', critical: true, value: encodeExtendedKeyUsage([KEY_PURPOSES.timeStamping]) });

    // ── Sign, then ask for a signature timestamp ──
    const document = new TextEncoder().encode('Contract, version 3.');
    const p7s = await createSignedData({ content: document, detached: true, certificate: signer }, signerKey.signer);

    // What is stamped is the hash of the signature VALUE (RFC 3161 Appendix A)
    // — not the document, not the signed attributes.
    const signature = parseSignedData(p7s).signerInfos[0]?.signature ?? new Uint8Array(0);
    const imprint = new Uint8Array(await crypto.subtle.digest('SHA-256', signature));
    // The nonce is what makes a replayed answer detectable; pkinative
    // generates none. certReq (true by default) asks the TSA to embed its
    // certificate, so the verifier does not have to find it.
    const nonce = new DataView(crypto.getRandomValues(new Uint8Array(8)).buffer).getBigUint64(0);
    const options: CreateTimeStampRequestOptions = { hashAlgorithm: 'SHA-256', nonce, certReq: true };
    const request = createTimeStampRequest(imprint, options);
    // In production: POST `request` as application/timestamp-query and read the body.
    const responseDer = await answer(imprint, nonce, NOW, tsa, tsaKey.signer);

    // ── Read the answer ──
    const response: TimeStampResponse = parseTimeStampResponse(responseDer);
    if (response.status !== 'granted' && response.status !== 'grantedWithMods') {
        return { available: 'yes', declined: `${response.status} ${response.failInfo.join(',')}` };
    }
    const tokenDer = response.tokenDer ?? new Uint8Array(0);
    const token: TimeStampToken = parseTimeStampToken(tokenDer);
    const info: TstInfo = parseTstInfo(token.tstInfo.der);

    // ── Judge the token ──
    // `request` is the strongest way to say what was stamped — the only one
    // that catches a replayed response. `data` and `imprint` are the others.
    const ask: VerifyTimeStampInput = { token: tokenDer, request, trustAnchors: [root], at: NOW };
    const stamp: VerifyTimeStampReport = await verifyTimeStampToken(ask);
    // Yesterday's answer, replayed against a new request with a new nonce.
    const replayed = await verifyTimeStampToken({ ...ask, request: createTimeStampRequest(imprint, { nonce: nonce ^ 1n }) });
    // A token over something else: the document instead of the signature value.
    const wrongThing = await verifyTimeStampToken({ token: tokenDer, data: document, trustAnchors: [root], at: NOW });

    // ── Attach it: CAdES-T, PAdES B-T ──
    // Surgery on the encoding: every signed octet is copied unchanged.
    const stamped = addTimeStampToken(p7s, 0, tokenDer);
    const later = NOW + 10 * DAY;   // the signer's certificate expired nine days ago
    const base = { signedData: stamped, content: document, trustAnchors: [root] };
    // Judged today, the signer's certificate has expired.
    const today = await verifySignedData({ ...base, at: later });
    // atTimeStamp judges the signer's chain at the time its verified token
    // proves — genTime plus the declared accuracy — which is the long-term
    // question: was the certificate good when this was signed?
    const whenSigned = await verifySignedData({ ...base, at: later, atTimeStamp: true });
    // The TSA's own chain is still judged at `at`, never at the genTime its
    // token asserts: otherwise a TSA key compromised after its certificate
    // expired could backdate tokens that would then be believed. Once the TSA
    // certificate has expired too, only an archive timestamp (PAdES B-LTA)
    // can carry the proof further.
    const afterTsa = await verifySignedData({ ...base, at: NOW + 40 * DAY, atTimeStamp: true });

    // ── A PkiCmsError: the wrong kind of SignedData ──
    // The signature itself is a SignedData over id-data, not over a TSTInfo.
    let notAToken = 'none';
    try {
        parseTimeStampToken(p7s);
    } catch (error) {
        if (!(error instanceof PkiCmsError)) throw error;
        notAToken = error.code;
    }

    return {
        available: 'yes',
        status: response.status,
        tstInfo: `policy=${info.policy} serial=${String(info.serialNumber.value)} genTime=${info.genTime.text} accuracy=${String(info.accuracy?.seconds)}s nonceEchoed=${String(info.nonce === nonce)}`,
        tokenSignedBy: token.signedData.contentType === ID_CT_TSTINFO ? 'id-ct-TSTInfo' : token.signedData.contentType,
        valid: `valid=${String(stamp.valid)} window=${String((stamp.earliest ?? 0) - NOW)}..${String((stamp.latest ?? 0) - NOW)}ms tsa=${String(stamp.tsaCertificate?.serialNumber.value)}`,
        replayed: codes(replayed),
        wrongThing: codes(wrongThing),
        timeStamps: String(parseSignedData(stamped).signerInfos[0]?.timeStampTokens.length),
        today: codes(today),
        whenSigned: `valid=${String(whenSigned.valid)} stampValid=${String(whenSigned.signers[0]?.timeStamps[0]?.valid)}`,
        afterTsa: codes(afterTsa),
        afterTsaIntact: String(afterTsa.signers[0]?.intact),
        notAToken,
    };
}
