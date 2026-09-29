/**
 * Recipe: sign a message as an RFC 5652 CMS SignedData, verify it the whole
 * way, and read the verdict apart.
 *
 * `createSignedData` writes the `.p7s`; `verifySignedData` answers the one
 * question a PDF validator, an S/MIME client and a code-signing check all
 * ask — *is this what its signer signed, and do I trust the signer?* — and
 * answers it as a report, never as an exception. Two booleans in that report
 * are worth keeping apart: `intact` needs no trust store (the content hashes
 * to what was committed, the signature verifies, the certificate is the one
 * the signer named), and `valid` adds the chain. `intact` without `valid`
 * means *unaltered, but not by anybody you trust*.
 *
 * The keys are the caller's, generated here with Web Crypto; pkinative
 * generates none.
 */
import {
    addUnsignedAttribute,
    canSign,
    createCertificate,
    createSignedData,
    encodeAttribute,
    encodeBasicConstraints,
    encodeKeyUsage,
    encodeString,
    getOidName,
    parseCertificate,
    parseSignedData,
    PkiCmsError,
    PkiError,
    verifySignedData,
    verifySignerInfoSignature,
    type Certificate,
    type CreateSignedDataInput,
    type ParseSignedDataOptions,
    type SignedData,
    type SignerInfo,
    type SigningKey,
    type VerifySignedDataInput,
    type VerifySignedDataReport,
} from 'pkinative';

const NOW = Date.UTC(2026, 0, 15);
const DAY = 86_400_000;
const CN = '2.5.4.3';
const quiet = { onDiagnostic: () => undefined };
const codes = (report: VerifySignedDataReport): string => report.reasons.map((reason) => reason.code).join(' ') || 'none';

/** A key pair the caller holds, and the SPKI pkinative is given instead of the public key. */
async function keyPair(): Promise<{ signer: SigningKey; spki: Uint8Array }> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return {
        signer: { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } },
        spki: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
    };
}

/** A root, and a signer certificate it issued — the smallest hierarchy a verdict can trust. */
async function hierarchy(): Promise<{ root: Certificate; signer: Certificate; signerKey: SigningKey }> {
    const ca = await keyPair();
    const leaf = await keyPair();
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
    const signer = parseCertificate(await createCertificate({
        serialNumber: 2n,
        issuerDer: root.subject.der,
        subject: [[{ type: CN, value: 'Example Signer' }]],
        notBefore: NOW - DAY,
        notAfter: NOW + 365 * DAY,
        subjectPublicKey: leaf.spki,
        extensions: [{ oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature', 'nonRepudiation']) }],
    }, ca.signer), quiet);
    return { root, signer, signerKey: leaf.signer };
}

export default async function run(): Promise<Record<string, string>> {
    if (!canSign()) return { available: 'no' };
    const { root, signer, signerKey } = await hierarchy();
    const message = new TextEncoder().encode('Pay 100 EUR to account 42.');

    // ── Sign ──
    // Detached, as a PDF signature and most S/MIME are: the .p7s carries the
    // signature, not what it signs. Signed attributes are always written —
    // contentType, messageDigest, SigningCertificateV2 and
    // CMSAlgorithmProtection by default, signingTime when you give one.
    const input: CreateSignedDataInput = { content: message, detached: true, certificate: signer, signingTime: NOW };
    const p7s = await createSignedData(input, signerKey);
    // Attached: the content travels inside, and the verifier needs nothing else.
    const p7m = await createSignedData({ content: message, certificate: signer }, signerKey);

    // ── Verify ──
    // `trustAnchors` is required, as for a chain. `at` is the instant the
    // chain is judged at — now by default.
    const ask: VerifySignedDataInput = { signedData: p7s, content: message, trustAnchors: [root], at: NOW };
    const good = await verifySignedData(ask);
    const attached = await verifySignedData({ signedData: p7m, trustAnchors: [root], at: NOW });

    // Absent content is never read as empty content: a detached signature
    // verified without its content is a reason, not a pass.
    const missing = await verifySignedData({ ...ask, content: undefined });
    // One changed byte: the signature still verifies over the attributes, and
    // the content no longer hashes to the messageDigest they commit to.
    const tampered = await verifySignedData({ ...ask, content: new TextEncoder().encode('Pay 900 EUR to account 42.') });
    // Nobody to trust: unaltered, but not by anybody you know.
    const untrusted = await verifySignedData({ ...ask, trustAnchors: [] });
    // The signer's certificate judged a year and a day later, when it has expired.
    const late = await verifySignedData({ ...ask, at: NOW + 366 * DAY });

    // ── Inspect ──
    // parseSignedData reads without judging. `content` is undefined for a
    // detached message; the certificates stay DER, because the bag is a claim
    // by whoever assembled it and parsing it all up front would spend work on
    // certificates nobody asks about.
    const parsed: SignedData = parseSignedData(p7s);
    const signerInfo: SignerInfo | undefined = parsed.signerInfos[0];
    if (signerInfo === undefined) throw new Error('a message createSignedData wrote has one signer');
    const attributes = (signerInfo.signedAttributes ?? []).map((attribute) => getOidName(attribute.oid) ?? attribute.oid).sort().join(',');

    // ── One signature, at the low level ──
    // verifySignerInfoSignature answers only "did this key sign these
    // attributes?". It reads no messageDigest, no sid and no chain — so it is
    // `true` for the tampered message above too. Use it to build a verifier,
    // never as the verdict on a message.
    const byKey = `${String(await verifySignerInfoSignature(signerInfo, signer))},${String(await verifySignerInfoSignature(signerInfo, root))}`;

    // ── Profiles that demand more ──
    // A signer that omitted SigningCertificateV2 and CMSAlgorithmProtection is
    // valid by default — RFC 5652 requires neither — and invalid for a caller
    // enforcing CAdES/PAdES (requireSigningCertificate) or RFC 6211
    // (requireAlgorithmProtection).
    const bare = await createSignedData({ ...input, signingCertificateV2: false, algorithmProtection: false }, signerKey);
    const lenient = await verifySignedData({ ...ask, signedData: bare });
    const strict = await verifySignedData({ ...ask, signedData: bare, requireSigningCertificate: true, requireAlgorithmProtection: true });

    // ── An unsigned attribute, added after signing ──
    // Nothing covers the unsigned attributes, so adding one leaves every
    // signed octet — and the verdict — unchanged. addTimeStampToken is this
    // call with the RFC 3161 attribute written for you (see timestamp.ts).
    const annotated = addUnsignedAttribute(p7s, 0, encodeAttribute('1.3.6.1.4.1.99999.1', [encodeString('utf8', 'archived by the example')]));
    const stillGood = await verifySignedData({ ...ask, signedData: annotated });

    // ── The three vocabularies ──
    // A PDF /Contents is a zero-padded placeholder: the padding is trailing
    // data, refused unless you say it is expected.
    const padded = new Uint8Array(p7s.length + 64);
    padded.set(p7s);
    const pdfContents: ParseSignedDataOptions = { allowTrailingData: true };
    const fromPdf = parseSignedData(padded, pdfContents).signerInfos.length;

    // Thrown: parseSignedData is a primitive, so bytes that are not a
    // SignedData are a PkiCmsError with a stable code and a path — here, a
    // certificate handed over where a .p7s was expected.
    let thrown = 'none';
    try {
        parseSignedData(root.der);
    } catch (error) {
        if (!(error instanceof PkiCmsError)) throw error;
        thrown = `${error.code}@${error.path ?? ''}`;
    }
    // Returned: verifySignedData is a composition, so the same bytes are a
    // reason that carries the code that would have been thrown.
    const malformed = await verifySignedData({ signedData: root.der, trustAnchors: [root] });
    const wrapped = malformed.reasons.map((reason) => `${reason.code}(${reason.errorCode ?? ''})`).join(' ');
    // Thrown, still: the call itself is wrong — content given for a message
    // that carries its own is two answers to which bytes were signed.
    let misuse = 'none';
    try {
        await verifySignedData({ signedData: p7m, content: message, trustAnchors: [root] });
    } catch (error) {
        if (!(error instanceof PkiError)) throw error;
        misuse = error.code;
    }

    return {
        available: 'yes',
        detached: `valid=${String(good.valid)} intact=${String(good.signers[0]?.intact)} signatureVerifications=${String(good.signatureVerifications)}`,
        attached: `valid=${String(attached.valid)} content=${new TextDecoder().decode(attached.signedData?.content)}`,
        missing: codes(missing),
        tampered: `intact=${String(tampered.signers[0]?.intact)} ${codes(tampered)}`,
        untrusted: `intact=${String(untrusted.signers[0]?.intact)} valid=${String(untrusted.valid)}`,
        untrustedWhy: untrusted.reasons.some((reason) => reason.code === 'PKI_REASON_NO_TRUST_ANCHOR') ? 'PKI_REASON_NO_TRUST_ANCHOR' : codes(untrusted),
        late: `intact=${String(late.signers[0]?.intact)} ${codes(late)}`,
        claimedTime: good.signers[0]?.signingTime?.text ?? '',
        parsed: `v${String(parsed.version)} ${getOidName(parsed.contentType) ?? parsed.contentType} detached=${String(parsed.content === undefined)} certificates=${String(parsed.certificates.length)} sid=${signerInfo.sid.kind}`,
        attributes,
        byKey,
        lenient: `valid=${String(lenient.valid)}`,
        strict: strict.reasons.map((reason) => `${reason.code}@${reason.path.slice(reason.path.lastIndexOf('.') + 1)}`).sort().join(' '),
        annotated: `valid=${String(stillGood.valid)} unsigned=${(parseSignedData(annotated).signerInfos[0]?.unsignedAttributes ?? []).map((a) => a.oid).join(',')}`,
        fromPdf: String(fromPdf),
        thrown,
        wrapped,
        misuse,
    };
}
