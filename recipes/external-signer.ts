/**
 * Recipe: sign with a key pkinative never sees — an HSM, a smart card, a
 * cloud KMS, a remote signing service — through an `ExternalSigner`.
 *
 * A `SigningKey` hands pkinative an opaque `CryptoKey` it passes straight to
 * `crypto.subtle.sign`. An `ExternalSigner` hands it a function instead, so
 * the key does not even have to live in this process. pkinative computes the
 * exact bytes to sign, calls `produceSignature(bytes)`, and expects back what
 * `crypto.subtle.sign` would return: **raw `r ‖ s` for ECDSA**, the plain
 * octets for RSA and EdDSA. Many remote APIs return an ECDSA signature as DER
 * instead; converting it is the caller's job, because guessing which form
 * arrived is how a signature gets encoded twice — and pkinative refuses the
 * DER form outright rather than guess.
 *
 * The second half is the PDF case: the signer hashes the document's
 * `/ByteRange` itself and hands over `contentDigest`, never the document.
 */
import {
    canSign,
    createCertificate,
    createSignedData,
    decodeAsn1,
    encodeBasicConstraints,
    encodeKeyUsage,
    encodeSubjectKeyIdentifier,
    parseCertificate,
    parseSignedData,
    PkiError,
    verifySignedData,
    type ExternalSigner,
    type Signer,
} from 'pkinative';

const NOW = Date.UTC(2026, 0, 15);
const DAY = 86_400_000;
const CN = '2.5.4.3';
const ALGORITHM = { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } as const;
const quiet = { onDiagnostic: () => undefined };

/**
 * A stand-in for a remote signing service. The private key is captured in
 * this closure and never leaves it; the only thing the rest of the program
 * holds is `signDer`, which — like AWS KMS or a PKCS #11 wrapper configured
 * for it — answers ECDSA in DER.
 */
async function remoteSigningService(): Promise<{ spki: Uint8Array; signDer: (bytes: Uint8Array) => Promise<Uint8Array> }> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const signDer = async (bytes: Uint8Array): Promise<Uint8Array> => {
        const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bytes));
        const integer = (half: Uint8Array): number[] => {
            let start = 0;
            while (start < half.length - 1 && half[start] === 0) start++;
            const body = Array.from(half.subarray(start));
            return [0x02, ...((body[0] ?? 0) & 0x80 ? [body.length + 1, 0] : [body.length]), ...body];
        };
        const body = [...integer(raw.subarray(0, 32)), ...integer(raw.subarray(32))];
        return Uint8Array.of(0x30, body.length, ...body);
    };
    return { spki: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)), signDer };
}

/** DER `Ecdsa-Sig-Value` → the fixed-width `r ‖ s` Web Crypto speaks, for a curve of `size`-octet coordinates. */
function derToRaw(der: Uint8Array, size: number): Uint8Array {
    const raw = new Uint8Array(2 * size);
    for (const [i, integer] of decodeAsn1(der).children.entries()) {
        const bytes = integer.content.subarray(Math.max(0, integer.content.length - size));
        raw.set(bytes, (i + 1) * size - bytes.length);
    }
    return raw;
}

export default async function run(): Promise<Record<string, string>> {
    if (!canSign()) return { available: 'no' };

    // The CA is ordinary; only the document signer's key is remote.
    const caPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const caKey: Signer = { key: caPair.privateKey, algorithm: ALGORITHM };
    const root = parseCertificate(await createCertificate({
        serialNumber: 1n,
        subject: [[{ type: CN, value: 'Example Root' }]],
        notBefore: NOW - 30 * DAY,
        notAfter: NOW + 3650 * DAY,
        subjectPublicKey: new Uint8Array(await crypto.subtle.exportKey('spki', caPair.publicKey)),
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
        ],
    }, caKey), quiet);

    const service = await remoteSigningService();
    const signer = parseCertificate(await createCertificate({
        serialNumber: 2n,
        issuerDer: root.subject.der,
        subject: [[{ type: CN, value: 'Example Document Signer' }]],
        notBefore: NOW - DAY,
        notAfter: NOW + 365 * DAY,
        subjectPublicKey: service.spki,
        extensions: [
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature', 'nonRepudiation']) },
            { oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8)) },
        ],
    }, caKey), quiet);

    // The adapter: exactly the bytes pkinative gives, and r ‖ s back.
    const external: ExternalSigner = {
        algorithm: ALGORITHM,
        produceSignature: async (bytes) => derToRaw(await service.signDer(bytes), 32),
    };

    // The PDF case. The /ByteRange is everything but the /Contents hole; the
    // signer hashes it and never holds the document whole.
    const pdf = new TextEncoder().encode(`%PDF-1.7 ... /Contents <${'0'.repeat(64)}> ... %%EOF`);
    const hole = { start: pdf.indexOf(0x3c), end: pdf.indexOf(0x3e) + 1 };   // '<' … '>'
    const byteRange = new Uint8Array(pdf.length - (hole.end - hole.start));
    byteRange.set(pdf.subarray(0, hole.start));
    byteRange.set(pdf.subarray(hole.end), hole.start);
    const contentDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', byteRange));

    // contentDigest implies detached. sid 'subjectKeyIdentifier' names the key
    // rather than the certificate (a version 3 SignerInfo); the signer is then
    // bound to its certificate by SigningCertificateV2, written by default.
    const signature = await createSignedData({ contentDigest, certificate: signer, sid: 'subjectKeyIdentifier' }, external);
    const signerInfo = parseSignedData(signature).signerInfos[0];

    // Verify the way a PDF validator does: with the digest of the /ByteRange.
    const report = await verifySignedData({ signedData: signature, contentDigest, trustAnchors: [root], at: NOW });

    // What the adapter is for. Hand pkinative the DER directly and it refuses
    // to guess: a PkiError naming the fix, not a signature encoded twice.
    const careless: ExternalSigner = { algorithm: ALGORITHM, produceSignature: service.signDer };
    let refused = 'none';
    try {
        await createSignedData({ contentDigest, certificate: signer }, careless);
    } catch (error) {
        if (!(error instanceof PkiError)) throw error;
        refused = error.code;
    }

    return {
        available: 'yes',
        sid: `${signerInfo?.sid.kind ?? ''} v${String(signerInfo?.version)}`,
        detached: String(parseSignedData(signature).content === undefined),
        valid: `valid=${String(report.valid)} intact=${String(report.signers[0]?.intact)}`,
        signedBy: String(report.signers[0]?.certificate?.serialNumber.value),
        refused,
    };
}
