/**
 * Recipe: issue a two-certificate hierarchy — a self-signed root and a leaf
 * it signs — and a certification request, with keys the caller holds.
 *
 * pkinative generates no key and exports none: `crypto.subtle.generateKey`
 * and `crypto.subtle.exportKey` are the caller's calls, here in this file,
 * and what reaches the library is a SubjectPublicKeyInfo in DER plus a
 * private `CryptoKey` it only ever hands back to `crypto.subtle.sign`. That
 * is why `generateKey` and `exportKey` are refused inside `src/` in every
 * version — the promise costs you two lines.
 *
 * Every certificate built here is read back by pkinative's own parser with
 * **no diagnostic**: a builder whose output its own reader complains about
 * has written something someone else's reader will refuse.
 */
import {
    canSign,
    createCertificate,
    createCertificationRequest,
    encodeAlgorithmIdentifier,
    encodeAttribute,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeExtension,
    encodeExtensions,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeSubjectPublicKeyInfo,
    encodeValidity,
    formatDistinguishedName,
    getExtension,
    KEY_USAGE_BITS,
    parseCertificate,
    signatureAlgorithmDer,
    verifyCertificateSignature,
    verifySelfSignature,
    type SigningKey,
} from 'pkinative';

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 0, 1);
const CN = '2.5.4.3';
const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** The caller's key pair, and the SPKI pkinative is given instead of the key. */
async function keyPair(): Promise<{ signer: SigningKey; spki: Uint8Array }> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return {
        signer: { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } },
        // One line, and the reason exportKey can stay refused inside pkinative.
        spki: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
    };
}

export default async function run(): Promise<Record<string, string>> {
    if (!canSign()) return { available: 'no' };

    const ca = await keyPair();
    const leaf = await keyPair();
    const quiet = { onDiagnostic: () => undefined };

    // A key identifier is conventionally a digest of the key bits; any
    // stable value does, and this recipe needs a deterministic one.
    const caKeyId = new Uint8Array(20).fill(0xca);

    const rootDer = await createCertificate({
        serialNumber: 0x0123456789abcdefn,
        subject: [
            [{ type: '2.5.4.6', value: 'US', stringType: 'printable' }],
            [{ type: CN, value: 'pkinative example root' }],
        ],
        notBefore: NOW,
        notAfter: NOW + 3650 * DAY,
        subjectPublicKey: ca.spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true, pathLenConstraint: 0 }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
            { oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(caKeyId) },
        ],
    }, ca.signer);
    const root = parseCertificate(rootDer, quiet);

    // The leaf's issuer is the CA's OWN bytes, not a name re-described. A
    // re-encoded name does not always reproduce the issuer's encoding, and a
    // chain whose names differ by one octet is a chain nothing will build.
    const leafDer = await createCertificate({
        serialNumber: 2n,
        issuerDer: root.subject.der,
        subject: [[{ type: CN, value: 'host.example' }]],
        notBefore: NOW,
        notAfter: NOW + 90 * DAY,
        subjectPublicKey: leaf.spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
            { oid: '2.5.29.37', value: encodeExtendedKeyUsage(['1.3.6.1.5.5.7.3.1']) },
            { oid: '2.5.29.17', value: encodeSubjectAltName([
                { kind: 'dNSName', value: 'host.example' },
                { kind: 'uniformResourceIdentifier', value: 'https://host.example/' },
            ]) },
            { oid: '2.5.29.35', value: encodeAuthorityKeyIdentifier(caKeyId) },
        ],
    }, ca.signer);
    const cert = parseCertificate(leafDer, quiet);

    // A PKCS#10 request: proof that the requester holds the private half of
    // the key it carries, so it is signed by the leaf's key, not the CA's.
    const csr = await createCertificationRequest({
        subject: [[{ type: CN, value: 'host.example' }]],
        subjectPublicKey: leaf.spki,
        extensions: [{ oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'host.example' }]) }],
    }, leaf.signer);

    // The structural encoders are public, for a structure this library does
    // not model yet. These are deterministic, so they can be asserted.
    const pieces = [
        hex(encodeAlgorithmIdentifier('1.2.840.113549.1.1.11')),
        hex(encodeNameAttribute({ type: CN, value: 'a' })),
        hex(encodeDistinguishedName([[{ type: CN, value: 'a' }]])),
        hex(encodeValidity(NOW, NOW).subarray(0, 2)),
        hex(encodeExtension({ oid: '2.5.29.19', value: encodeBasicConstraints({ cA: false }) })),
        hex(encodeExtensions([{ oid: '2.5.29.19', value: encodeBasicConstraints({ cA: false }) }])),
        hex(encodeAttribute('1.2.3', [encodeBasicConstraints({ cA: false })])),
        hex(encodeSubjectPublicKeyInfo('1.3.101.112', new Uint8Array(4)).subarray(0, 2)),
        hex(signatureAlgorithmDer(ca.signer)),
    ].join(' ');

    return {
        available: 'yes',
        root: `${formatDistinguishedName(root.subject)} v${String(root.version)} self=${String(await verifySelfSignature(root))} diag=${String(root.diagnostics.length)}`,
        leaf: `${formatDistinguishedName(cert.subject)} signedByRoot=${String(await verifyCertificateSignature(cert, root))} diag=${String(cert.diagnostics.length)}`,
        leafExtensions: cert.extensions.map((e) => e.kind).join(','),
        leafUsage: getExtension(cert, 'keyUsage')?.usages.join(',') ?? '',
        leafNames: getExtension(cert, 'subjectAltName')?.names.map((n) => n.kind).join(',') ?? '',
        keyUsageBits: `${String(KEY_USAGE_BITS.get('keyCertSign'))},${String(KEY_USAGE_BITS.get('cRLSign'))}`,
        csrIsDer: String(csr[0] === 0x30),
        pieces,
    };
}
