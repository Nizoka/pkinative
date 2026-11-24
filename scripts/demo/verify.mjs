// The demo of README.md and pkinative.dev — fictitious names (RFC 2606), keys made on the spot.
import { createCertificate, encodeBasicConstraints, encodeSubjectAltName,
    parseCertificate, verifyCertificateChain } from 'pkinative';

const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const day = 86_400_000, now = Math.floor(Date.now() / day) * day;
const keyPair = async () => {   // your key, in your code: pkinative never generates one
    const k = await crypto.subtle.generateKey(EC, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', k.publicKey));
    return { spki, signer: { key: k.privateKey, algorithm: EC } };
};
const issue = async (by, subject, key, days, extensions, issuerDer) => parseCertificate(
    await createCertificate({ serialNumber: BigInt(now), subject: [[{ type: '2.5.4.3', value: subject }]],
        issuerDer, notBefore: now - day, notAfter: now + days * day, subjectPublicKey: key.spki, extensions },
    by.signer), { onDiagnostic: () => {} });   // profile notes, not errors: kept out of the demo

const ca = await keyPair(), site = await keyPair();
const root = await issue(ca, 'Example Root CA', ca, 365,
    [{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) }]);
const leaf = await issue(ca, 'shop.example.com', site, 90,
    [{ oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'shop.example.com' }]) }],
    root.subject.der);

for (const host of ['api.example.com', 'shop.example.com']) {
    const report = await verifyCertificateChain({
        leaf, trustAnchors: [root], serverName: { kind: 'dns', value: host },
    });
    if (report.valid) console.log(`✓ ${host}  valid, ${report.path.length} certificates`);
    else console.log(`✗ ${host}`);
    for (const reason of report.reasons) {
        console.log(`  ${reason.code}  (${reason.standard})\n  ${reason.message}`);
    }
}
