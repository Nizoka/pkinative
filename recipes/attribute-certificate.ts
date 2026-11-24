/**
 * Recipe: read an RFC 5755 attribute certificate, check its signature, and
 * compose the rest of what RFC 5755 §5 asks before acting on it.
 *
 * An attribute certificate (AC) binds attributes — here a role — to a holder
 * named by reference to the holder's public-key certificate, and is signed by
 * an AC issuer whose own certificate chains to a trust anchor. pkinative
 * reads the AC (`parseAttributeCertificate`) and checks one link
 * (`verifyAttributeCertificateSignature`). It does not judge the AC: holder
 * binding, targeting, the AC's validity at your instant, the issuer's path and
 * the rule that an AC issuer is not a CA are yours to compose, as below
 * (ADR 0028). An AC's revocation, the last step of §5, is not shown:
 * `checkRevocation` takes a public-key certificate.
 *
 * pkinative writes no AC: the one read here is assembled with the public
 * structural encoders, which is also how to write a structure this library
 * does not model.
 */
import {
    canSign,
    createCertificate,
    encodeAlgorithmIdentifier,
    encodeAttribute,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeBitString,
    encodeExplicit,
    encodeExtensions,
    encodeImplicit,
    encodeInteger,
    encodeKeyUsage,
    encodeSequence,
    encodeTime,
    encodeTlv,
    formatDistinguishedName,
    getExtension,
    parseAttributeCertificate,
    parseCertificate,
    verifyAttributeCertificateSignature,
    verifyCertificateChain,
    type AttributeCertificate,
    type Certificate,
    type GeneralName,
    type PkiDiagnostic,
    type SigningKey,
} from 'pkinative';

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 0, 1);
const CN = '2.5.4.3';
const ED25519 = '1.3.101.112';
const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const ascii = (text: string): Uint8Array => new TextEncoder().encode(text);

async function keyPair(): Promise<{ signer: SigningKey; sign: (data: Uint8Array) => Promise<Uint8Array>; spki: Uint8Array }> {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    if (!('privateKey' in pair)) throw new Error('Ed25519 returns a key pair');
    return {
        signer: { key: pair.privateKey, algorithm: { name: 'Ed25519' } },
        sign: async (data) => new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, data)),
        spki: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
    };
}

// ── Writing an AC with the structural encoders (RFC 5755 §4.1) ──────
// The module is DEFINITIONS IMPLICIT TAGS: a tagged SEQUENCE is re-tagged,
// a tagged CHOICE — a GeneralName — is wrapped.

const directoryName = (nameDer: Uint8Array): Uint8Array => encodeExplicit(4, nameDer);
const uri = (text: string): Uint8Array => encodeTlv('context', 6, false, ascii(text));
const dnsName = (text: string): Uint8Array => encodeTlv('context', 2, false, ascii(text));

async function writeAttributeCertificate(holder: Certificate, issuer: Certificate, sign: (data: Uint8Array) => Promise<Uint8Array>): Promise<Uint8Array> {
    const issuerKeyId = getExtension(issuer, 'subjectKeyIdentifier')?.keyIdentifier ?? new Uint8Array(0);
    const acinfo = encodeSequence([
        encodeInteger(1), // v2
        // Holder: baseCertificateID [0] IssuerSerial — the holder's certificate by issuer and serial (§4.2.2).
        encodeSequence([encodeImplicit(0, encodeSequence([encodeSequence([directoryName(holder.issuer.der)]), encodeInteger(holder.serialNumber.value)]))]),
        // AttCertIssuer: v2Form [0] holding one directoryName, the issuer's subject (§4.2.3).
        encodeImplicit(0, encodeSequence([encodeSequence([directoryName(issuer.subject.der)])])),
        encodeAlgorithmIdentifier(ED25519),
        encodeInteger(0x5a5an),
        encodeSequence([encodeTime(NOW, 'GeneralizedTime'), encodeTime(NOW + 30 * DAY, 'GeneralizedTime')]),
        // One role (§4.4.5): roleName [1] is a URI.
        encodeSequence([encodeAttribute('2.5.4.72', [encodeSequence([encodeExplicit(1, uri('urn:example:role:operator'))])])]),
        encodeExtensions([
            { oid: '2.5.29.35', value: encodeAuthorityKeyIdentifier(issuerKeyId) },
            // targetInformation (§4.3.2), critical: usable at one server only.
            { oid: '2.5.29.55', critical: true, value: encodeSequence([encodeSequence([encodeExplicit(0, dnsName('server.example'))])]) },
        ]),
    ]);
    const signature = await sign(acinfo);
    return encodeSequence([acinfo, encodeAlgorithmIdentifier(ED25519), encodeBitString(signature)]);
}

// ── What RFC 5755 §5 leaves to the caller ───────────────────────────

const sameName = (a: GeneralName | undefined, der: Uint8Array): boolean => a?.kind === 'directoryName' && hex(a.name.der) === hex(der);

/** The holder check of §5 for a holder named by baseCertificateID: the presented certificate's issuer and serial. */
function holderMatches(ac: AttributeCertificate, presented: Certificate): boolean {
    const base = ac.holder.baseCertificateId;
    return base !== undefined && base.issuer.length === 1 && sameName(base.issuer[0], presented.issuer.der) && base.serial.hex === presented.serialNumber.hex;
}

/** The targeting check of §4.3.2: an AC with targetInformation is usable only at a server it names. */
function targetedAt(ac: AttributeCertificate, server: string): boolean {
    const targeting = ac.extensions.find((e) => e.kind === 'targetInformation');
    if (targeting?.kind !== 'targetInformation') return true;
    return targeting.targets.some((t) => t.kind === 'targetName' && t.name.kind === 'dNSName' && t.name.value === server);
}

export default async function run(): Promise<Record<string, string>> {
    if (!canSign()) return { available: 'no' };
    const quiet = { onDiagnostic: () => undefined };
    const rootKey = await keyPair();
    const issuerKey = await keyPair();
    const holderKey = await keyPair();

    const root = parseCertificate(await createCertificate({
        serialNumber: 1n,
        subject: [[{ type: CN, value: 'Example Root' }]],
        notBefore: NOW,
        notAfter: NOW + 3650 * DAY,
        subjectPublicKey: rootKey.spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
        ],
    }, rootKey.signer), quiet);
    // §4.5: the AC issuer's certificate is not a CA's, and its key may sign.
    const issue = async (serialNumber: bigint, cn: string, spki: Uint8Array): Promise<Certificate> => parseCertificate(await createCertificate({
        serialNumber,
        issuerDer: root.subject.der,
        subject: [[{ type: CN, value: cn }]],
        notBefore: NOW,
        notAfter: NOW + 365 * DAY,
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
        ],
    }, rootKey.signer), quiet);
    const issuer = await issue(2n, 'Example AC Issuer', issuerKey.spki);
    const holder = await issue(3n, 'alice', holderKey.spki);

    const diagnostics: PkiDiagnostic[] = [];
    const ac = parseAttributeCertificate(await writeAttributeCertificate(holder, issuer, issuerKey.sign), { onDiagnostic: (d) => diagnostics.push(d) });
    const at = NOW + DAY;

    // Each step of §5, in the order a verifier fails fastest.
    const signed = await verifyAttributeCertificateSignature(ac, issuer);
    const named = ac.issuer.name !== undefined && hex(ac.issuer.name.der) === hex(issuer.subject.der);
    const issuerPath = await verifyCertificateChain({ leaf: issuer, trustAnchors: [root], at });
    const notCa = getExtension(issuer, 'basicConstraints')?.cA !== true;
    const current = ac.validity.notBefore.epochMilliseconds <= at && at <= ac.validity.notAfter.epochMilliseconds;
    const role = ac.attributes.find((a) => a.kind === 'role');

    // A forgery: the same acinfo signed by the holder's key is not the issuer's AC.
    const forged = parseAttributeCertificate(await writeAttributeCertificate(holder, issuer, holderKey.sign), quiet);

    return {
        available: 'yes',
        version: String(ac.version),
        diagnostics: String(diagnostics.length),
        issuer: ac.issuer.name === undefined ? '' : formatDistinguishedName(ac.issuer.name),
        role: role?.kind === 'role' && role.roles[0]?.roleName.kind === 'uniformResourceIdentifier' ? role.roles[0].roleName.value : '',
        extensions: ac.extensions.map((e) => e.kind).join(','),
        signed: String(signed),
        named: String(named),
        issuerPath: String(issuerPath.valid),
        notCa: String(notCa),
        current: String(current),
        holder: String(holderMatches(ac, holder)),
        otherHolder: String(holderMatches(ac, issuer)),
        targeted: String(targetedAt(ac, 'server.example')),
        elsewhere: String(targetedAt(ac, 'other.example')),
        forged: String(await verifyAttributeCertificateSignature(forged, issuer)),
    };
}
