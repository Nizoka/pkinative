/**
 * pkinative — the interoperability matrix: what pkinative writes, fresh
 * =====================================================================
 * The frozen sample catalogue (scripts/lib/samples.ts) is Ed25519 and
 * nothing else, because its bytes are hashed against a baseline and only a
 * deterministic signature has a stable hash. That left every other signature
 * family the 1.0 API writes — RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA — and every
 * structure other than a certificate or a CSR unread by any foreign tool: an
 * RSASSA-PSS AlgorithmIdentifier that the CA/Browser Forum profile refuses
 * passed the whole gate.
 *
 * This set is the other half. It is generated **per run**, with keys the
 * harness makes through Web Crypto (`generateKey` is the caller's to call,
 * never pkinative's — it stays refused in `src/`), so nothing here has a
 * stable hash and nothing is compared by one: each foreign tool is held to
 * facts with exactly one right answer — a serial, a name, a verified
 * signature, a digest echoed back.
 *
 * For every signature family (`PROFILES`): a CA with name constraints, a leaf
 * with every extension a server certificate carries plus a BMPString and a
 * multi-valued RDN in its subject, a leaf shaped by the CA/Browser Forum
 * baseline requirements, a CSR with and without the extensionRequest
 * attribute, CMS SignedData attached, detached and identified by subject key
 * identifier, and an OCSP request; then three RFC 3161 TimeStampReqs. Each
 * one is written as DER and as RFC 7468 PEM.
 *
 * @module scripts/lib/interop-artefacts
 */

import { createHash, randomBytes, type webcrypto } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
    computeKeyIdentifier,
    createCertificate,
    createCertificationRequest,
    createOcspRequest,
    createSignedData,
    createTimeStampRequest,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeExplicit,
    encodeExtendedKeyUsage,
    encodeImplicit,
    encodeKeyUsage,
    encodeObjectIdentifier,
    encodePem,
    encodeSequence,
    encodeString,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    parseCertificate,
    type NameDescription,
    type SignatureAlgorithm,
    type SigningKey,
} from '../../src/index.js';

// ── The signature families ──────────────────────────────────────────

/** What `crypto.subtle.generateKey` is asked for — by the harness, never by `src/`. */
export type KeyGeneration =
    | { readonly name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS'; readonly modulusLength: number; readonly publicExponent: Uint8Array; readonly hash: string }
    | { readonly name: 'ECDSA'; readonly namedCurve: string }
    | { readonly name: 'Ed25519' };

export interface Profile {
    readonly id: string;
    readonly generate: KeyGeneration;
    readonly algorithm: SignatureAlgorithm;
    /** The signature AlgorithmIdentifier OID pkinative must write. */
    readonly signatureOid: string;
    /** `webpki`: the profile is one the CA/Browser Forum and Mozilla accept, so their lints apply to its BR-shaped leaf. */
    readonly webpki: boolean;
}

const E65537 = new Uint8Array([1, 0, 1]);
const rsa = (name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS', hash: 'SHA-256' | 'SHA-384' | 'SHA-512'): KeyGeneration =>
    ({ name, modulusLength: 2048, publicExponent: E65537, hash });

export const PROFILES: readonly Profile[] = Object.freeze([
    { id: 'rsa', generate: rsa('RSASSA-PKCS1-v1_5', 'SHA-256'), algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, signatureOid: '1.2.840.113549.1.1.11', webpki: true },
    { id: 'pss-sha256', generate: rsa('RSA-PSS', 'SHA-256'), algorithm: { name: 'RSA-PSS', hash: 'SHA-256' }, signatureOid: '1.2.840.113549.1.1.10', webpki: true },
    { id: 'pss-sha384', generate: rsa('RSA-PSS', 'SHA-384'), algorithm: { name: 'RSA-PSS', hash: 'SHA-384' }, signatureOid: '1.2.840.113549.1.1.10', webpki: true },
    { id: 'pss-sha512', generate: rsa('RSA-PSS', 'SHA-512'), algorithm: { name: 'RSA-PSS', hash: 'SHA-512' }, signatureOid: '1.2.840.113549.1.1.10', webpki: true },
    { id: 'p256', generate: { name: 'ECDSA', namedCurve: 'P-256' }, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' }, signatureOid: '1.2.840.10045.4.3.2', webpki: true },
    { id: 'p384', generate: { name: 'ECDSA', namedCurve: 'P-384' }, algorithm: { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' }, signatureOid: '1.2.840.10045.4.3.3', webpki: true },
    // P-521 and Ed25519 are outside the Mozilla and CA/Browser Forum
    // allow-lists by policy, so only the PKIX lints judge them.
    { id: 'p521', generate: { name: 'ECDSA', namedCurve: 'P-521' }, algorithm: { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }, signatureOid: '1.2.840.10045.4.3.4', webpki: false },
    { id: 'ed25519', generate: { name: 'Ed25519' }, algorithm: { name: 'Ed25519' }, signatureOid: '1.3.101.112', webpki: false },
]);

// ── What an artefact is, and what is true of it ─────────────────────

export type ArtefactKind = 'cert' | 'csr' | 'cms' | 'ocsp-request' | 'tsq';

/**
 * Facts with exactly one right answer, each in one spelling: hex lowercase
 * without leading zeros for a serial, lowercase hex for octets, sorted and
 * comma-joined for a list, `true`/`false` for a boolean. A tool's reading is
 * compared field by field to these and nothing else.
 */
export type Facts = Readonly<Record<string, string>>;

export interface Artefact {
    /** `<profile>/<name>`, e.g. `p384/leaf-rich`. */
    readonly id: string;
    readonly profile: string;
    readonly kind: ArtefactKind;
    /** Absolute paths of the DER and PEM files. */
    readonly der: string;
    readonly pem: string;
    /** For a certificate, the id of its issuer (itself for the CA); for a CMS or an OCSP request, the CA. */
    readonly issuer?: string;
    /** For a CMS: the content file, and whether the SignedData omits it. */
    readonly content?: string;
    readonly detached?: boolean;
    /** For a CMS: the signer identifier kind. */
    readonly sid?: 'issuerAndSerialNumber' | 'subjectKeyIdentifier';
    /**
     * For a certificate: `ca` (a self-issued certificate, never chain-checked), `rich` (every
     * extension, BMPString, multi-valued RDN), `br` (the CA/B baseline shape) or `leaf` (a frozen sample).
     */
    readonly shape?: 'ca' | 'rich' | 'br' | 'leaf';
    /** For a certificate: whether its signature family is one the Web PKI profile admits (`Profile.webpki`). */
    readonly webpki?: boolean;
    /** For a leaf: the name a chain is verified for. */
    readonly serverName?: string;
    /** For a leaf: the instant its chain is judged at, epoch milliseconds; now when absent. */
    readonly verifyAt?: number;
    readonly expect: Facts;
}

export interface ArtefactSet {
    readonly dir: string;
    readonly artefacts: readonly Artefact[];
    /** Where the manifest every helper program reads was written. */
    readonly manifest: string;
}

// ── Helpers ─────────────────────────────────────────────────────────

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const OID = { cn: '2.5.4.3', c: '2.5.4.6', o: '2.5.4.10', ou: '2.5.4.11', l: '2.5.4.7' } as const;
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
const EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4';

/** The subjectPublicKey BIT STRING content of a DER SubjectPublicKeyInfo, unused-bits octet excluded. */
export function spkiKeyBits(spki: Uint8Array): Uint8Array {
    const header = (at: number): { body: number; length: number } => {
        const first = spki[at + 1] ?? 0;
        if (first < 0x80) return { body: at + 2, length: first };
        let length = 0;
        for (let i = 0; i < (first & 0x7f); i++) length = length * 256 + (spki[at + 2 + i] ?? 0);
        return { body: at + 2 + (first & 0x7f), length };
    };
    const outer = header(0);
    const algorithm = header(outer.body);
    const bits = header(algorithm.body + algorithm.length);
    return spki.subarray(bits.body + 1, bits.body + bits.length);
}

/** A 16-octet positive serial: 127 bits of entropy, well above the 64 the CA/B baseline requires. */
function serial(): bigint {
    const b = randomBytes(16);
    b[0] = ((b[0] ?? 0) & 0x7f) | 0x10;
    return BigInt(`0x${b.toString('hex')}`);
}

/** The GeneralName inside a one-entry subjectAltName, for reuse in AIA, CRLDP and name constraints. */
function generalName(name: Parameters<typeof encodeSubjectAltName>[0][number]): Uint8Array {
    const seq = encodeSubjectAltName([name]);
    const first = seq[1] ?? 0;
    return seq.subarray(first < 0x80 ? 2 : 2 + (first & 0x7f));
}
const uri = (value: string): Uint8Array => generalName({ kind: 'uniformResourceIdentifier', value });

/** RFC 5280 §4.2.1.10: permitted DNS and rfc822Name subtrees under example.com. */
const nameConstraints = (): Uint8Array => encodeSequence([encodeImplicit(0, encodeSequence([
    encodeSequence([generalName({ kind: 'dNSName', value: 'example.com' })]),
    encodeSequence([generalName({ kind: 'rfc822Name', value: 'example.com' })]),
]))]);

/** RFC 5280 §4.2.1.4, with a CPS pointer qualifier when `cps` is given. */
const certificatePolicies = (policy: string, cps?: string): Uint8Array => encodeSequence([encodeSequence([
    encodeObjectIdentifier(policy),
    ...(cps === undefined ? [] : [encodeSequence([encodeSequence([encodeObjectIdentifier('1.3.6.1.5.5.7.2.1'), encodeString('ia5', cps)])])]),
])]);

const authorityInfoAccess = (): Uint8Array => encodeSequence([
    encodeSequence([encodeObjectIdentifier('1.3.6.1.5.5.7.48.1'), uri('http://ocsp.example.com/')]),
    encodeSequence([encodeObjectIdentifier('1.3.6.1.5.5.7.48.2'), uri('http://pki.example.com/ca.crt')]),
]);

const crlDistributionPoints = (): Uint8Array =>
    encodeSequence([encodeSequence([encodeExplicit(0, encodeImplicit(0, encodeSequence([uri('http://pki.example.com/ca.crl')])))])]);

interface KeyPair { readonly signer: SigningKey; readonly spki: Uint8Array; readonly keyId: Uint8Array }

async function keyPair(p: Profile): Promise<KeyPair> {
    // The harness generates; pkinative is handed the SPKI and an opaque handle.
    const pair = await crypto.subtle.generateKey(p.generate as Parameters<typeof crypto.subtle.generateKey>[0], true, ['sign', 'verify']) as webcrypto.CryptoKeyPair;
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    return { signer: { key: pair.privateKey, algorithm: p.algorithm }, spki, keyId: computeKeyIdentifier(spkiKeyBits(spki)) };
}

// ── The set ─────────────────────────────────────────────────────────

/** The rich subject: PrintableString C, a BMPString O, a multi-valued RDN (OU + L) and a UTF8String CN. */
export const RICH_SUBJECT = Object.freeze({ organization: 'Société Ωmega', organizationalUnit: 'Ingénierie', locality: 'Paris', commonName: 'www.example.com' });

/**
 * Build the whole set into `dir`, with keys generated now. Every file is
 * written as `<profile>-<name>.der` and `.pem`, and `manifest.json` lists them
 * with their expected facts for the helper programs.
 */
export async function buildArtefacts(dir: string): Promise<ArtefactSet> {
    mkdirSync(dir, { recursive: true });
    const artefacts: Artefact[] = [];
    const now = Math.floor(Date.now() / 1000) * 1000;
    const HOUR = 3_600_000;
    const DAY = 24 * HOUR;

    const save = (profile: string, name: string, der: Uint8Array, label: string): { der: string; pem: string } => {
        const base = join(dir, `${profile}-${name}`);
        writeFileSync(`${base}.der`, der);
        writeFileSync(`${base}.pem`, encodePem(label, der));
        return { der: `${base}.der`, pem: `${base}.pem` };
    };

    for (const p of PROFILES) {
        const ca = await keyPair(p);
        const leaf = await keyPair(p);
        const ku = p.generate.name === 'ECDSA' || p.generate.name === 'Ed25519'
            ? ['digitalSignature'] as const
            : ['digitalSignature', 'keyEncipherment'] as const;

        // The CA.
        const caSerial = serial();
        const caName = `pkinative interop root ${p.id}`;
        const caDer = await createCertificate({
            serialNumber: caSerial,
            subject: [[{ type: OID.c, value: 'FR', stringType: 'printable' }], [{ type: OID.o, value: 'pkinative interop' }], [{ type: OID.cn, value: caName }]],
            notBefore: now - HOUR, notAfter: now + 5 * 365 * DAY, subjectPublicKey: ca.spki,
            extensions: [
                { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
                { oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(ca.keyId) },
                { oid: '2.5.29.30', critical: true, value: nameConstraints() },
            ],
        }, ca.signer);
        const caFiles = save(p.id, 'ca', caDer, 'CERTIFICATE');
        const caId = `${p.id}/ca`;
        artefacts.push({ id: caId, profile: p.id, kind: 'cert', shape: 'ca', webpki: p.webpki, issuer: caId, ...caFiles, expect: { serial: caSerial.toString(16), commonName: caName, dnsNames: '', signatureOid: p.signatureOid } });
        const caCert = parseCertificate(caDer, { onDiagnostic: () => undefined });

        // The rich leaf.
        const richSubject: NameDescription = [
            [{ type: OID.c, value: 'FR', stringType: 'printable' }],
            [{ type: OID.o, value: encodeString('bmp', RICH_SUBJECT.organization) }],
            [{ type: OID.ou, value: RICH_SUBJECT.organizationalUnit }, { type: OID.l, value: RICH_SUBJECT.locality }],
            [{ type: OID.cn, value: RICH_SUBJECT.commonName }],
        ];
        const richSerial = serial();
        const richDer = await createCertificate({
            serialNumber: richSerial, issuerDer: caCert.subject.der, subject: richSubject,
            notBefore: now - HOUR, notAfter: now + 90 * DAY, subjectPublicKey: leaf.spki,
            extensions: [
                { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage([...ku]) },
                { oid: '2.5.29.37', value: encodeExtendedKeyUsage([SERVER_AUTH, CLIENT_AUTH, EMAIL_PROTECTION]) },
                { oid: '2.5.29.17', value: encodeSubjectAltName([
                    { kind: 'dNSName', value: 'www.example.com' },
                    { kind: 'dNSName', value: 'example.com' },
                    { kind: 'rfc822Name', value: 'pki@example.com' },
                    { kind: 'uniformResourceIdentifier', value: 'https://www.example.com/' },
                    { kind: 'iPAddress', value: Uint8Array.of(192, 0, 2, 10) },
                    { kind: 'iPAddress', value: Uint8Array.of(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a) },
                ]) },
                { oid: '2.5.29.32', value: certificatePolicies('1.3.6.1.4.1.99999.1.1', 'http://pki.example.com/cps') },
                { oid: '1.3.6.1.5.5.7.1.1', value: authorityInfoAccess() },
                { oid: '2.5.29.31', value: crlDistributionPoints() },
                { oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(leaf.keyId) },
                { oid: '2.5.29.35', value: encodeAuthorityKeyIdentifier(ca.keyId) },
            ],
        }, ca.signer);
        const richId = `${p.id}/leaf-rich`;
        artefacts.push({
            id: richId, profile: p.id, kind: 'cert', shape: 'rich', webpki: p.webpki, serverName: 'www.example.com', issuer: caId, ...save(p.id, 'leaf-rich', richDer, 'CERTIFICATE'),
            expect: { serial: richSerial.toString(16), commonName: RICH_SUBJECT.commonName, dnsNames: 'example.com,www.example.com', organization: RICH_SUBJECT.organization, organizationalUnit: RICH_SUBJECT.organizationalUnit, locality: RICH_SUBJECT.locality, signatureOid: p.signatureOid },
        });
        const richCert = parseCertificate(richDer, { onDiagnostic: () => undefined });

        // The CA/Browser Forum-shaped leaf: a DV server certificate.
        const brSerial = serial();
        const brDer = await createCertificate({
            serialNumber: brSerial, issuerDer: caCert.subject.der, subject: [[{ type: OID.cn, value: 'www.example.com' }]],
            notBefore: now - HOUR, notAfter: now + 90 * DAY, subjectPublicKey: leaf.spki,
            extensions: [
                { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage([...ku]) },
                { oid: '2.5.29.37', value: encodeExtendedKeyUsage([SERVER_AUTH]) },
                { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'www.example.com' }]) },
                { oid: '2.5.29.32', value: certificatePolicies('2.23.140.1.2.1') },
                { oid: '1.3.6.1.5.5.7.1.1', value: authorityInfoAccess() },
                { oid: '2.5.29.31', value: crlDistributionPoints() },
                { oid: '2.5.29.35', value: encodeAuthorityKeyIdentifier(ca.keyId) },
            ],
        }, ca.signer);
        artefacts.push({
            id: `${p.id}/leaf-br`, profile: p.id, kind: 'cert', shape: 'br', webpki: p.webpki, serverName: 'www.example.com', issuer: caId, ...save(p.id, 'leaf-br', brDer, 'CERTIFICATE'),
            expect: { serial: brSerial.toString(16), commonName: 'www.example.com', dnsNames: 'www.example.com', signatureOid: p.signatureOid },
        });

        // Certification requests: without attributes, and with extensionRequest.
        const csrPlain = await createCertificationRequest({ subject: [[{ type: OID.cn, value: 'www.example.com' }]], subjectPublicKey: leaf.spki }, leaf.signer);
        artefacts.push({ id: `${p.id}/csr-plain`, profile: p.id, kind: 'csr', ...save(p.id, 'csr-plain', csrPlain, 'CERTIFICATE REQUEST'), expect: { commonName: 'www.example.com', signatureOid: p.signatureOid } });
        const csrExt = await createCertificationRequest({
            subject: richSubject, subjectPublicKey: leaf.spki,
            extensions: [
                { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'www.example.com' }, { kind: 'iPAddress', value: Uint8Array.of(192, 0, 2, 10) }]) },
                { oid: '2.5.29.15', critical: true, value: encodeKeyUsage([...ku]) },
            ],
        }, leaf.signer);
        artefacts.push({ id: `${p.id}/csr-ext`, profile: p.id, kind: 'csr', ...save(p.id, 'csr-ext', csrExt, 'CERTIFICATE REQUEST'), expect: { commonName: 'www.example.com', signatureOid: p.signatureOid } });

        // CMS SignedData, signed by the rich leaf, the CA certificate carried.
        const content = new TextEncoder().encode(`pkinative interop content, ${p.id}\n`);
        const contentPath = join(dir, `${p.id}-content.bin`);
        writeFileSync(contentPath, content);
        const contentFacts = { certificateCount: '2', contentSha256: createHash('sha256').update(content).digest('hex'), signerSerial: richSerial.toString(16) };
        const cms = async (name: string, detached: boolean, sid: 'issuerAndSerialNumber' | 'subjectKeyIdentifier'): Promise<void> => {
            const der = await createSignedData({ content, detached, certificate: richCert, certificates: [caDer], signingTime: now, sid }, leaf.signer);
            artefacts.push({ id: `${p.id}/${name}`, profile: p.id, kind: 'cms', issuer: caId, content: contentPath, detached, sid, ...save(p.id, name, der, 'CMS'), expect: { ...contentFacts, version: sid === 'subjectKeyIdentifier' ? '3' : '1' } });
        };
        await cms('cms-attached', false, 'issuerAndSerialNumber');
        await cms('cms-detached', true, 'issuerAndSerialNumber');
        await cms('cms-ski', false, 'subjectKeyIdentifier');

        // An OCSP request for the rich leaf.
        const nonce = new Uint8Array(randomBytes(16));
        const ocsp = createOcspRequest(richCert, caCert, { nonce });
        artefacts.push({
            id: `${p.id}/ocsp-request`, profile: p.id, kind: 'ocsp-request', issuer: caId, ...save(p.id, 'ocsp-request', ocsp, 'OCSP REQUEST'),
            expect: {
                serial: richSerial.toString(16),
                issuerNameHash: createHash('sha1').update(caCert.subject.der).digest('hex'),
                issuerKeyHash: createHash('sha1').update(spkiKeyBits(ca.spki)).digest('hex'),
                nonce: hex(nonce),
            },
        });
    }

    // RFC 3161 TimeStampReqs: the digest, a nonce, certReq and a policy each vary.
    const tsq = (name: string, hash: 'SHA-256' | 'SHA-384' | 'SHA-512', oid: string, options: { nonce?: bigint; certReq?: boolean; policy?: string }): void => {
        const digest = new Uint8Array(createHash(hash.replace('-', '').toLowerCase()).update(`pkinative interop ${name}`).digest());
        const der = createTimeStampRequest(digest, { hashAlgorithm: hash, ...options });
        artefacts.push({
            id: `tsp/${name}`, profile: 'tsp', kind: 'tsq', ...save('tsp', name, der, 'TIME STAMP REQUEST'),
            expect: { hashOid: oid, imprint: hex(digest), nonce: options.nonce?.toString(16) ?? '', policy: options.policy ?? '', certReq: String(options.certReq ?? true) },
        });
    };
    tsq('tsq-sha256', 'SHA-256', '2.16.840.1.101.3.4.2.1', { nonce: BigInt(`0x${randomBytes(8).toString('hex')}`) | 1n, certReq: true });
    tsq('tsq-sha384-policy', 'SHA-384', '2.16.840.1.101.3.4.2.2', { policy: '1.3.6.1.4.1.99999.2.1', certReq: false });
    tsq('tsq-sha512', 'SHA-512', '2.16.840.1.101.3.4.2.3', { nonce: BigInt(`0x${randomBytes(8).toString('hex')}`) | 1n, policy: '1.3.6.1.4.1.99999.2.2' });

    const manifest = join(dir, 'manifest.json');
    writeFileSync(manifest, JSON.stringify({ artefacts }, null, 1));
    return { dir, artefacts, manifest };
}
