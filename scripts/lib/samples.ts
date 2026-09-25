/**
 * pkinative — the sample catalogue
 * ================================
 * The artefacts pkinative writes, built once and used twice: hashed against
 * a reviewed baseline by `scripts/verify-samples.ts`, and handed to foreign
 * tools by `scripts/run-interop.ts`. One catalogue, so the bytes a baseline
 * freezes are the bytes OpenSSL is asked to read — a baseline blessed over
 * one set of artefacts and an interop matrix run over another would each be
 * green about something the other never saw.
 *
 * **Determinism, and why there is no key in this repository.** A signature
 * must be reproducible for a signed sample to have a stable hash, so every
 * signed sample uses Ed25519 (RFC 8032: deterministic by construction —
 * ECDSA and RSASSA-PSS are not, and are covered by the unsigned samples).
 * The key comes from a fixed 32-octet seed wrapped in the PKCS#8 prefix
 * below, so nothing secret-looking is committed and the rule "never commit
 * what our own code can build" holds. `node:crypto` derives the public half,
 * which is why the sample certificates are genuinely self-signed rather than
 * merely well-formed.
 *
 * @module scripts/lib/samples
 */

import { createPrivateKey, createPublicKey } from 'node:crypto';
import {
    createCertificate,
    createCertificationRequest,
    encodeAlgorithmIdentifier,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeExtensions,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeValidity,
    parseCertificate,
    type SigningKey,
} from '../../src/index.js';

// ── The deterministic signer ─────────────────────────────────────────

/** An Ed25519 PKCS#8 wrapper: version 0, the algorithm, then the seed in an OCTET STRING. */
const PKCS8_ED25519_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
/** Visibly not a real key: thirty-two 0x42 octets. */
const SEED = new Uint8Array(32).fill(0x42);

async function signer(): Promise<{ readonly signer: SigningKey; readonly spki: Uint8Array }> {
    const pkcs8 = new Uint8Array([...PKCS8_ED25519_PREFIX, ...SEED]);
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
    // Web Crypto cannot give the public half of a private key, and pkinative
    // is not allowed to compute it (that is scalar multiplication on secret
    // material). node:crypto can, and scripts/ may use node:.
    const spki = new Uint8Array(createPublicKey(createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }));
    return { signer: { key, algorithm: { name: 'Ed25519' } }, spki };
}

// ── The catalogue ────────────────────────────────────────────────────

const CN = '2.5.4.3';
const C = '2.5.4.6';
const KEY_ID = new Uint8Array(20).fill(0xab);

/** Every sample is named for what would break if its bytes moved. */
/**
 * Every artefact pkinative writes, named for what would break if its bytes
 * moved.
 *
 * @returns The samples, in a stable order, keyed by name.
 */
export async function samples(): Promise<Map<string, Uint8Array>> {
    const out = new Map<string, Uint8Array>();
    const { signer: key, spki } = await signer();

    // AlgorithmIdentifier: the absent-versus-NULL parameter, which is the
    // single most common way a hand-written encoder produces a signature
    // that verifies nowhere while every field still reads correctly.
    out.set('algid/rsa-sha256-with-null', encodeAlgorithmIdentifier('1.2.840.113549.1.1.11'));
    out.set('algid/ecdsa-sha256-no-params', encodeAlgorithmIdentifier('1.2.840.10045.4.3.2'));
    out.set('algid/ed25519-no-params', encodeAlgorithmIdentifier('1.3.101.112'));

    // Names: the string-type chooser, and RDN ordering.
    out.set('name/attribute-utf8', encodeNameAttribute({ type: CN, value: 'Ünicode Authority' }));
    out.set('name/attribute-printable', encodeNameAttribute({ type: C, value: 'FR', stringType: 'printable' }));
    out.set('name/two-rdns', encodeDistinguishedName([[{ type: C, value: 'FR', stringType: 'printable' }], [{ type: CN, value: 'pkinative sample' }]]));
    out.set('name/multi-valued-rdn', encodeDistinguishedName([[{ type: C, value: 'FR', stringType: 'printable' }, { type: CN, value: 'a' }]]));

    // Validity: RFC 5280 §4.1.2.5 switches representation at 2050, and the
    // two encodings differ in length as well as in tag.
    out.set('validity/utctime-both', encodeValidity(Date.UTC(2026, 0, 1), Date.UTC(2027, 0, 1)));
    out.set('validity/utctime-to-generalized', encodeValidity(Date.UTC(2049, 11, 31), Date.UTC(2050, 0, 1)));

    // Extension values, one per encoder.
    out.set('ext/basic-constraints-ca', encodeBasicConstraints({ cA: true, pathLenConstraint: 3 }));
    out.set('ext/basic-constraints-leaf', encodeBasicConstraints({ cA: false }));
    out.set('ext/key-usage-ca', encodeKeyUsage(['keyCertSign', 'cRLSign']));
    out.set('ext/key-usage-leaf', encodeKeyUsage(['digitalSignature', 'keyEncipherment']));
    out.set('ext/key-usage-decipher-only', encodeKeyUsage(['decipherOnly']));
    out.set('ext/extended-key-usage', encodeExtendedKeyUsage(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']));
    out.set('ext/subject-key-identifier', encodeSubjectKeyIdentifier(KEY_ID));
    out.set('ext/authority-key-identifier', encodeAuthorityKeyIdentifier(KEY_ID));
    out.set('ext/subject-alt-name', encodeSubjectAltName([
        { kind: 'dNSName', value: 'sample.example' },
        { kind: 'rfc822Name', value: 'pki@sample.example' },
        { kind: 'uniformResourceIdentifier', value: 'https://sample.example/' },
        // 192.0.2.1 (RFC 5737 documentation range) and 2001:db8::1
        // (RFC 3849), in network byte order.
        { kind: 'iPAddress', value: Uint8Array.of(192, 0, 2, 1) },
        { kind: 'iPAddress', value: Uint8Array.of(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) },
        { kind: 'registeredID', value: '1.3.6.1.4.1.99999.1' },
    ]));
    out.set('ext/sequence-of-three', encodeExtensions([
        { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
        { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
        { oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(KEY_ID) },
    ]));

    // Whole structures, signed with the deterministic key.
    const root = await createCertificate({
        serialNumber: 0x0123456789abcdefn,
        subject: [[{ type: C, value: 'FR', stringType: 'printable' }], [{ type: CN, value: 'pkinative sample root' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2036, 0, 1),
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true, pathLenConstraint: 0 }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
            { oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(KEY_ID) },
        ],
    }, key);
    out.set('cert/v3-ed25519-root', root);

    out.set('cert/v1-no-extensions', await createCertificate({
        serialNumber: Uint8Array.of(0x01),
        subject: [[{ type: CN, value: 'pkinative sample v1' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2027, 0, 1),
        subjectPublicKey: spki,
    }, key));

    out.set('cert/v3-leaf-issued-by-root', await createCertificate({
        serialNumber: 2n,
        issuerDer: parseCertificate(root, { onDiagnostic: () => undefined }).subject.der,
        subject: [[{ type: CN, value: 'sample.example' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2026, 3, 1),
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'sample.example' }]) },
            { oid: '2.5.29.35', value: encodeAuthorityKeyIdentifier(KEY_ID) },
        ],
    }, key));

    out.set('csr/no-attributes', await createCertificationRequest({
        subject: [[{ type: CN, value: 'sample.example' }]],
        subjectPublicKey: spki,
    }, key));

    out.set('csr/with-requested-extensions', await createCertificationRequest({
        subject: [[{ type: C, value: 'FR', stringType: 'printable' }], [{ type: CN, value: 'sample.example' }]],
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'sample.example' }, { kind: 'dNSName', value: 'www.sample.example' }]) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
        ],
    }, key));

    return out;
}


/** What the signed samples say, for a foreign tool to be held to. */
export const EXPECTED = Object.freeze({
    'cert/v3-ed25519-root': { commonName: 'pkinative sample root', serialHex: '0123456789abcdef', dnsNames: [] as readonly string[] },
    'cert/v3-leaf-issued-by-root': { commonName: 'sample.example', serialHex: '02', dnsNames: ['sample.example'] },
    'cert/v1-no-extensions': { commonName: 'pkinative sample v1', serialHex: '01', dnsNames: [] as readonly string[] },
});
