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
 * signed sample uses EdDSA (RFC 8032: deterministic by construction — ECDSA
 * and RSASSA-PSS are not): Ed25519 throughout, and Ed448 for the one
 * certificate and the one SignedData that freeze the RFC 8419 §3.1 shape, a
 * SHAKE256 digest under an Ed448 signature. Every other signature family the
 * API writes, and every other signed structure, is covered by the set
 * scripts/lib/interop-artefacts.ts generates afresh on each interop run and
 * holds to facts rather than to hashes.
 * Each key comes from a fixed seed — 32 octets for Ed25519, 57 for Ed448 —
 * wrapped in the PKCS#8 prefix below, so nothing secret-looking is committed
 * and the rule "never commit what our own code can build" holds.
 * `node:crypto` derives the public half, which is why the sample
 * certificates are genuinely self-signed rather than merely well-formed.
 *
 * @module scripts/lib/samples
 */

import { createPrivateKey, createPublicKey } from 'node:crypto';
import {
    addTimeStampToken,
    createCertificate,
    createCertificationRequest,
    createOcspRequest,
    createSignedData,
    createTimeStampRequest,
    decodeAsn1,
    encodeAlgorithmIdentifier,
    encodeAsn1Node,
    encodeAttribute,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeBitString,
    encodeBoolean,
    encodeDistinguishedName,
    encodeEnumerated,
    encodeExplicit,
    encodeExtendedKeyUsage,
    encodeExtension,
    encodeExtensions,
    encodeImplicit,
    encodeInteger,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeNamedBits,
    encodeNull,
    encodeObjectIdentifier,
    encodeOcspCertId,
    encodeOctetString,
    encodeOid,
    encodePem,
    encodeRelativeOid,
    encodeSequence,
    encodeSet,
    encodeSetOf,
    encodeSignatureAlgorithm,
    encodeString,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeSubjectPublicKeyInfo,
    encodeTime,
    encodeTlv,
    encodeValidity,
    parseCertificate,
    type SigningKey,
} from '../../src/index.js';

// ── The deterministic signer ─────────────────────────────────────────

/** An Ed25519 PKCS#8 wrapper: version 0, the algorithm, then the seed in an OCTET STRING. */
const PKCS8_ED25519_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
/** Visibly not a real key: thirty-two 0x42 octets. */
const SEED = new Uint8Array(32).fill(0x42);
/** The Ed448 wrapper (RFC 8410 §7): version 0, id-Ed448, then the 57-octet seed in an OCTET STRING. */
const PKCS8_ED448_PREFIX = Uint8Array.from([0x30, 0x47, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x04, 0x3b, 0x04, 0x39]);
/** Visibly not a real key either: fifty-seven 0x43 octets. */
const SEED_448 = new Uint8Array(57).fill(0x43);

async function signer(name: 'Ed25519' | 'Ed448' = 'Ed25519'): Promise<{ readonly signer: SigningKey; readonly spki: Uint8Array }> {
    const pkcs8 = name === 'Ed25519' ? new Uint8Array([...PKCS8_ED25519_PREFIX, ...SEED]) : new Uint8Array([...PKCS8_ED448_PREFIX, ...SEED_448]);
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name }, false, ['sign']);
    // Web Crypto cannot give the public half of a private key, and pkinative
    // is not allowed to compute it (that is scalar multiplication on secret
    // material). node:crypto can, and scripts/ may use node:.
    const spki = new Uint8Array(createPublicKey(createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }));
    return { signer: { key, algorithm: { name } }, spki };
}

// ── The catalogue ────────────────────────────────────────────────────

const CN = '2.5.4.3';
const C = '2.5.4.6';
const KEY_ID = new Uint8Array(20).fill(0xab);
/** A stand-in for a SHA-256 digest: thirty-two 0x5a octets. */
const IMPRINT = new Uint8Array(32).fill(0x5a);
const NONCE = Uint8Array.of(0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef);
const DATA = new TextEncoder().encode('the bytes a signer committed to');
const QUIET = { onDiagnostic: (): undefined => undefined };

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

    const leaf = await createCertificate({
        serialNumber: 2n,
        issuerDer: parseCertificate(root, QUIET).subject.der,
        subject: [[{ type: CN, value: 'sample.example' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2026, 3, 1),
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'sample.example' }]) },
            { oid: '2.5.29.35', value: encodeAuthorityKeyIdentifier(KEY_ID) },
        ],
    }, key);
    out.set('cert/v3-leaf-issued-by-root', leaf);

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

    // The other structures the API writes. Every one is deterministic: the
    // signer is Ed25519, no signingTime is defaulted, every nonce is given.
    const rootCertificate = parseCertificate(root, QUIET);
    const leafCertificate = parseCertificate(leaf, QUIET);
    out.set('algid/signature-from-ed25519-signer', encodeSignatureAlgorithm(key));
    out.set('spki/ed25519', encodeSubjectPublicKeyInfo('1.3.101.112', spki.subarray(spki.length - 32)));
    out.set('ext/one-critical-extension', encodeExtension({ oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) }));
    out.set('attr/extension-request', encodeAttribute('1.2.840.113549.1.9.14', [
        encodeExtensions([{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) }]),
    ]));
    out.set('pem/certificate', new TextEncoder().encode(encodePem('CERTIFICATE', root)));

    // CMS (RFC 5652): attached under issuerAndSerialNumber; detached under the
    // subjectKeyIdentifier with a signingTime; then a timestamp token on the
    // attached signature (RFC 3161 Appendix A), the TSTInfo written by hand.
    const attached = await createSignedData({ content: DATA, certificate: leafCertificate }, key);
    out.set('cms/signed-data-attached', attached);
    out.set('cms/signed-data-detached-ski-signing-time', await createSignedData({
        content: DATA, detached: true, certificate: rootCertificate, sid: 'subjectKeyIdentifier', signingTime: Date.UTC(2026, 0, 2, 12, 0, 0),
    }, key));
    const tstInfo = encodeSequence([
        encodeInteger(1),
        encodeObjectIdentifier('1.3.6.1.4.1.99999.2'),
        encodeSequence([encodeAlgorithmIdentifier('2.16.840.1.101.3.4.2.1'), encodeOctetString(IMPRINT)]),
        encodeInteger(77),
        encodeTime(Date.UTC(2026, 0, 2, 12, 0, 1), 'GeneralizedTime'),
    ]);
    const token = await createSignedData({ content: tstInfo, contentType: '1.2.840.113549.1.9.16.1.4', certificate: rootCertificate }, key);
    out.set('cms/timestamp-token', token);
    out.set('cms/signed-data-with-timestamp-token', addTimeStampToken(attached, 0, token));

    // RFC 8419 §3.1 under Ed448: the digest is SHAKE256 with a 512-bit output,
    // which pkinative computes, and the signature the host's. The signer's
    // certificate is Ed448 too, self-signed, so the pair stands alone.
    const { signer: key448, spki: spki448 } = await signer('Ed448');
    const ed448 = await createCertificate({
        serialNumber: 3n,
        subject: [[{ type: CN, value: 'pkinative sample ed448' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2027, 0, 1),
        subjectPublicKey: spki448,
        extensions: [{ oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(KEY_ID) }],
    }, key448);
    out.set('cert/v3-ed448-self-signed', ed448);
    out.set('cms/signed-data-ed448-shake256', await createSignedData({ content: DATA, certificate: parseCertificate(ed448, QUIET) }, key448));

    // RFC 3161 and RFC 6960 requests.
    out.set('tsp/request-minimal', createTimeStampRequest(IMPRINT));
    out.set('tsp/request-nonce-policy-certreq', createTimeStampRequest(IMPRINT, { nonce: 0x0123456789abcdefn, policy: '1.3.6.1.4.1.99999.2', certReq: true }));
    out.set('ocsp/request-sha1-nonce', createOcspRequest(leafCertificate, rootCertificate, { nonce: NONCE }));
    out.set('ocsp/cert-id-sha256', encodeOcspCertId(leafCertificate, rootCertificate, 'SHA-256'));

    // The ASN.1 primitives, one each, at the values where encoders differ:
    // minimal INTEGER at both sign boundaries, SET OF sorted and SET as given,
    // the 2050 pivot, the DER trimming of named bits.
    out.set('asn1/node-reencoded-root', encodeAsn1Node(decodeAsn1(root)));
    out.set('asn1/bit-string-three-unused', encodeBitString(Uint8Array.of(0x6e, 0x5d, 0xc0), 3));
    out.set('asn1/boolean-true', encodeBoolean(true));
    out.set('asn1/enumerated-3', encodeEnumerated(3));
    out.set('asn1/explicit-0-null', encodeExplicit(0, encodeNull()));
    out.set('asn1/implicit-1-octets', encodeImplicit(1, encodeOctetString(Uint8Array.of(0xde, 0xad))));
    out.set('asn1/integer-minus-129', encodeInteger(-129n));
    out.set('asn1/integer-2-pow-64', encodeInteger(18446744073709551616n));
    out.set('asn1/named-bits-0-3-8', encodeNamedBits([0, 3, 8]));
    out.set('asn1/null', encodeNull());
    out.set('asn1/object-identifier-basic-constraints', encodeObjectIdentifier('2.5.29.19'));
    out.set('asn1/oid-contents-sha256-with-rsa', encodeOid('1.2.840.113549.1.1.11'));
    // X.690 §8.20.2's own example: no first-two-arcs packing, so 8571 is one subidentifier.
    out.set('asn1/relative-oid-8571-3-2', encodeRelativeOid('8571.3.2'));
    out.set('asn1/octet-string-four', encodeOctetString(Uint8Array.of(1, 2, 3, 4)));
    out.set('asn1/sequence-integer-boolean', encodeSequence([encodeInteger(1), encodeBoolean(false)]));
    out.set('asn1/set-as-given', encodeSet([encodeOctetString(Uint8Array.of(2)), encodeInteger(1)]));
    out.set('asn1/set-of-sorted', encodeSetOf([encodeOctetString(Uint8Array.of(0x62)), encodeOctetString(Uint8Array.of(0x61))]));
    out.set('asn1/string-printable', encodeString('printable', 'pkinative sample'));
    out.set('asn1/string-bmp', encodeString('bmp', 'pkinative'));
    out.set('asn1/time-utc-2026', encodeTime(Date.UTC(2026, 0, 1), 'UTCTime'));
    out.set('asn1/time-generalized-2050', encodeTime(Date.UTC(2050, 0, 1), 'GeneralizedTime'));
    out.set('asn1/time-rfc5280-pivot', encodeTime(Date.UTC(2049, 11, 31, 23, 59, 59), 'rfc5280'));
    out.set('asn1/tlv-private-7', encodeTlv('private', 7, false, Uint8Array.of(0x07)));

    return out;
}


/**
 * What the signed samples say, for a foreign tool to be held to: the facts
 * with one right answer, the certificate that issued each one, and — since
 * the samples' validity is fixed in 2026 — the instant a chain is judged at.
 */
export const EXPECTED = Object.freeze({
    'cert/v3-ed25519-root': { kind: 'cert', shape: 'ca', issuer: 'cert/v3-ed25519-root', facts: { commonName: 'pkinative sample root', serial: '123456789abcdef', dnsNames: '' } },
    'cert/v3-leaf-issued-by-root': { kind: 'cert', shape: 'leaf', issuer: 'cert/v3-ed25519-root', serverName: 'sample.example', verifyAt: Date.UTC(2026, 1, 1), facts: { commonName: 'sample.example', serial: '2', dnsNames: 'sample.example' } },
    'cert/v1-no-extensions': { kind: 'cert', shape: 'ca', issuer: 'cert/v1-no-extensions', facts: { commonName: 'pkinative sample v1', serial: '1', dnsNames: '' } },
    'csr/no-attributes': { kind: 'csr', facts: { commonName: 'sample.example' } },
    'csr/with-requested-extensions': { kind: 'csr', facts: { commonName: 'sample.example' } },
} as const);
