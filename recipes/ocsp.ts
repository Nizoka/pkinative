/**
 * Recipe: build an OCSP request, and read a response without losing the three
 * states RFC 6960 gives you.
 *
 * Two things this file is really about.
 *
 * On the way out: a `CertID` identifies the issuer by **hashes of its encoded
 * name and of its public key bits** — not by its name, and not by a hash of the
 * whole SubjectPublicKeyInfo. Hashing the SPKI is the single most common OCSP
 * client bug, and it produces a request the responder answers `unknown` to,
 * which a careless client then reports as "not revoked". This recipe shows both
 * hashes computed the right way, and asserts they differ from the wrong way.
 *
 * On the way back: `good`, `revoked` and `unknown` are three states.
 *
 * No network. A responder is simulated by assembling a response from raw DER,
 * the way one would emit it — so this runs on a plane, and nothing here depends
 * on pkinative being able to write an OCSP response, which it cannot.
 */
import {
    checkOcspStatus,
    OCSP_NONCE_OID,
    computeFingerprint,
    createCertificate,
    createOcspRequest,
    decodeAsn1,
    encodeBasicConstraints,
    encodeCertId,
    encodeOctetString,
    encodeSequence,
    encodeTime,
    encodeTlv,
    parseCertificate,
    parseOcspResponse,
    verifyOcspSignature,
    type Certificate,
    type OcspBasicResponse,
    type OcspCheckInput,
    type OcspHashAlgorithm,
    type OcspResponse,
    type OcspSingleResponse,
} from 'pkinative';
import { fixture } from './_fixtures.js';

const QUIET = { onDiagnostic: (): undefined => undefined };
const PRODUCED_AT = Date.UTC(2026, 5, 1);
const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const ROOT: Certificate = parseCertificate(fixture('isrg-root-x1'), QUIET);
const R12: Certificate = parseCertificate(fixture('lets-encrypt-r12'), QUIET);

/** `AlgorithmIdentifier { id-Ed25519 }` — no parameters, as RFC 8410 requires. */
const ALG_ED25519 = encodeSequence([encodeTlv('universal', 6, false, Uint8Array.of(0x2b, 0x65, 0x70))]);
/** `id-pkix-ocsp-basic`, the only `responseType` RFC 6960 defines. */
const OID_BASIC = encodeTlv('universal', 6, false, Uint8Array.of(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01));

/** A `CertStatus`: `[0] IMPLICIT NULL` for good, `[2] IMPLICIT` for unknown. */
const GOOD = encodeTlv('context', 0, false, new Uint8Array(0));
const UNKNOWN = encodeTlv('context', 2, false, new Uint8Array(0));

/**
 * `[1] IMPLICIT RevokedInfo`. The tag **replaces** the SEQUENCE's rather than
 * wrapping it, so the fields sit directly inside — wrapping them in a SEQUENCE
 * is the mistake IMPLICIT tagging invites.
 */
const revoked = (at: number, reason: number): Uint8Array => encodeTlv('context', 1, true, concat(
    encodeTime(at, 'GeneralizedTime'),
    encodeTlv('context', 0, true, encodeTlv('universal', 10, false, Uint8Array.of(reason))),
));

function concat(...parts: readonly Uint8Array[]): Uint8Array {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (const part of parts) { out.set(part, at); at += part.length; }
    return out;
}

/** One `SingleResponse` about `R12` under `ROOT`. */
const single = (status: Uint8Array, id?: Uint8Array): Uint8Array => encodeSequence([
    id ?? encodeCertId(R12, ROOT),
    status,
    encodeTime(PRODUCED_AT, 'GeneralizedTime'),
]);

/** How the caller signs: bound once, so nothing here needs a key type. */
type Sign = (data: Uint8Array) => Promise<Uint8Array>;

/** A signed `OCSPResponse` carrying the given answers. */
async function respond(statuses: readonly Uint8Array[], sign: Sign, keyHash: Uint8Array, id?: Uint8Array): Promise<Uint8Array> {
    const tbs = encodeSequence([
        // responderID byKey [2] EXPLICIT KeyHash, which is an OCTET STRING.
        encodeTlv('context', 2, true, encodeOctetString(keyHash)),
        encodeTime(PRODUCED_AT, 'GeneralizedTime'),
        encodeSequence(statuses.map((status) => single(status, id))),
    ]);
    const signature = await sign(tbs);
    const basic = encodeSequence([tbs, ALG_ED25519, encodeTlv('universal', 3, false, concat(Uint8Array.of(0x00), signature))]);
    return encodeSequence([
        encodeTlv('universal', 10, false, Uint8Array.of(0x00)),   // successful
        encodeTlv('context', 0, true, encodeSequence([OID_BASIC, encodeOctetString(basic)])),
    ]);
}

/** A responder that declines: a status with no body, which the protocol requires. */
const declines = (code: number): Uint8Array => encodeSequence([encodeTlv('universal', 10, false, Uint8Array.of(code))]);

const describeStatus = (single: OcspSingleResponse): string =>
    single.status.kind === 'revoked'
        ? `revoked on ${new Date(single.status.revocationTime.epochMilliseconds).toISOString().slice(0, 10)} reason=${String(single.status.reason)}`
        : single.status.kind;

const describe = (response: OcspResponse): string => {
    const basic: OcspBasicResponse | undefined = response.basicResponse;
    return basic === undefined
        ? `${response.status}, no body`
        : `${response.status}: ${basic.responses.map(describeStatus).join(' | ')}`;
};

export default async function run(): Promise<Record<string, string>> {
    // ── The request ──
    const nonce = Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4);
    const request = createOcspRequest(R12, ROOT, { nonce });
    const tbsRequest = decodeAsn1(request, QUIET).children[0];

    const certId = decodeAsn1(encodeCertId(R12, ROOT), QUIET);
    const nameHash = certId.children[1]?.content ?? new Uint8Array(0);
    const keyHash = certId.children[2]?.content ?? new Uint8Array(0);

    // SHA-256 is offered, but SHA-1 is the default on purpose: RFC 6960 §4.3
    // makes it mandatory for responders, and a SHA-256 CertID comes back
    // `unknown` from many of them — which a client must not read as "good".
    const wider: OcspHashAlgorithm = 'SHA-256';
    const sha256Id = decodeAsn1(encodeCertId(R12, ROOT, wider), QUIET);

    // ── The responses ──
    // `generateKey` is typed as returning `CryptoKey | CryptoKeyPair` for an
    // algorithm the standard library's unions do not list, and Ed25519 is one.
    // Narrowing with `in` is what a consumer writing this has to do too — and
    // it is a real runtime check rather than a cast that hides a wrong guess.
    const generated = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    if (!('privateKey' in generated)) throw new Error('Ed25519 returns a key pair');
    const sign: Sign = async (data) => new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, generated.privateKey, data));
    const responderSpki = new Uint8Array(await crypto.subtle.exportKey('spki', generated.publicKey));

    const good = parseOcspResponse(await respond([GOOD], sign, responderSpki.subarray(-32)), QUIET);
    const mixed = parseOcspResponse(await respond([GOOD, revoked(Date.UTC(2026, 4, 1), 1), UNKNOWN], sign, responderSpki.subarray(-32)), QUIET);
    const tryLater = parseOcspResponse(declines(3), QUIET);

    // A responder's signature says the bytes came from that key. Which key is
    // entitled to answer for this CA is a separate question, and not one this
    // library answers: `basicResponse.certificates` are certificates the
    // responder ATTACHED, and trusting them because they arrived would let the
    // responder nominate its own authority.
    const responder = parseCertificate(await createCertificate({
        serialNumber: 1n,
        subject: [[{ type: '2.5.4.3', value: 'Example OCSP Responder' }]],
        notBefore: PRODUCED_AT - 86_400_000,
        notAfter: PRODUCED_AT + 86_400_000,
        subjectPublicKey: responderSpki,
        extensions: [{ oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) }],
    }, { key: generated.privateKey, algorithm: { name: 'Ed25519' } }), QUIET);

    const signedByResponder = good.basicResponse === undefined
        ? 'no body'
        : `${String(await verifyOcspSignature(good.basicResponse, responder))} / wrongKey=${String(await verifyOcspSignature(good.basicResponse, ROOT))}`;

    // `parseOcspResponse` reads. It does not decide. RFC 6960 §3.2 makes a
    // client responsible for four things, and `checkOcspStatus` reports each:
    // the answer is about the certificate asked about, the signature verified,
    // the signer is authorised, and the answer is fresh. The middle two arrive
    // as verdicts the caller computed — which is what keeps the decision
    // synchronous and keeps policy out of this library.
    const expected = {
        issuerNameHash: computeFingerprint(ROOT.subject.der, 'SHA-1'),
        issuerKeyHash: computeFingerprint(ROOT.subjectPublicKeyInfo.publicKey.bytes, 'SHA-1'),
        serialNumber: R12.serialNumber.bytes,
    };
    const decide = (der: Uint8Array, overrides: Partial<OcspCheckInput> = {}): string => {
        const found = checkOcspStatus({
            response: parseOcspResponse(der, QUIET),
            expected, at: PRODUCED_AT + 3600_000,
            signatureVerified: true, responderAuthorised: true,
            ...overrides,
        });
        return found.length === 0 ? 'clean' : found.map((r) => r.code).sort().join(',');
    };

    const goodDer = await respond([GOOD], sign, responderSpki.subarray(-32));
    // An answer about another serial: a response a client trusting
    // `responses[0]` would accept as its own.
    const substituted = await respond([GOOD], sign, responderSpki.subarray(-32), encodeSequence([
        encodeSequence([
            encodeTlv('universal', 6, false, Uint8Array.of(0x2b, 0x0e, 0x03, 0x02, 0x1a)),
            encodeTlv('universal', 5, false, new Uint8Array(0)),
        ]),
        encodeOctetString(expected.issuerNameHash),
        encodeOctetString(expected.issuerKeyHash),
        encodeTlv('universal', 2, false, Uint8Array.of(0x99)),
    ]));

    return {
        requestFields: String(tbsRequest?.children.length),
        // The nonce extension's OID, exported so a caller can find the echo
        // themselves rather than hard-coding it.
        nonceOid: OCSP_NONCE_OID,
        decisionClean: decide(goodDer),
        decisionUnsigned: decide(goodDer, { signatureVerified: undefined }),
        decisionUnauthorised: decide(goodDer, { responderAuthorised: false }),
        decisionSubstituted: decide(substituted),
        decisionDeclined: decide(declines(3)),
        nonceEchoed: hex(nonce),
        nameHashBytes: String(nameHash.length),
        keyHashBytes: String(keyHash.length),
        // The bug this recipe exists to prevent: `issuerKeyHash` is over the
        // key BITS, so it must equal SHA-1 of `publicKey.bytes` and must NOT
        // equal SHA-1 of the whole SubjectPublicKeyInfo. Both halves are
        // asserted, because getting the first right by accident while the
        // second also matched would mean nothing.
        keyHashIsOverKeyBits: String(hex(keyHash) === hex(computeFingerprint(ROOT.subjectPublicKeyInfo.publicKey.bytes, 'SHA-1'))),
        keyHashIsNotSpkiHash: String(hex(keyHash) !== hex(computeFingerprint(ROOT.subjectPublicKeyInfo.der, 'SHA-1'))),
        nameHashIsOverEncodedName: String(hex(nameHash) === hex(computeFingerprint(ROOT.subject.der, 'SHA-1'))),
        sha256HashBytes: String(sha256Id.children[1]?.content.length),
        good: describe(good),
        threeStates: describe(mixed),
        declined: describe(tryLater),
        signatureChecked: signedByResponder,
        responderNamed: responder.subject.rdns.length === 1 ? 'one RDN' : 'unexpected',
    };
}
