/**
 * Recipe: read a request back — what is about to be sent to a timestamp
 * authority or an OCSP responder, or what a log kept of it.
 *
 * pkinative writes requests and reads responses; this is the other reading
 * direction, for the tool that inspects a request before it leaves, replays
 * one from a capture, or explains why an authority declined it. Both readers
 * read what is **asked** and judge nothing: whether a token answers a
 * timestamp request is `verifyTimeStampToken`'s verdict, whether a response
 * answers an OCSP request is `checkOcspStatus`'s, and pkinative is neither a
 * TSA nor a responder — a signed OCSP request has its signature exposed, not
 * verified.
 *
 * A request another client wrote is read the same way, and what it does
 * differently is said rather than hidden — here, a timestamp request whose
 * `certReq` is written out as the FALSE it defaults to, and a signed OCSP
 * request that does not name who signed it.
 */
import {
    computeFingerprint,
    createOcspRequest,
    createTimeStampRequest,
    encodeAlgorithmIdentifier,
    encodeBitString,
    encodeBoolean,
    encodeExplicit,
    encodeInteger,
    encodeNull,
    encodeOcspCertId,
    encodeOctetString,
    encodeSequence,
    parseCertificate,
    parseOcspRequest,
    parseTimeStampRequest,
    PkiCertificateError,
    PkiCmsError,
    type OcspRequest,
    type OcspRequestEntry,
    type OcspRequestSignature,
    type PkiDiagnostic,
    type TimeStampHashAlgorithm,
    type TimeStampRequest,
} from 'pkinative';
import { fixture } from './_fixtures.ts';

const QUIET = { onDiagnostic: (): undefined => undefined };
const SHA256 = '2.16.840.1.101.3.4.2.1';
const HASH_NAMES: ReadonlyMap<string, TimeStampHashAlgorithm> = new Map([
    [SHA256, 'SHA-256'],
    ['2.16.840.1.101.3.4.2.2', 'SHA-384'],
    ['2.16.840.1.101.3.4.2.3', 'SHA-512'],
]);
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, i) => byte === b[i]);
const where = (diagnostics: readonly PkiDiagnostic[]): string => diagnostics.map((d) => `${d.code}@${d.path}`).join(' ') || 'none';

const describeTimeStampRequest = (request: TimeStampRequest): string => [
    `version=${String(request.version)}`,
    `hash=${HASH_NAMES.get(request.messageImprint.hashAlgorithm.oid) ?? request.messageImprint.hashAlgorithm.oid}`,
    `imprint=${String(request.messageImprint.hashedMessage.length)} octets`,
    `policy=${request.policy ?? 'the default of the TSA'}`,
    `nonce=${request.nonce === undefined ? 'none' : `0x${request.nonce.toString(16)}`}`,
    `certReq=${String(request.certReq)}`,
    `extensions=${String(request.extensions.length)}`,
].join(' ');

const describeSignature = (signature: OcspRequestSignature | undefined): string =>
    signature === undefined ? 'no' : `${signature.signatureAlgorithm.oid} over tbsDer, ${String(signature.certificates.length)} certificate(s) attached, not verified`;

const describeOcspRequest = (request: OcspRequest): string => [
    `version=${String(request.version)}`,
    `requests=${request.requests.map((entry: OcspRequestEntry) => `${entry.certId.hashAlgorithm.oid}/${entry.certId.serialNumber.hex}`).join(',')}`,
    `nonce=${request.nonce === undefined ? 'none' : `${String(request.nonce.length)} octets`}`,
    `requestor=${request.requestorName?.kind ?? 'unnamed'}`,
    `signed=${describeSignature(request.signature)}`,
].join(' ');

function timeStampRequests(): Record<string, string> {
    const hash = computeFingerprint(new TextEncoder().encode('the document to stamp'), 'SHA-256');

    // The request this library writes, read back with nothing to say about it.
    const diagnostics: PkiDiagnostic[] = [];
    const written = createTimeStampRequest(hash, { nonce: 0x1f2e3d4c5b6a7988n, policy: '1.3.6.1.4.1.99999.2' });
    const request = parseTimeStampRequest(written, { onDiagnostic: (d) => { diagnostics.push(d); } });

    // Every field a request holds is one the writer takes: the parsed request
    // rebuilds the bytes it was read from.
    const rebuilt = createTimeStampRequest(request.messageImprint.hashedMessage, {
        hashAlgorithm: HASH_NAMES.get(request.messageImprint.hashAlgorithm.oid),
        policy: request.policy,
        nonce: request.nonce,
        certReq: request.certReq,
    });

    // A request from another client: certReq written as FALSE, its DEFAULT.
    const imprint = encodeSequence([encodeAlgorithmIdentifier(SHA256, encodeNull()), encodeOctetString(hash)]);
    const foreign = parseTimeStampRequest(encodeSequence([encodeInteger(1n), imprint, encodeBoolean(false)]), QUIET);

    // A version this reader does not know is refused by name, not guessed at.
    let refused = 'accepted';
    try {
        parseTimeStampRequest(encodeSequence([encodeInteger(2n), imprint]));
    } catch (error) {
        refused = error instanceof PkiCmsError ? error.code : 'another error';
    }

    return {
        timeStampRequest: describeTimeStampRequest(request),
        timeStampDiagnostics: where(diagnostics),
        timeStampRebuilt: String(same(rebuilt, written)),
        timeStampForeign: `${describeTimeStampRequest(foreign)} ${where(foreign.diagnostics)}`,
        timeStampRefused: refused,
    };
}

function ocspRequests(): Record<string, string> {
    const issuer = parseCertificate(fixture('isrg-root-x1'), QUIET);
    const certificate = parseCertificate(fixture('lets-encrypt-r12'), QUIET);

    // The request this library writes: one certificate, a nonce, no signature.
    const diagnostics: PkiDiagnostic[] = [];
    const nonce = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
    const written = createOcspRequest(certificate, issuer, { nonce });
    const request = parseOcspRequest(written, { onDiagnostic: (d) => { diagnostics.push(d); } });

    // Which certificate is it about? The CertID is kept as encoded, so the
    // answer is a comparison of bytes — no hash is recomputed by hand.
    const [entry] = request.requests;
    const aboutThisCertificate = entry !== undefined && same(entry.certIdDer, encodeOcspCertId(certificate, issuer));

    // A signed request from another client that does not say who signed it:
    // the Signature under [0] EXPLICIT, and no requestorName in the tbsRequest.
    const tbsRequest = request.tbsDer;
    const signature = encodeSequence([encodeAlgorithmIdentifier('1.3.101.112'), encodeBitString(new Uint8Array(64))]);
    const signed = parseOcspRequest(encodeSequence([tbsRequest, encodeExplicit(0, signature, { tagClass: 'context' })]), QUIET);

    // Bytes that are not a request are refused by name, never half-read.
    let refused = 'accepted';
    try {
        parseOcspRequest(encodeSequence([encodeInteger(0n)]));
    } catch (error) {
        refused = error instanceof PkiCertificateError ? error.code : 'another error';
    }

    return {
        ocspRequest: describeOcspRequest(request),
        ocspDiagnostics: where(diagnostics),
        ocspNonceEchoes: String(request.nonce !== undefined && same(request.nonce, nonce)),
        ocspAboutThisCertificate: String(aboutThisCertificate),
        ocspSigned: `${describeOcspRequest(signed)} ${where(signed.diagnostics)}`,
        ocspSignatureCovers: String(same(signed.tbsDer, tbsRequest)),
        ocspRefused: refused,
    };
}

export default function run(): Record<string, string> {
    return { ...timeStampRequests(), ...ocspRequests() };
}
