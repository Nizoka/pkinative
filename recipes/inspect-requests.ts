/**
 * Recipe: read a request back — what is about to be sent to a timestamp
 * authority, or what a log kept of it.
 *
 * pkinative writes requests and reads responses; this is the other reading
 * direction, for the tool that inspects a request before it leaves, replays
 * one from a capture, or explains why an authority declined it. It reads what
 * is **asked** and judges nothing: whether a token answers a request is
 * `verifyTimeStampToken`'s verdict, taken from the same bytes.
 *
 * A request another client wrote is read the same way, and what it does
 * differently is said rather than hidden — here, a `certReq` written out as
 * the FALSE it defaults to, which DER omits.
 */
import {
    computeFingerprint,
    createTimeStampRequest,
    encodeAlgorithmIdentifier,
    encodeBoolean,
    encodeInteger,
    encodeNull,
    encodeOctetString,
    encodeSequence,
    parseTimeStampRequest,
    PkiCmsError,
    type PkiDiagnostic,
    type TimeStampHashAlgorithm,
    type TimeStampRequest,
} from 'pkinative';

const SHA256 = '2.16.840.1.101.3.4.2.1';
const HASH_NAMES: ReadonlyMap<string, TimeStampHashAlgorithm> = new Map([
    [SHA256, 'SHA-256'],
    ['2.16.840.1.101.3.4.2.2', 'SHA-384'],
    ['2.16.840.1.101.3.4.2.3', 'SHA-512'],
]);
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, i) => byte === b[i]);

const describeTimeStampRequest = (request: TimeStampRequest): string => [
    `version=${String(request.version)}`,
    `hash=${HASH_NAMES.get(request.messageImprint.hashAlgorithm.oid) ?? request.messageImprint.hashAlgorithm.oid}`,
    `imprint=${String(request.messageImprint.hashedMessage.length)} octets`,
    `policy=${request.policy ?? 'the default of the TSA'}`,
    `nonce=${request.nonce === undefined ? 'none' : `0x${request.nonce.toString(16)}`}`,
    `certReq=${String(request.certReq)}`,
    `extensions=${String(request.extensions.length)}`,
].join(' ');

export default function run(): Record<string, string> {
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
    const foreign = parseTimeStampRequest(encodeSequence([encodeInteger(1n), imprint, encodeBoolean(false)]), { onDiagnostic: () => undefined });

    // A version this reader does not know is refused by name, not guessed at.
    let refused = 'accepted';
    try {
        parseTimeStampRequest(encodeSequence([encodeInteger(2n), imprint]));
    } catch (error) {
        refused = error instanceof PkiCmsError ? error.code : 'another error';
    }

    return {
        timeStampRequest: describeTimeStampRequest(request),
        timeStampDiagnostics: String(diagnostics.length),
        timeStampRebuilt: String(same(rebuilt, written)),
        timeStampForeign: `${describeTimeStampRequest(foreign)} ${foreign.diagnostics.map((d) => `${d.code}@${d.path}`).join(' ')}`,
        timeStampRefused: refused,
    };
}
