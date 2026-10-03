/**
 * Recipe: read a PKCS#10 certification request and judge its proof of
 * possession — what a CA does before it looks at anything else.
 *
 * A request is signed with the private half of the very key it carries, so
 * `verifyCertificationRequest` needs no trust anchor: the signature over
 * `certificationRequestInfo` either verifies under `subjectPKInfo` or it does
 * not. Like every report in pkinative it resolves — bytes that are not a
 * request, a false signature and a host that cannot put the question are
 * reasons, not exceptions — and a `valid` report says the requester holds
 * the key, nothing about whether the name or the extensions should be
 * granted. That decision stays the CA's.
 *
 * The request is built here with `createCertificationRequest`, by a key the
 * caller generates and pkinative never sees; what it writes, its own reader
 * reads back with no diagnostic.
 */
import {
    canSign,
    canVerify,
    createCertificationRequest,
    encodeKeyUsage,
    encodeSubjectAltName,
    formatDistinguishedName,
    parseCertificationRequest,
    verifyCertificationRequest,
} from 'pkinative';
import type { CertificationRequest, CsrAttribute, VerifyCertificationRequestOptions, VerifyCertificationRequestReport } from 'pkinative';

/** The one-line summary of a report: the verdict, then each reason at its path. */
const verdict = (report: VerifyCertificationRequestReport): string =>
    [`valid=${String(report.valid)}`, ...report.reasons.map((r) => `${r.code}@${r.path}`)].join(' ');

export default async function run(): Promise<Record<string, string>> {
    if (!canSign() || !canVerify()) return { available: 'no' };

    // The requester's key. pkinative generates none: this is the caller's call.
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const der = await createCertificationRequest({
        subject: [[{ type: '2.5.4.6', value: 'US', stringType: 'printable' }], [{ type: '2.5.4.3', value: 'host.example' }]],
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'host.example' }, { kind: 'dNSName', value: 'www.host.example' }]) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
        ],
    }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });

    // Read it: the subject, the key and the extensions it asks for, which
    // travel inside the PKCS#9 extensionRequest attribute and are decoded with
    // the certificate's own decoders. Zero diagnostics is the assertion.
    const diagnostics: string[] = [];
    const request: CertificationRequest = parseCertificationRequest(der, { onDiagnostic: (d) => { diagnostics.push(d.code); } });
    const attributes: readonly CsrAttribute[] = request.attributes;
    const requested = (request.extensions ?? []).map((e) => `${e.kind}${e.critical ? '!' : ''}`).join(',');
    const names = request.extensions?.flatMap((e) => (e.kind === 'subjectAltName' ? e.names.map((n) => (n.kind === 'dNSName' ? n.value : n.kind)) : [])) ?? [];

    // Judge it: the proof of possession, with the key inside the request.
    const options: VerifyCertificationRequestOptions = { allowSha1: false };
    const sound = await verifyCertificationRequest(der, options);

    // One octet of the subject changed after signing: the structure still
    // parses, the signature no longer covers it.
    const tampered = der.slice();
    const at = tampered.findIndex((_, i) => tampered[i] === 0x68 && tampered[i + 1] === 0x6f && tampered[i + 2] === 0x73 && tampered[i + 3] === 0x74); // "host"
    tampered[at] = 0x6a; // 'j'
    const altered = await verifyCertificationRequest(tampered);

    // Bytes that are not a request at all: a reason carrying the code the
    // parser would have thrown, never an exception.
    const garbage = await verifyCertificationRequest(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01));

    return {
        available: 'yes',
        subject: formatDistinguishedName(request.subject),
        key: `${request.subjectPublicKeyInfo.kind} version=${String(request.version)} diagnostics=${String(diagnostics.length)}`,
        attributes: attributes.map((a) => `${a.oid}(${String(a.values.length)})`).join(' '),
        requested,
        names: names.join(','),
        sound: `${verdict(sound)} verifications=${String(sound.signatureVerifications)}`,
        altered: `${verdict(altered)} subject=${altered.request === undefined ? '?' : formatDistinguishedName(altered.request.subject)}`,
        garbage: `${verdict(garbage)} errorCode=${garbage.reasons[0]?.errorCode ?? '?'} request=${String(garbage.request)}`,
    };
}
