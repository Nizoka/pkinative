/**
 * pkinative — path and revocation benchmarks (`npm run bench`)
 * ============================================================
 * The 0.5 decision paths over a small real PKI: the one-call chain report,
 * the path search over a bag, a revocation list of ten thousand entries read
 * and consulted, and an OCSP response read and judged. Every signature is
 * real (Ed25519, so the numbers are not dominated by ECDSA's randomness) and
 * is verified inside the measured call where the call verifies it: read the
 * `verifyCertificateChain` rows as Web Crypto plus pkinative, the parse and
 * check rows as pkinative alone. Numbers go to bench/RESULTS.md WITH their
 * run context — numbers without context are not evidence.
 */

import { bench, describe } from 'vitest';
import {
    buildCertificatePath,
    checkOcspStatus,
    checkRevocation,
    encodeAlgorithmIdentifier,
    encodeExplicit,
    encodeInteger,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeSequence,
    encodeTime,
    encodeTlv,
    parseCertificateList,
    parseOcspResponse,
    validateCertificatePath,
    verifyCertificateChain,
    type Certificate,
    type SignatureResult,
} from '../src/index.js';
import { AT, DAY, issue, makeRoot, rawSign } from '../tests/verify/_cms-pki.js';

const QUIET = { onDiagnostic: (): undefined => undefined };
const SHA256_ALG = encodeAlgorithmIdentifier('2.16.840.1.101.3.4.2.1');
const ED25519 = encodeSequence([encodeObjectIdentifier('1.3.101.112')]);

/** A CRL of `count` revoked serials (none of them the leaf's), really signed by the root. */
async function bigCrl(root: Awaited<ReturnType<typeof makeRoot>>, count: number): Promise<Uint8Array> {
    const entries: Uint8Array[] = [];
    for (let i = 0; i < count; i += 1) {
        entries.push(encodeSequence([encodeInteger(BigInt(1_000_000 + i)), encodeTime(AT - 2 * DAY, 'UTCTime')]));
    }
    const tbs = encodeSequence([
        encodeInteger(1), ED25519, root.certificate.subject.der,
        encodeTime(AT - 20 * DAY, 'UTCTime'), encodeTime(AT + 20 * DAY, 'UTCTime'),
        encodeSequence(entries),
    ]);
    return encodeSequence([tbs, ED25519, encodeTlv('universal', 3, false, Uint8Array.of(0, ...await rawSign({ name: 'Ed25519' }, root.key, tbs)))]);
}

/** A `good` OCSP answer about `certificate`, signed by the root itself. */
async function ocspResponse(root: Awaited<ReturnType<typeof makeRoot>>, certificate: Certificate): Promise<Uint8Array> {
    const certId = encodeSequence([SHA256_ALG, encodeOctetString(new Uint8Array(32)), encodeOctetString(new Uint8Array(32)), encodeTlv('universal', 2, false, certificate.serialNumber.bytes)]);
    const single = encodeSequence([certId, encodeTlv('context', 0, false, new Uint8Array(0)), encodeTime(AT - DAY, 'GeneralizedTime'), encodeExplicit(0, encodeTime(AT + DAY, 'GeneralizedTime'), { tagClass: 'context' })]);
    const tbs = encodeSequence([encodeExplicit(1, root.certificate.subject.der, { tagClass: 'context' }), encodeTime(AT - DAY, 'GeneralizedTime'), encodeSequence([single])]);
    const basic = encodeSequence([tbs, ED25519, encodeTlv('universal', 3, false, Uint8Array.of(0, ...await rawSign({ name: 'Ed25519' }, root.key, tbs)))]);
    return encodeSequence([encodeTlv('universal', 10, false, Uint8Array.of(0)), encodeExplicit(0, encodeSequence([encodeObjectIdentifier('1.3.6.1.5.5.7.48.1.1'), encodeOctetString(basic)]), { tagClass: 'context' })]);
}

// Top-level await: the PKI exists once for the whole file, so no row measures
// key generation or certificate issuance.
const world = await (async () => {
    const root = await makeRoot('Bench Root');
    const leaf = (await issue(root, { subject: 'bench.example', family: 'Ed25519' })).certificate;
    const bag: Certificate[] = [];
    for (let i = 0; i < 20; i += 1) bag.push((await issue(root, { subject: `Bystander ${String(i)}`, serial: BigInt(100 + i) })).certificate);
    const crl = await bigCrl(root, 10_000);
    const list = parseCertificateList(crl, QUIET);
    const ocsp = await ocspResponse(root, leaf);
    const response = parseOcspResponse(ocsp, QUIET);
    const signatures: SignatureResult[] = [{ certificate: leaf, issuer: root.certificate, verdict: 'valid' }];
    return { root: root.certificate, leaf, bag, crl, list, ocsp, response, signatures };
})();

describe('Path', () => {
    bench('verifyCertificateChain — leaf under a root, name checked (Ed25519 verify dominates)', async () => {
        await verifyCertificateChain({ leaf: world.leaf, trustAnchors: [world.root], at: AT, serverName: { kind: 'dns', value: 'bench.example' } });
    });
    bench('buildCertificatePath — leaf, 20 bystanders in the bag, verdicts supplied', () => {
        buildCertificatePath({ leaf: world.leaf, candidates: world.bag, trustAnchors: [world.root], at: AT, signatures: world.signatures });
    });
    bench('validateCertificatePath — §6 over [leaf], anchor implicit, verdicts supplied', () => {
        validateCertificatePath({ path: [world.leaf], trustAnchors: [world.root], at: AT, signatures: world.signatures });
    });
});

describe('Revocation', () => {
    bench('parseCertificateList — 10 000 entries', () => { parseCertificateList(world.crl, QUIET); });
    bench('checkRevocation — one serial against 10 000 entries, signature verdict supplied', () => {
        checkRevocation({ certificate: world.leaf, crl: world.list, crlDer: world.crl, at: AT, signatureVerified: true });
    });
    bench('verifyCertificateChain — with a 10 000-entry CRL, required (parse, sign check, lookup)', async () => {
        await verifyCertificateChain({ leaf: world.leaf, trustAnchors: [world.root], at: AT, crls: [world.crl], requireRevocation: true });
    });
    bench('parseOcspResponse — one good answer', () => { parseOcspResponse(world.ocsp, QUIET); });
    bench('checkOcspStatus — one good answer, verdicts supplied', () => {
        checkOcspStatus({
            response: world.response,
            expected: { issuerNameHash: new Uint8Array(32), issuerKeyHash: new Uint8Array(32), serialNumber: world.leaf.serialNumber.bytes },
            at: AT, signatureVerified: true, responderAuthorized: true,
        });
    });
});
