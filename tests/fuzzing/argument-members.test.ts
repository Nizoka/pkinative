import { webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import * as api from '../../src/index.js';
import type { OcspBasicResponse, OcspCertId } from '../../src/index.js';
import { refusal, wrongInOnePlace } from '../core/_arguments.js';
import { attributeCertificate } from '../helpers/attribute-certificate-builder.js';
import { authenticatedSafe, certBag, dataInfo, friendlyName, keyBag, pbmac1MacData, pfx, safeContents, shroudKey } from '../helpers/pkcs12-builder.js';
import { AT, issue, issueTsa, keyPair, makeCrl, makeOcspResponse, makeRoot, makeToken, quiet, sha, tstInfo } from '../verify/_cms-pki.js';

/**
 * One member of the wrong type, in a call that is otherwise valid.
 *
 * `arguments.test.ts` makes everything wrong at once, so the first guard of a
 * function answers and the ones after it are never reached. Here each call
 * starts valid and is wrong in **one** place — an argument, one of its
 * members, or a member of one of those — which is the only way to reach the
 * read of `expected` behind a valid `response`, of the second argument behind
 * a valid first, or of an option nested in `limits`. The answer must be a
 * returned value or a `PkiError`. What a reader returned is replaced whole and
 * never edited: the guards tell a parsed value by what the function reads
 * from it, and promise no more.
 *
 * Only the members a call names are swept, so each call names the optional
 * ones too. Every function of the entry point has a call: one added later
 * fails the first test until it has its own.
 */

type Call = readonly [name: keyof typeof api, args: readonly unknown[]];

const LIMITS = { maxDepth: 32 };
const OPTIONS = { strict: false, limits: LIMITS, ...quiet };
const NAME = [[{ type: '2.5.4.3', value: 'One Wrong Member', stringType: 'utf8' as const }]];
const ECDSA = { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' };
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';

/** The `PkiError` family is the only thing the entry point exports that is called with `new`. */
const isErrorClass = (value: unknown): boolean => (value as { readonly prototype?: unknown }).prototype instanceof Error;

describe('one member of the wrong type', () => {
    const calls: Call[] = [];

    beforeAll(async () => {
        const authority = await makeRoot();
        const root = authority.certificate;
        const holder = await issue(authority, { ski: Uint8Array.of(1, 2, 3, 4) });
        const leaf = holder.certificate;
        const spki = leaf.subjectPublicKeyInfo.der;
        const content = Uint8Array.of(1, 2, 3);
        const hash = await sha('SHA-256', content);
        const node = (der: Uint8Array): unknown => api.decodeAsn1(der);

        // ── Revocation ──
        const crlDer = await makeCrl(authority);
        const crl = api.parseCertificateList(crlDer, quiet);
        const ocspDer = await makeOcspResponse(authority, leaf, 'good');
        const ocsp = api.parseOcspResponse(ocspDer, quiet);
        const id = (ocsp.basicResponse as OcspBasicResponse).responses[0]?.certId as OcspCertId;
        // The CertID the response answers about: a match, so the call goes on to the freshness of the answer.
        const expected = { issuerNameHash: id.issuerNameHash, issuerKeyHash: id.issuerKeyHash, serialNumber: id.serialNumber.bytes };

        // ── CMS and timestamps ──
        const signedData = await api.createSignedData({ content, certificate: leaf, signingTime: AT }, holder.signer);
        const signerInfo = api.parseSignedData(signedData, quiet).signerInfos[0];
        const tsa = await issueTsa(authority);
        const info = tstInfo({ imprint: hash });
        const token = await makeToken(tsa, info);
        const request = api.createTimeStampRequest(hash, { hashAlgorithm: 'SHA-256', nonce: 5n, policy: '1.2.3.4', certReq: true });
        const response = api.encodeSequence([api.encodeSequence([api.encodeInteger(0)]), token]);

        // ── Keys ──
        const pair = await keyPair('ECDSA');
        const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey as never));
        const shrouded = await shroudKey(pkcs8, 'password');
        const authSafe = authenticatedSafe(dataInfo(safeContents(certBag(leaf.der, [friendlyName('leaf')]), keyBag(pkcs8))));
        const pfxDer = pfx({ authSafe, macData: await pbmac1MacData(authSafe, 'password') });
        const pkcs12 = api.parsePkcs12(pfxDer, quiet);

        // ── Requests and attribute certificates ──
        const extension = { oid: '2.5.29.19', critical: true, value: api.encodeBasicConstraints({ cA: false }) };
        const description = { serialNumber: 7n, issuer: NAME, subject: NAME, notBefore: AT, notAfter: AT + 1000, subjectPublicKey: spki, extensions: [extension] };
        const requestDescription = { subject: NAME, subjectPublicKey: spki, extensions: [extension] };
        const csrDer = await api.createCertificationRequest(requestDescription, holder.signer);
        const acDer = attributeCertificate();
        const signatures = [{ certificate: leaf, issuer: root, verdict: 'valid' }];
        const dns = { kind: 'dns', value: 'example.com' };

        calls.push(
            // ── ASN.1: decoding ──
            ['decodeAsn1', [root.der, { ...OPTIONS, encodingRules: 'der', allowTrailingData: false }]],
            ['decodeAsn1Sequence', [root.der, { ...OPTIONS, encodingRules: 'der' }]],
            ['decodeOid', [Uint8Array.of(0x2a, 0x03), OPTIONS]],
            ['readBoolean', [node(api.encodeBoolean(true)), OPTIONS]],
            ['readInteger', [node(api.encodeInteger(5)), OPTIONS]],
            ['readSmallInteger', [node(api.encodeInteger(5))]],
            ['readEnumerated', [node(api.encodeEnumerated(1)), OPTIONS]],
            ['readNull', [node(api.encodeNull())]],
            ['readBitString', [node(api.encodeBitString(content, 0)), OPTIONS]],
            ['readOctetString', [node(api.encodeOctetString(content)), OPTIONS]],
            ['readObjectIdentifier', [node(api.encodeObjectIdentifier('1.2.3')), OPTIONS]],
            ['readRelativeOid', [node(api.encodeRelativeOid('2.3')), OPTIONS]],
            ['readString', [node(api.encodeString('utf8', 'x')), OPTIONS]],
            ['readString', [node(api.encodeImplicit(0, api.encodeString('utf8', 'x'))), { ...OPTIONS, stringType: 'utf8' }]],
            ['readTime', [node(api.encodeTime(AT, 'UTCTime')), OPTIONS]],
            ['readTime', [node(api.encodeImplicit(0, api.encodeTime(AT, 'UTCTime'))), { ...OPTIONS, timeType: 'UTCTime' }]],
            // ── ASN.1: encoding ──
            ['encodeTlv', ['universal', 4, false, content]],
            ['encodeSequence', [[content]]],
            ['encodeSet', [[api.encodeNull()]]],
            ['encodeSetOf', [[api.encodeNull()]]],
            ['encodeInteger', [5]],
            ['encodeBoolean', [true]],
            ['encodeNull', []],
            ['encodeBitString', [content, 0]],
            ['encodeOctetString', [content]],
            ['encodeEnumerated', [1]],
            ['encodeExplicit', [0, api.encodeNull(), { tagClass: 'context' }]],
            ['encodeImplicit', [0, api.encodeNull(), { tagClass: 'context' }]],
            ['encodeNamedBits', [[0, 5]]],
            ['encodeObjectIdentifier', ['1.2.3']],
            ['encodeRelativeOid', ['2.3']],
            ['encodeOid', ['1.2.3']],
            ['encodeString', ['utf8', 'x']],
            ['encodeTime', [AT, 'rfc5280']],
            ['encodeAsn1Node', [node(root.der)]],
            ['isValidOid', ['1.2.3']],
            ['getOidName', ['2.5.4.3']],
            // ── PEM and hashes ──
            ['decodePem', [api.encodePem('CERTIFICATE', root.der), { ...OPTIONS, label: 'CERTIFICATE', mode: 'strict' }]],
            ['encodePem', ['CERTIFICATE', root.der]],
            ['computeFingerprint', [root.der, 'SHA-256']],
            ['computeFingerprintAsync', [root.der, 'SHA-256']],
            ['formatFingerprint', [hash, { separator: ':', letterCase: 'upper' }]],
            ['computeKeyIdentifier', [content, 'SHA-1']],
            ['shake256', [content, 32]],
            // ── X.509: readers ──
            ['parseCertificate', [root.der, { ...OPTIONS, decodeExtensions: true }]],
            ['parseCertificationRequest', [csrDer, OPTIONS]],
            ['parseAttributeCertificate', [acDer, OPTIONS]],
            ['decodeExtensionValue', [extension.oid, extension.value, OPTIONS]],
            ['getExtension', [leaf, '2.5.29.15']],
            ['formatDistinguishedName', [leaf.subject]],
            // ── Writers ──
            ['encodeAlgorithmIdentifier', ['1.2.840.113549.1.1.11', api.encodeNull()]],
            ['encodeNameAttribute', [{ type: '2.5.4.3', value: 'x', stringType: 'utf8' }]],
            ['encodeDistinguishedName', [NAME, { limits: LIMITS }]],
            ['encodeValidity', [AT, AT + 1000]],
            ['encodeAttribute', ['1.2.3', [api.encodeNull()]]],
            ['encodeSubjectPublicKeyInfo', ['1.2.840.10045.2.1', content, api.encodeObjectIdentifier('1.2.840.10045.3.1.7')]],
            ['encodeExtension', [extension]],
            ['encodeExtensions', [[extension], { limits: LIMITS }]],
            ['encodeBasicConstraints', [{ cA: true, pathLenConstraint: 0 }]],
            ['encodeKeyUsage', [['digitalSignature']]],
            ['encodeExtendedKeyUsage', [[SERVER_AUTH]]],
            ['encodeSubjectAltName', [[{ kind: 'dNSName', value: 'example.com' }]]],
            ['encodeSubjectKeyIdentifier', [content]],
            ['encodeAuthorityKeyIdentifier', [content]],
            ['encodeSignatureAlgorithm', [holder.signer]],
            ['canSign', []],
            ['canVerify', []],
            ['canDecrypt', []],
            ['createCertificate', [description, holder.signer, { limits: LIMITS }]],
            ['createCertificationRequest', [requestDescription, holder.signer, { limits: LIMITS }]],
            ['createSignedData', [{ content, certificate: leaf, sid: 'issuerAndSerialNumber', certificates: [root.der], crls: [crlDer], signedAttributes: [], unsignedAttributes: [], signingTime: AT, detached: false, contentType: '1.2.840.113549.1.7.1', signingCertificateV2: true, algorithmProtection: true }, holder.signer, { limits: LIMITS }]],
            ['createSignedData', [{ contentDigest: hash, certificate: leaf, sid: 'subjectKeyIdentifier' }, holder.signer]],
            ['addUnsignedAttribute', [signedData, 0, api.encodeAttribute('1.2.3.4', [api.encodeNull()]), { limits: LIMITS }]],
            ['addTimeStampToken', [signedData, 0, token, { limits: LIMITS }]],
            ['createTimeStampRequest', [hash, { hashAlgorithm: 'SHA-256', nonce: 5n, policy: '1.2.3.4', certReq: true }]],
            ['encodeOcspCertId', [leaf, root, 'SHA-1']],
            ['createOcspRequest', [leaf, root, { nonce: new Uint8Array(16), hashAlgorithm: 'SHA-256' }]],
            // ── Paths ──
            ['buildCertificatePath', [{ leaf, candidates: [root], trustAnchors: [root], at: AT, signatures, purposes: [SERVER_AUTH], initialPolicySet: ['2.5.29.32.0'], limits: LIMITS }]],
            ['validateCertificatePath', [{ path: [leaf, root], trustAnchors: [root], at: AT, signatures, initialPolicySet: ['2.5.29.32.0'], requireExplicitPolicy: false, inhibitPolicyMapping: false, inhibitAnyPolicy: false, limits: LIMITS }]],
            ['checkExtendedKeyUsage', [[leaf, root], SERVER_AUTH, { restrictIssuers: true, requireExplicitPurpose: true }]],
            ['checkServerName', [leaf, dns, { allowCommonNameFallback: true, path: [leaf, root], allowWildcards: true }]],
            ['checkServerName', [leaf, { kind: 'ip', value: Uint8Array.of(192, 0, 2, 1) }]],
            ['matchDnsName', ['*.example.com', 'www.example.com', { allowWildcards: true }]],
            // ── Revocation ──
            ['parseCertificateList', [crlDer, OPTIONS]],
            ['findRevocation', [crlDer, leaf.serialNumber.bytes, { ...OPTIONS, issuerDer: leaf.issuer.der }]],
            ['checkRevocation', [{ certificate: leaf, crl, crlDer, at: AT, signatureVerified: true, staleTolerance: 0, delta: { crl, crlDer, signatureVerified: true }, limits: LIMITS, strict: false, ...quiet }]],
            ['parseOcspRequest', [api.createOcspRequest(leaf, root), OPTIONS]],
            ['parseOcspResponse', [ocspDer, OPTIONS]],
            ['checkOcspStatus', [{ response: ocsp, expected, at: AT, signatureVerified: true, responderAuthorized: true, signer: root, nonce: Uint8Array.of(1), requireNonce: false, staleTolerance: 0, futureTolerance: 60_000, strict: false, ...quiet }]],
            // ── CMS and timestamps ──
            ['parseSignedData', [signedData, { ...OPTIONS, encodingRules: 'der', allowTrailingData: false }]],
            ['parseTimeStampRequest', [request, OPTIONS]],
            ['parseTimeStampResponse', [response, OPTIONS]],
            ['parseTimeStampToken', [token, OPTIONS]],
            ['parseTstInfo', [info, OPTIONS]],
            // ── Keys ──
            ['parsePrivateKeyInfo', [pkcs8, OPTIONS]],
            ['parseEncryptedPrivateKeyInfo', [shrouded, OPTIONS]],
            ['parsePkcs12', [pfxDer, OPTIONS]],
            ['importPrivateKey', [pkcs8, { algorithm: ECDSA }]],
            ['decryptPrivateKey', [shrouded, { password: 'password', algorithm: ECDSA }]],
            ['verifyPkcs12Mac', [pkcs12, 'password']],
            ['openSafeContents', [pkcs12.contents[0], 'password', OPTIONS]],
            // ── Signatures ──
            ['verifyCertificateSignature', [leaf, root, { allowSha1: false }]],
            ['verifySelfSignature', [root, { allowSha1: false }]],
            ['verifyCrlSignature', [crl, root, { allowSha1: false }]],
            ['verifyOcspSignature', [ocsp.basicResponse, root, { allowSha1: false }]],
            ['verifyAttributeCertificateSignature', [api.parseAttributeCertificate(acDer, quiet), root, { allowSha1: false }]],
            ['verifySignerInfoSignature', [signerInfo, leaf, { content }]],
            // ── Compositions ──
            ['verifyCertificationRequest', [csrDer, { allowSha1: false, limits: LIMITS, strict: false, ...quiet }]],
            ['verifyCertificateChain', [{ leaf, candidates: [root], trustAnchors: [root], at: AT, serverName: dns, purposes: [SERVER_AUTH], crls: [crlDer], ocspResponses: [ocspDer], ocspNonce: Uint8Array.of(1), requireOcspNonce: false, requireRevocation: false, allowSha1: false, initialPolicySet: ['2.5.29.32.0'], limits: LIMITS, strict: false, ...quiet }]],
            ['verifySignedData', [{ signedData, certificates: [leaf], trustAnchors: [root], purposes: [SERVER_AUTH], at: AT, crls: [crlDer], ocspResponses: [ocspDer], requireRevocation: false, atTimeStamp: false, allowSha1: false, allowTrailingData: false, encodingRules: 'der', limits: LIMITS, strict: false, ...quiet }]],
            ['verifyTimeStampToken', [{ token, data: content, request, certificates: [tsa.certificate], trustAnchors: [root], at: AT, crls: [crlDer], ocspResponses: [ocspDer], requireRevocation: false, allowSha1: false, limits: LIMITS, strict: false, ...quiet }]],
            ['openPkcs12', [pfxDer, { password: 'password', allowUnverifiedIntegrity: false, limits: LIMITS, strict: false, ...quiet }]],
        );
    });

    it('should have a call for every function of the entry point', () => {
        const functions = Object.entries(api as Readonly<Record<string, unknown>>)
            .filter(([, value]) => typeof value === 'function' && !isErrorClass(value))
            .map(([name]) => name)
            .sort();
        expect([...new Set(calls.map(([name]) => name as string))].sort()).toEqual(functions);
    });

    it('should start from calls that are valid', async () => {
        for (const [name, args] of calls) {
            // A valid call returns: a throw here would hide every guard behind it.
            expect(await refusal(() => (api[name] as (...a: never[]) => unknown)(...(args as never[]))), name).toBeUndefined();
        }
    });

    it('should return, or throw a PkiError, wherever the one wrong member is', async () => {
        const report: string[] = [];
        for (const [name, args] of calls) {
            const lines = await wrongInOnePlace(api[name] as (...a: never[]) => unknown, args);
            report.push(...lines.map((line) => `${name}: ${line}`));
        }
        expect(report, report.join('\n')).toEqual([]);
    }, 300_000);
});
