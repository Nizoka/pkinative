import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import * as api from '../../src/index.js';
import type { OcspBasicResponse, OcspCertId } from '../../src/index.js';
import { NOT_FLAGS, NOT_OBJECTS, refusal, takenInOnePlace, wrongInOnePlace } from '../core/_arguments.js';
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
            ['parseCertificationRequest', [csrDer, { ...OPTIONS, decodeExtensions: true }]],
            ['parseAttributeCertificate', [acDer, { ...OPTIONS, decodeExtensions: true }]],
            ['decodeExtensionValue', [extension.oid, extension.value, { ...OPTIONS, critical: true }]],
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
            ['importPrivateKey', [pkcs8, { algorithm: ECDSA, strict: false }]],
            ['decryptPrivateKey', [shrouded, { password: 'password', algorithm: ECDSA, strict: false }]],
            ['verifyPkcs12Mac', [pkcs12, 'password']],
            ['openSafeContents', [pkcs12.contents[0], 'password', OPTIONS]],
            // ── Signatures ──
            ['verifyCertificateSignature', [leaf, root, { allowSha1: false, requireAlgorithmMatch: true }]],
            ['verifySelfSignature', [root, { allowSha1: false, requireAlgorithmMatch: true }]],
            ['verifyCrlSignature', [crl, root, { allowSha1: false, requireAlgorithmMatch: true }]],
            ['verifyOcspSignature', [ocsp.basicResponse, root]],
            ['verifyAttributeCertificateSignature', [api.parseAttributeCertificate(acDer, quiet), root, { allowSha1: false, requireAlgorithmMatch: true }]],
            ['verifySignerInfoSignature', [signerInfo, leaf, { content, allowSha1: false }]],
            // ── Compositions ──
            ['verifyCertificationRequest', [csrDer, { allowSha1: false, decodeExtensions: true, limits: LIMITS, strict: false, ...quiet }]],
            ['verifyCertificateChain', [{ leaf, candidates: [root], trustAnchors: [root], at: AT, serverName: dns, purposes: [SERVER_AUTH], crls: [crlDer], ocspResponses: [ocspDer], ocspNonce: Uint8Array.of(1), requireOcspNonce: false, requireRevocation: false, allowSha1: false, initialPolicySet: ['2.5.29.32.0'], requireExplicitPolicy: false, inhibitPolicyMapping: false, inhibitAnyPolicy: false, limits: LIMITS, strict: false, ...quiet }]],
            ['verifySignedData', [{ signedData, certificates: [leaf], trustAnchors: [root], purposes: [SERVER_AUTH], at: AT, crls: [crlDer], ocspResponses: [ocspDer], requireRevocation: false, atTimeStamp: false, allowSha1: false, requireSigningCertificate: false, requireAlgorithmProtection: false, allowTrailingData: false, encodingRules: 'der', limits: LIMITS, strict: false, ...quiet }]],
            ['verifyTimeStampToken', [{ token, data: content, request, certificates: [tsa.certificate], trustAnchors: [root], at: AT, crls: [crlDer], ocspResponses: [ocspDer], requireRevocation: false, allowSha1: false, allowNonCriticalTimeStampingEku: false, limits: LIMITS, strict: false, ...quiet }]],
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

    it('should refuse a flag that is not a boolean, on every function', async () => {
        // `requireRevocation: 'true'` read as `=== true` is a check that stays
        // off without a word; `cA: 'false'` read as truthy is a CA.
        const report: string[] = [];
        for (const [name, args] of calls) {
            // One code for every flag; `encodeBoolean` takes a value to encode, not a flag.
            const lines = await takenInOnePlace(api[name] as (...a: never[]) => unknown, args, (value) => typeof value === 'boolean', NOT_FLAGS, name === 'encodeBoolean' ? 'PKI_INVALID_INPUT' : 'PKI_INVALID_OPTION');
            report.push(...lines.map((line) => `${name}: ${line}`));
        }
        expect(report, report.join('\n')).toEqual([]);
    }, 300_000);

    it('should refuse a number, a string or a boolean where an object, a list or bytes are expected', async () => {
        const report: string[] = [];
        for (const [name, args] of calls) {
            const lines = await takenInOnePlace(api[name] as (...a: never[]) => unknown, args, (value) => typeof value === 'object' && value !== null, NOT_OBJECTS);
            report.push(...lines.map((line) => `${name}: ${line}`));
        }
        const place = (line: string): string => line.replace(/ = .*$/, '');
        const unexplained = report.filter((line) => !(place(line) in NOT_READ));
        expect(unexplained, unexplained.join('\n')).toEqual([]);
        // An exemption that no longer applies would hide the next defect at that place.
        expect(Object.keys(NOT_READ).filter((exempt) => !report.some((line) => place(line) === exempt))).toEqual([]);
    }, 300_000);

    it('should refuse options that are not an object with one code, on every function', async () => {
        // The readers have refused them with PKI_INVALID_OPTION since 1.0.0: two codes for one mistake is one too many.
        const manifest = JSON.parse(readFileSync(new URL('../../docs/assets/api.json', import.meta.url), 'utf8')) as { exports: readonly Declared[] };
        const report: string[] = [];
        const seen: string[] = [];
        for (const fn of manifest.exports.filter((entry) => typeof (api as Readonly<Record<string, unknown>>)[entry.name] === 'function')) {
            const names = (fn.params ?? []).map((parameter) => parameter.name);
            // A parameter documented twice moves every index after it: `options` would be looked for one place too far.
            if (new Set(names).size !== names.length) report.push(`${fn.name}: a parameter is documented twice (${names.join(', ')})`);
            const index = names.indexOf('options');
            if (index < 0) continue;
            seen.push(fn.name);
            for (const [, args] of calls.filter(([name]) => name === fn.name)) {
                for (const [label, value] of [...NOT_OBJECTS, ['null', null] as const]) {
                    const call = Array.from({ length: Math.max(args.length, index + 1) }, (_, i) => (i === index ? value : args[i]));
                    const error = await refusal(() => (api[fn.name as keyof typeof api] as (...a: never[]) => unknown)(...(call as never[])));
                    const code = error instanceof api.PkiError ? error.code : String(error);
                    if (code !== (OPTIONS_ARE_THE_INPUT[fn.name] === undefined ? 'PKI_INVALID_OPTION' : 'PKI_INVALID_INPUT')) report.push(`${fn.name}: options = ${label}: ${code}`);
                }
            }
        }
        expect(report, report.join('\n')).toEqual([]);
        expect(seen.length).toBeGreaterThan(50);
        expect(Object.keys(OPTIONS_ARE_THE_INPUT).filter((exempt) => !seen.includes(exempt))).toEqual([]);
    }, 300_000);

    it('should name, in a call, every flag the types declare', () => {
        // The manifest is generated from the sources: an optional boolean member of a type a
        // function's signature names is a flag of that function, here or one level down.
        const manifest = JSON.parse(readFileSync(new URL('../../docs/assets/api.json', import.meta.url), 'utf8')) as { exports: readonly Declared[] };
        const flagsOf = new Map(manifest.exports.map((entry) => [entry.name, (entry.members ?? []).filter((m) => m.optional === true && /^boolean\b/.test((m.type ?? '').trim())).map((m) => m.name)] as const).filter(([, flags]) => flags.length > 0));
        const namedIn = (text: string): string[] => [...new Set(text.match(/\b[A-Z][A-Za-z0-9]+\b/g) ?? [])].filter((type) => flagsOf.has(type));
        const carries = (value: unknown, flag: string): boolean => {
            const holder: unknown = Array.isArray(value) ? value[0] : value;
            return typeof holder === 'object' && holder !== null && typeof (holder as Readonly<Record<string, unknown>>)[flag] === 'boolean';
        };
        const below = (value: unknown, member: string): unknown => {
            const held = typeof value === 'object' && value !== null ? (value as Readonly<Record<string, unknown>>)[member] : undefined;
            return Array.isArray(held) ? held[0] : held;
        };
        const missing: string[] = [];
        for (const fn of manifest.exports.filter((entry) => typeof entry.signature === 'string' && typeof (api as Readonly<Record<string, unknown>>)[entry.name] === 'function')) {
            const mine = calls.filter(([name]) => name === fn.name).flatMap(([, args]) => args);
            for (const type of namedIn(fn.signature ?? '')) {
                for (const flag of flagsOf.get(type) ?? []) {
                    if (!mine.some((argument) => carries(argument, flag))) missing.push(`${fn.name}: ${type}.${flag}`);
                }
                // One level down: the delta of a revocation check, the extensions of a description.
                for (const member of manifest.exports.find((entry) => entry.name === type)?.members ?? []) {
                    for (const nested of namedIn(member.type ?? '')) {
                        for (const flag of flagsOf.get(nested) ?? []) {
                            if (!mine.some((argument) => carries(below(argument, member.name), flag))) missing.push(`${fn.name}: ${type}.${member.name} → ${nested}.${flag}`);
                        }
                    }
                }
            }
        }
        expect(missing.filter((line) => !(line in NOT_A_FLAG_HERE)), missing.join('\n')).toEqual([]);
        expect(Object.keys(NOT_A_FLAG_HERE).filter((exempt) => !missing.includes(exempt))).toEqual([]);
    });
});

/** Flags a function's options type declares and the function has no use for, each with the reason. */
const NOT_A_FLAG_HERE: Readonly<Record<string, string>> = {
    'decodeAsn1Sequence: DecodeAsn1Options.allowTrailingData': 'every value of the input is decoded in turn: nothing trails, so there is nothing to allow',
};

/** What the manifest says of an export: its signature when it is a function, its members when it is a type. */
/** The functions whose parameter named `options` is not optional settings but what they encode. */
const OPTIONS_ARE_THE_INPUT: Readonly<Record<string, string>> = {
    encodeBasicConstraints: 'its one argument is the description of the extension to write, required: what is not an object there is a wrong input',
};

interface Declared {
    readonly name: string;
    readonly signature?: string;
    readonly params?: ReadonlyArray<{ readonly name: string }>;
    readonly members?: ReadonlyArray<{ readonly name: string; readonly type?: string; readonly optional?: boolean }>;
}

/**
 * Places where a wrong value is taken because the call never reads it: each
 * with the reason, and each still required to be taken — an entry that stops
 * applying fails the test.
 */
const NOT_READ: Readonly<Record<string, string>> = {
    'checkRevocation: argument 0.delta.crlDer': 'this delta is not one for this base (it is the base itself), so its bytes are never walked',
    'checkServerName: argument 2.path': 'the certificate has a dNSName, so the commonName fallback that reads the path is not taken',
    'checkServerName: argument 2.path.0': 'as above: the path is read only by the commonName fallback',
    'encodeSignatureAlgorithm: argument 0.key': 'only the algorithm is encoded; the key is read by the functions that sign',
    'findRevocation: argument 2.issuerDer': 'the list is not indirect, so no entry names an issuer to compare',
    'verifySignerInfoSignature: argument 2.content': 'this signer has signed attributes, which are what its signature covers',
};
