/**
 * A small PKI for the CMS and RFC 3161 suites: an Ed25519 root, end-entity
 * certificates of every family it signs, timestamp authorities, TSTInfos,
 * tokens and CRLs — every signature real, made here with Web Crypto.
 *
 * Tests may generate keys; `src/` may not. The structures the verdicts are
 * asserted on are built here field by field (the TSTInfo, the CRL, the
 * surgery on a SignedData), so that a verdict is not checked against the
 * library's own reading of what it wrote.
 */

import { webcrypto } from 'node:crypto';
import { decodeAsn1 } from '../../src/asn1/asn1-decode.js';
import {
    encodeBitString,
    encodeBoolean,
    encodeEnumerated,
    encodeExplicit,
    encodeInteger,
    encodeNull,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeSequence,
    encodeTime,
    encodeTlv,
} from '../../src/asn1/asn1-encode.js';
import { createCertificate } from '../../src/build/build-certificate.js';
import { createSignedData, type CreateSignedDataInput } from '../../src/build/build-signed-data.js';
import {
    encodeAlgorithmIdentifier,
    encodeBasicConstraints,
    encodeExtendedKeyUsage,
    encodeKeyUsage,
    encodeSubjectKeyIdentifier,
} from '../../src/build/build-structures.js';
import type { ExtensionDescription } from '../../src/types/build-types.js';
import type { SignatureAlgorithm, SigningKey } from '../../src/types/crypto-types.js';
import type { CryptoKeyHandle } from '../../src/types/webcrypto.js';
import type { Certificate } from '../../src/types/x509-types.js';
import { parseCertificate } from '../../src/x509/x509-certificate.js';

/** A fixed instant in the past: every certificate here has expired by the time the suite runs without `at`. */
export const AT = Date.UTC(2026, 0, 15);
export const DAY = 86_400_000;
export const quiet = { onDiagnostic: (): undefined => undefined };

export const OID = {
    data: '1.2.840.113549.1.7.1',
    signedData: '1.2.840.113549.1.7.2',
    tstInfo: '1.2.840.113549.1.9.16.1.4',
    timeStampToken: '1.2.840.113549.1.9.16.2.14',
    timeStamping: '1.3.6.1.5.5.7.3.8',
    codeSigning: '1.3.6.1.5.5.7.3.3',
    emailProtection: '1.3.6.1.5.5.7.3.4',
    sha1: '1.3.14.3.2.26',
    sha256: '2.16.840.1.101.3.4.2.1',
    sha384: '2.16.840.1.101.3.4.2.2',
    sha512: '2.16.840.1.101.3.4.2.3',
    sha224: '2.16.840.1.101.3.4.2.4',
    policy: '1.3.6.1.4.1.99999.1',
} as const;

export const codes = (report: { readonly reasons: ReadonlyArray<{ readonly code: string }> }): string[] => report.reasons.map((r) => r.code);

export const sha = async (name: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512', data: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await webcrypto.subtle.digest(name, data));

// ── Keys ──

export type Family = 'ECDSA' | 'RSA' | 'Ed25519';

interface Pair { readonly privateKey: CryptoKeyHandle; readonly publicKey: CryptoKeyHandle }

const KEY_PARAMS: Record<Family, object> = {
    ECDSA: { name: 'ECDSA', namedCurve: 'P-256' },
    RSA: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' },
    Ed25519: { name: 'Ed25519' },
};
const SIGN_WITH: Record<Family, SignatureAlgorithm> = {
    ECDSA: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
    RSA: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    Ed25519: { name: 'Ed25519' },
};

export async function keyPair(family: Family, params: object = KEY_PARAMS[family]): Promise<Pair> {
    return await webcrypto.subtle.generateKey(params as never, true, ['sign', 'verify']) as unknown as Pair;
}

export async function spkiOf(pair: Pair): Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.exportKey('spki', pair.publicKey as never));
}

/** Web Crypto's raw sign, for the structures built by hand. */
export async function rawSign(params: object, key: CryptoKeyHandle, data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.sign(params as never, key as never, data));
}

// ── Certificates ──

export interface Authority {
    readonly certificate: Certificate;
    readonly key: CryptoKeyHandle;
}

export interface Holder {
    readonly certificate: Certificate;
    readonly pair: Pair;
    readonly signer: SigningKey;
}

/**
 * A self-signed root that may sign certificates and CRLs, valid AT ± 30 days:
 * Ed25519 by default, ECDSA P-256 when it must be able to sign over SHA-1.
 */
export async function makeRoot(cn = 'CMS Test Root', family: 'Ed25519' | 'ECDSA' = 'Ed25519'): Promise<Authority> {
    const pair = await keyPair(family);
    const name = [[{ type: '2.5.4.3', value: cn }]];
    const der = await createCertificate({
        serialNumber: 1n, issuer: name, subject: name,
        notBefore: AT - 30 * DAY, notAfter: AT + 30 * DAY,
        subjectPublicKey: await spkiOf(pair),
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
        ],
    }, { key: pair.privateKey, algorithm: SIGN_WITH[family] });
    return { certificate: parseCertificate(der, quiet), key: pair.privateKey };
}

export interface IssueOptions {
    readonly subject?: string;
    readonly serial?: bigint;
    readonly family?: Family;
    /** Reuse a key pair — how two certificates for one key are made. */
    readonly pair?: Pair;
    readonly notBefore?: number;
    readonly notAfter?: number;
    readonly extensions?: readonly ExtensionDescription[];
    /** A subjectKeyIdentifier, so the certificate can be named by `sid: 'subjectKeyIdentifier'`. */
    readonly ski?: Uint8Array;
    /** How `ca` signs the certificate; Ed25519 by default, which only an Ed25519 `ca` can do. */
    readonly signWith?: SignatureAlgorithm;
}

/** An end-entity certificate issued by `ca`, valid AT − 1 day to AT + 1 day unless told otherwise. */
export async function issue(ca: Authority, options: IssueOptions = {}): Promise<Holder> {
    const family = options.family ?? 'ECDSA';
    const pair = options.pair ?? await keyPair(family);
    const der = await createCertificate({
        serialNumber: options.serial ?? 2n,
        issuerDer: ca.certificate.subject.der,
        subject: [[{ type: '2.5.4.3', value: options.subject ?? 'CMS Test Signer' }]],
        notBefore: options.notBefore ?? AT - DAY,
        notAfter: options.notAfter ?? AT + DAY,
        subjectPublicKey: await spkiOf(pair),
        extensions: [
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
            ...(options.ski === undefined ? [] : [{ oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(options.ski) }]),
            ...(options.extensions ?? []),
        ],
    }, { key: ca.key, algorithm: options.signWith ?? { name: 'Ed25519' } });
    return { certificate: parseCertificate(der, quiet), pair, signer: { key: pair.privateKey, algorithm: SIGN_WITH[family] } };
}

export const eku = (purposes: readonly string[], critical = true): ExtensionDescription =>
    ({ oid: '2.5.29.37', critical, value: encodeExtendedKeyUsage([...purposes]) });

/** A timestamp authority as RFC 3161 §2.3 wants it: critical extKeyUsage, timestamping alone. Valid AT − 1 day to AT + 9 days. */
export async function issueTsa(ca: Authority, options: IssueOptions = {}): Promise<Holder> {
    return issue(ca, {
        subject: 'CMS Test TSA', serial: 3n, notAfter: AT + 9 * DAY,
        extensions: [eku([OID.timeStamping])],
        ...options,
    });
}

// ── RFC 3161 ──

export interface TstInfoOptions {
    /** The stamped hash. */
    readonly imprint: Uint8Array;
    readonly hashOid?: string;
    readonly policy?: string;
    readonly genTime?: number;
    /** The Accuracy SEQUENCE, whole. */
    readonly accuracy?: Uint8Array;
    /** `ordering`, written even when it is the DEFAULT FALSE that DER omits. */
    readonly ordering?: boolean;
    readonly nonce?: bigint;
    /** The GeneralName TLV of `tsa [0]`. */
    readonly tsa?: Uint8Array;
}

/** `TSTInfo` (RFC 3161 §2.4.2), field by field. */
export function tstInfo(options: TstInfoOptions): Uint8Array {
    return encodeSequence([
        encodeInteger(1),
        encodeObjectIdentifier(options.policy ?? OID.policy),
        encodeSequence([encodeAlgorithmIdentifier(options.hashOid ?? OID.sha256), encodeOctetString(options.imprint)]),
        encodeInteger(77),
        encodeTime(options.genTime ?? AT, 'GeneralizedTime'),
        ...(options.accuracy === undefined ? [] : [options.accuracy]),
        ...(options.ordering === undefined ? [] : [encodeBoolean(options.ordering)]),
        ...(options.nonce === undefined ? [] : [encodeInteger(options.nonce)]),
        ...(options.tsa === undefined ? [] : [encodeExplicit(0, options.tsa, { tagClass: 'context' })]),
    ]);
}

/** A TimeStampToken: `info` signed by `tsa`, as a TSA would. */
export async function makeToken(tsa: Holder, info: Uint8Array, extra: Partial<CreateSignedDataInput> = {}): Promise<Uint8Array> {
    return createSignedData({ content: info, contentType: OID.tstInfo, certificate: tsa.certificate, ...extra }, tsa.signer);
}

// ── CRLs ──

const ED25519 = encodeSequence([encodeObjectIdentifier('1.3.101.112')]);

/** A v2 CRL issued and really signed by `ca`, listing `revoked` when given, current at AT ± 20 days. */
export async function makeCrl(ca: Authority, revoked: readonly Certificate[] = []): Promise<Uint8Array> {
    const entries = revoked.map((certificate) => encodeSequence([
        encodeTlv('universal', 2, false, certificate.serialNumber.bytes),
        encodeTime(AT - 2 * DAY, 'UTCTime'),
    ]));
    const tbs = encodeSequence([
        encodeInteger(1),
        ED25519,
        ca.certificate.subject.der,
        encodeTime(AT - 20 * DAY, 'UTCTime'),
        encodeTime(AT + 20 * DAY, 'UTCTime'),
        ...(entries.length === 0 ? [] : [encodeSequence(entries)]),
    ]);
    return encodeSequence([tbs, ED25519, encodeBitString(await rawSign({ name: 'Ed25519' }, ca.key, tbs))]);
}

// ── OCSP ──

/**
 * A successful BasicOCSPResponse (RFC 6960 §4.2.1) about `certificate`, signed
 * by the Ed25519 `ca` that issued it, current at AT ± 1 day.
 */
export async function makeOcspResponse(ca: Authority, certificate: Certificate, status: 'good' | 'revoked', options: { readonly responderKeyHash?: Uint8Array } = {}): Promise<Uint8Array> {
    const keyHash = await sha('SHA-1', ca.certificate.subjectPublicKeyInfo.publicKey.bytes);
    const certId = encodeSequence([
        encodeSequence([encodeObjectIdentifier(OID.sha1), encodeNull()]),
        encodeOctetString(await sha('SHA-1', ca.certificate.subject.der)),
        encodeOctetString(keyHash),
        encodeTlv('universal', 2, false, certificate.serialNumber.bytes),
    ]);
    // CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo { revocationTime } }
    const certStatus = status === 'good'
        ? encodeTlv('context', 0, false, new Uint8Array(0))
        : encodeTlv('context', 1, true, encodeTime(AT - 2 * DAY, 'GeneralizedTime'));
    const tbs = encodeSequence([
        // responderID ::= [2] KeyHash — the CA's own, unless a test claims otherwise.
        encodeExplicit(2, encodeOctetString(options.responderKeyHash ?? keyHash), { tagClass: 'context' }),
        encodeTime(AT - DAY, 'GeneralizedTime'),
        encodeSequence([encodeSequence([
            certId,
            certStatus,
            encodeTime(AT - DAY, 'GeneralizedTime'),
            encodeExplicit(0, encodeTime(AT + DAY, 'GeneralizedTime'), { tagClass: 'context' }),
        ])]),
    ]);
    const basic = encodeSequence([tbs, ED25519, encodeBitString(await rawSign({ name: 'Ed25519' }, ca.key, tbs))]);
    return encodeSequence([
        encodeEnumerated(0),
        encodeExplicit(0, encodeSequence([encodeObjectIdentifier('1.3.6.1.5.5.7.48.1.1'), encodeOctetString(basic)]), { tagClass: 'context' }),
    ]);
}

// ── Surgery on a SignedData ──

/**
 * The same ContentInfo with the SignedData's fields replaced: `edit` gets the
 * encoding of every field, in order, and returns the new list.
 */
export function rebuildSignedData(der: Uint8Array, edit: (fields: Uint8Array[]) => Uint8Array[]): Uint8Array {
    const contentInfo = decodeAsn1(der);
    const [type, explicit] = contentInfo.children;
    const signedData = explicit?.children[0];
    if (type === undefined || signedData === undefined) throw new Error('not a ContentInfo');
    return encodeSequence([type.bytes, encodeExplicit(0, encodeSequence(edit(signedData.children.map((c) => c.bytes))), { tagClass: 'context' })]);
}

const isCertificateBag = (field: Uint8Array): boolean => field[0] === 0xa0;

/** The same message carrying exactly `certificates` in its bag (sorted as DER sorts a SET OF), or no bag at all. */
export function withCertificates(der: Uint8Array, certificates: readonly Uint8Array[]): Uint8Array {
    return rebuildSignedData(der, (fields) => {
        const kept = fields.filter((field) => !isCertificateBag(field));
        if (certificates.length === 0) return kept;
        const sorted = [...certificates].sort((a, b) => Buffer.compare(a, b));
        return [...kept.slice(0, 3), encodeTlv('context', 0, true, Buffer.concat(sorted)), ...kept.slice(3)];
    });
}

/** The same message with `signerInfos` holding exactly `signers`, in the order given. */
export function withSigners(der: Uint8Array, signers: readonly Uint8Array[]): Uint8Array {
    return rebuildSignedData(der, (fields) => [...fields.slice(0, -1), encodeTlv('universal', 17, true, Buffer.concat([...signers]))]);
}

/** The encoding of every SignerInfo of a message. */
export function signerInfosOf(der: Uint8Array): Uint8Array[] {
    const signedData = decodeAsn1(der).children[1]?.children[0];
    return (signedData?.children.at(-1)?.children ?? []).map((c) => c.bytes);
}

/** A copy of `der` with the last octet of `needle` flipped — a signature altered in place. */
export function flipLastOctetOf(der: Uint8Array, needle: Uint8Array): Uint8Array {
    const at = Buffer.from(der).indexOf(Buffer.from(needle));
    if (at < 0) throw new Error('needle not found');
    const out = der.slice();
    out[at + needle.length - 1] = (out[at + needle.length - 1] as number) ^ 0x01;
    return out;
}
