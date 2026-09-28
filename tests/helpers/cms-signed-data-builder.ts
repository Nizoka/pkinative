/**
 * An engine-independent SignedData builder for tests. Like raw-der-builder.ts,
 * it NEVER imports src/: every ContentInfo the CMS suites parse is assembled
 * here from the RFC 5652 ASN.1 module, field by field, so that the parser is
 * checked against the standard and not against pkinative's own encoders.
 *
 * Every field can be replaced by raw bytes, which is how the hostile inputs
 * are made: a default for everything, and one field swapped per test.
 */

import { ascii, concat, sequence, tlv, universal } from './raw-der-builder.js';

// ── Primitives ──

/** An OBJECT IDENTIFIER TLV from its dotted form (X.690 §8.19). */
export function oid(dotted: string): Uint8Array {
    const arcs = dotted.split('.').map((arc) => BigInt(arc));
    const [first = 0n, second = 0n, ...rest] = arcs;
    const content: number[] = [];
    for (const arc of [first * 40n + second, ...rest]) {
        const digits: number[] = [];
        let value = arc;
        do {
            digits.unshift(Number(value % 128n));
            value /= 128n;
        } while (value > 0n);
        content.push(...digits.map((d, i) => (i < digits.length - 1 ? d | 0x80 : d)));
    }
    return universal(6, content);
}

/** A small non-negative INTEGER, minimally encoded. */
export function int(value: number): Uint8Array {
    const body: number[] = [];
    let rest = value;
    do {
        body.unshift(rest % 256);
        rest = Math.floor(rest / 256);
    } while (rest > 0);
    if ((body[0] as number) & 0x80) body.unshift(0);
    return universal(2, body);
}

/** A SET, in the order given. */
export const set = (...children: ReadonlyArray<ArrayLike<number>>): Uint8Array => universal(17, concat(...children), true);

/** Compare two encodings as X.690 §11.6 does. */
function compare(a: Uint8Array, b: Uint8Array): number {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
    return a.length - b.length;
}

/** The children of a DER SET OF, sorted as X.690 §11.6 requires. */
export const sorted = (children: readonly Uint8Array[]): Uint8Array[] => [...children].sort(compare);

export const octets = (bytes: ArrayLike<number>): Uint8Array => universal(4, bytes);
/** A context-specific TLV. */
export const context = (tag: number, constructed: boolean, content: ArrayLike<number>): Uint8Array => tlv(2, constructed, tag, content);
/** An AlgorithmIdentifier, with NULL parameters unless told otherwise. */
export const alg = (dotted: string, parameters: Uint8Array | null = universal(5, [])): Uint8Array =>
    sequence(oid(dotted), ...(parameters === null ? [] : [parameters]));
/** A Name with one CN. */
export const name = (cn: string): Uint8Array => sequence(universal(17, sequence(oid('2.5.4.3'), universal(12, ascii(cn))), true));
/** `Attribute ::= SEQUENCE { attrType, attrValues SET OF }`. */
export const attribute = (type: string, ...values: readonly Uint8Array[]): Uint8Array => sequence(oid(type), set(...values));

// ── OIDs ──

export const OIDS = Object.freeze({
    data: '1.2.840.113549.1.7.1',
    signedData: '1.2.840.113549.1.7.2',
    envelopedData: '1.2.840.113549.1.7.3',
    tstInfo: '1.2.840.113549.1.9.16.1.4',
    contentType: '1.2.840.113549.1.9.3',
    messageDigest: '1.2.840.113549.1.9.4',
    signingTime: '1.2.840.113549.1.9.5',
    signingCertificate: '1.2.840.113549.1.9.16.2.12',
    signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
    timeStampToken: '1.2.840.113549.1.9.16.2.14',
    ocspResponse: '1.3.6.1.5.5.7.16.2',
    sha1: '1.3.14.3.2.26',
    sha256: '2.16.840.1.101.3.4.2.1',
    sha384: '2.16.840.1.101.3.4.2.2',
    sha512: '2.16.840.1.101.3.4.2.3',
    rsaEncryption: '1.2.840.113549.1.1.1',
});

export const DIGEST = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
export const SIGNATURE = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
export const ISSUER = name('Example CA');
export const SERIAL = int(0x1234);
export const SKI = Uint8Array.of(0xbe, 0x6c, 0x11, 0x22);

/** The two attributes RFC 5652 §5.3 requires when signed attributes are present, DER-sorted. */
export const defaultSignedAttributes = (): Uint8Array[] => sorted([
    attribute(OIDS.contentType, oid(OIDS.data)),
    attribute(OIDS.messageDigest, octets(DIGEST)),
]);

// ── Structures ──

export interface SignerParts {
    readonly version?: Uint8Array;
    /** The sid TLV; `issuerAndSerialNumber` of ISSUER and SERIAL by default. */
    readonly sid?: Uint8Array;
    readonly digestAlgorithm?: Uint8Array;
    /** The Attribute TLVs of `signedAttrs [0]`, in the order given; `null` omits the field. */
    readonly signedAttrs?: readonly Uint8Array[] | null;
    /** The whole `signedAttrs` TLV, replacing the above. */
    readonly signedAttrsRaw?: Uint8Array;
    readonly signatureAlgorithm?: Uint8Array;
    readonly signature?: Uint8Array;
    /** The Attribute TLVs of `unsignedAttrs [1]`; omitted when absent. */
    readonly unsignedAttrs?: readonly Uint8Array[];
    /** Replace the field list entirely. */
    readonly fields?: readonly Uint8Array[];
}

export const issuerAndSerial = (issuer: Uint8Array = ISSUER, serial: Uint8Array = SERIAL): Uint8Array => sequence(issuer, serial);
export const subjectKeyIdentifier = (keyId: ArrayLike<number> = SKI): Uint8Array => context(0, false, keyId);

/** One SignerInfo. */
export function signerInfo(parts: SignerParts = {}): Uint8Array {
    if (parts.fields !== undefined) return sequence(...parts.fields);
    const signed = parts.signedAttrsRaw
        ?? (parts.signedAttrs === null ? undefined : context(0, true, concat(...(parts.signedAttrs ?? defaultSignedAttributes()))));
    return sequence(
        parts.version ?? int(1),
        parts.sid ?? issuerAndSerial(),
        parts.digestAlgorithm ?? alg(OIDS.sha256),
        ...(signed === undefined ? [] : [signed]),
        parts.signatureAlgorithm ?? alg(OIDS.rsaEncryption),
        parts.signature ?? octets(SIGNATURE),
        ...(parts.unsignedAttrs === undefined ? [] : [context(1, true, concat(...parts.unsignedAttrs))]),
    );
}

export interface SignedDataParts {
    readonly version?: Uint8Array;
    readonly digestAlgorithms?: readonly Uint8Array[];
    readonly contentType?: string;
    /** The inner TLV of `eContent [0]`; `null` makes the content detached. Defaults to an OCTET STRING of "hello". */
    readonly eContent?: Uint8Array | null;
    /** The whole EncapsulatedContentInfo TLV, replacing the two fields above. */
    readonly encapRaw?: Uint8Array;
    /** The CertificateChoices TLVs of `certificates [0]`; omitted when absent. */
    readonly certificates?: readonly Uint8Array[];
    /** The RevocationInfoChoice TLVs of `crls [1]`; omitted when absent. */
    readonly crls?: readonly Uint8Array[];
    /** The SignerInfo TLVs; one default signer when absent. */
    readonly signers?: readonly Uint8Array[];
    /** Replace the field list entirely. */
    readonly fields?: readonly Uint8Array[];
}

export const CONTENT = Uint8Array.from(ascii('hello'));

/** A SignedData SEQUENCE. */
export function signedData(parts: SignedDataParts = {}): Uint8Array {
    if (parts.fields !== undefined) return sequence(...parts.fields);
    const eContent = parts.eContent === undefined ? octets(CONTENT) : parts.eContent;
    const encap = parts.encapRaw
        ?? sequence(oid(parts.contentType ?? OIDS.data), ...(eContent === null ? [] : [context(0, true, eContent)]));
    return sequence(
        parts.version ?? int(1),
        set(...(parts.digestAlgorithms ?? [alg(OIDS.sha256)])),
        encap,
        ...(parts.certificates === undefined ? [] : [context(0, true, concat(...parts.certificates))]),
        ...(parts.crls === undefined ? [] : [context(1, true, concat(...parts.crls))]),
        set(...(parts.signers ?? [signerInfo()])),
    );
}

/** `ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT }`. */
export function contentInfo(content: Uint8Array = signedData(), type: string = OIDS.signedData): Uint8Array {
    return sequence(oid(type), context(0, true, content));
}
