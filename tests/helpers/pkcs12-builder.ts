/**
 * An engine-independent PKCS#12 writer for tests. Like raw-der-builder.ts, it
 * NEVER imports src/: every PFX the PKCS#12 suites parse is assembled here
 * from the RFC 7292, RFC 5652, RFC 8018 and RFC 9579 ASN.1 modules, and every
 * ciphertext and MAC is computed by the host's own Web Crypto — so the reader
 * is checked against the standards and not against pkinative's own encoders.
 *
 * Every function returns bytes, and every structure can be replaced by raw
 * bytes, which is how the hostile inputs are made.
 */

import { alg, attribute, context, int, octets, oid } from './cms-signed-data-builder.js';
import { concat, sequence, tlv, universal } from './raw-der-builder.js';

// ── OIDs ──

export const P12 = Object.freeze({
    data: '1.2.840.113549.1.7.1',
    signedData: '1.2.840.113549.1.7.2',
    envelopedData: '1.2.840.113549.1.7.3',
    digestedData: '1.2.840.113549.1.7.5',
    encryptedData: '1.2.840.113549.1.7.6',
    keyBag: '1.2.840.113549.1.12.10.1.1',
    shroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
    certBag: '1.2.840.113549.1.12.10.1.3',
    crlBag: '1.2.840.113549.1.12.10.1.4',
    secretBag: '1.2.840.113549.1.12.10.1.5',
    safeContentsBag: '1.2.840.113549.1.12.10.1.6',
    x509Certificate: '1.2.840.113549.1.9.22.1',
    sdsiCertificate: '1.2.840.113549.1.9.22.2',
    x509Crl: '1.2.840.113549.1.9.23.1',
    friendlyName: '1.2.840.113549.1.9.20',
    localKeyId: '1.2.840.113549.1.9.21',
    pbes2: '1.2.840.113549.1.5.13',
    pbkdf2: '1.2.840.113549.1.5.12',
    pbmac1: '1.2.840.113549.1.5.14',
    pbeWithSHAAnd3KeyTripleDES: '1.2.840.113549.1.12.1.3',
    sha256: '2.16.840.1.101.3.4.2.1',
    sha1: '1.3.14.3.2.26',
});

export const HMAC_OID = Object.freeze({
    'SHA-1': '1.2.840.113549.2.7',
    'SHA-224': '1.2.840.113549.2.8',
    'SHA-256': '1.2.840.113549.2.9',
    'SHA-384': '1.2.840.113549.2.10',
    'SHA-512': '1.2.840.113549.2.11',
});

export const AES_OID = Object.freeze({ 128: '2.16.840.1.101.3.4.1.2', 192: '2.16.840.1.101.3.4.1.22', 256: '2.16.840.1.101.3.4.1.42' });

type Hash = keyof typeof HMAC_OID;

// ── Structures ──

/** `ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT }`. */
export const contentInfo = (type: string, content: Uint8Array): Uint8Array => sequence(oid(type), context(0, true, content));

/** A `data` ContentInfo around the given octets. */
export const dataInfo = (inner: Uint8Array): Uint8Array => contentInfo(P12.data, octets(inner));

/** A BMPString, UCS-2 big-endian. */
export function bmp(text: string): Uint8Array {
    const units: number[] = [];
    for (let i = 0; i < text.length; i++) {
        const unit = text.charCodeAt(i);
        units.push(unit >> 8, unit & 0xff);
    }
    return universal(30, units);
}

export const friendlyName = (text: string): Uint8Array => attribute(P12.friendlyName, bmp(text));
export const localKeyId = (id: ArrayLike<number>): Uint8Array => attribute(P12.localKeyId, octets(id));

/** `SafeBag ::= SEQUENCE { bagId, bagValue [0] EXPLICIT, bagAttributes SET OF OPTIONAL }`; `null` attributes omits the SET. */
export const safeBag = (bagId: string, value: Uint8Array, attributes: readonly Uint8Array[] | null = null): Uint8Array =>
    sequence(oid(bagId), context(0, true, value), ...(attributes === null ? [] : [universal(17, concat(...attributes), true)]));

export const certBag = (der: Uint8Array, attributes: readonly Uint8Array[] | null = null, certType: string = P12.x509Certificate): Uint8Array =>
    safeBag(P12.certBag, sequence(oid(certType), context(0, true, octets(der))), attributes);

export const crlBag = (der: Uint8Array, attributes: readonly Uint8Array[] | null = null): Uint8Array =>
    safeBag(P12.crlBag, sequence(oid(P12.x509Crl), context(0, true, octets(der))), attributes);

export const keyBag = (pkcs8: Uint8Array, attributes: readonly Uint8Array[] | null = null): Uint8Array => safeBag(P12.keyBag, pkcs8, attributes);

export const shroudedKeyBag = (encryptedPrivateKeyInfo: Uint8Array, attributes: readonly Uint8Array[] | null = null): Uint8Array =>
    safeBag(P12.shroudedKeyBag, encryptedPrivateKeyInfo, attributes);

export const secretBag = (secret: Uint8Array, attributes: readonly Uint8Array[] | null = null): Uint8Array =>
    safeBag(P12.secretBag, sequence(oid('1.2.3.4'), context(0, true, octets(secret))), attributes);

export const safeContentsBag = (bags: readonly Uint8Array[], attributes: readonly Uint8Array[] | null = null): Uint8Array =>
    safeBag(P12.safeContentsBag, sequence(...bags), attributes);

/** `SafeContents ::= SEQUENCE OF SafeBag`. */
export const safeContents = (...bags: readonly Uint8Array[]): Uint8Array => sequence(...bags);

/** `AuthenticatedSafe ::= SEQUENCE OF ContentInfo`. */
export const authenticatedSafe = (...infos: readonly Uint8Array[]): Uint8Array => sequence(...infos);

export interface PfxParts {
    readonly version?: number;
    /** The AuthenticatedSafe octets, wrapped in a data ContentInfo. */
    readonly authSafe: Uint8Array;
    /** The MacData, or omitted. */
    readonly macData?: Uint8Array;
    /** Replace the whole authSafe ContentInfo. */
    readonly authSafeInfo?: Uint8Array;
    readonly extra?: readonly Uint8Array[];
}

/** `PFX ::= SEQUENCE { version, authSafe ContentInfo, macData OPTIONAL }`. */
export const pfx = (parts: PfxParts): Uint8Array => sequence(
    int(parts.version ?? 3),
    parts.authSafeInfo ?? dataInfo(parts.authSafe),
    ...(parts.macData === undefined ? [] : [parts.macData]),
    ...(parts.extra ?? []),
);

/** The same PFX in BER as Windows writes it: indefinite lengths, and the AuthenticatedSafe in a constructed OCTET STRING of `chunk`-octet segments. */
export function berPfx(authSafe: Uint8Array, macData: Uint8Array | undefined, chunk = 7): Uint8Array {
    const segments: Uint8Array[] = [];
    for (let at = 0; at < authSafe.length; at += chunk) segments.push(octets(authSafe.subarray(at, at + chunk)));
    const constructedOctets = tlv(0, true, 4, concat(...segments), { indefinite: true });
    const info = tlv(0, true, 16, concat(oid(P12.data), tlv(2, true, 0, constructedOctets, { indefinite: true })), { indefinite: true });
    return tlv(0, true, 16, concat(int(3), info, ...(macData === undefined ? [] : [macData])), { indefinite: true });
}

// ── PBES2 (RFC 8018) ──

export interface Pbes2Options {
    readonly salt?: Uint8Array;
    readonly iterations?: number;
    readonly prf?: Hash;
    readonly keyBits?: 128 | 192 | 256;
    readonly iv?: Uint8Array;
}

const SALT = Uint8Array.from({ length: 16 }, (_, i) => 0x30 + i);
const IV = Uint8Array.from({ length: 16 }, (_, i) => 0x60 + i);

/** A PBES2 AlgorithmIdentifier with PBKDF2 and AES-CBC. */
export function pbes2Algorithm(options: Pbes2Options = {}): Uint8Array {
    const kdf = alg(P12.pbkdf2, sequence(octets(options.salt ?? SALT), int(options.iterations ?? 2048), alg(HMAC_OID[options.prf ?? 'SHA-256'])));
    return alg(P12.pbes2, sequence(kdf, alg(AES_OID[options.keyBits ?? 256], octets(options.iv ?? IV))));
}

const encoder = new TextEncoder();
const passwordBytes = (password: string | Uint8Array): Uint8Array => (typeof password === 'string' ? encoder.encode(password) : password);

/** Encrypt under PBES2 with the host's Web Crypto. */
export async function pbes2Encrypt(plaintext: Uint8Array, password: string | Uint8Array, options: Pbes2Options = {}): Promise<Uint8Array> {
    const subtle = globalThis.crypto.subtle;
    const base = await subtle.importKey('raw', passwordBytes(password), 'PBKDF2', false, ['deriveKey']);
    const key = await subtle.deriveKey(
        { name: 'PBKDF2', salt: options.salt ?? SALT, iterations: options.iterations ?? 2048, hash: options.prf ?? 'SHA-256' },
        base,
        { name: 'AES-CBC', length: options.keyBits ?? 256 },
        false,
        ['encrypt'],
    );
    return new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: options.iv ?? IV }, key, plaintext));
}

/** An RFC 5958 §3 EncryptedPrivateKeyInfo around a PKCS#8, under PBES2. */
export async function shroudKey(pkcs8: Uint8Array, password: string | Uint8Array, options: Pbes2Options = {}): Promise<Uint8Array> {
    return sequence(pbes2Algorithm(options), octets(await pbes2Encrypt(pkcs8, password, options)));
}

export interface EncryptedDataParts {
    readonly version?: Uint8Array;
    readonly contentType?: string;
    readonly algorithm?: Uint8Array;
    /** The `[0] IMPLICIT` ciphertext TLV, or `null` to omit it. */
    readonly encryptedContent?: Uint8Array | null;
    readonly trailing?: readonly Uint8Array[];
    readonly infoTrailing?: readonly Uint8Array[];
}

/** An `encryptedData` ContentInfo (RFC 5652 §8) around raw parts. */
export function encryptedDataInfo(ciphertext: Uint8Array, parts: EncryptedDataParts = {}): Uint8Array {
    const info = sequence(
        oid(parts.contentType ?? P12.data),
        parts.algorithm ?? pbes2Algorithm(),
        ...(parts.encryptedContent === null ? [] : [parts.encryptedContent ?? context(0, false, ciphertext)]),
        ...(parts.infoTrailing ?? []),
    );
    return contentInfo(P12.encryptedData, sequence(parts.version ?? int(0), info, ...(parts.trailing ?? [])));
}

/** A SafeContents encrypted under PBES2, as an `encryptedData` ContentInfo. */
export async function encryptedSafeContents(contents: Uint8Array, password: string | Uint8Array, options: Pbes2Options = {}): Promise<Uint8Array> {
    return encryptedDataInfo(await pbes2Encrypt(contents, password, options), { algorithm: pbes2Algorithm(options) });
}

// ── MacData ──

export interface Pbmac1Options {
    readonly salt?: Uint8Array;
    readonly iterations?: number;
    readonly prf?: Hash;
    readonly hmac?: Hash;
    readonly keyLength?: number;
    readonly macSalt?: Uint8Array;
    readonly macIterations?: number | null;
}

/** RFC 9579 PBMAC1 MacData: HMAC over the AuthenticatedSafe octets, keyed by PBKDF2 — computed by the host. */
export async function pbmac1MacData(authSafe: Uint8Array, password: string | Uint8Array, options: Pbmac1Options = {}): Promise<Uint8Array> {
    const subtle = globalThis.crypto.subtle;
    const salt = options.salt ?? SALT;
    const iterations = options.iterations ?? 2048;
    const prf = options.prf ?? 'SHA-256';
    const hmac = options.hmac ?? 'SHA-256';
    const keyLength = options.keyLength ?? 32;
    const base = await subtle.importKey('raw', passwordBytes(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: prf }, base, keyLength * 8);
    const key = await subtle.importKey('raw', bits, { name: 'HMAC', hash: hmac }, false, ['sign']);
    const mac = new Uint8Array(await subtle.sign('HMAC', key, authSafe));
    const params = sequence(
        alg(P12.pbkdf2, sequence(octets(salt), int(iterations), int(keyLength), alg(HMAC_OID[prf]))),
        alg(HMAC_OID[hmac]),
    );
    return macData(alg(P12.pbmac1, params), mac, options.macSalt ?? Uint8Array.of(0x4e, 0x4f, 0x54, 0x55, 0x53, 0x45, 0x44), options.macIterations === undefined ? 2048 : options.macIterations);
}

/** A MacData from its parts; `iterations` `null` omits the field (DEFAULT 1). */
export const macData = (digestAlgorithm: Uint8Array, mac: Uint8Array, salt: Uint8Array, iterations: number | null = 2048): Uint8Array =>
    sequence(sequence(digestAlgorithm, octets(mac)), octets(salt), ...(iterations === null ? [] : [int(iterations)]));

/** A MacData shaped like the RFC 7292 Appendix B construction — not a valid MAC, which nothing here computes. */
export const legacyMacData = (): Uint8Array =>
    macData(alg(P12.sha256), Uint8Array.from({ length: 32 }, (_, i) => i), Uint8Array.from({ length: 8 }, (_, i) => 0x80 + i), 2048);
