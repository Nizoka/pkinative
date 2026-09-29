/**
 * pkinative — One call that opens a PKCS#12
 * =========================================
 * RFC 7292 read the whole way, for the caller who has a `.p12` and a password
 * and wants the signing key and its certificate: the MAC checked where it can
 * be, every SafeContents opened, every certificate parsed, and every key
 * unwrapped straight into a non-extractable `CryptoKey`.
 *
 * It **reports and never throws for the file's sake**. A container is a bag of
 * independent things — one certificate may be malformed, one key encrypted
 * with a scheme pkinative refuses — and a caller is better served by the rest
 * and a list of what went wrong than by an exception about the first problem.
 * It throws only for a call that could never succeed: a missing password or an
 * argument of the wrong type.
 *
 * **Integrity fails closed.** Most PKCS#12 MACs are keyed with RFC 7292
 * Appendix B, which pkinative will not implement, so most files cannot have
 * their integrity checked here. Such a file is still read — its contents are in
 * the report — but `valid` is `false` with `PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED`
 * unless the caller passes `allowUnverifiedIntegrity`, because without a MAC an
 * unencrypted bag can be replaced by anyone who can write the file.
 *
 * **A key's algorithm comes from its certificate.** It is unwrapped without its
 * plaintext ever existing here, so Web Crypto must be told what it is before
 * decrypting it; the certificate sharing its `localKeyId` says so. An RSA
 * certificate says "RSA" and not which scheme the key will sign with, so
 * `rsaAlgorithm` decides, defaulting to the scheme of nearly every RSA signing
 * certificate in use.
 *
 * @module verify/verify-pkcs12
 */

import { assertBytes, bytesEqual } from '../core/bytes.js';
import {
    inputMalformedReason,
    pkcs12DecryptionFailedReason,
    pkcs12EncryptionUnsupportedReason,
    pkcs12IntegrityUnverifiedReason,
    pkcs12KeyUnmatchedReason,
    pkcs12KeyUnsupportedReason,
    pkcs12MacMismatchReason,
} from '../core/pki-reasons.js';
import { canDecrypt } from '../crypto/webcrypto.js';
import { decryptPrivateKey, importPrivateKey } from '../keys/key-import.js';
import { openSafeContents, parsePkcs12, verifyPkcs12Mac } from '../keys/key-pkcs12.js';
import type { SignatureAlgorithm, SigningKey } from '../types/crypto-types.js';
import type { Pkcs12, SafeBag } from '../types/key-types.js';
import { PkiCryptoError, PkiError } from '../types/pki-errors.js';
import type { PkiReason } from '../types/pki-reasons.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { Certificate } from '../types/x509-types.js';
import { parseCertificate } from '../x509/x509-certificate.js';
import { _assertArguments, _pkiError } from './verify-chain.js';

/** What `readPkcs12` takes. */
export interface ReadPkcs12Options extends PkiParseOptions {
    /**
     * The password. A string is encoded as UTF-8, which is what OpenSSL and
     * RFC 9579 use; a `Uint8Array` is used as given, for a file written with
     * another encoding, and is never modified — it is yours to wipe.
     */
    readonly password: Uint8Array | string;
    /**
     * Accept a container whose integrity cannot be checked — a MAC keyed with
     * RFC 7292 Appendix B, which is most files written before OpenSSL 3.4, or
     * no MAC at all — and report it `valid`. Off by default: without a MAC, an
     * unencrypted bag can be swapped by anyone who can write the file. The
     * report's `integrity` says what was established either way.
     */
    readonly allowUnverifiedIntegrity?: boolean | undefined;
    /**
     * What an RSA key will sign with. The certificate names the key, not the
     * scheme, and a Web Crypto key is bound to one scheme and one hash.
     * Defaults to `{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }`.
     */
    readonly rsaAlgorithm?: Extract<SignatureAlgorithm, { readonly name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' }> | undefined;
}

/** One private key the container holds, and what became of it. */
export interface Pkcs12Key {
    /** Where it was, e.g. `authSafe[1].bags[0]`. */
    readonly path: string;
    /** Its `localKeyId`, when it has one. */
    readonly localKeyId: Uint8Array | undefined;
    /** Its `friendlyName`, when it has one. */
    readonly friendlyName: string | undefined;
    /** The certificate sharing its `localKeyId`, when there is one. */
    readonly certificate: Certificate | undefined;
    /** The key, non-extractable, ready for `createCertificate` or `createSignedData`; `undefined` when it could not be opened — the reasons say why. */
    readonly signingKey: SigningKey | undefined;
}

/** What `readPkcs12` found. */
export interface ReadPkcs12Report {
    /** Whether everything was opened, and its integrity verified or explicitly waived. */
    readonly valid: boolean;
    /** `verified` for a matching RFC 9579 MAC; `unverified` when it could not be checked; `mismatch` when it did not match, in which case nothing was decrypted. */
    readonly integrity: 'verified' | 'unverified' | 'mismatch';
    /** The container as parsed, or `undefined` when it could not be. */
    readonly pkcs12: Pkcs12 | undefined;
    /** Every private key, in encoded order. */
    readonly keys: readonly Pkcs12Key[];
    /** Every certificate that parsed, in encoded order — the keys' own and any chain the file carries. */
    readonly certificates: readonly Certificate[];
    /** Every CRL bag's DER, in encoded order. */
    readonly crls: readonly Uint8Array[];
    /** Why `valid` is false; empty when it is true. */
    readonly reasons: readonly PkiReason[];
}

/** The ECDSA hash a curve customarily signs with — the one RFC 5480 §4 pairs it with. */
const CURVE_HASH = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' } as const;

/**
 * Open a PKCS#12 in one call: its MAC, its SafeContents, its certificates and
 * its keys.
 *
 * ```ts
 * import { readPkcs12, createSignedData } from 'pkinative';
 *
 * const report = await readPkcs12(p12Bytes, { password });
 * if (!report.valid) throw new Error(report.reasons.map((r) => r.message).join('; '));
 * const [{ signingKey, certificate }] = report.keys;
 * const signed = await createSignedData({ content, certificate: certificate! }, signingKey!);
 * ```
 *
 * @param der     The PFX, as DER — or BER with `encodingRules: 'ber'`, which Windows writes.
 * @param options The password, and what to accept.
 * @returns What was opened and why anything was not. Never rejects for a problem with the file.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` when the runtime has no Web Crypto to open anything with — see `canDecrypt`.
 * @throws {PkiError} `PKI_INVALID_OPTION` when `options` or its `password` is missing or of the wrong type, when
 *   `rsaAlgorithm` is not an RSA signature algorithm, or for a bad `encodingRules`; `PKI_LIMIT_INVALID` for an unknown
 *   or non-positive key in `limits`; `PKI_INVALID_INPUT` when `der` is not a Uint8Array.
 */
export async function readPkcs12(der: Uint8Array, options: ReadPkcs12Options): Promise<ReadPkcs12Report> {
    // Misuse is decided here, before the first catch: past it, every PkiError
    // is converted into a reason about the file.
    const password = _password(options);
    const rsaAlgorithm = _rsaAlgorithm(options.rsaAlgorithm);
    assertBytes(der, 'readPkcs12 input');
    const reading: PkiParseOptions = {
        limits: options.limits ?? {},
        onDiagnostic: (): undefined => undefined,
        ...(options.encodingRules === undefined ? {} : { encodingRules: options.encodingRules }),
    };
    _assertArguments([], reading);
    // Without Web Crypto nothing in a PKCS#12 can be opened or checked, so the
    // call could never succeed: that is said once, here, rather than once per
    // bag in a report that would read like a fact about the file.
    if (!canDecrypt()) {
        throw new PkiCryptoError('PKI_CRYPTO_UNAVAILABLE',
            'pkinative: this runtime exposes no crypto.subtle with the operations PBES2 needs, so no PKCS#12 can be opened — call canDecrypt() first, or run where Web Crypto exists (Node 22+, any browser on a secure origin, Deno, Bun, Workers)', 'PBES2');
    }
    const reasons: PkiReason[] = [];

    let pkcs12: Pkcs12;
    try {
        pkcs12 = parsePkcs12(der, reading);
    } catch (error) {
        const refused = _pkiError(error);
        // An AuthenticatedSafe that is signed data: public-key integrity mode,
        // which is a statement about the file rather than a malformation.
        reasons.push(refused.code === 'PKI_KEY_MAC_UNSUPPORTED'
            ? pkcs12IntegrityUnverifiedReason('authSafe', 'public-key')
            : inputMalformedReason(refused.code, refused.message, 'pkcs12'));
        return _report(reasons, 'unverified', undefined, [], [], []);
    }

    // ── Integrity ──
    let integrity: ReadPkcs12Report['integrity'] = 'unverified';
    const mac = pkcs12.mac;
    let unverified: 'pkcs12-kdf' | 'absent' | 'pbmac1-unsupported' | undefined;
    if (mac === undefined) unverified = 'absent';
    else if (mac.kind === 'pkcs12-kdf') unverified = 'pkcs12-kdf';
    else if (mac.pbmac1 === undefined) unverified = 'pbmac1-unsupported';
    else {
        try {
            integrity = await verifyPkcs12Mac(pkcs12, password) ? 'verified' : 'mismatch';
        } catch (error) {
            // The MAC's presence and kind were decided above and Web Crypto's
            // before anything, so what reaches here is a host that refuses the
            // PBMAC1 derivation or its HMAC: the MAC cannot be checked on it.
            _pkiError(error);
            unverified = 'pbmac1-unsupported';
        }
        if (integrity === 'mismatch') {
            // A wrong password, most likely: decrypting with it would only
            // report the same fact once per bag.
            reasons.push(pkcs12MacMismatchReason('macData'));
            return _report(reasons, integrity, pkcs12, [], [], []);
        }
    }
    if (unverified !== undefined && options.allowUnverifiedIntegrity !== true) {
        reasons.push(pkcs12IntegrityUnverifiedReason('macData', unverified));
    }

    // ── Contents ──
    const bags: SafeBag[] = [];
    // Bags this call decrypted, as opposed to views into the caller's input:
    // the only memory it may wipe.
    const decrypted = new Set<SafeBag>();
    for (const contents of pkcs12.contents) {
        try {
            const opened = await openSafeContents(contents, password, reading);
            bags.push(...opened);
            if (contents.encrypted) for (const bag of opened) decrypted.add(bag);
        } catch (error) {
            reasons.push(_openingReason(_pkiError(error), contents.path, contents.encryption?.scheme ?? 'envelopedData, public-key privacy mode'));
        }
    }

    const certificates: { readonly certificate: Certificate; readonly localKeyId: Uint8Array | undefined }[] = [];
    const crls: Uint8Array[] = [];
    for (const bag of bags) {
        if (bag.certificateDer !== undefined) {
            try {
                certificates.push({ certificate: parseCertificate(bag.certificateDer, reading), localKeyId: bag.localKeyId });
            } catch (error) {
                const refused = _pkiError(error);
                reasons.push(inputMalformedReason(refused.code, refused.message, bag.path));
            }
        } else if (bag.crlDer !== undefined) {
            crls.push(bag.crlDer);
        }
    }

    // ── Keys ──
    const keys: Pkcs12Key[] = [];
    for (const bag of bags) {
        const held = bag.encryptedKey ?? bag.privateKey;
        if (held === undefined) continue;
        const localKeyId = bag.localKeyId;
        const certificate = localKeyId === undefined
            ? undefined
            : certificates.find((c) => c.localKeyId !== undefined && bytesEqual(c.localKeyId, localKeyId))?.certificate;
        const entry = { path: bag.path, localKeyId, friendlyName: bag.friendlyName, certificate };
        if (certificate === undefined) {
            reasons.push(pkcs12KeyUnmatchedReason(bag.path));
            keys.push(Object.freeze({ ...entry, signingKey: undefined }));
            continue;
        }
        const algorithm = _algorithmOf(certificate, rsaAlgorithm);
        if (algorithm === undefined) {
            reasons.push(pkcs12KeyUnsupportedReason(bag.path,
                `the key's certificate carries a ${certificate.subjectPublicKeyInfo.kind} key${certificate.subjectPublicKeyInfo.kind === 'ec' ? ' on a curve Web Crypto does not sign with' : ''}, which Web Crypto cannot import as a signing key`));
            keys.push(Object.freeze({ ...entry, signingKey: undefined }));
            continue;
        }
        let signingKey: SigningKey | undefined;
        try {
            signingKey = 'encryption' in held
                ? await decryptPrivateKey(held.der, { ...reading, password, algorithm })
                : await importPrivateKey(held.der, { ...reading, algorithm });
        } catch (error) {
            reasons.push(_openingReason(_pkiError(error), bag.path, 'encryption' in held ? held.encryption.scheme : 'no encryption'));
        } finally {
            // A plain keyBag is plaintext by definition. Inside an encrypted
            // SafeContents it is plaintext only because this call decrypted it,
            // so once Web Crypto has taken its copy the bytes are wiped — a best
            // effort, since the engine may have copied them already. A keyBag in
            // an unencrypted SafeContents is the caller's own input and is left
            // alone. A shrouded key never needs this: it is unwrapped, never
            // decrypted into memory at all.
            if (!('encryption' in held) && decrypted.has(bag)) held.der.fill(0);
        }
        keys.push(Object.freeze({ ...entry, signingKey }));
    }

    return _report(reasons, integrity === 'verified' ? 'verified' : 'unverified', pkcs12, keys, certificates.map((c) => c.certificate), crls);
}

// ── Helpers ──

/** The password, refused before anything is read when it cannot be one. */
function _password(options: ReadPkcs12Options | undefined): Uint8Array | string {
    const password = (options as { readonly password?: unknown } | undefined)?.password;
    if (typeof password !== 'string' && !(password instanceof Uint8Array)) {
        throw new PkiError('PKI_INVALID_OPTION', 'pkinative: readPkcs12 needs options.password, as a string or a Uint8Array — an empty string is a password, undefined is not');
    }
    return password;
}

/** The RSA scheme a caller chose, refused before anything is read when it is not one. */
function _rsaAlgorithm(chosen: unknown): ReadPkcs12Options['rsaAlgorithm'] {
    if (chosen === undefined) return undefined;
    const candidate = chosen as { readonly name?: unknown; readonly hash?: unknown } | null;
    if (typeof chosen !== 'object' || candidate === null
        || (candidate.name !== 'RSASSA-PKCS1-v1_5' && candidate.name !== 'RSA-PSS')
        || !RSA_HASHES.has(candidate.hash as string)) {
        throw new PkiError('PKI_INVALID_OPTION', 'pkinative: readPkcs12 options.rsaAlgorithm must be { name: \'RSASSA-PKCS1-v1_5\' | \'RSA-PSS\', hash: \'SHA-256\' | \'SHA-384\' | \'SHA-512\' | \'SHA-1\' } — it says what an RSA key will sign with');
    }
    return chosen as ReadPkcs12Options['rsaAlgorithm'];
}

/** The digests an RSA signing key may be bound to. */
const RSA_HASHES: ReadonlySet<string> = /*#__PURE__*/ new Set(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']);

/** The reason a SafeContents or a key could not be opened. */
function _openingReason(refused: PkiError, path: string, scheme: string): PkiReason {
    switch (refused.code) {
        case 'PKI_KEY_ENCRYPTION_UNSUPPORTED':
            return pkcs12EncryptionUnsupportedReason(path, scheme);
        case 'PKI_CRYPTO_DECRYPTION_FAILED':
            return pkcs12DecryptionFailedReason(path);
        case 'PKI_CRYPTO_ALGORITHM_UNSUPPORTED':
            // The host refused the PBKDF2 PRF or the AES key size: an
            // encryption this runtime cannot perform, not a key it cannot hold.
            return pkcs12EncryptionUnsupportedReason(path, scheme, true);
        case 'PKI_CRYPTO_KEY_UNSUPPORTED':
            return pkcs12KeyUnsupportedReason(path, refused.message.slice('pkinative: '.length));
        case 'PKI_API_MISUSE':
            // The one misuse importPrivateKey can find here is ours to phrase:
            // the algorithm came from the certificate, so a key of another kind
            // is a file whose key and certificate disagree.
            return pkcs12KeyUnsupportedReason(path, 'the key is not of the algorithm its certificate names, so the two do not belong together');
        default:
            return inputMalformedReason(refused.code, refused.message, path);
    }
}

/**
 * What a key signs with, read from its certificate: the curve for ECDSA, the
 * name for EdDSA, and the caller's choice for RSA. `undefined` for a key Web
 * Crypto cannot sign with.
 */
function _algorithmOf(certificate: Certificate, rsa: ReadPkcs12Options['rsaAlgorithm']): SignatureAlgorithm | undefined {
    const spki = certificate.subjectPublicKeyInfo;
    switch (spki.kind) {
        case 'rsa':
            return rsa ?? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
        case 'ec':
            return spki.curve === undefined ? undefined : { name: 'ECDSA', namedCurve: spki.curve, hash: CURVE_HASH[spki.curve] };
        case 'ed25519':
            return { name: 'Ed25519' };
        case 'ed448':
            return { name: 'Ed448' };
        default:
            return undefined;
    }
}

function _report(
    reasons: readonly PkiReason[],
    integrity: ReadPkcs12Report['integrity'],
    pkcs12: Pkcs12 | undefined,
    keys: readonly Pkcs12Key[],
    certificates: readonly Certificate[],
    crls: readonly Uint8Array[],
): ReadPkcs12Report {
    return Object.freeze({
        valid: reasons.length === 0,
        integrity,
        pkcs12,
        keys: Object.freeze([...keys]),
        certificates: Object.freeze([...certificates]),
        crls: Object.freeze([...crls]),
        reasons: Object.freeze([...reasons]),
    });
}
