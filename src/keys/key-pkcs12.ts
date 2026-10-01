/**
 * pkinative — PKCS#12 containers
 * ==============================
 * RFC 7292 §4 `PFX`, read and described: the AuthenticatedSafe and its
 * SafeContents, every SafeBag with its attributes, and the `MacData` — and,
 * on demand, a PBES2-encrypted SafeContents opened and an RFC 9579 PBMAC1
 * MAC checked through the Web Crypto door.
 *
 * Reading and opening are two steps. `parsePkcs12` needs no password and
 * says, before anyone types one, which parts are encrypted, with what, and
 * how the file is authenticated. A plain SafeContents comes back with its
 * bags read; an encrypted one comes back with its scheme and its ciphertext,
 * for `openSafeContents`.
 *
 * RFC 7292 Appendix B is never implemented: a MAC keyed by it is described as
 * `kind: 'pkcs12-kdf'` and `verifyPkcs12Mac` refuses it; a SafeContents
 * encrypted under an Appendix C scheme parses with `pbes2` undefined and
 * `openSafeContents` refuses it. Public-key privacy mode (`envelopedData`) is
 * reported as encrypted with no password scheme; public-key integrity mode
 * (an AuthenticatedSafe that is `signedData`) is refused at parse time. The
 * layer does not import `x509` or `cms`: a certificate bag yields DER for
 * the caller to hand to `parseCertificate`.
 *
 * Nested `safeContentsBag`s are flattened with an explicit stack, depth
 * first in encoded order, and every bag in the call counts against
 * `maxPkcs12Bags` before any is read.
 *
 * **The file declares its own cost**, one PBKDF2 count per derivation, and
 * may declare thousands of derivations. `maxKdfIterations` bounds each one;
 * `maxPkcs12KdfIterations` bounds what one file costs in total, so the sum
 * of what a call can see is checked before anything is derived.
 *
 * @module keys/key-pkcs12
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { createAsn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readInteger, _readOctetString, _readSmallInteger, _readString } from '../asn1/asn1-read.js';
import { TAG_BMP_STRING, TAG_INTEGER, TAG_NULL, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET } from '../asn1/asn1-tags.js';
import { assertBytes } from '../core/bytes.js';
import { OID_DATA, OID_ENCRYPTED_DATA, OID_ENVELOPED_DATA, OID_SIGNED_DATA } from '../core/cms-oids.js';
import {
    HMAC_OIDS,
    OID_ATTR_FRIENDLY_NAME,
    OID_ATTR_LOCAL_KEY_ID,
    OID_CERT_BAG,
    OID_CERT_TYPE_X509,
    OID_CRL_BAG,
    OID_CRL_TYPE_X509,
    OID_KEY_BAG,
    OID_PBMAC1,
    OID_PKCS8_SHROUDED_KEY_BAG,
    OID_SAFE_CONTENTS_BAG,
    OID_SECRET_BAG,
} from '../core/key-oids.js';
import { defaultEncodedDiagnostic } from '../core/pki-diagnostics.js';
import { enforceLimit } from '../core/pki-limits.js';
import { decryptContent, derivePasswordKey, verifyMac } from '../crypto/webcrypto.js';
import type { Asn1Node } from '../types/asn1-types.js';
import type { Attribute } from '../types/cms-types.js';
import type { EncryptedPrivateKeyInfo, Pkcs12, Pkcs12Mac, PrivateKeyInfo, SafeBag, SafeBagKind, SafeContentsInfo } from '../types/key-types.js';
import { PkiError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { AlgorithmIdentifier } from '../types/x509-types.js';
import { _derivePbes2Key, _expectField, _keyError, _passwordOctets, _readKeyAlgorithm, _readPasswordEncryption, _readPbkdf2, _requirePbes2 } from './key-pbes2.js';
import { _readAttributes, _readEncryptedPrivateKeyInfo, _readPrivateKeyInfo } from './key-pkcs8.js';

/** SafeBag types (RFC 7292 §4.2), by OID. */
const BAG_KINDS: ReadonlyMap<string, SafeBagKind> = /*#__PURE__*/ new Map<string, SafeBagKind>([
    [OID_KEY_BAG, 'keyBag'],
    [OID_PKCS8_SHROUDED_KEY_BAG, 'pkcs8ShroudedKeyBag'],
    [OID_CERT_BAG, 'certBag'],
    [OID_CRL_BAG, 'crlBag'],
    [OID_SECRET_BAG, 'secretBag'],
    [OID_SAFE_CONTENTS_BAG, 'safeContentsBag'],
]);

// ── Shared shapes ──

/** An `[n] EXPLICIT` wrapper around exactly one value; returns that value. */
function _explicit(node: Asn1Node | undefined, tagNumber: number, path: string, parentOffset: number, what: string): Asn1Node {
    if (node === undefined) throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, parentOffset, `is missing; expected ${what}`);
    if (node.tagClass !== 'context' || node.tagNumber !== tagNumber || !node.constructed || node.children.length !== 1) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, node.offset, `is not ${what} around exactly one value`);
    }
    return node.children[0] as Asn1Node;
}

/** `ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT }` — the content is required everywhere PKCS#12 uses one. */
function _readContentInfo(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): { readonly contentType: string; readonly content: Asn1Node; readonly offset: number } {
    const seq = _expectField(node, TAG_SEQUENCE, path, parentOffset, 'a ContentInfo SEQUENCE');
    if (seq.children.length !== 2) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, seq.offset, `holds ${String(seq.children.length)} values; a ContentInfo here is a content type and its content`);
    }
    const contentType = _readObjectIdentifier(_expectField(seq.children[0], TAG_OID, `${path}.contentType`, seq.offset, 'an OBJECT IDENTIFIER'), ctx);
    const content = _explicit(seq.children[1], 0, `${path}.content`, seq.offset, 'content [0] EXPLICIT');
    return { contentType, content, offset: seq.offset };
}

/** A typed value — `CertBag`, `CRLBag` and `SecretBag` share `SEQUENCE { typeId OID, value [0] EXPLICIT }`. */
function _readTypedValue(node: Asn1Node, ctx: Asn1Context, path: string, parentOffset: number, what: string): { readonly typeId: string; readonly value: Asn1Node } {
    const seq = _expectField(node, TAG_SEQUENCE, path, parentOffset, `a ${what} SEQUENCE`);
    if (seq.children.length !== 2) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, seq.offset, `holds ${String(seq.children.length)} values; a ${what} is a type and a value`);
    }
    const typeId = _readObjectIdentifier(_expectField(seq.children[0], TAG_OID, `${path}.typeId`, seq.offset, 'an OBJECT IDENTIFIER'), ctx);
    return { typeId, value: _explicit(seq.children[1], 0, `${path}.value`, seq.offset, 'value [0] EXPLICIT') };
}

/** The DER an x509Certificate or x509CRL value wraps in an OCTET STRING, or `undefined` for another type. */
function _wrappedDer(node: Asn1Node, ctx: Asn1Context, path: string, parentOffset: number, what: string, x509Type: string): Uint8Array | undefined {
    const typed = _readTypedValue(node, ctx, path, parentOffset, what);
    if (typed.typeId !== x509Type) return undefined;
    return _readOctetString(_expectField(typed.value, TAG_OCTET_STRING, `${path}.value`, node.offset, 'an OCTET STRING'), ctx);
}

/** The single value of an attribute present exactly once with exactly one value, or `undefined`. */
function _singleValue(set: Asn1Node, attributes: readonly Attribute[], oid: string): Asn1Node | undefined {
    let found: number | undefined;
    // Bounded: `attributes` was read under maxAttributes, one entry per child of `set`.
    for (const [i, attribute] of attributes.entries()) {
        if (attribute.oid !== oid) continue;
        if (found !== undefined) return undefined;
        found = i;
    }
    if (found === undefined || (attributes[found] as Attribute).values.length !== 1) return undefined;
    // _readAttributes checked this shape: SEQUENCE { type, SET { value } }.
    return ((set.children[found] as Asn1Node).children[1] as Asn1Node).children[0];
}

// ── SafeBags (RFC 7292 §4.2) ──

/** A SafeBag waiting on the stack, with where it came from. */
interface _PendingBag {
    readonly node: Asn1Node | undefined;
    readonly path: string;
    readonly parentOffset: number;
}

/** How many bags this call has scheduled, against `maxPkcs12Bags`. */
interface _BagBudget {
    scheduled: number;
}

/** Push a SafeContents' bags on the stack in reverse, so they pop in encoded order — after counting them. */
function _schedule(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number, stack: _PendingBag[], budget: _BagBudget): void {
    const contents = _expectField(node, TAG_SEQUENCE, path, parentOffset, 'a SafeContents SEQUENCE OF SafeBag');
    budget.scheduled += contents.children.length;
    enforceLimit(ctx.limits, 'maxPkcs12Bags', budget.scheduled, `the SafeBags of the PKCS#12 up to ${path}`);
    for (let i = contents.children.length - 1; i >= 0; i--) {
        stack.push({ node: contents.children[i], path: `${path}.bags[${String(i)}]`, parentOffset: contents.offset });
    }
}

/** One SafeBag, and the SafeContents it holds when it is a safeContentsBag. */
function _readBag(pending: _PendingBag, ctx: Asn1Context): { readonly bag: SafeBag; readonly nested: Asn1Node | undefined } {
    const { path } = pending;
    const seq = _expectField(pending.node, TAG_SEQUENCE, path, pending.parentOffset, 'a SafeBag SEQUENCE');
    const [idNode, valueNode, attributesNode, ...extra] = seq.children;
    if (extra.length > 0) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, seq.offset, 'holds more than bagId, bagValue and bagAttributes');
    }
    const oid = _readObjectIdentifier(_expectField(idNode, TAG_OID, `${path}.bagId`, seq.offset, 'an OBJECT IDENTIFIER'), ctx);
    const value = _explicit(valueNode, 0, `${path}.bagValue`, seq.offset, 'bagValue [0] EXPLICIT');

    let attributes: readonly Attribute[] = [];
    let friendlyName: string | undefined;
    let localKeyId: Uint8Array | undefined;
    if (attributesNode !== undefined) {
        const at = `${path}.bagAttributes`;
        const set = _expectField(attributesNode, TAG_SET, at, seq.offset, 'a SET OF attributes');
        attributes = Object.freeze(_readAttributes(set, ctx, at));
        const name = _singleValue(set, attributes, OID_ATTR_FRIENDLY_NAME);
        if (name !== undefined) {
            friendlyName = _readString(_expectField(name, TAG_BMP_STRING, `${at}.friendlyName`, set.offset, 'a BMPString'), ctx, undefined, `${at}.friendlyName`).value;
        }
        const keyId = _singleValue(set, attributes, OID_ATTR_LOCAL_KEY_ID);
        if (keyId !== undefined) {
            localKeyId = _readOctetString(_expectField(keyId, TAG_OCTET_STRING, `${at}.localKeyId`, set.offset, 'an OCTET STRING'), ctx);
        }
    }

    const kind = BAG_KINDS.get(oid) ?? 'unknown';
    const valuePath = `${path}.bagValue`;
    let certificateDer: Uint8Array | undefined;
    let crlDer: Uint8Array | undefined;
    let encryptedKey: EncryptedPrivateKeyInfo | undefined;
    let privateKey: PrivateKeyInfo | undefined;
    let nested: Asn1Node | undefined;
    const before = ctx.emitter.diagnostics.length;
    switch (kind) {
        case 'keyBag': {
            const info = _readPrivateKeyInfo(value, ctx, valuePath, seq.offset);
            privateKey = Object.freeze({ ...info, diagnostics: Object.freeze(ctx.emitter.diagnostics.slice(before)) });
            break;
        }
        case 'pkcs8ShroudedKeyBag': {
            const info = _readEncryptedPrivateKeyInfo(value, ctx, valuePath, seq.offset);
            encryptedKey = Object.freeze({ ...info, diagnostics: Object.freeze(ctx.emitter.diagnostics.slice(before)) });
            break;
        }
        case 'certBag':
            certificateDer = _wrappedDer(value, ctx, valuePath, seq.offset, 'CertBag', OID_CERT_TYPE_X509);
            break;
        case 'crlBag':
            crlDer = _wrappedDer(value, ctx, valuePath, seq.offset, 'CRLBag', OID_CRL_TYPE_X509);
            break;
        case 'secretBag':
            _readTypedValue(value, ctx, valuePath, seq.offset, 'SecretBag');
            break;
        case 'safeContentsBag':
            nested = value;
            break;
        case 'unknown':
            break;
    }
    const bag: SafeBag = Object.freeze({
        kind, oid, valueDer: value.bytes, friendlyName, localKeyId, attributes, certificateDer, crlDer, encryptedKey, privateKey, path,
    });
    return { bag, nested };
}

/**
 * Read a SafeContents into its bags, nested safeContentsBags flattened
 * depth first in encoded order — iteratively, with an explicit stack.
 */
function _readSafeContents(node: Asn1Node, ctx: Asn1Context, path: string, budget: _BagBudget): readonly SafeBag[] {
    const out: SafeBag[] = [];
    const stack: _PendingBag[] = [];
    _schedule(node, ctx, path, node.offset, stack, budget);
    // Bounded: every entry pushed was first counted against maxPkcs12Bags by _schedule.
    while (stack.length > 0) {
        const pending = stack.pop() as _PendingBag;
        const { bag, nested } = _readBag(pending, ctx);
        out.push(bag);
        if (nested !== undefined) _schedule(nested, ctx, pending.path, pending.parentOffset, stack, budget);
    }
    return Object.freeze(out);
}

// ── The AuthenticatedSafe ──

/** One ContentInfo of the AuthenticatedSafe. */
function _readSafeContentsInfo(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number, budget: _BagBudget): SafeContentsInfo {
    const { contentType, content, offset } = _readContentInfo(node, ctx, path, parentOffset);
    if (contentType === OID_DATA) {
        const octets = _readOctetString(_expectField(content, TAG_OCTET_STRING, `${path}.content`, offset, 'an OCTET STRING'), ctx);
        const bags = _readSafeContents(decodeWithContext(octets, ctx, false), ctx, path, budget);
        return Object.freeze({ encrypted: false, encryption: undefined, encryptedContent: undefined, bags, path });
    }
    if (contentType === OID_ENVELOPED_DATA) {
        return Object.freeze({ encrypted: true, encryption: undefined, encryptedContent: undefined, bags: Object.freeze([]), path });
    }
    if (contentType !== OID_ENCRYPTED_DATA) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.contentType`, offset, `is ${contentType}; an AuthenticatedSafe entry is data, encryptedData or envelopedData`);
    }

    // RFC 5652 §8: EncryptedData ::= SEQUENCE { version, encryptedContentInfo, unprotectedAttrs [1] IMPLICIT OPTIONAL }
    const at = `${path}.content`;
    const encryptedData = _expectField(content, TAG_SEQUENCE, at, offset, 'an EncryptedData SEQUENCE');
    const [versionNode, infoNode, unprotected, ...extra] = encryptedData.children;
    const version = _readSmallInteger(_expectField(versionNode, TAG_INTEGER, `${at}.version`, encryptedData.offset, 'an INTEGER version'), ctx);
    if (version !== 0 && version !== 2) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${at}.version`, encryptedData.offset, `is ${String(version)}; RFC 5652 §8 gives EncryptedData version 0, or 2 with unprotected attributes`);
    }
    if (extra.length > 0 || (unprotected !== undefined && (unprotected.tagClass !== 'context' || unprotected.tagNumber !== 1 || !unprotected.constructed))) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', at, encryptedData.offset, 'holds a value after encryptedContentInfo other than unprotectedAttrs [1]');
    }

    // EncryptedContentInfo ::= SEQUENCE { contentType, contentEncryptionAlgorithm, encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL }
    const infoPath = `${at}.encryptedContentInfo`;
    const info = _expectField(infoNode, TAG_SEQUENCE, infoPath, encryptedData.offset, 'an EncryptedContentInfo SEQUENCE');
    const [typeNode, algorithmNode, ciphertextNode, ...more] = info.children;
    if (more.length > 0) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', infoPath, info.offset, 'holds more than contentType, contentEncryptionAlgorithm and encryptedContent');
    }
    const innerType = _readObjectIdentifier(_expectField(typeNode, TAG_OID, `${infoPath}.contentType`, info.offset, 'an OBJECT IDENTIFIER'), ctx);
    if (innerType !== OID_DATA) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${infoPath}.contentType`, info.offset, `is ${innerType}; an encrypted SafeContents is data`);
    }
    const encryption = _readPasswordEncryption(algorithmNode, ctx, `${infoPath}.contentEncryptionAlgorithm`, info.offset);
    if (ciphertextNode === undefined || ciphertextNode.tagClass !== 'context' || ciphertextNode.tagNumber !== 0) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${infoPath}.encryptedContent`, info.offset, 'is not encryptedContent [0]; PKCS#12 never detaches the ciphertext');
    }
    const encryptedContent = _readOctetString(ciphertextNode, ctx);
    return Object.freeze({ encrypted: true, encryption, encryptedContent, bags: Object.freeze([]), path });
}

// ── MacData (RFC 7292 §4, RFC 9579 §3) ──

/** Parameters that are absent or NULL — what an HMAC identifier may carry. */
function _absentOrNull(parameters: Asn1Node | undefined): boolean {
    return parameters === undefined || (parameters.tagClass === 'universal' && parameters.tagNumber === TAG_NULL && parameters.contentLength === 0);
}

/** PBMAC1-params, or `undefined` when they name a KDF or an HMAC pkinative does not run. */
function _readPbmac1(algorithm: AlgorithmIdentifier, ctx: Asn1Context, path: string, offset: number): Pkcs12Mac['pbmac1'] {
    const params = _expectField(algorithm.parameters, TAG_SEQUENCE, `${path}.parameters`, offset, 'PBMAC1-params');
    if (params.children.length !== 2) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.parameters`, params.offset, `holds ${String(params.children.length)} values; PBMAC1-params is a keyDerivationFunc and a messageAuthScheme`);
    }
    const kdfPath = `${path}.parameters.keyDerivationFunc`;
    const kdf = _readKeyAlgorithm(params.children[0], ctx, kdfPath, params.offset);
    const scheme = _readKeyAlgorithm(params.children[1], ctx, `${path}.parameters.messageAuthScheme`, params.offset);
    const derivation = _readPbkdf2(kdf, ctx, kdfPath, params.offset);
    if (!derivation.ok) return undefined;
    if (derivation.keyLength === undefined) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${kdfPath}.parameters.keyLength`, params.offset, 'is missing; RFC 9579 §3 requires it under PBMAC1');
    }
    const hmac = HMAC_OIDS.get(scheme.oid);
    if (hmac === undefined || !_absentOrNull(scheme.parameters)) return undefined;
    // The key length sits in the unauthenticated MacData, so whoever edits the
    // file chooses it: at one octet the MAC is forged in 256 guesses. A MAC
    // keyed below the smallest HMAC output here (20 octets, HMAC-SHA-1) is not
    // one this reader verifies, and the file is left `unverified` rather than
    // called sound.
    if (derivation.keyLength < 20) return undefined;
    return Object.freeze({ salt: derivation.salt, iterations: derivation.iterations, prf: derivation.prf, keyLength: derivation.keyLength, hmac });
}

/** `MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 }`. */
function _readMacData(node: Asn1Node, ctx: Asn1Context): Pkcs12Mac {
    const path = 'macData';
    const seq = _expectField(node, TAG_SEQUENCE, path, node.offset, 'a MacData SEQUENCE');
    const [digestInfoNode, saltNode, iterationsNode, ...extra] = seq.children;
    if (extra.length > 0) throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, seq.offset, 'holds more than mac, macSalt and iterations');

    const digestInfo = _expectField(digestInfoNode, TAG_SEQUENCE, `${path}.mac`, seq.offset, 'a DigestInfo SEQUENCE');
    if (digestInfo.children.length !== 2) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.mac`, digestInfo.offset, `holds ${String(digestInfo.children.length)} values; a DigestInfo is an algorithm and a digest`);
    }
    const algorithmPath = `${path}.mac.digestAlgorithm`;
    const algorithm = _readKeyAlgorithm(digestInfo.children[0], ctx, algorithmPath, digestInfo.offset);
    const mac = _readOctetString(_expectField(digestInfo.children[1], TAG_OCTET_STRING, `${path}.mac.digest`, digestInfo.offset, 'an OCTET STRING'), ctx);
    const salt = _readOctetString(_expectField(saltNode, TAG_OCTET_STRING, `${path}.macSalt`, seq.offset, 'an OCTET STRING salt'), ctx);

    let iterations = 1;
    if (iterationsNode !== undefined) {
        const countField = _expectField(iterationsNode, TAG_INTEGER, `${path}.iterations`, seq.offset, 'an INTEGER iteration count');
        const count = _readInteger(countField, ctx);
        if (count < 1n) {
            throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.iterations`, countField.offset, `is ${String(count)}; an iteration count is at least 1`);
        }
        iterations = _readSmallInteger(countField, ctx);
        if (iterations === 1) ctx.emitter.emit(defaultEncodedDiagnostic(`${path}.iterations`, '1', countField.offset));
    }

    if (algorithm.oid === OID_PBMAC1) {
        const pbmac1 = _readPbmac1(algorithm, ctx, algorithmPath, digestInfo.offset);
        return Object.freeze({ kind: 'pbmac1', algorithm, mac, salt, iterations, pbmac1 });
    }
    return Object.freeze({ kind: 'pkcs12-kdf', algorithm, mac, salt, iterations, pbmac1: undefined });
}

// ── Public API ──

/**
 * Read a PKCS#12 file (`.p12`, `.pfx`) and describe it, without a password.
 *
 * The result says which SafeContents are encrypted and with what, reads the
 * bags of every plain one, and describes the MAC: `kind: 'pbmac1'` when RFC
 * 9579 PBMAC1 protects it (verifiable with {@link verifyPkcs12Mac}), and
 * `kind: 'pkcs12-kdf'` for the RFC 7292 Appendix B construction, which
 * pkinative never computes. Nothing is decrypted and nothing is verified.
 *
 * Windows writes the PFX in BER; pass `encodingRules: 'ber'` for such a file.
 * Offsets in errors below an AuthenticatedSafe entry count from the start of
 * `authenticatedSafe`, the octets the MAC covers; the path says where.
 *
 * ```ts
 * import { parsePkcs12, verifyPkcs12Mac, openSafeContents } from 'pkinative';
 *
 * const p12 = parsePkcs12(bytes);
 * if (p12.mac?.kind === 'pbmac1' && !(await verifyPkcs12Mac(p12, password))) throw new Error('wrong password or altered file');
 * for (const contents of p12.contents) {
 *     const bags = contents.encrypted ? await openSafeContents(contents, password) : contents.bags;
 *     for (const bag of bags) if (bag.certificateDer) console.log(bag.path, bag.friendlyName);
 * }
 * ```
 *
 * @param der     The DER (or, with `encodingRules: 'ber'`, the BER) of an RFC 7292 `PFX`.
 * @param options Encoding rules, limits (`maxPkcs12Bags`, `maxKdfIterations`, `maxPkcs12KdfIterations`) and diagnostics.
 * @returns The container, read but not opened.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `der` is not a Uint8Array; `PKI_INVALID_OPTION` for a bad option.
 * @throws {PkiEncodingError} When the bytes, or the bytes inside an OCTET STRING, are not valid DER (or BER).
 * @throws {PkiKeyError} `PKI_KEY_STRUCTURE_INVALID`; `PKI_KEY_VERSION_UNSUPPORTED` for a PFX version other than 3;
 *   `PKI_KEY_MAC_UNSUPPORTED` when the AuthenticatedSafe is `signedData` (public-key integrity mode).
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxPkcs12Bags`, `maxKdfIterations`, `maxAttributes` or another named limit,
 *   and past `maxPkcs12KdfIterations` when the MAC, the encrypted SafeContents and the shrouded keys read here declare more PBKDF2 iterations together.
 */
export function parsePkcs12(der: Uint8Array, options?: PkiParseOptions): Pkcs12 {
    const bytes = assertBytes(der, 'parsePkcs12 input');
    const ctx = createAsn1Context(options);
    const pfx = _expectField(decodeWithContext(bytes, ctx, false), TAG_SEQUENCE, 'pfx', 0, 'a PFX SEQUENCE');
    const [versionNode, authSafeNode, macDataNode, ...extra] = pfx.children;
    const version = _readSmallInteger(_expectField(versionNode, TAG_INTEGER, 'pfx.version', pfx.offset, 'an INTEGER version'), ctx);
    if (version !== 3) {
        throw _keyError('PKI_KEY_VERSION_UNSUPPORTED', 'pfx.version', pfx.offset, `is ${String(version)}; RFC 7292 §4 defines v3 only`);
    }
    if (extra.length > 0) throw _keyError('PKI_KEY_STRUCTURE_INVALID', 'pfx', pfx.offset, 'holds more than version, authSafe and macData');

    const { contentType, content, offset } = _readContentInfo(authSafeNode, ctx, 'authSafe', pfx.offset);
    if (contentType === OID_SIGNED_DATA) {
        throw _keyError('PKI_KEY_MAC_UNSUPPORTED', 'authSafe.contentType', offset, 'is signedData, public-key integrity mode, which pkinative does not verify');
    }
    if (contentType !== OID_DATA) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', 'authSafe.contentType', offset, `is ${contentType}; RFC 7292 §4 puts the AuthenticatedSafe in data or signedData`);
    }
    const authenticatedSafe = _readOctetString(_expectField(content, TAG_OCTET_STRING, 'authSafe.content', offset, 'an OCTET STRING'), ctx);

    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
    const safe = _expectField(decodeWithContext(authenticatedSafe, ctx, false), TAG_SEQUENCE, 'authSafe', 0, 'an AuthenticatedSafe SEQUENCE OF ContentInfo');
    // Each entry holds SafeBags or costs a decryption: bounded by the same limit as the bags themselves.
    enforceLimit(ctx.limits, 'maxPkcs12Bags', safe.children.length, 'the entries of the AuthenticatedSafe');
    const budget: _BagBudget = { scheduled: 0 };
    const contents = Object.freeze(safe.children.map((entry, i) => _readSafeContentsInfo(entry, ctx, `authSafe[${String(i)}]`, safe.offset, budget)));

    const mac = macDataNode === undefined ? undefined : _readMacData(macDataNode, ctx);
    // Every derivation the file already shows, summed: the PBMAC1 MAC, each
    // PBES2 SafeContents and each shrouded key read in the clear. Each count
    // passed maxKdfIterations on its own; the file as a whole must fit too.
    const declared = (mac?.pbmac1?.iterations ?? 0)
        + contents.reduce((sum, entry) => sum + (entry.encryption?.pbes2?.iterations ?? 0) + _keysKdfIterations(entry.bags), 0);
    enforceLimit(ctx.limits, 'maxPkcs12KdfIterations', declared, 'the PBKDF2 iterations this PKCS#12 declares across its MAC, its encrypted SafeContents and its shrouded keys');
    return Object.freeze({ der: pfx.bytes, version, authenticatedSafe, contents, mac, diagnostics: ctx.emitter.diagnostics });
}

/**
 * The PBKDF2 iterations unwrapping every PBES2-shrouded key among `bags` would
 * cost — a key under a scheme pkinative refuses costs nothing, since it is
 * never derived.
 *
 * @internal
 */
export function _keysKdfIterations(bags: readonly SafeBag[]): number {
    // Bounded: `bags` were read under maxPkcs12Bags.
    return bags.reduce((sum, bag) => sum + (bag.encryptedKey?.encryption.pbes2?.iterations ?? 0), 0);
}

/**
 * Check a PKCS#12 MAC under RFC 9579 PBMAC1: derive the HMAC key with
 * PBKDF2 from the password, and verify the HMAC over `authenticatedSafe`.
 *
 * A string password is encoded as UTF-8, as RFC 9579 specifies; pass a
 * `Uint8Array` for a file written with another encoding. This function's own
 * copy of the password is wiped once the host has it.
 *
 * ```ts
 * const p12 = parsePkcs12(bytes);
 * if (p12.mac === undefined) throw new Error('the file carries no integrity protection');
 * if (p12.mac.kind !== 'pbmac1') throw new Error('re-export with openssl pkcs12 -export -pbmac1_pbkdf2');
 * const intact = await verifyPkcs12Mac(p12, 'correct horse battery staple');
 * ```
 *
 * @param pkcs12   A container returned by {@link parsePkcs12}.
 * @param password The password, as a string (UTF-8) or as exact octets.
 * @returns `true` when the MAC matches; `false` for a wrong password or altered content — the two are indistinguishable.
 * @throws {PkiError} `PKI_API_MISUSE` when the container carries no MAC — check `pkcs12.mac` first;
 *   `PKI_INVALID_INPUT` for an argument of the wrong type.
 * @throws {PkiKeyError} `PKI_KEY_MAC_UNSUPPORTED` for an RFC 7292 Appendix B MAC, or a PBMAC1 whose KDF or HMAC Web Crypto does not run.
 * @throws {PkiCryptoError} `PKI_CRYPTO_UNAVAILABLE` without Web Crypto; `PKI_CRYPTO_ALGORITHM_UNSUPPORTED` when the host refuses the derivation.
 */
export async function verifyPkcs12Mac(pkcs12: Pkcs12, password: Uint8Array | string): Promise<boolean> {
    if (typeof pkcs12 !== 'object' || pkcs12 === null) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: verifyPkcs12Mac expects the result of parsePkcs12');
    }
    const mac = pkcs12.mac;
    if (mac === undefined) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: this PKCS#12 carries no MacData, so there is no MAC to verify — check pkcs12.mac before calling verifyPkcs12Mac');
    }
    const path = 'macData.mac.digestAlgorithm';
    if (mac.kind !== 'pbmac1') {
        throw _keyError('PKI_KEY_MAC_UNSUPPORTED', path, undefined, `is ${mac.algorithm.oid}, a MAC keyed by the RFC 7292 Appendix B KDF, which pkinative never implements`);
    }
    const params = mac.pbmac1;
    if (params === undefined) {
        throw _keyError('PKI_KEY_MAC_UNSUPPORTED', path, undefined, 'is PBMAC1 with a key derivation function or an HMAC that Web Crypto does not run');
    }
    const { octets, wipe } = _passwordOctets(password);
    try {
        const key = await derivePasswordKey(
            octets,
            { name: 'PBKDF2', salt: params.salt, iterations: params.iterations, hash: { name: params.prf } },
            { name: 'HMAC', hash: { name: params.hmac }, length: params.keyLength * 8 },
            OID_PBMAC1,
        );
        return await verifyMac(key, mac.mac, pkcs12.authenticatedSafe);
    } finally {
        wipe();
    }
}

/**
 * The bags of one SafeContents: those already read when it is plain, or,
 * when it is PBES2-encrypted, the plaintext decrypted through Web Crypto and
 * read with the same bag reader, with paths under `contents.path`.
 *
 * AES-CBC cannot tell a wrong password from altered ciphertext, so both are
 * `PKI_CRYPTO_DECRYPTION_FAILED` — and, in the rare case the padding of a
 * wrong key happens to check out, a `PkiEncodingError` from the garbage.
 *
 * ```ts
 * const p12 = parsePkcs12(bytes);
 * for (const contents of p12.contents) {
 *     for (const bag of await openSafeContents(contents, password)) {
 *         if (bag.kind === 'certBag') certificates.push(parseCertificate(bag.certificateDer!));
 *     }
 * }
 * ```
 *
 * @param contents An entry of `parsePkcs12(…).contents`.
 * @param password The password, as a string (UTF-8) or as exact octets; unused for a plain SafeContents.
 * @param options  Encoding rules, limits (`maxPkcs12Bags`, `maxKdfIterations`, `maxPkcs12KdfIterations`) and diagnostics for the decrypted SafeContents.
 * @returns The bags, in encoded order, nested safeContentsBags flattened.
 * @throws {PkiError} `PKI_INVALID_INPUT` or `PKI_INVALID_OPTION` for a bad argument; `PKI_API_MISUSE` for an encrypted entry without its ciphertext.
 * @throws {PkiKeyError} `PKI_KEY_ENCRYPTION_UNSUPPORTED` for a scheme other than PBES2 with PBKDF2 and AES-CBC, or for `envelopedData`;
 *   `PKI_KEY_STRUCTURE_INVALID` for decrypted content that is not a SafeContents.
 * @throws {PkiCryptoError} `PKI_CRYPTO_DECRYPTION_FAILED` for a wrong password or altered data; `PKI_CRYPTO_UNAVAILABLE`; `PKI_CRYPTO_ALGORITHM_UNSUPPORTED`.
 * @throws {PkiEncodingError} When the decrypted bytes are not valid DER.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxPkcs12Bags`, `maxKdfIterations` or another named limit, and past
 *   `maxPkcs12KdfIterations` when this derivation, or it and the shrouded keys the plaintext holds, would cost more.
 */
export async function openSafeContents(contents: SafeContentsInfo, password: Uint8Array | string, options?: PkiParseOptions): Promise<readonly SafeBag[]> {
    if (typeof contents !== 'object' || contents === null) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: openSafeContents expects an entry of parsePkcs12(…).contents');
    }
    const ctx = createAsn1Context(options);
    if (!contents.encrypted) return contents.bags;
    const { encryption, encryptedContent, path } = contents;
    if (encryption === undefined) {
        throw _keyError('PKI_KEY_ENCRYPTION_UNSUPPORTED', path, undefined, 'is envelopedData, public-key privacy mode, which pkinative does not open');
    }
    const pbes2 = _requirePbes2(encryption, `${path}.content.encryptedContentInfo.contentEncryptionAlgorithm`, undefined);
    if (encryptedContent === undefined) {
        throw new PkiError('PKI_API_MISUSE', `pkinative: ${path} is marked encrypted but carries no ciphertext — pass an entry of parsePkcs12(…).contents unchanged`);
    }
    enforceLimit(ctx.limits, 'maxKdfIterations', pbes2.iterations, `${path} PBKDF2 iteration count`);
    enforceLimit(ctx.limits, 'maxPkcs12KdfIterations', pbes2.iterations, `${path} PBKDF2 iteration count`);
    const key = await _derivePbes2Key(password, pbes2, encryption.algorithm.oid);
    const plaintext = await decryptContent(key, pbes2.iv, encryptedContent, encryption.algorithm.oid);
    const bags = _readSafeContents(decodeWithContext(plaintext, ctx, false), ctx, path, { scheduled: 0 });
    // What the plaintext reveals it would cost next: the shrouded keys inside,
    // on top of the derivation that opened them.
    enforceLimit(ctx.limits, 'maxPkcs12KdfIterations', pbes2.iterations + _keysKdfIterations(bags),
        `the PBKDF2 iterations of ${path} and of the shrouded keys it holds`);
    return bags;
}
