/**
 * pkinative — PKCS#8 private keys
 * ===============================
 * RFC 5958 `OneAsymmetricKey` (RFC 5208 PKCS#8 `PrivateKeyInfo` is its version
 * 0) and `EncryptedPrivateKeyInfo`, read and described.
 *
 * Reading a private key without holding it. A `PrivateKeyInfo` is returned
 * with its algorithm, its curve, its attributes and its optional public key —
 * and **without** its `privateKey` octets, which are validated for shape and
 * never copied into a field. The structure's `der` is the caller's own input,
 * so nothing is exposed that they did not already hold; what is withheld is a
 * convenient second name for the secret, which is how secrets end up in logs.
 *
 * @module keys/key-pkcs8
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { createAsn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString, _readOctetString, _readSmallInteger } from '../asn1/asn1-read.js';
import { TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET } from '../asn1/asn1-tags.js';
import { assertBytes } from '../core/bytes.js';
import { EC_CURVE_OIDS, OID_EC_PUBLIC_KEY, OID_ED25519, OID_ED448, OID_RSA_ENCRYPTION, OID_RSASSA_PSS } from '../core/key-oids.js';
import { enforceLimit } from '../core/pki-limits.js';
import type { Asn1Node, BitString } from '../types/asn1-types.js';
import type { Attribute } from '../types/cms-types.js';
import type { EncryptedPrivateKeyInfo, PrivateKeyInfo, PrivateKeyKind } from '../types/key-types.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import { _expectField, _keyError, _readKeyAlgorithm, _readPasswordEncryption } from './key-pbes2.js';

/** Private key algorithm OIDs, by what they name. */
const KEY_TYPES: ReadonlyMap<string, PrivateKeyKind> = /*#__PURE__*/ new Map<string, PrivateKeyKind>([
    [OID_RSA_ENCRYPTION, 'rsa'],
    [OID_RSASSA_PSS, 'rsa-pss'],
    [OID_EC_PUBLIC_KEY, 'ec'],
    [OID_ED25519, 'ed25519'],
    [OID_ED448, 'ed448'],
]);

// ── Attributes (X.501, shared with CMS and PKCS#12) ──

/**
 * An `Attributes` SET OF — the syntax PKCS#8, PKCS#12 bags and CMS signers
 * share — kept as encoded: order, duplicates and multi-valued sets and all.
 *
 * Bounded by `maxAttributes`, the limit on one attribute set whatever
 * structure carries it.
 *
 * @internal
 */
export function _readAttributes(set: Asn1Node, ctx: Asn1Context, path: string): Attribute[] {
    const out: Attribute[] = [];
    for (const [i, attribute] of set.children.entries()) {
        enforceLimit(ctx.limits, 'maxAttributes', i + 1, path);
        const at = `${path}[${String(i)}]`;
        const seq = _expectField(attribute, TAG_SEQUENCE, at, set.offset, 'an Attribute SEQUENCE');
        if (seq.children.length !== 2) {
            throw _keyError('PKI_KEY_STRUCTURE_INVALID', at, seq.offset, `holds ${String(seq.children.length)} values; an Attribute is a type and a SET of values`);
        }
        const oid = _readObjectIdentifier(_expectField(seq.children[0], TAG_OID, `${at}.type`, seq.offset, 'an OBJECT IDENTIFIER'), ctx);
        const values = _expectField(seq.children[1], TAG_SET, `${at}.values`, seq.offset, 'a SET of attribute values');
        if (values.children.length === 0) {
            throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${at}.values`, values.offset, 'is empty; an attribute carries at least one value');
        }
        out.push(Object.freeze({ oid, values: Object.freeze(values.children.map((v) => v.bytes)), der: seq.bytes }));
    }
    return out;
}

// ── PrivateKeyInfo (RFC 5958 §2) ──

/**
 * Read a `OneAsymmetricKey` from its decoded node.
 *
 * @internal
 */
export function _readPrivateKeyInfo(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): Omit<PrivateKeyInfo, 'diagnostics'> {
    const seq = _expectField(node, TAG_SEQUENCE, path, parentOffset, 'a PrivateKeyInfo SEQUENCE');
    const [versionNode, algorithmNode, keyNode, ...optional] = seq.children;
    const version = _readSmallInteger(_expectField(versionNode, TAG_INTEGER, `${path}.version`, seq.offset, 'an INTEGER version'), ctx);
    if (version !== 0 && version !== 1) {
        throw _keyError('PKI_KEY_VERSION_UNSUPPORTED', `${path}.version`, seq.offset, `is ${String(version)}; RFC 5958 defines v1 (0) and v2 (1)`);
    }
    const algorithm = _readKeyAlgorithm(algorithmNode, ctx, `${path}.privateKeyAlgorithm`, seq.offset);
    // The octets are the secret: checked for shape, never kept.
    _readOctetString(_expectField(keyNode, TAG_OCTET_STRING, `${path}.privateKey`, seq.offset, 'an OCTET STRING private key'), ctx);

    let attributes: readonly Attribute[] = [];
    let publicKey: BitString | undefined;
    let rank = -1;
    for (const field of optional) {
        const tag = field.tagClass === 'context' ? field.tagNumber : -1;
        if ((tag !== 0 && tag !== 1) || tag <= rank) {
            throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, field.offset, 'holds a value after the private key other than attributes [0] followed by publicKey [1]');
        }
        rank = tag;
        if (tag === 0) {
            if (!field.constructed) throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.attributes`, field.offset, 'is primitive; attributes [0] is an IMPLICIT SET OF');
            attributes = Object.freeze(_readAttributes(field, ctx, `${path}.attributes`));
        } else {
            if (version === 0) {
                throw _keyError('PKI_KEY_STRUCTURE_INVALID', `${path}.publicKey`, field.offset, 'is present in a version 0 structure; only v2 (1) may carry the public key');
            }
            publicKey = _readBitString(field, ctx);
        }
    }

    const kind = KEY_TYPES.get(algorithm.oid) ?? 'unknown';
    const parameters = algorithm.parameters;
    const curve = kind === 'ec' && parameters !== undefined && parameters.tagClass === 'universal' && parameters.tagNumber === TAG_OID
        ? EC_CURVE_OIDS.get(_readObjectIdentifier(parameters, ctx))
        : undefined;
    return Object.freeze({ der: seq.bytes, version, algorithm, kind, curve, attributes, publicKey });
}

/**
 * Read an `EncryptedPrivateKeyInfo` from its decoded node.
 *
 * @internal
 */
export function _readEncryptedPrivateKeyInfo(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): Omit<EncryptedPrivateKeyInfo, 'diagnostics'> {
    const seq = _expectField(node, TAG_SEQUENCE, path, parentOffset, 'an EncryptedPrivateKeyInfo SEQUENCE');
    if (seq.children.length !== 2) {
        throw _keyError('PKI_KEY_STRUCTURE_INVALID', path, seq.offset, `holds ${String(seq.children.length)} values; an EncryptedPrivateKeyInfo is a scheme and ciphertext`);
    }
    const encryption = _readPasswordEncryption(seq.children[0], ctx, `${path}.encryptionAlgorithm`, seq.offset);
    const dataNode = _expectField(seq.children[1], TAG_OCTET_STRING, `${path}.encryptedData`, seq.offset, 'an OCTET STRING of ciphertext');
    const encryptedData = _readOctetString(dataNode, ctx);
    return Object.freeze({ der: seq.bytes, encryption, encryptedData });
}

// ── Public readers ──

/**
 * Read an unencrypted PKCS#8 private key — the DER of a `PRIVATE KEY` PEM
 * block — and describe it without exposing its secret.
 *
 * ```ts
 * import { decodePem, parsePrivateKeyInfo } from 'pkinative';
 *
 * const [block] = decodePem(pemText, { label: 'PRIVATE KEY' });
 * const info = parsePrivateKeyInfo(block.bytes);
 * console.log(info.kind, info.curve);   // 'ec' 'P-256'
 * ```
 *
 * @param der     The DER of a RFC 5958 `OneAsymmetricKey` (version 0 is RFC 5208 PKCS#8).
 * @param options Encoding rules, limits and diagnostics.
 * @returns The key's description. The `privateKey` octets are not a field.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `der` is not a Uint8Array; `PKI_INVALID_OPTION` for a bad option.
 * @throws {PkiEncodingError} When the bytes are not valid DER.
 * @throws {PkiKeyError} `PKI_KEY_STRUCTURE_INVALID` or `PKI_KEY_VERSION_UNSUPPORTED`.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past a named limit.
 */
export function parsePrivateKeyInfo(der: Uint8Array, options?: PkiParseOptions): PrivateKeyInfo {
    const bytes = assertBytes(der, 'parsePrivateKeyInfo input');
    const ctx = createAsn1Context(options);
    const info = _readPrivateKeyInfo(decodeWithContext(bytes, ctx, false), ctx, 'privateKeyInfo', 0);
    return Object.freeze({ ...info, diagnostics: ctx.emitter.diagnostics });
}

/**
 * Read an encrypted PKCS#8 private key — the DER of an `ENCRYPTED PRIVATE KEY`
 * PEM block — and say how it is protected, before anyone types a password.
 *
 * A scheme pkinative will not open still parses: `encryption.pbes2` is then
 * `undefined` and `encryption.scheme` names it, so a tool can say why.
 *
 * @param der     The DER of a RFC 5958 §3 `EncryptedPrivateKeyInfo`.
 * @param options Encoding rules, limits and diagnostics.
 * @returns The scheme and the ciphertext.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `der` is not a Uint8Array; `PKI_INVALID_OPTION` for a bad option.
 * @throws {PkiEncodingError} When the bytes are not valid DER.
 * @throws {PkiKeyError} `PKI_KEY_STRUCTURE_INVALID`.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxKdfIterations` or another named limit.
 */
export function parseEncryptedPrivateKeyInfo(der: Uint8Array, options?: PkiParseOptions): EncryptedPrivateKeyInfo {
    const bytes = assertBytes(der, 'parseEncryptedPrivateKeyInfo input');
    const ctx = createAsn1Context(options);
    const info = _readEncryptedPrivateKeyInfo(decodeWithContext(bytes, ctx, false), ctx, 'encryptedPrivateKeyInfo', 0);
    return Object.freeze({ ...info, diagnostics: ctx.emitter.diagnostics });
}
