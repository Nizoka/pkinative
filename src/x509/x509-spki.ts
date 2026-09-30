/**
 * pkinative — SubjectPublicKeyInfo
 * ================================
 * RFC 5280 §4.1.2.7, with the key of each recognised algorithm checked
 * against its definition: RSA (RFC 3279 §2.3.1) and RSASSA-PSS (RFC 4055),
 * elliptic curves (RFC 5480), EdDSA and XDH (RFC 8410 §3 and §4) and ML-DSA
 * (RFC 9881 §2, with the key sizes of FIPS 204). Any other algorithm is kept
 * as `kind: 'unknown'`.
 *
 * This reads public keys; it performs no arithmetic on them.
 *
 * @module x509/x509-spki
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBitString, _readInteger } from '../asn1/asn1-read.js';
import { TAG_BIT_STRING, TAG_INTEGER, TAG_OID, TAG_SEQUENCE } from '../asn1/asn1-tags.js';
import type { Asn1Node, BitString } from '../types/asn1-types.js';
import { PkiEncodingError } from '../types/pki-errors.js';
import type {
    AlgorithmIdentifier,
    EcCurve,
    EcPublicKeyInfo,
    OctetPublicKeyInfo,
    RsaPublicKeyInfo,
    SubjectPublicKeyInfo,
    UnknownPublicKeyInfo,
} from '../types/x509-types.js';
import { _readAlgorithmIdentifier } from './x509-algorithm.js';
import { certificateError, expectUniversalField } from './x509-fields.js';

const CODE = 'PKI_X509_SPKI_INVALID';

const OID_RSA = '1.2.840.113549.1.1.1';
const OID_RSA_PSS = '1.2.840.113549.1.1.10';
const OID_EC = '1.2.840.10045.2.1';

/** Named curves and the octet length of one coordinate. */
const CURVES: ReadonlyMap<string, { readonly curve: EcCurve; readonly size: number }> = /*#__PURE__*/ new Map([
    ['1.2.840.10045.3.1.7', { curve: 'P-256', size: 32 }],
    ['1.3.132.0.34', { curve: 'P-384', size: 48 }],
    ['1.3.132.0.35', { curve: 'P-521', size: 66 }],
]);

/** Algorithms whose subjectPublicKey is the raw key, with the key length. */
/** A key held as a fixed-length octet string, and the clause that requires its parameters absent. */
interface OctetKeySpec {
    readonly kind: OctetPublicKeyInfo['kind'];
    readonly length: number;
    readonly standard: 'RFC 8410 §3' | 'RFC 9881 §2';
}

const OCTET_KEYS: ReadonlyMap<string, OctetKeySpec> = /*#__PURE__*/ new Map<string, OctetKeySpec>([
    ['1.3.101.110', { kind: 'x25519', length: 32, standard: 'RFC 8410 §3' }],
    ['1.3.101.111', { kind: 'x448', length: 56, standard: 'RFC 8410 §3' }],
    ['1.3.101.112', { kind: 'ed25519', length: 32, standard: 'RFC 8410 §3' }],
    ['1.3.101.113', { kind: 'ed448', length: 57, standard: 'RFC 8410 §3' }],
    ['2.16.840.1.101.3.4.3.17', { kind: 'ml-dsa-44', length: 1312, standard: 'RFC 9881 §2' }],
    ['2.16.840.1.101.3.4.3.18', { kind: 'ml-dsa-65', length: 1952, standard: 'RFC 9881 §2' }],
    ['2.16.840.1.101.3.4.3.19', { kind: 'ml-dsa-87', length: 2592, standard: 'RFC 9881 §2' }],
]);

interface KeyParts {
    readonly algorithm: AlgorithmIdentifier;
    readonly publicKey: BitString;
    readonly der: Uint8Array;
    readonly keyPath: string;
    readonly keyOffset: number;
}

function requireWholeOctets(parts: KeyParts, what: string): void {
    if (parts.publicKey.unusedBits !== 0) {
        throw certificateError(CODE, parts.keyPath, parts.keyOffset, `has ${parts.publicKey.unusedBits} unused bits; ${what} key is a whole number of octets`);
    }
}

function readRsa(parts: KeyParts, kind: RsaPublicKeyInfo['kind'], ctx: Asn1Context): RsaPublicKeyInfo {
    requireWholeOctets(parts, 'an RSA');
    try {
        const key = decodeWithContext(parts.publicKey.bytes, ctx, false);
        const modulusNode = key.children[0];
        const exponentNode = key.children[1];
        if (key.tagClass !== 'universal' || key.tagNumber !== TAG_SEQUENCE || key.children.length !== 2
            || modulusNode?.tagClass !== 'universal' || modulusNode.tagNumber !== TAG_INTEGER
            || exponentNode?.tagClass !== 'universal' || exponentNode.tagNumber !== TAG_INTEGER) {
            throw certificateError(CODE, parts.keyPath, parts.keyOffset, 'is not an RSAPublicKey: a SEQUENCE of the modulus and the public exponent, two INTEGERs');
        }
        const modulus = _readInteger(modulusNode, ctx);
        const publicExponent = _readInteger(exponentNode, ctx);
        if (modulus <= 0n || publicExponent <= 0n) {
            throw certificateError(CODE, parts.keyPath, parts.keyOffset, 'has a modulus or public exponent that is not positive');
        }
        const content = modulusNode.content;
        const info: RsaPublicKeyInfo = {
            kind,
            algorithm: parts.algorithm,
            publicKey: parts.publicKey,
            der: parts.der,
            modulus: content[0] === 0 ? content.subarray(1) : content,
            modulusBits: modulus.toString(2).length,
            publicExponent,
        };
        return Object.freeze(info);
    } catch (error) {
        if (error instanceof PkiEncodingError) {
            throw certificateError(CODE, parts.keyPath, parts.keyOffset, `is not a DER RSAPublicKey (${error.code})`);
        }
        throw error;
    }
}

function readEc(parts: KeyParts, ctx: Asn1Context): EcPublicKeyInfo {
    const parameters = parts.algorithm.parameters;
    if (parameters === undefined) {
        throw certificateError(CODE, `${parts.keyPath.replace(/subjectPublicKey$/, 'algorithm')}.parameters`, parts.keyOffset, 'are absent; an EC key names its curve (RFC 5480 §2.1.1)');
    }
    const namedCurve = parameters.tagClass === 'universal' && parameters.tagNumber === TAG_OID ? _readObjectIdentifier(parameters, ctx) : undefined;
    const spec = namedCurve === undefined ? undefined : CURVES.get(namedCurve);
    requireWholeOctets(parts, 'an EC');
    const point = parts.publicKey.bytes;
    const first = point[0];
    let pointFormat: EcPublicKeyInfo['pointFormat'];
    if (first === 0x04) {
        pointFormat = 'uncompressed';
        const valid = spec === undefined ? point.length >= 3 && point.length % 2 === 1 : point.length === 1 + 2 * spec.size;
        if (!valid) throw certificateError(CODE, parts.keyPath, parts.keyOffset, `is an uncompressed point of ${point.length} octets, which ${spec?.curve ?? 'no curve'} allows`);
    } else if (first === 0x02 || first === 0x03) {
        pointFormat = 'compressed';
        const valid = spec === undefined ? point.length >= 2 : point.length === 1 + spec.size;
        if (!valid) throw certificateError(CODE, parts.keyPath, parts.keyOffset, `is a compressed point of ${point.length} octets, which ${spec?.curve ?? 'no curve'} allows`);
    } else {
        throw certificateError(CODE, parts.keyPath, parts.keyOffset, 'does not start with 0x04 (uncompressed) or 0x02/0x03 (compressed); RFC 5480 §2.2 allows no other point form');
    }
    const info: EcPublicKeyInfo = {
        kind: 'ec',
        algorithm: parts.algorithm,
        publicKey: parts.publicKey,
        der: parts.der,
        namedCurve,
        curve: spec?.curve,
        pointFormat,
        point,
    };
    return Object.freeze(info);
}

function readOctetKey(parts: KeyParts, spec: OctetKeySpec): OctetPublicKeyInfo {
    if (parts.algorithm.parameters !== undefined) {
        throw certificateError(CODE, parts.keyPath, parts.keyOffset, `belongs to ${spec.kind}, whose AlgorithmIdentifier must omit the parameters (${spec.standard})`);
    }
    requireWholeOctets(parts, `an ${spec.kind}`);
    if (parts.publicKey.bytes.length !== spec.length) {
        throw certificateError(CODE, parts.keyPath, parts.keyOffset, `is ${parts.publicKey.bytes.length} octets; an ${spec.kind} key is ${spec.length}`);
    }
    const info: OctetPublicKeyInfo = { kind: spec.kind, algorithm: parts.algorithm, publicKey: parts.publicKey, der: parts.der, key: parts.publicKey.bytes };
    return Object.freeze(info);
}

/**
 * Read a SubjectPublicKeyInfo under the operation context.
 *
 * @internal
 */
export function _readSubjectPublicKeyInfo(node: Asn1Node | undefined, ctx: Asn1Context, path: string, parentOffset: number): SubjectPublicKeyInfo {
    const seq = expectUniversalField(node, TAG_SEQUENCE, path, CODE, parentOffset);
    if (seq.children.length > 2) {
        throw certificateError(CODE, path, seq.offset, `holds ${seq.children.length} values; SubjectPublicKeyInfo is an AlgorithmIdentifier and a BIT STRING`);
    }
    const algorithm = _readAlgorithmIdentifier(seq.children[0], ctx, `${path}.algorithm`, CODE, seq.offset);
    const keyPath = `${path}.subjectPublicKey`;
    const keyNode = expectUniversalField(seq.children[1], TAG_BIT_STRING, keyPath, CODE, seq.offset);
    const parts: KeyParts = { algorithm, publicKey: _readBitString(keyNode, ctx), der: seq.bytes, keyPath, keyOffset: keyNode.offset };

    if (algorithm.oid === OID_RSA) return readRsa(parts, 'rsa', ctx);
    if (algorithm.oid === OID_RSA_PSS) return readRsa(parts, 'rsa-pss', ctx);
    if (algorithm.oid === OID_EC) return readEc(parts, ctx);
    const octetKey = OCTET_KEYS.get(algorithm.oid);
    if (octetKey !== undefined) return readOctetKey(parts, octetKey);
    const info: UnknownPublicKeyInfo = { kind: 'unknown', algorithm, publicKey: parts.publicKey, der: seq.bytes };
    return Object.freeze(info);
}
