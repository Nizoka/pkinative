/**
 * pkinative — X.509 structural encoders
 * =====================================
 * The SEQUENCEs RFC 5280 is made of, one function each.
 *
 * They live here and not in `asn1/` because `asn1/` knows nothing of
 * certificates (AGENTS.md §Architecture): an `AlgorithmIdentifier` is X.509
 * vocabulary, a SEQUENCE is not. They are public because `revocation` will
 * need them for OCSP requests at 0.5 and `cms` for signed attributes at 0.7,
 * and because a caller building something this library does not model yet
 * should be able to reach the same pieces rather than reimplement them.
 *
 * @module build/build-structures
 */

import {
    encodeBitString,
    encodeBoolean,
    encodeExplicit,
    encodeImplicit,
    encodeInteger,
    encodeNamedBits,
    encodeNull,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeSequence,
    encodeSetOf,
    encodeString,
    encodeTime,
} from '../asn1/asn1-encode.js';
import { assertBytes } from '../core/bytes.js';
import { NAME_ATTRIBUTE_SYNTAX, OID_COUNTRY_NAME } from '../core/name-oids.js';
import { DEFAULT_PKI_LIMITS, enforceLimit, resolveLimits } from '../core/pki-limits.js';
import type { ExtensionDescription, NameAttribute, NameDescription, PkiBuildOptions } from '../types/build-types.js';
import { PkiError } from '../types/pki-errors.js';

/**
 * Algorithms whose parameters RFC 3279 §2.2.1 requires to be present and
 * NULL. The Edwards curves and ECDSA require them **absent** (RFC 8410 §3,
 * RFC 5758 §3.2), and the difference is not cosmetic: a verifier that
 * re-encodes the AlgorithmIdentifier to check it against `tbsCertificate`
 * sees two different byte strings.
 */
const PARAMETERS_NULL: ReadonlySet<string> = /*#__PURE__*/ new Set([
    '1.2.840.113549.1.1.1',
    '1.2.840.113549.1.1.5',
    '1.2.840.113549.1.1.11',
    '1.2.840.113549.1.1.12',
    '1.2.840.113549.1.1.13',
]);

/**
 * Encode an `AlgorithmIdentifier`, with the parameters its OID requires.
 *
 * @param oid        The algorithm OID.
 * @param parameters The encoded parameters. Omitted, the RFC 3279 rule
 *   decides: NULL for the PKCS#1 v1.5 family, absent for everything else.
 * @returns The `AlgorithmIdentifier` encoding.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed OID.
 */
export function encodeAlgorithmIdentifier(oid: string, parameters?: Uint8Array): Uint8Array {
    const fields = [encodeObjectIdentifier(oid)];
    if (parameters !== undefined) fields.push(assertBytes(parameters, 'encodeAlgorithmIdentifier parameters'));
    else if (PARAMETERS_NULL.has(oid)) fields.push(encodeNull());
    return encodeSequence(fields);
}

/** The string types RFC 5280 §4.1.2.4 lets a conforming CA write for a DirectoryString. */
const DIRECTORY_STRING_TYPES: ReadonlySet<string> = /*#__PURE__*/ new Set(['utf8', 'printable']);

/**
 * The string type of one attribute value: the caller's, or the one RFC 5280
 * Appendix A.1 gives the attribute — PrintableString for `countryName`,
 * `serialNumber` and `dnQualifier`, IA5String for `domainComponent` and
 * `emailAddress`, UTF8String for a DirectoryString and for any attribute the
 * appendix does not define. Refuses a type the attribute's syntax excludes,
 * and a value outside its SIZE bounds.
 */
function nameStringType(type: string, value: string, requested: NameAttribute['stringType']): NonNullable<NameAttribute['stringType']> {
    const spec = NAME_ATTRIBUTE_SYNTAX.get(type);
    if (spec === undefined) return requested ?? 'utf8';
    const fixed = spec.syntax === 'directory' ? undefined : spec.syntax;
    const chosen = requested ?? fixed ?? 'utf8';
    const allowed = fixed === undefined ? DIRECTORY_STRING_TYPES.has(chosen) : chosen === fixed;
    if (!allowed) {
        const expected = fixed === undefined ? 'a DirectoryString, which a conforming CA writes as UTF8String or PrintableString (RFC 5280 §4.1.2.4)' : `${fixed === 'printable' ? 'a PrintableString' : 'an IA5String'} (RFC 5280 Appendix A.1)`;
        throw new PkiError('PKI_API_MISUSE', `pkinative: ${spec.name} (${type}) is ${expected}, not stringType '${chosen}' — omit stringType to get the right one, or pass the value's DER as a Uint8Array to reproduce an existing name byte for byte`);
    }
    // SIZE counts characters: code points, not UTF-16 units or octets.
    const size = [...value].length;
    if (size < spec.min || (spec.max !== undefined && size > spec.max)) {
        const bounds = spec.max === spec.min ? `exactly ${String(spec.min)}` : `${String(spec.min)} to ${String(spec.max)}`;
        const hint = type === OID_COUNTRY_NAME ? ' — an ISO 3166 alpha-2 code such as \'US\'' : '';
        throw new PkiError('PKI_API_MISUSE', `pkinative: ${spec.name} (${type}) is ${String(size)} characters long; RFC 5280 Appendix A bounds it to ${bounds}${hint}`);
    }
    return chosen;
}

/**
 * Encode one `AttributeTypeAndValue`.
 *
 * A string value takes the string type RFC 5280 Appendix A.1 defines for the
 * attribute unless `stringType` says otherwise: PrintableString for
 * `countryName` (2.5.4.6), `serialNumber` (2.5.4.5) and `dnQualifier`
 * (2.5.4.46), IA5String for `domainComponent` and `emailAddress`, UTF8String
 * for every DirectoryString attribute (`commonName`, `organizationName`, …)
 * and for any attribute the appendix does not define. A string value is also
 * held to the attribute's SIZE bounds — `countryName` is exactly two
 * characters, `commonName` at most 64.
 *
 * @param attribute The type OID and its value.
 * @returns The `AttributeTypeAndValue` encoding.
 * @throws {PkiError} `PKI_INVALID_INPUT` when the value is neither a string
 *   nor a Uint8Array; `PKI_API_MISUSE` when `stringType` is one the
 *   attribute's syntax excludes (`'utf8'` for `countryName`, `'ia5'` for
 *   `commonName`), or the value is outside the attribute's SIZE bounds.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed type OID; `PKI_ASN1_VALUE_OUT_OF_RANGE` for a character the chosen string type cannot carry.
 */
export function encodeNameAttribute(attribute: NameAttribute): Uint8Array {
    const { type, value, stringType } = attribute;
    const encoded = value instanceof Uint8Array
        ? value
        : typeof value === 'string'
            ? encodeString(nameStringType(type, value, stringType), value)
            : null;
    if (encoded === null) {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: the value of name attribute ${type} must be a string or a Uint8Array of its DER, got ${typeof value}`);
    }
    return encodeSequence([encodeObjectIdentifier(type), encoded]);
}

/**
 * Encode a `Name` (an RDNSequence).
 *
 * Each RDN is a SET OF, sorted canonically as DER requires — which is why a
 * multi-valued RDN built here is byte-identical however the caller ordered
 * its attributes, and why it may **not** match a name some other tool
 * produced. When the name must match one that exists, pass that name's DER
 * instead of describing it.
 *
 * @param name    The RDNs, most significant first.
 * @param options `limits` bounds the attribute count.
 * @returns The `Name` encoding.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `name` is not an array of arrays.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` when the name has more attributes than `maxNameAttributes`.
 */
export function encodeDistinguishedName(name: NameDescription, options?: PkiBuildOptions): Uint8Array {
    if (!Array.isArray(name)) {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: a name is an array of relative distinguished names, got ${typeof name}`);
    }
    const limits = options?.limits === undefined ? DEFAULT_PKI_LIMITS : resolveLimits(options.limits);
    let attributes = 0;
    const rdns: Uint8Array[] = [];
    for (const rdn of name) {
        if (!Array.isArray(rdn) || rdn.length === 0) {
            throw new PkiError('PKI_INVALID_INPUT', 'pkinative: every relative distinguished name is a non-empty array of attributes');
        }
        attributes += rdn.length;
        enforceLimit(limits, 'maxNameAttributes', attributes, 'the name being built');
        rdns.push(encodeSetOf(rdn.map(encodeNameAttribute)));
    }
    return encodeSequence(rdns);
}

/**
 * Encode a `Validity`.
 *
 * Both ends follow the RFC 5280 §4.1.2.5 rule automatically: UTCTime through
 * 2049, GeneralizedTime from 2050. Writing a GeneralizedTime before 2050 is
 * a conformance defect real issuers commit, and one this library will not.
 *
 * @param notBefore Start, in epoch milliseconds.
 * @param notAfter  End, in epoch milliseconds.
 * @returns The `Validity` encoding.
 * @throws {PkiError} `PKI_API_MISUSE` when `notAfter` precedes `notBefore`.
 * @throws {PkiEncodingError} `PKI_ASN1_VALUE_OUT_OF_RANGE` for a year outside 0000–9999.
 */
export function encodeValidity(notBefore: number, notAfter: number): Uint8Array {
    if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: notBefore and notAfter are epoch milliseconds, and both must be finite numbers');
    }
    if (notAfter < notBefore) {
        throw new PkiError('PKI_API_MISUSE',
            `pkinative: notAfter (${new Date(notAfter).toISOString()}) precedes notBefore (${new Date(notBefore).toISOString()}) — a certificate valid for a negative interval is valid nowhere`);
    }
    return encodeSequence([encodeTime(notBefore), encodeTime(notAfter)]);
}

/**
 * Encode one `Extension`.
 *
 * `critical` is omitted when false, as DER requires of a DEFAULT: encoding
 * it anyway produces a certificate every strict reader diagnoses, which is
 * the single most common defect in the wild.
 *
 * @param extension The OID, the criticality and the value's DER.
 * @returns The `Extension` encoding.
 * @throws {PkiError} `PKI_INVALID_INPUT` when the value is not a Uint8Array.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed OID.
 */
export function encodeExtension(extension: ExtensionDescription): Uint8Array {
    const fields = [encodeObjectIdentifier(extension.oid)];
    if (extension.critical === true) fields.push(encodeBoolean(true));
    fields.push(encodeOctetString(assertBytes(extension.value, `extension ${extension.oid} value`)));
    return encodeSequence(fields);
}

/**
 * Encode an `Extensions` SEQUENCE.
 *
 * @param extensions The extensions, in the order they are placed.
 * @param options    `limits` bounds the count.
 * @returns The `Extensions` encoding.
 * @throws {PkiError} `PKI_API_MISUSE` when two extensions share an OID — which extension a verifier reads would be undefined, so a certificate carrying one twice is refused on the way out as it is on the way in.
 * @throws {PkiLimitError} `PKI_LIMIT_EXCEEDED` past `maxExtensions`.
 */
export function encodeExtensions(extensions: readonly ExtensionDescription[], options?: PkiBuildOptions): Uint8Array {
    const limits = options?.limits === undefined ? DEFAULT_PKI_LIMITS : resolveLimits(options.limits);
    enforceLimit(limits, 'maxExtensions', extensions.length, 'the extensions being built');
    const seen = new Set<string>();
    for (const extension of extensions) {
        if (seen.has(extension.oid)) {
            throw new PkiError('PKI_API_MISUSE', `pkinative: extension ${extension.oid} appears twice; RFC 5280 §4.2 allows one instance, and which one a verifier reads is undefined`);
        }
        seen.add(extension.oid);
    }
    return encodeSequence(extensions.map(encodeExtension));
}

/**
 * Encode an `Attribute` — a type OID and a SET OF values.
 *
 * Used by PKCS#10 requests (the `extensionRequest` attribute) and, from
 * 0.7, by CMS signed attributes.
 *
 * @param oid    The attribute type OID.
 * @param values The DER encodings of the values.
 * @returns The `Attribute` encoding.
 * @throws {PkiError} `PKI_INVALID_INPUT` when a value is not a Uint8Array.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed OID.
 */
export function encodeAttribute(oid: string, values: readonly Uint8Array[]): Uint8Array {
    return encodeSequence([encodeObjectIdentifier(oid), encodeSetOf(values)]);
}

/**
 * Encode a `SubjectPublicKeyInfo` from its parts.
 *
 * A caller who already has one — the usual case, from
 * `crypto.subtle.exportKey('spki', key)` — passes it straight to
 * `createCertificate` and never needs this.
 *
 * @param algorithmOid The key algorithm OID, e.g. `1.2.840.113549.1.1.1`.
 * @param publicKey    The key bits, as the BIT STRING's octets.
 * @param parameters   The algorithm parameters, following the RFC 3279 rule when omitted.
 * @returns The `SubjectPublicKeyInfo` encoding.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `publicKey` is not a Uint8Array.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed OID.
 */
export function encodeSubjectPublicKeyInfo(algorithmOid: string, publicKey: Uint8Array, parameters?: Uint8Array): Uint8Array {
    return encodeSequence([
        encodeAlgorithmIdentifier(algorithmOid, parameters),
        // A public key is a whole number of octets: no unused bits, ever.
        encodeBitString(assertBytes(publicKey, 'encodeSubjectPublicKeyInfo publicKey'), 0),
    ]);
}

// ── The extension values a caller needs to make a real certificate ───

/**
 * `basicConstraints` (RFC 5280 §4.2.1.9). Mark the extension critical.
 *
 * @param options `cA`, and `pathLenConstraint` for a CA that limits how many
 *   intermediates may follow it.
 * @returns The extension value's DER.
 * @throws {PkiError} `PKI_API_MISUSE` for a negative or fractional
 *   `pathLenConstraint`, or one on an end entity, which constrains no path.
 */
export function encodeBasicConstraints(options: { readonly cA: boolean; readonly pathLenConstraint?: number | undefined }): Uint8Array {
    const fields: Uint8Array[] = [];
    // cA DEFAULT FALSE: omitted when false, as DER requires.
    if (options.cA) fields.push(encodeBoolean(true));
    if (options.pathLenConstraint !== undefined) {
        if (!Number.isInteger(options.pathLenConstraint) || options.pathLenConstraint < 0) {
            throw new PkiError('PKI_API_MISUSE', `pkinative: pathLenConstraint must be a non-negative integer, got ${String(options.pathLenConstraint)}`);
        }
        if (!options.cA) {
            throw new PkiError('PKI_API_MISUSE', 'pkinative: pathLenConstraint is meaningful only when cA is true (RFC 5280 §4.2.1.9) — an end-entity certificate constrains no path');
        }
        fields.push(encodeInteger(options.pathLenConstraint));
    }
    return encodeSequence(fields);
}

const KEY_USAGE_ENTRIES: ReadonlyArray<readonly [string, number]> = [
    ['digitalSignature', 0], ['nonRepudiation', 1], ['keyEncipherment', 2], ['dataEncipherment', 3],
    ['keyAgreement', 4], ['keyCertSign', 5], ['cRLSign', 6], ['encipherOnly', 7], ['decipherOnly', 8],
];

/**
 * The table `encodeKeyUsage` reads. Never exported, so what the encoder
 * accepts cannot be changed by anything else running in the process — not
 * even through `Map.prototype.set.call` on the public copy.
 */
const KEY_USAGE_TABLE: ReadonlyMap<string, number> = /*#__PURE__*/ new Map(KEY_USAGE_ENTRIES);

/**
 * A `Map` whose mutators throw, frozen. `Object.freeze` alone leaves a Map's
 * entries writable — they live in an internal slot, not in properties — so
 * `set`, `delete` and `clear` are shadowed on the instance, where freezing
 * keeps them.
 */
function readOnlyMap(name: string, entries: ReadonlyArray<readonly [string, number]>): ReadonlyMap<string, number> {
    const map = new Map(entries);
    const refuse = (): never => {
        throw new PkiError('PKI_API_MISUSE', `pkinative: ${name} is read-only — every caller in the process shares it; copy it with new Map(${name}) to extend it`);
    };
    Object.defineProperties(map, { set: { value: refuse }, delete: { value: refuse }, clear: { value: refuse } });
    return Object.freeze(map);
}

/**
 * The `KeyUsage` bit positions of RFC 5280 §4.2.1.3, in their defined order.
 *
 * Read-only at runtime as well as in its type: `set`, `delete` and `clear`
 * throw `PKI_API_MISUSE`, and `encodeKeyUsage` reads a private table, so no
 * caller can change what it accepts for every other caller.
 */
export const KEY_USAGE_BITS: ReadonlyMap<string, number> = /*#__PURE__*/ readOnlyMap('KEY_USAGE_BITS', KEY_USAGE_ENTRIES);

/**
 * `keyUsage` (RFC 5280 §4.2.1.3). Mark the extension critical.
 *
 * @param usages The usage names, in any order — {@link KEY_USAGE_BITS} lists them.
 * @returns The extension value's DER, with every trailing zero bit dropped.
 * @throws {PkiError} `PKI_INVALID_OPTION` for a name RFC 5280 does not define.
 */
export function encodeKeyUsage(usages: Iterable<string>): Uint8Array {
    const bits: number[] = [];
    for (const usage of usages) {
        const bit = KEY_USAGE_TABLE.get(usage);
        if (bit === undefined) {
            throw new PkiError('PKI_INVALID_OPTION', `pkinative: ${usage} is not a KeyUsage of RFC 5280 §4.2.1.3 — one of ${[...KEY_USAGE_TABLE.keys()].join(', ')}`);
        }
        bits.push(bit);
    }
    return encodeNamedBits(bits);
}

/**
 * `extendedKeyUsage` (RFC 5280 §4.2.1.12): a SEQUENCE OF key-purpose OIDs.
 *
 * @param purposes The purpose OIDs, e.g. `1.3.6.1.5.5.7.3.1` for serverAuth.
 * @returns The extension value's DER.
 * @throws {PkiError} `PKI_API_MISUSE` when the list is empty, which permits nothing.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed OID.
 */
export function encodeExtendedKeyUsage(purposes: readonly string[]): Uint8Array {
    if (purposes.length === 0) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: an extendedKeyUsage with no purpose permits nothing and is refused by RFC 5280 §4.2.1.12');
    }
    return encodeSequence(purposes.map(encodeObjectIdentifier));
}

/**
 * `subjectKeyIdentifier` (RFC 5280 §4.2.1.2): an OCTET STRING, conventionally
 * the SHA-1 of the subject public key's bits.
 *
 * @param keyIdentifier The identifier octets.
 * @returns The extension value's DER.
 * @throws {PkiError} `PKI_INVALID_INPUT` when the argument is not a Uint8Array.
 */
export function encodeSubjectKeyIdentifier(keyIdentifier: Uint8Array): Uint8Array {
    return encodeOctetString(assertBytes(keyIdentifier, 'subjectKeyIdentifier'));
}

/**
 * `authorityKeyIdentifier` (RFC 5280 §4.2.1.1) with the issuer's key identifier.
 *
 * @param keyIdentifier The issuing certificate's subjectKeyIdentifier octets.
 * @returns The extension value's DER.
 * @throws {PkiError} `PKI_INVALID_INPUT` when the argument is not a Uint8Array.
 */
export function encodeAuthorityKeyIdentifier(keyIdentifier: Uint8Array): Uint8Array {
    // [0] IMPLICIT KeyIdentifier: an OCTET STRING re-tagged, so it stays
    // primitive — which is what encodeImplicit reads off the value rather
    // than being told.
    return encodeSequence([encodeImplicit(0, encodeOctetString(assertBytes(keyIdentifier, 'authorityKeyIdentifier')))]);
}

/** A GeneralName this encoder writes. See {@link encodeSubjectAltName}. */
export type GeneralNameDescription =
    /** `[1]`, `[2]` and `[6]`: an IA5String, implicitly tagged, so it stays primitive. */
    | { readonly kind: 'dNSName' | 'rfc822Name' | 'uniformResourceIdentifier'; readonly value: string }
    /**
     * `[7]`: the address in **network byte order** — 4 octets for IPv4, 16
     * for IPv6, and nothing else. It takes bytes rather than text on
     * purpose: the same rule as `issuerDer`, applied to a value that must be
     * exact. `'192.0.2.1'` has one encoding, but `'::ffff:192.0.2.1'`,
     * `'2001:db8::1'` and `'2001:0db8:0000:0000:0000:0000:0000:0001'` are
     * three spellings a text parser has to choose between, and a certificate
     * that names the wrong host because a `::` expanded differently is not a
     * bug anyone finds quickly.
     */
    | { readonly kind: 'iPAddress'; readonly value: Uint8Array }
    /** `[8]`: an OBJECT IDENTIFIER, implicitly tagged. */
    | { readonly kind: 'registeredID'; readonly value: string }
    /** `[4]` **explicit**, because a Name is itself constructed. Takes the DER of a Name. */
    | { readonly kind: 'directoryNameDer'; readonly value: Uint8Array };

/**
 * `subjectAltName` (RFC 5280 §4.2.1.6), and `issuerAltName`, which has the
 * same value syntax.
 *
 * @param names The names, in the order they are placed.
 * @returns The extension value's DER.
 * @throws {PkiError} `PKI_API_MISUSE` for an empty list, which RFC 5280
 *   refuses; `PKI_INVALID_OPTION` for a GeneralName form this encoder does
 *   not write — build that one with `encodeImplicit` and place it yourself —
 *   or for an `iPAddress` that is not 4 or 16 octets.
 * @throws {PkiEncodingError} `PKI_ASN1_VALUE_OUT_OF_RANGE` for a character an IA5String cannot carry.
 * @throws {PkiError} `PKI_OID_INVALID` for a malformed `registeredID`.
 */
export function encodeSubjectAltName(names: readonly GeneralNameDescription[]): Uint8Array {
    if (names.length === 0) {
        throw new PkiError('PKI_API_MISUSE', 'pkinative: a subjectAltName with no name is refused by RFC 5280 §4.2.1.6 — omit the extension instead');
    }
    const tags: Readonly<Record<string, number>> = { rfc822Name: 1, dNSName: 2, uniformResourceIdentifier: 6 };
    return encodeSequence(names.map((name) => {
        if (name.kind === 'directoryNameDer') return encodeExplicit(4, assertBytes(name.value, 'directoryName'));
        if (name.kind === 'iPAddress') {
            const address = assertBytes(name.value, 'iPAddress');
            // RFC 5280 §4.2.1.6: 4 or 16 octets in a subjectAltName. The
            // 8-and-32-octet forms carrying a mask belong to nameConstraints
            // and are refused here, where they would mean nothing.
            if (address.length !== 4 && address.length !== 16) {
                throw new PkiError('PKI_INVALID_OPTION', `pkinative: an iPAddress in a subjectAltName is 4 octets (IPv4) or 16 (IPv6), not ${String(address.length)} — the 8- and 32-octet forms carry a mask and belong to nameConstraints (RFC 5280 §4.2.1.6)`);
            }
            return encodeImplicit(7, encodeOctetString(address));
        }
        if (name.kind === 'registeredID') return encodeImplicit(8, encodeObjectIdentifier(name.value));
        const tag = tags[name.kind];
        if (tag === undefined) {
            throw new PkiError('PKI_INVALID_OPTION', `pkinative: ${String((name as { kind: string }).kind)} is not a GeneralName form this encoder writes — pass a directoryNameDer, or build the GeneralName with encodeImplicit`);
        }
        return encodeImplicit(tag, encodeString('ia5', name.value));
    }));
}
