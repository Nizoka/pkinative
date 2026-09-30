/**
 * pkinative — creation types
 * ==========================
 * The typed descriptions a certificate and a certification request are built
 * from.
 *
 * One rule runs through all of them, and it is the rule that prevents the
 * classic PKI defect: **anything that must be byte-identical to a parsed
 * object is passed as DER, never as a structure to re-render.** An issuer
 * name re-encoded from its decoded attributes will not reproduce a
 * TeletexString, an oddly-cased PrintableString, or an attribute order the
 * CA chose — and a chain whose `issuer` differs from the CA's `subject` by
 * one octet is a chain nothing will build. So `issuerDer` takes
 * `ca.subject.der`, and `subjectPublicKey` takes a SubjectPublicKeyInfo the
 * caller exported, rather than a `CryptoKey` this library would have to
 * export itself.
 *
 * @module types/build-types
 */

import type { PkiLimits } from './pki-types.js';

/**
 * Options of every function that builds a structure from a description —
 * the certificate, the request, the SignedData and the encoders they share.
 */
export interface PkiBuildOptions {
    /** Bounds on what is built; each function names under `@throws` the limits that apply to it. */
    readonly limits?: Partial<PkiLimits> | undefined;
}

/** One `AttributeTypeAndValue` of a distinguished name. */
export interface NameAttribute {
    /** The attribute type OID, e.g. `2.5.4.3` for commonName. */
    readonly type: string;
    /**
     * The value. A string is encoded as `stringType`; bytes are used as the
     * complete DER encoding of the value, for a type this shorthand does
     * not cover.
     */
    readonly value: string | Uint8Array;
    /**
     * How a string value is encoded. Leave it out: the default is the type
     * RFC 5280 Appendix A.1 defines for the attribute — `'printable'` for
     * `countryName`, `serialNumber` and `dnQualifier`, `'ia5'` for
     * `domainComponent` and `emailAddress`, and `'utf8'` for a
     * DirectoryString attribute (`commonName`, `organizationName`, …) and for
     * any attribute the appendix does not define.
     *
     * For a DirectoryString, RFC 5280 §4.1.2.4 lets a conforming CA write
     * either `'printable'` or `'utf8'` (the rule that new names be UTF8String
     * was RFC 3280's, and RFC 5280 dropped it), so both are accepted; a type
     * the attribute's syntax excludes — `'utf8'` for `countryName`, `'ia5'`
     * for `commonName` — is refused with `PKI_API_MISUSE`. To reproduce an
     * existing name byte for byte, pass its value's DER as `value`, or the
     * whole name's DER as `issuerDer` or `subjectDer`.
     */
    readonly stringType?: 'utf8' | 'printable' | 'ia5' | 'numeric' | undefined;
}

/**
 * A distinguished name to build: one array per RDN, most significant first
 * — `[[{ type: '2.5.4.6', value: 'US' }], [{ type: '2.5.4.3', value: 'Example CA' }]]`
 * is `C=US, CN=Example CA`, with `US` a PrintableString and `Example CA` a
 * UTF8String, as RFC 5280 Appendix A.1 defines them.
 *
 * Multi-valued RDNs are the inner array with more than one entry; their
 * SET OF is sorted canonically, as DER requires.
 */
export type NameDescription = ReadonlyArray<readonly NameAttribute[]>;

/** One extension to place in a certificate or request. */
export interface ExtensionDescription {
    /** The extension OID. */
    readonly oid: string;
    /** Whether a relying party that does not understand it must reject the certificate. Defaults to false. */
    readonly critical?: boolean | undefined;
    /** The DER encoding of the extension's value — what goes inside `extnValue`'s OCTET STRING. */
    readonly value: Uint8Array;
}

/** What a certificate is built from. */
export interface CertificateDescription {
    /**
     * The serial. A `bigint` is encoded as a positive INTEGER, minimally.
     * A `Uint8Array` is used as the content octets unchanged, so an existing
     * serial can be reproduced byte for byte; it must still be a valid DER
     * INTEGER — non-empty and in the shortest form — or `PKI_API_MISUSE` is
     * thrown.
     *
     * What is **not** policed here is conformance: RFC 5280 §4.1.2.2 asks
     * for a positive serial of at most 20 octets, and a value outside that
     * is reported by `parseCertificate` as `PKI_DIAG_SERIAL_NOT_POSITIVE` or
     * `PKI_DIAG_SERIAL_TOO_LONG` when the certificate is read back — which
     * is the one place in the library that judges conformance.
     *
     * A serial should carry at least 64 bits of entropy (CA/Browser Forum
     * BR §7.1): generate it with `crypto.getRandomValues`, not a counter.
     */
    readonly serialNumber: bigint | Uint8Array;
    /**
     * The issuer name, as the **DER of the issuing certificate's subject**.
     * For a self-signed certificate, leave it out and `subject` is used.
     */
    readonly issuerDer?: Uint8Array | undefined;
    /** The issuer name to build, when there is no certificate to copy it from. Ignored when `issuerDer` is given. */
    readonly issuer?: NameDescription | undefined;
    /** The subject name to build. */
    readonly subject: NameDescription;
    /** The subject name as DER, used instead of `subject` when given. */
    readonly subjectDer?: Uint8Array | undefined;
    /** Start of validity, in epoch milliseconds. */
    readonly notBefore: number;
    /** End of validity, in epoch milliseconds. */
    readonly notAfter: number;
    /**
     * The subject's public key, as a complete SubjectPublicKeyInfo in DER —
     * `new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))`.
     *
     * One line in your code, and the reason `exportKey` can stay refused
     * inside pkinative in every version.
     */
    readonly subjectPublicKey: Uint8Array;
    /** The extensions, in the order they are placed. A v3 certificate is produced when this is non-empty. */
    readonly extensions?: readonly ExtensionDescription[] | undefined;
}

/** What a PKCS#10 certification request is built from. */
export interface CertificationRequestDescription {
    /** The subject name to build. */
    readonly subject: NameDescription;
    /** The subject name as DER, used instead of `subject` when given. */
    readonly subjectDer?: Uint8Array | undefined;
    /**
     * The requester's public key, as a complete SubjectPublicKeyInfo in DER.
     * It must be the public half of the key that signs the request — a CSR
     * is a proof of possession, and a mismatch makes one that verifies
     * nowhere.
     */
    readonly subjectPublicKey: Uint8Array;
    /**
     * Extensions to request, carried in the `extensionRequest` attribute
     * (PKCS#9, OID 1.2.840.113549.1.9.14). A CA is free to ignore them.
     */
    readonly extensions?: readonly ExtensionDescription[] | undefined;
}
