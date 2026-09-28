/**
 * pkinative — RFC 6960 OCSP requests
 * ==================================
 * Build the bytes you POST to a responder.
 *
 * The part worth reading is what a `CertID` identifies the issuer **by**: not
 * its name, but hashes of its encoded name and of its public key bits. That
 * is RFC 6960 §4.1.1's own choice, and it has two consequences this module has
 * to get exactly right or the responder answers about a different certificate.
 *
 * `issuerNameHash` is over the **encoded `Name`**, tag and length included —
 * `issuer.subject.der`, never a rendering and never the content octets alone.
 * `issuerKeyHash` is over the `subjectPublicKey` BIT STRING's **content
 * without its unused-bits octet**, not over the whole SubjectPublicKeyInfo.
 * Hashing the SPKI instead is the single most common OCSP client bug, and it
 * produces a request a responder answers `unknown` to — which a careless
 * client then reports as "not revoked".
 *
 * SHA-1 is the default because RFC 6960 §4.3 makes it mandatory for
 * responders and nothing else is universally supported. It is **not** used as
 * a security primitive here: these hashes are identifiers over public data,
 * and a collision buys an attacker the right to ask a question about a
 * certificate they could have named directly.
 *
 * @module revocation/ocsp-request
 */

import { encodeOctetString, encodeSequence, encodeTlv } from '../asn1/asn1-encode.js';
import { encodeAlgorithmIdentifier } from '../build/build-structures.js';
import { computeKeyIdentifier } from '../hash/key-identifier.js';
import { sha1 } from '../hash/sha1.js';
import { sha256 } from '../hash/sha256.js';
import { PkiError } from '../types/pki-errors.js';
import type { Certificate } from '../types/x509-types.js';

/** The digests RFC 6960 §4.3 lets a `CertID` use. */
export type OcspHashAlgorithm = 'SHA-1' | 'SHA-256';

const HASH_OID: Readonly<Record<OcspHashAlgorithm, string>> = Object.freeze({
    'SHA-1': '1.3.14.3.2.26',
    'SHA-256': '2.16.840.1.101.3.4.2.1',
});

/** Options of {@link createOcspRequest}. */
export interface CreateOcspRequestOptions {
    /**
     * The digest for the two issuer hashes. SHA-1 by default, because RFC 6960
     * §4.3 makes it mandatory for responders and a SHA-256 `CertID` is
     * answered `unknown` by many of them — which a client must not read as
     * "not revoked".
     */
    readonly hashAlgorithm?: OcspHashAlgorithm | undefined;
    /**
     * A nonce (RFC 6960 §4.4.1), which binds the response to this request.
     * Without one a responder may serve a cached answer, and an attacker who
     * can replay it can serve a stale "good" indefinitely. Supply your own
     * random bytes; pkinative generates none.
     */
    readonly nonce?: Uint8Array | undefined;
}

/**
 * Build a `CertID` for one certificate under one issuer.
 *
 * Exposed because a caller matching a response back to a question needs the
 * same three values, and recomputing them by hand is where the two hashes get
 * taken over the wrong bytes.
 *
 * @param certificate The certificate being asked about.
 * @param issuer      The certificate that issued it.
 * @param algorithm   The digest; SHA-1 by default.
 * @returns The encoded `CertID`.
 * @throws {PkiError} `PKI_INVALID_INPUT` when either argument is not parsed.
 */
export function encodeCertId(certificate: Certificate, issuer: Certificate, algorithm: OcspHashAlgorithm = 'SHA-1'): Uint8Array {
    assertParsed(certificate, 'certificate');
    assertParsed(issuer, 'issuer');
    const digest = algorithm === 'SHA-1' ? sha1 : sha256;
    // The encoded Name, tag and length included. RFC 6960 §4.1.1: "the hash of
    // the issuer's distinguished name (DN)", and the DN is the encoded field.
    const nameHash = digest(issuer.subject.der);
    // The BIT STRING's content WITHOUT its unused-bits octet — not the SPKI.
    // `subjectPublicKey.bytes` is already that content in this library, and this
    // is byte for byte the RFC 5280 §4.2.1.2 key identifier: one value, named
    // once, so the two callers cannot drift into hashing different things.
    const keyHash = computeKeyIdentifier(issuer.subjectPublicKeyInfo.publicKey.bytes, algorithm);
    return encodeSequence([
        encodeAlgorithmIdentifier(HASH_OID[algorithm], NULL_PARAMETERS),
        encodeOctetString(nameHash),
        encodeOctetString(keyHash),
        encodeTlv('universal', 2, false, certificate.serialNumber.bytes),
    ]);
}

/**
 * The explicit NULL a digest `AlgorithmIdentifier` carries here.
 *
 * RFC 5754 §2 says implementations SHOULD omit the parameters for SHA
 * algorithms and MUST accept both forms. Real OCSP responders are less
 * forgiving than that sentence: the absent form is answered `unknown` by
 * enough of them that writing NULL is the interoperable choice, and an
 * `unknown` a client misreads is worse than a redundant two octets.
 */
const NULL_PARAMETERS = /*#__PURE__*/ encodeTlv('universal', 5, false, new Uint8Array(0));

/**
 * Build an OCSP request for one certificate.
 *
 * ```ts
 * const body = createOcspRequest(certificate, issuer, { nonce: crypto.getRandomValues(new Uint8Array(16)) });
 * await fetch(url, { method: 'POST', headers: { 'content-type': 'application/ocsp-request' }, body });
 * ```
 *
 * The request is **unsigned**. RFC 6960 §4.1.2 makes the signature optional,
 * almost no responder requires it, and signing would mean this library holding
 * a key — which it does not do. A responder that answers `sigRequired` is
 * telling you to sign, and that is the caller's own `signData` call plus the
 * `[0] EXPLICIT Signature` wrapper.
 *
 * @param certificate The certificate being asked about.
 * @param issuer      The certificate that issued it.
 * @param options     See {@link CreateOcspRequestOptions}.
 * @returns The encoded `OCSPRequest`, ready to POST.
 * @throws {PkiError} `PKI_INVALID_INPUT` when either certificate is not parsed,
 *   or the nonce is not bytes.
 */
export function createOcspRequest(certificate: Certificate, issuer: Certificate, options?: CreateOcspRequestOptions): Uint8Array {
    const certId = encodeCertId(certificate, issuer, options?.hashAlgorithm ?? 'SHA-1');
    const requestList = encodeSequence([encodeSequence([certId])]);

    const fields: Uint8Array[] = [requestList];
    const nonce = options?.nonce;
    if (nonce !== undefined) {
        if (!(nonce instanceof Uint8Array)) {
            throw new PkiError('PKI_INVALID_INPUT', 'pkinative: the OCSP nonce must be a Uint8Array of random bytes — pkinative generates none, so this is yours to produce with crypto.getRandomValues');
        }
        // requestExtensions [2] EXPLICIT Extensions, holding id-pkix-ocsp-nonce
        // (1.3.6.1.5.5.7.48.1.2). The nonce value is itself an OCTET STRING
        // inside the extension's OCTET STRING — two layers, and getting that
        // wrong is a nonce a responder silently ignores.
        fields.push(encodeTlv('context', 2, true, encodeSequence([
            encodeSequence([
                encodeTlv('universal', 6, false, Uint8Array.of(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02)),
                encodeOctetString(encodeOctetString(nonce)),
            ]),
        ])));
    }
    // version [0] takes its DEFAULT v1 and is omitted, as DER requires.
    return encodeSequence([encodeSequence(fields)]);
}

function assertParsed(value: unknown, what: string): void {
    if (typeof value !== 'object' || value === null || !((value as Certificate).der instanceof Uint8Array)) {
        throw new PkiError('PKI_INVALID_INPUT', `pkinative: ${what} must be a Certificate from parseCertificate(), not raw bytes`);
    }
}
