/**
 * pkinative — RFC 3161 timestamp requests
 * =======================================
 * The question a timestamp authority is asked, in both directions: written by
 * `createTimeStampRequest`, and read back by the verifier so that a token can
 * be held to the request it claims to answer.
 *
 * pkinative does not send the request. RFC 3161 §3 defines four transports and
 * none of them belongs in a library with no I/O: the caller POSTs these bytes
 * as `application/timestamp-query` and hands back what comes in response.
 *
 * @module cms/tsp-request
 */

import { createAsn1Context } from '../asn1/asn1-context.js';
import { decodeWithContext } from '../asn1/asn1-decode.js';
import { encodeBoolean, encodeInteger, encodeObjectIdentifier, encodeOctetString, encodeSequence, encodeTlv } from '../asn1/asn1-encode.js';
import { _readObjectIdentifier } from '../asn1/asn1-oid.js';
import { _readBoolean, _readInteger } from '../asn1/asn1-read.js';
import { encodeAlgorithmIdentifier } from '../build/build-structures.js';
import { PkiCmsError, PkiError } from '../types/pki-errors.js';
import type { PkiParseOptions } from '../types/pki-types.js';
import type { MessageImprint } from '../types/tsp-types.js';
import { _readMessageImprint, _tspError } from './tsp-tst-info.js';

/**
 * The digests a new request may stamp.
 *
 * SHA-1 is not among them. A timestamp binds a time to a hash, and a hash
 * whose collisions are practical binds that time to every document with the
 * same digest — one token covering two contracts. pkinative still **reads**
 * SHA-1 imprints in existing tokens; it will not write a new one.
 */
export type TimeStampHashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

const HASHES: Readonly<Record<TimeStampHashAlgorithm, { readonly oid: string; readonly bytes: number }>> = /*#__PURE__*/ Object.freeze({
    'SHA-256': { oid: '2.16.840.1.101.3.4.2.1', bytes: 32 },
    'SHA-384': { oid: '2.16.840.1.101.3.4.2.2', bytes: 48 },
    'SHA-512': { oid: '2.16.840.1.101.3.4.2.3', bytes: 64 },
});

/**
 * The explicit NULL a digest `AlgorithmIdentifier` carries in a request.
 *
 * RFC 5754 §2 says to omit the parameters and to accept both forms. Timestamp
 * authorities, like OCSP responders, are less forgiving than that sentence,
 * and OpenSSL's own `ts -query` writes NULL — so this writes what is accepted
 * everywhere rather than what is preferred on paper, for the same reason
 * `createOcspRequest` does.
 */
const NULL_PARAMETERS = /*#__PURE__*/ encodeTlv('universal', 5, false, new Uint8Array(0));

/** Options of {@link createTimeStampRequest}. */
export interface CreateTimeStampRequestOptions {
    /** The digest `hash` was computed with. SHA-256 by default. */
    readonly hashAlgorithm?: TimeStampHashAlgorithm | undefined;
    /**
     * A nonce (RFC 3161 §2.4.1), which the TSA must echo in the token.
     *
     * Without one, the only thing that says a response answers **this** request
     * is its time, and an attacker who can replay yesterday's response for the
     * same hash is indistinguishable from the TSA. Supply at least 64 random
     * bits; pkinative generates none.
     */
    readonly nonce?: bigint | undefined;
    /** The TSA policy to issue under; the TSA's default when absent. The token must then carry it. */
    readonly policy?: string | undefined;
    /**
     * Ask the TSA to include its certificate in the token. `true` by default,
     * which is **not** the grammar's default: with `certReq` FALSE the TSA must
     * not send its certificate, and the caller is left to find it — so the
     * helpful default is written out, which DER allows because it is not the
     * DEFAULT value.
     */
    readonly certReq?: boolean | undefined;
}

/**
 * Build an RFC 3161 `TimeStampReq` for a hash.
 *
 * ```ts
 * const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', document));
 * const nonce = new DataView(crypto.getRandomValues(new Uint8Array(8)).buffer).getBigUint64(0);
 * const body = createTimeStampRequest(hash, { nonce });
 * const response = await fetch(tsaUrl, { method: 'POST', headers: { 'content-type': 'application/timestamp-query' }, body });
 * ```
 *
 * It takes the **hash**, not the data: a timestamp is over a digest, the data
 * may be gigabytes, and for a signature timestamp it is the hash of the
 * signature value (RFC 3161 Appendix A) that is stamped, which only the caller
 * knows to compute.
 *
 * @param hash    The digest to stamp, computed with `hashAlgorithm`.
 * @param options See {@link CreateTimeStampRequestOptions}.
 * @returns The DER `TimeStampReq`, ready to POST.
 * @throws {PkiError} `PKI_INVALID_INPUT` when `hash` is not bytes or `nonce`
 *   not a bigint; `PKI_INVALID_OPTION` for an unsupported `hashAlgorithm`;
 *   `PKI_API_MISUSE` when the hash is not as long as the algorithm's output.
 * @throws {PkiEncodingError} `PKI_OID_INVALID` for a malformed `policy`.
 */
export function createTimeStampRequest(hash: Uint8Array, options?: CreateTimeStampRequestOptions): Uint8Array {
    if (!(hash instanceof Uint8Array)) {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: the hash to timestamp must be a Uint8Array — hash the data first, with the algorithm you name in hashAlgorithm');
    }
    const name = options?.hashAlgorithm ?? 'SHA-256';
    const algorithm = HASHES[name];
    if (typeof algorithm !== 'object') {
        throw new PkiError('PKI_INVALID_OPTION', `pkinative: hashAlgorithm must be 'SHA-256', 'SHA-384' or 'SHA-512', got ${String(name)} — SHA-1 is not offered for new timestamps, because a collision would let one token cover two documents`);
    }
    if (hash.length !== algorithm.bytes) {
        throw new PkiError('PKI_API_MISUSE', `pkinative: a ${name} hash is ${String(algorithm.bytes)} octets and this one is ${String(hash.length)} — pass the digest itself, computed with the algorithm you name`);
    }
    const nonce = options?.nonce;
    if (nonce !== undefined && typeof nonce !== 'bigint') {
        throw new PkiError('PKI_INVALID_INPUT', 'pkinative: the timestamp nonce must be a bigint of random bits — pkinative generates none, so this is yours to produce with crypto.getRandomValues');
    }

    const fields: Uint8Array[] = [
        encodeInteger(1n),
        encodeSequence([encodeAlgorithmIdentifier(algorithm.oid, NULL_PARAMETERS), encodeOctetString(hash)]),
    ];
    if (options?.policy !== undefined) fields.push(encodeObjectIdentifier(options.policy));
    if (nonce !== undefined) fields.push(encodeInteger(nonce));
    // certReq BOOLEAN DEFAULT FALSE: TRUE is written, FALSE is omitted — the
    // only encoding DER allows for each.
    if (options?.certReq !== false) fields.push(encodeBoolean(true));
    return encodeSequence(fields);
}

/** What a verifier holds a token to: the parts of a request that a response must echo. */
export interface _TimeStampRequestDetails {
    readonly messageImprint: MessageImprint;
    readonly policy: string | undefined;
    readonly nonce: bigint | undefined;
    readonly certReq: boolean;
}

/**
 * Read back a `TimeStampReq` — the caller's own request, which a token must
 * answer.
 *
 * Internal because its one use is `verifyTimeStampToken`: a library that
 * issued tokens would need it public, and pkinative does not issue tokens.
 * Extensions are read past rather than decoded — a request's extensions are
 * the TSA's concern, and nothing a client checks depends on them.
 *
 * @internal
 */
export function _parseTimeStampRequest(der: Uint8Array, options?: PkiParseOptions): _TimeStampRequestDetails {
    const ctx = createAsn1Context({ ...options, encodingRules: 'der' });
    const root = decodeWithContext(der, ctx, false);
    const path = 'TimeStampReq';
    if (root.tagClass !== 'universal' || root.tagNumber !== 16) throw _tspError(path, root.offset, 'is not a SEQUENCE');
    const [versionNode, imprintNode, ...rest] = root.children;
    if (versionNode?.tagClass !== 'universal' || versionNode.tagNumber !== 2) throw _tspError(`${path}.version`, root.offset, 'is missing or not an INTEGER');
    if (_readInteger(versionNode, ctx) !== 1n) {
        throw new PkiCmsError('PKI_CMS_VERSION_UNSUPPORTED', `pkinative: ${path}.version is not 1, the only version RFC 3161 §2.4.1 defines`, `${path}.version`, versionNode.offset);
    }
    const messageImprint = _readMessageImprint(imprintNode, ctx, `${path}.messageImprint`, root.offset);

    let policy: string | undefined;
    let nonce: bigint | undefined;
    let certReq = false;
    // 0 = reqPolicy, 1 = nonce, 2 = certReq, 3 = extensions [0] — once each, in order.
    let last = -1;
    for (const field of rest) {
        const slot = field.tagClass === 'universal'
            ? (field.tagNumber === 6 ? 0 : field.tagNumber === 2 ? 1 : field.tagNumber === 1 ? 2 : -1)
            : field.tagClass === 'context' && field.tagNumber === 0 ? 3 : -1;
        if (slot <= last) throw _tspError(path, field.offset, 'holds a field TimeStampReq does not define, or holds its fields twice or out of order');
        last = slot;
        if (slot === 0) policy = _readObjectIdentifier(field, ctx);
        if (slot === 1) nonce = _readInteger(field, ctx);
        if (slot === 2) certReq = _readBoolean(field, ctx);
    }
    return Object.freeze({ messageImprint, policy, nonce, certReq });
}
