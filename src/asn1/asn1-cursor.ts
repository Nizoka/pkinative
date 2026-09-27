/**
 * pkinative — the lazy TLV cursor
 * ===============================
 * A reader that returns one value's *header* and where its content lies,
 * without building a node and without counting against `maxNodes`.
 *
 * It exists for one reason, and it is a real one rather than an optimisation.
 * `maxNodes` is 200 000, and a CRL entry costs three nodes, so materialising
 * `revokedCertificates` as a tree refuses any CRL past roughly 65 000 entries
 * — long before `maxInputBytes` (64 MiB) would bite. Real CRLs are larger than
 * that. A revocation list is therefore **walked**, not decoded: the cursor
 * steps over entries, the caller decodes only the small parts it needs with
 * `decodeValueAt`, and the bound that applies is the one written for the job
 * (`maxRevokedCertificates`) rather than one written for a different structure.
 *
 * It is strict in the same places the decoder is strict — a non-minimal
 * length, an indefinite length, a reserved high tag — because a cursor that
 * accepted what the decoder refuses would be a second, weaker parser for the
 * same bytes, which is exactly the ambiguity DER exists to remove.
 *
 * @module asn1/asn1-cursor
 */

import { PkiEncodingError } from '../types/pki-errors.js';
import type { TagClass } from '../types/asn1-types.js';

/** Where one value is, without its content decoded. */
export interface TlvHeader {
    readonly tagClass: TagClass;
    readonly tagNumber: number;
    readonly constructed: boolean;
    /** Offset of the identifier octet. */
    readonly offset: number;
    /** Offset of the first content octet. */
    readonly contentStart: number;
    /** Content length in octets. */
    readonly length: number;
    /** Offset just past the content — where the next value begins. */
    readonly end: number;
}

const CLASSES: readonly TagClass[] = ['universal', 'application', 'context', 'private'];

/**
 * Read the header of the value at `offset`.
 *
 * @param data   The bytes being walked.
 * @param offset Where the value's identifier octet is.
 * @param path   Where this is, for the error message.
 * @returns The header and the content's bounds.
 * @throws {PkiEncodingError} `PKI_ASN1_TRUNCATED` when the header or the content
 *   runs past the input; `PKI_ASN1_LENGTH_INVALID` for an indefinite or
 *   non-minimal length, or one wider than 6 octets; `PKI_ASN1_TAG_INVALID`
 *   for a non-minimal or oversized high tag number.
 */
export function readTlvHeader(data: Uint8Array, offset: number, path: string): TlvHeader {
    const first = data[offset];
    if (first === undefined) {
        throw new PkiEncodingError('PKI_ASN1_TRUNCATED', `pkinative: ${path} expects a value at offset ${String(offset)} and the input ends there — the structure is truncated`, offset);
    }
    const tagClass = CLASSES[(first >> 6) & 0x03] as TagClass;
    const constructed = (first & 0x20) !== 0;
    let tagNumber = first & 0x1f;
    let at = offset + 1;

    if (tagNumber === 0x1f) {
        // X.690 §8.1.2.4: a high tag number, base 128, minimally encoded.
        tagNumber = 0;
        let octets = 0;
        for (;;) {
            const byte = data[at];
            if (byte === undefined) {
                throw new PkiEncodingError('PKI_ASN1_TRUNCATED', `pkinative: ${path} has a high tag number that runs past the input`, offset);
            }
            if (octets === 0 && byte === 0x80) {
                throw new PkiEncodingError('PKI_ASN1_TAG_INVALID', `pkinative: ${path} has a high tag number whose first octet is 0x80, which is not the shortest form (X.690 §8.1.2.4.2)`, offset);
            }
            octets += 1;
            if (octets > 4) {
                throw new PkiEncodingError('PKI_ASN1_TAG_INVALID', `pkinative: ${path} has a tag number wider than four octets — no PKI structure uses one, and accepting it invites an integer overflow`, offset);
            }
            tagNumber = (tagNumber << 7) | (byte & 0x7f);
            at += 1;
            if ((byte & 0x80) === 0) break;
        }
    }

    const lengthByte = data[at];
    if (lengthByte === undefined) {
        throw new PkiEncodingError('PKI_ASN1_TRUNCATED', `pkinative: ${path} has no length octet — the structure is truncated`, offset);
    }
    at += 1;
    let length: number;
    if (lengthByte < 0x80) {
        length = lengthByte;
    } else if (lengthByte === 0x80) {
        throw new PkiEncodingError('PKI_ASN1_LENGTH_INVALID', `pkinative: ${path} uses an indefinite length, which DER forbids (X.690 §10.1) and this cursor never accepts`, offset);
    } else {
        const octets = lengthByte & 0x7f;
        if (octets > 6) {
            throw new PkiEncodingError('PKI_ASN1_LENGTH_INVALID', `pkinative: ${path} declares a length in ${String(octets)} octets; nothing this library reads is that large, and a wider length is an overflow waiting to happen`, offset);
        }
        length = 0;
        for (let i = 0; i < octets; i += 1) {
            const byte = data[at + i];
            if (byte === undefined) {
                throw new PkiEncodingError('PKI_ASN1_TRUNCATED', `pkinative: ${path} has a length that runs past the input`, offset);
            }
            if (i === 0 && byte === 0x00) {
                throw new PkiEncodingError('PKI_ASN1_LENGTH_INVALID', `pkinative: ${path} has a long-form length with a leading zero octet, which is not the shortest form (X.690 §10.1)`, offset);
            }
            length = length * 256 + byte;
        }
        if (length < 0x80) {
            throw new PkiEncodingError('PKI_ASN1_LENGTH_INVALID', `pkinative: ${path} encodes the length ${String(length)} in long form, and DER requires the short form below 128 (X.690 §10.1)`, offset);
        }
        at += octets;
    }

    const end = at + length;
    if (end > data.length) {
        throw new PkiEncodingError('PKI_ASN1_TRUNCATED', `pkinative: ${path} declares ${String(length)} content octets and only ${String(data.length - at)} remain — the structure is truncated`, offset);
    }
    return { tagClass, tagNumber, constructed, offset, contentStart: at, length, end };
}

/**
 * Walk the children of a constructed value, one header at a time.
 *
 * The generator never holds more than one header, which is the whole point:
 * a caller can step through a million CRL entries in constant memory.
 *
 * @param data   The bytes being walked.
 * @param parent The constructed value whose children to yield.
 * @param path   Where this is, for the error messages.
 * @returns Each child's header, in encoded order.
 * @throws {PkiEncodingError} As {@link readTlvHeader}, plus
 *   `PKI_ASN1_TRUNCATED` when the children do not exactly fill the parent.
 */
export function* walkChildren(data: Uint8Array, parent: TlvHeader, path: string): Generator<TlvHeader> {
    let at = parent.contentStart;
    let index = 0;
    while (at < parent.end) {
        const child = readTlvHeader(data, at, `${path}[${String(index)}]`);
        if (child.end > parent.end) {
            throw new PkiEncodingError('PKI_ASN1_TRUNCATED', `pkinative: ${path}[${String(index)}] runs past the end of its parent — the two lengths disagree, and a value that overruns its container is how one parser reads what another does not`, child.offset);
        }
        yield child;
        at = child.end;
        index += 1;
    }
}
