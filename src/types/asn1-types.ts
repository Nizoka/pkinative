/**
 * pkinative — ASN.1 types
 * =======================
 * The decoded shape of ITU-T X.690 values. Nodes are immutable and hold
 * zero-copy views of the caller's input: the caller must not mutate the
 * bytes it decoded while it holds the nodes (pass `data.slice()` to decouple).
 *
 * @module types/asn1-types
 */

import type { PkiParseOptions } from './pki-types.js';

/** The class bits of an identifier octet (X.690 §8.1.2.2). */
export type TagClass = 'universal' | 'application' | 'context' | 'private';

/** One decoded tag-length-value, with its exact position in the input. */
export interface Asn1Node {
    /** The two leading bits of the identifier octet. `'universal'` is a type X.680 defines; anything else is an implicit or explicit tag, whose meaning its context decides. */
    readonly tagClass: TagClass;
    /** The tag number. Under `'universal'` it names the type — 2 INTEGER, 4 OCTET STRING, 6 OBJECT IDENTIFIER, 16 SEQUENCE, 17 SET. */
    readonly tagNumber: number;
    /** Whether the value is built from other values (bit 6 of the identifier octet): `children` is populated exactly when this is true. */
    readonly constructed: boolean;
    /** Absolute offset of the identifier octet in the decoded input. */
    readonly offset: number;
    /** Identifier and length octets (the `0x80` octet included for the indefinite form). */
    readonly headerLength: number;
    /** Content octets, excluding the end-of-contents marker of the indefinite form. */
    readonly contentLength: number;
    /** True only for a BER indefinite-length value; always false under DER. */
    readonly indefinite: boolean;
    /** The whole encoding of this value, exactly as it appears in the input. */
    readonly bytes: Uint8Array;
    /** The content octets (for a constructed value, the concatenated encodings of its children). */
    readonly content: Uint8Array;
    /** The decoded children of a constructed value; empty for a primitive value. */
    readonly children: readonly Asn1Node[];
}

/** Options of `decodeAsn1` and `decodeAsn1Sequence`. */
export interface DecodeAsn1Options extends PkiParseOptions {
    /**
     * Accept bytes after the outermost value (`decodeAsn1` only). Off by default:
     * trailing bytes are an ambiguity unless the container defines them.
     */
    readonly allowTrailingData?: boolean | undefined;
}

/** A BIT STRING: the octets and the number of unused bits in the last one (0–7). */
export interface BitString {
    /** The octets, most significant bit first. The last `unusedBits` bits of the final octet are padding, not data. */
    readonly bytes: Uint8Array;
    /** How many bits of the final octet are padding, 0 to 7. Under DER every one of them is zero. */
    readonly unusedBits: number;
}

/** The character string types pkinative decodes. */
export type Asn1StringType = 'utf8' | 'numeric' | 'printable' | 'teletex' | 'ia5' | 'visible' | 'universal' | 'bmp';

/** A decoded character string with its original content octets. */
export interface Asn1String {
    /** Which of the eight string types it was encoded as — the charset that decided how `raw` became `value`. */
    readonly stringType: Asn1StringType;
    /** The decoded text. Attacker-controlled: escape it before displaying it, and use `formatDistinguishedName` for a name. */
    readonly value: string;
    /** The content octets before decoding, for a comparison by bytes. */
    readonly raw: Uint8Array;
}

/** The two time types of X.680. */
export type TimeType = 'UTCTime' | 'GeneralizedTime';

/** A decoded time: the instant, and the text it was decoded from. */
export interface PkiTime {
    /** Which type it was encoded as. RFC 5280 requires UTCTime through 2049 and GeneralizedTime from 2050. */
    readonly type: TimeType;
    /** Milliseconds since 1970-01-01T00:00:00Z (negative before 1970). */
    readonly epochMilliseconds: number;
    /** The time exactly as encoded, e.g. `250101000000Z`. */
    readonly text: string;
}

/** Options of `readString`: the type of an implicitly tagged string. */
export interface ReadStringOptions extends PkiParseOptions {
    /** Required when the node carries a non-universal (implicit) tag. */
    readonly stringType?: Asn1StringType | undefined;
}

/** Options of `readTime`: the type of an implicitly tagged time. */
export interface ReadTimeOptions extends PkiParseOptions {
    /** Required when the node carries a non-universal (implicit) tag. */
    readonly timeType?: TimeType | undefined;
}
