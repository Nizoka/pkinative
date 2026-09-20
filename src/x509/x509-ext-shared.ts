/**
 * pkinative — Extension decoder helpers
 * =====================================
 * What the extension decoders share: their input, the error of a value that
 * does not match its ASN.1 definition, context-tagged field lists, counters
 * and named bit lists.
 *
 * @module x509/x509-ext-shared
 */

import type { Asn1Context } from '../asn1/asn1-context.js';
import { _readInteger } from '../asn1/asn1-read.js';
import { TAG_SEQUENCE, tagLabel } from '../asn1/asn1-tags.js';
import { byteView } from '../core/bytes.js';
import { namedBitsTrailingZeroDiagnostic } from '../core/pki-diagnostics.js';
import type { Asn1Node, BitString } from '../types/asn1-types.js';
import type { PkiCertificateError } from '../types/pki-errors.js';
import type { ExtensionBase } from '../types/x509-types.js';
import { certificateError, expectUniversalField } from './x509-fields.js';

export const MALFORMED = 'PKI_X509_EXTENSION_MALFORMED';

/** One extension value to decode. */
export interface ExtensionInput {
    /** The decoded extnValue. */
    readonly node: Asn1Node;
    readonly ctx: Asn1Context;
    readonly path: string;
    readonly oid: string;
    readonly critical: boolean;
    readonly valueDer: Uint8Array;
}

/** @internal */
export function baseOf(input: ExtensionInput): ExtensionBase {
    return { oid: input.oid, critical: input.critical, valueDer: input.valueDer };
}

/** @internal */
export function malformed(path: string, offset: number, why: string): PkiCertificateError {
    return certificateError(MALFORMED, path, offset, why);
}

/** @internal */
export function expectSequence(node: Asn1Node | undefined, path: string, parentOffset: number): Asn1Node {
    return expectUniversalField(node, TAG_SEQUENCE, path, MALFORMED, parentOffset);
}

/**
 * A SEQUENCE SIZE (1..MAX): refuse an empty one.
 *
 * @internal
 */
export function expectNonEmpty(seq: Asn1Node, path: string, what: string): void {
    if (seq.children.length === 0) throw malformed(path, seq.offset, `holds no ${what}; the extension requires at least one`);
}

/**
 * Context-tagged optional fields `[0]` to `[maxTag]`, each at most once and
 * in increasing order, indexed by tag number.
 *
 * @internal
 */
export function contextFields(children: readonly Asn1Node[], maxTag: number, path: string): Array<Asn1Node | undefined> {
    const fields: Array<Asn1Node | undefined> = new Array<Asn1Node | undefined>(maxTag + 1).fill(undefined);
    let last = -1;
    for (const child of children) {
        if (child.tagClass !== 'context' || child.tagNumber > maxTag || child.tagNumber <= last) {
            throw malformed(path, child.offset, `holds ${tagLabel(child.tagClass, child.tagNumber)} where only [0] to [${maxTag}], once each and in order, may appear`);
        }
        fields[child.tagNumber] = child;
        last = child.tagNumber;
    }
    return fields;
}

/**
 * A non-negative INTEGER that fits a number: SkipCerts, BaseDistance, a path length.
 *
 * @internal
 */
export function readCount(node: Asn1Node, ctx: Asn1Context, path: string): number {
    const value = _readInteger(node, ctx);
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw malformed(path, node.offset, `is ${String(value)}; expected an integer from 0 to 2^53 − 1`);
    }
    return Number(value);
}

function bitAt(view: DataView, index: number): number {
    return (view.getUint8(index >> 3) >> (7 - (index & 7))) & 1;
}

/**
 * The names of the bits set in a named bit list. A set bit beyond the named
 * ones is malformed; a trailing zero bit, which DER removes, is a diagnostic.
 *
 * @internal
 */
export function readNamedBits<T extends string>(bits: BitString, names: readonly T[], ctx: Asn1Context, path: string, offset: number): T[] {
    const total = bits.bytes.length * 8 - bits.unusedBits;
    // index < total <= bytes.length * 8, so index >> 3 is always in range.
    const view = byteView(bits.bytes);
    const set: T[] = [];
    for (let i = 0; i < total; i++) {
        if (bitAt(view, i) === 0) continue;
        const name = names[i];
        if (name === undefined) throw malformed(path, offset, `sets bit ${i}, beyond the ${names.length} named bits`);
        set.push(name);
    }
    if (total > 0 && bitAt(view, total - 1) === 0) ctx.emitter.emit(namedBitsTrailingZeroDiagnostic(path, offset));
    return set;
}
