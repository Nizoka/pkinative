/**
 * pkinative — ECDSA signature conversion
 * ======================================
 * X.509 carries an ECDSA signature as a DER `Ecdsa-Sig-Value ::= SEQUENCE {
 * r INTEGER, s INTEGER }` (RFC 5480 §2.2). Web Crypto takes it as raw
 * `r ‖ s`, each fixed at the curve's coordinate size (IEEE P1363). Nothing
 * converts between them for you, so this does.
 *
 * It touches only public data — a signature is public by definition — so it
 * is legal TypeScript cryptography under SECURITY.md §Cryptographic
 * Implementation Scope: there is no key here, no secret, and no arithmetic
 * beyond copying bytes.
 *
 * It is also where a lenient converter becomes a vulnerability, which is why
 * this one is strict. Wycheproof's `ecdsa_*` suites exist almost entirely to
 * catch converters that accept a non-minimal INTEGER, a negative r, a
 * trailing byte after the SEQUENCE, or a value longer than the curve —
 * every one of which lets an attacker present the same signature in several
 * encodings. Each is refused here, and the corpus is already pinned.
 *
 * @module crypto/crypto-signature
 */

/**
 * Identifier **octets**, not tag numbers.
 *
 * `asn1-tags.ts` holds tag numbers — `TAG_SEQUENCE` is 16 — because that is
 * what a decoded node carries. This module reads raw bytes, where a
 * constructed universal SEQUENCE is `0x30`: the tag number with the
 * constructed bit set. The two happen to coincide for INTEGER (`0x02`),
 * which is exactly why mixing them up is worth naming here rather than
 * importing a constant that means something else.
 */
const SEQUENCE_OCTET = 0x30;
const INTEGER_OCTET = 0x02;

/**
 * Convert a DER `Ecdsa-Sig-Value` to raw `r ‖ s` of `2 × size` bytes.
 *
 * Returns `null` rather than throwing, for every malformed input: a
 * signature that cannot be read is not valid, and a verifier that returns
 * "no" is safer than one whose exception a caller may swallow into a
 * success path. The caller turns `null` into `false`.
 *
 * Decoding is done here rather than through `decodeAsn1` on purpose. The
 * grammar is six lines, it must refuse things the general decoder has no
 * reason to care about, and keeping it here means a bundle that verifies
 * signatures does not ship the ASN.1 decoder.
 *
 * @param der The signature octets exactly as the certificate carries them.
 * @param size The curve's coordinate size in bytes (32, 48 or 66).
 * @returns `r ‖ s`, or `null` when `der` is not a canonical Ecdsa-Sig-Value.
 */
export function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array | null {
    // The smallest legal Ecdsa-Sig-Value is `30 04 02 01 r 02 01 s`.
    // A DataView reads a byte as a number rather than `number | undefined`,
    // so every bound below is checked once, here, instead of being re-checked
    // by a `?? 0` at each access that could never fire.
    if (der.length < 8) return null;
    const view = new DataView(der.buffer, der.byteOffset, der.byteLength);
    if (view.getUint8(0) !== SEQUENCE_OCTET) return null;

    let at = 2;
    let content = view.getUint8(1);
    if (content === 0x81) {
        content = view.getUint8(2);
        at = 3;
        if (content < 0x80) return null; // non-minimal long form (CWE-436)
    } else if (content > 0x7f) {
        // Two length octets means ≥ 256 content bytes; no curve reaches that.
        return null;
    }
    if (at + content !== der.length) return null; // trailing bytes, or a short read

    const r = readInteger(der, view, at, size);
    if (r === null) return null;
    const s = readInteger(der, view, r.next, size);
    if (s === null || s.next !== der.length) return null;

    const raw = new Uint8Array(size * 2);
    raw.set(r.value, size - r.value.length);
    raw.set(s.value, size * 2 - s.value.length);
    return raw;
}

/** One INTEGER of the pair, as a non-negative big-endian value of at most `size` bytes. */
function readInteger(der: Uint8Array, view: DataView, at: number, size: number): { value: Uint8Array; next: number } | null {
    if (at + 2 > der.length || view.getUint8(at) !== INTEGER_OCTET) return null;
    const length = view.getUint8(at + 1);
    // r and s are short by construction, so only the short form is legal.
    if (length === 0 || length > 0x7f) return null;
    const start = at + 2;
    const end = start + length;
    if (end > der.length) return null;

    // DER INTEGER minimality (X.690 §8.3.2): a leading 0x00 is allowed only
    // to clear a high bit, and a leading 0xFF never is — r and s are
    // non-negative, so a negative encoding is not a small value but a
    // different signature wearing the same bytes.
    const first = view.getUint8(start);
    if ((first & 0x80) !== 0) return null;
    const padded = first === 0x00 && length > 1;
    if (padded && (view.getUint8(start + 1) & 0x80) === 0) return null;

    // length ≥ 1 and at most one octet is dropped, so the value is never
    // empty — the only bound left to check is the curve's.
    const value = der.subarray(padded ? start + 1 : start, end);
    if (value.length > size) return null;
    return { value, next: end };
}
