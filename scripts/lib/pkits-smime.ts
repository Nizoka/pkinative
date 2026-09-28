/**
 * pkinative — NIST PKITS signed messages, unwrapped
 * =================================================
 * Each of the 224 messages in the archive's `smime/` directory is a
 * `multipart/signed` e-mail (RFC 1847, RFC 8551 §3.5.3): a first body part that
 * was signed, and a second that holds the detached CMS signature in base64.
 * This module takes one apart into those two, and nothing else — MIME is a text
 * layer, and pkinative's engine does not read it.
 *
 * **Which bytes are signed was measured, not assumed.** The signed part is
 * everything after the line break that ends the opening delimiter line, up to
 * but **excluding** the line break that precedes the next delimiter: RFC 2046
 * §5.1.1 gives that line break to the delimiter, not to the content. In these
 * files the envelope ends its lines with a bare LF while the signed part uses
 * CRLF, so the rule has to be applied to whichever break is actually there — a
 * splitter that canonicalised the whole file to CRLF first would hash an extra
 * octet and report every one of the 224 signatures as a digest mismatch.
 *
 * @module scripts/lib/pkits-smime
 */

/** One signed message, taken apart. */
export interface PkitsSignedMessage {
    /** The PKITS test this message belongs to, as its file name gives it (`AllCertificatesNoPoliciesTest2`). */
    readonly test: string;
    /** The exact octets the signer hashed. */
    readonly content: Uint8Array;
    /** The detached CMS `ContentInfo`, decoded from base64. */
    readonly signature: Uint8Array;
}

const LATIN1 = new TextDecoder('latin1');

/**
 * Split one PKITS `.eml` file.
 *
 * @param name  The file name inside the archive, e.g. `smime/SignedValidBasicSelfIssuedNewWithOldTest3.eml`.
 * @param bytes The file's bytes.
 * @returns The test name, the signed content and the signature.
 * @throws {Error} When the file is not a two-part `multipart/signed` message —
 *   which, for a corpus pinned by digest, means the extraction went wrong.
 */
export function splitPkitsMessage(name: string, bytes: Uint8Array): PkitsSignedMessage {
    // latin1 maps every octet to one code unit and back, so indices into the
    // string are indices into the bytes: the content is sliced from `bytes`,
    // never re-encoded from text.
    const text = LATIN1.decode(bytes);
    const boundary = /boundary="([^"]+)"/.exec(text)?.[1];
    if (boundary === undefined) throw new Error(`pkits-smime: ${name} names no multipart boundary`);
    const delimiter = `--${boundary}`;

    const first = text.indexOf(delimiter);
    const second = text.indexOf(delimiter, first + delimiter.length);
    const closing = text.indexOf(`${delimiter}--`, second + delimiter.length);
    if (first < 0 || second < 0 || closing < 0) throw new Error(`pkits-smime: ${name} is not a two-part multipart/signed message`);

    const start = afterLineBreak(text, first + delimiter.length);
    const end = beforeLineBreak(text, second);
    const signaturePart = text.slice(afterLineBreak(text, second + delimiter.length), beforeLineBreak(text, closing));
    // The part's own headers end at the first empty line; the body is base64.
    const body = signaturePart.slice(signaturePart.search(/\r?\n\r?\n/)).replace(/\s+/g, '');
    const signature = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));

    const test = /(?:^|\/)Signed(.+)\.eml$/.exec(name)?.[1];
    if (test === undefined) throw new Error(`pkits-smime: ${name} does not follow the Signed<Test>.eml naming PKITS uses`);
    return { test, content: bytes.subarray(start, end), signature };
}

/** The index just after the line break that ends the line containing `from`. */
function afterLineBreak(text: string, from: number): number {
    const lf = text.indexOf('\n', from);
    return lf < 0 ? text.length : lf + 1;
}

/** The index of the line break (CRLF or bare LF) that ends just before `at`. */
function beforeLineBreak(text: string, at: number): number {
    if (text[at - 1] !== '\n') return at;
    return text[at - 2] === '\r' ? at - 2 : at - 1;
}
