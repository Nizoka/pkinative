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
 * ## Which test a message belongs to
 *
 * **The signer says, not the file name.** The message names are close to the
 * certificate names and not equal to them: `SignedMissingCRLTest1.eml` belongs
 * to `InvalidMissingCRLTest1EE.crt`, `SignedValidSignaturesTest1.eml` and
 * `SignedAllCertificatesSamePolicyTest1.eml` both to
 * `ValidCertificatePathTest1EE.crt`, and fourteen more differ in case or in a
 * word. A hand-written table of those pairs would be a transcription of the
 * archive; the `SignerIdentifier` inside each message already names the
 * certificate that signed it, so the link is read from there, and a message
 * whose signer matches no end-entity certificate — or two — fails the gate.
 *
 * @module scripts/lib/pkits-smime
 */

import type * as Pki from '../../src/index.js';

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

// ── Scoring ──────────────────────────────────────────────────────────

/**
 * The PKITS tests whose end-entity certificate the signer names.
 *
 * `issuerAndSerialNumber` is matched on the encoded issuer and the serial's
 * content octets, never on a rendering; `subjectKeyIdentifier` on the
 * certificate's own extension. Exactly one match is the only answer the
 * runner accepts — none means the message is signed by a certificate PKITS
 * does not ship as a test, two that the link is ambiguous.
 *
 * @param pki   The built package.
 * @param sid   The signer's identifier, as `parseSignedData` read it.
 * @param tests The end-entity certificates, by test name (`readPkits`).
 * @returns Every matching test name, in the map's order.
 */
export function testsOfSigner(pki: typeof Pki, sid: Pki.SignerIdentifier, tests: ReadonlyMap<string, Pki.Certificate>): string[] {
    const matches: string[] = [];
    for (const [name, certificate] of tests) {
        const hit = sid.kind === 'issuerAndSerialNumber'
            ? sameBytes(certificate.issuer.der, sid.issuer.der) && sameBytes(certificate.serialNumber.bytes, sid.serialNumber.bytes)
            : sameBytes(pki.getExtension(certificate, 'subjectKeyIdentifier')?.keyIdentifier, sid.keyIdentifier);
        if (hit) matches.push(name);
    }
    return matches;
}

/** Where a reason came from: the signer itself, or the chain of its certificate. */
export type ReasonLayer = 'cms' | 'chain';

/**
 * Which layer of `verifySignedData` raised a reason, read from its path.
 *
 * `verifySignedData` puts every reason of a signer's chain under
 * `signerInfos[i].chain`; everything else about a signer — its attributes,
 * its algorithms, the digest, the signature, the certificate it committed to —
 * is the CMS layer. The distinction is the whole of L8's first claim: the CMS
 * layer must find every PKITS message intact, whatever its path says.
 *
 * @param path A `PkiReason.path` from a `VerifySignedDataReport`.
 * @returns `'chain'` for a reason under a signer's chain, `'cms'` otherwise.
 */
export function reasonLayer(path: string): ReasonLayer {
    return /^signerInfos\[\d+\]\.chain(?:[.[]|$)/.test(path) ? 'chain' : 'cms';
}

/**
 * The chain reasons of a message that the path verdict of its own test does
 * not give.
 *
 * L8's second claim is that a message is refused **for a reason its path is
 * refused for**. The comparison is on the *set* of codes, not on the list,
 * for two measured reasons: the candidate bag L7 hands the path builder holds
 * cross-certificates a message does not carry, so a path search there can
 * record a `PKI_REASON_SIGNATURE_INVALID` detour a message never takes; and a
 * list supplied twice — carried by the message and supplied by the caller —
 * is reported twice. Neither changes what the verdict is about.
 *
 * @param message The codes of the message's chain reasons, in any order.
 * @param path    The codes L7 measured for the linked test.
 * @returns Each code the message gives and the path does not, once, sorted.
 */
export function reasonsBeyondPath(message: readonly string[], path: readonly string[]): string[] {
    const known = new Set(path);
    return [...new Set(message)].filter((code) => !known.has(code)).sort();
}

function sameBytes(a: Uint8Array | undefined, b: Uint8Array): boolean {
    if (a?.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}
