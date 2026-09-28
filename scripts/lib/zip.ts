/**
 * pkinative — a ZIP reader for the conformance corpora
 * ====================================================
 * NIST publishes PKITS as a ZIP archive and nothing else, so reading one is
 * the price of that corpus. This is the whole of it: about a hundred lines
 * over `node:zlib`, in `scripts/` where `node:` imports are allowed and where
 * nothing the engine ships can reach it.
 *
 * It is not a general ZIP library and does not want to be. What it does, it
 * does the strict way, because the argument for reading an archive at all is
 * that the archive is pinned — and a reader that could be confused would make
 * the pin meaningless.
 *
 * ## Four rules, each of them a known attack
 *
 * **The central directory is the truth.** Every entry is read from there, and
 * the local header is checked to agree on the name. A ZIP whose two directories
 * disagree is read one way by one tool and another way by another, which is how
 * one file is scanned and a different one extracted.
 *
 * **Nothing is trusted to fit.** Every offset and length is checked against the
 * buffer before it is used, so a truncated or doctored archive ends in a message
 * and never in a read past the end.
 *
 * **A name is a name, not a path.** `..`, a leading separator and a backslash
 * are all refused: an extractor that honours them writes outside the directory
 * it was pointed at, which is zip-slip.
 *
 * **Only stored and deflated.** Every other method — and Zip64, which this
 * refuses rather than half-reads — is a shape this reader would be guessing at.
 *
 * @module scripts/lib/zip
 */

import { inflateRawSync } from 'node:zlib';

/** One file of an archive, already decompressed. */
export interface ZipEntry {
    /** The name as the central directory spells it, `/` separated. */
    readonly name: string;
    readonly bytes: Uint8Array;
}

const SIGNATURE_EOCD = 0x06054b50;
const SIGNATURE_CENTRAL = 0x02014b50;
const SIGNATURE_LOCAL = 0x04034b50;
/** The end-of-central-directory record is 22 bytes plus a comment of at most 65 535. */
const MAX_EOCD_SEARCH = 22 + 0xffff;

class ZipError extends Error {}

const fail = (message: string): never => {
    throw new ZipError(`zip: ${message}`);
};

/**
 * Every file of a ZIP archive, decompressed, in central-directory order.
 *
 * @param archive The whole archive.
 * @returns One entry per file; directories, which carry no content, are absent.
 * @throws {Error} On anything this reader will not guess at — a bad signature,
 *   an offset past the end, an unsupported compression method, Zip64, a local
 *   header naming a different file, or a name that is a path.
 */
export function readZip(archive: Uint8Array): readonly ZipEntry[] {
    const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
    const u32 = (at: number): number => {
        if (at < 0 || at + 4 > archive.length) fail(`a 4-byte field at ${String(at)} runs past the end of the archive`);
        return view.getUint32(at, true);
    };
    const u16 = (at: number): number => {
        if (at < 0 || at + 2 > archive.length) fail(`a 2-byte field at ${String(at)} runs past the end of the archive`);
        return view.getUint16(at, true);
    };

    // The end-of-central-directory record, found by scanning backwards: it is
    // the only structure whose position is not written down anywhere.
    let eocd = -1;
    const floor = Math.max(0, archive.length - MAX_EOCD_SEARCH);
    for (let at = archive.length - 22; at >= floor; at -= 1) {
        if (u32(at) === SIGNATURE_EOCD) { eocd = at; break; }
    }
    if (eocd < 0) fail('no end-of-central-directory record — this is not a ZIP archive, or it is truncated');

    const count = u16(eocd + 10);
    const directoryAt = u32(eocd + 16);
    // 0xffff and 0xffffffff are Zip64's "look elsewhere" markers. Reading them
    // literally would walk into the middle of the file, so they are refused.
    if (count === 0xffff || directoryAt === 0xffffffff || u32(eocd + 12) === 0xffffffff) {
        fail('the archive uses Zip64, which this reader does not implement');
    }
    if (directoryAt >= archive.length) fail('the central directory starts past the end of the archive');

    const out: ZipEntry[] = [];
    let at = directoryAt;
    for (let index = 0; index < count; index += 1) {
        if (u32(at) !== SIGNATURE_CENTRAL) fail(`entry ${String(index)} has no central-directory signature at ${String(at)}`);
        const method = u16(at + 10);
        const compressedSize = u32(at + 20);
        const uncompressedSize = u32(at + 24);
        const nameLength = u16(at + 28);
        const extraLength = u16(at + 30);
        const commentLength = u16(at + 32);
        const localAt = u32(at + 42);
        if (at + 46 + nameLength > archive.length) fail(`entry ${String(index)} has a name running past the end of the archive`);
        const name = _text(archive.subarray(at + 46, at + 46 + nameLength));
        at += 46 + nameLength + extraLength + commentLength;

        // A directory entry is a name ending in `/` with no content.
        if (name.endsWith('/')) continue;
        _assertPlainName(name, index);
        if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localAt === 0xffffffff) {
            fail(`entry ${name} uses Zip64 sizes, which this reader does not implement`);
        }
        if (u32(localAt) !== SIGNATURE_LOCAL) fail(`entry ${name} has no local header at ${String(localAt)}`);

        // The two directories must agree on the name. One that scans the
        // central entry and extracts the local one is how a file is checked and
        // a different file written.
        const localNameLength = u16(localAt + 26);
        const localExtraLength = u16(localAt + 28);
        if (localAt + 30 + localNameLength > archive.length) fail(`entry ${name} has a local name running past the end of the archive`);
        const localName = _text(archive.subarray(localAt + 30, localAt + 30 + localNameLength));
        if (localName !== name) fail(`entry ${name} is called ${localName} by its local header — the two directories disagree`);

        const start = localAt + 30 + localNameLength + localExtraLength;
        if (start + compressedSize > archive.length) fail(`entry ${name} has content running past the end of the archive`);
        const compressed = archive.subarray(start, start + compressedSize);

        let bytes: Uint8Array;
        if (method === 0) {
            bytes = compressed;
        } else if (method === 8) {
            try {
                bytes = new Uint8Array(inflateRawSync(compressed));
            } catch (error) {
                return fail(`entry ${name} does not inflate: ${String((error as Error).message)}`);
            }
        } else {
            return fail(`entry ${name} uses compression method ${String(method)}; only stored (0) and deflate (8) are read here`);
        }
        // The declared size is a claim, and a reader that ignored it would hand
        // back whatever the stream produced — including a decompression bomb.
        if (bytes.length !== uncompressedSize) {
            fail(`entry ${name} inflates to ${String(bytes.length)} bytes and declares ${String(uncompressedSize)}`);
        }
        out.push({ name, bytes });
    }
    return out;
}

/** ZIP names are CP437 or UTF-8; every name in a pinned corpus is ASCII. */
function _text(bytes: Uint8Array): string {
    let out = '';
    for (const byte of bytes) out += String.fromCharCode(byte);
    return out;
}

/** A name that is a name: no traversal, no absolute path, no backslash. */
function _assertPlainName(name: string, index: number): void {
    if (name === '') fail(`entry ${String(index)} has an empty name`);
    if (name.includes('\\')) fail(`entry ${name} uses a backslash, which some extractors read as a separator`);
    if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) fail(`entry ${name} is an absolute path`);
    if (name.split('/').includes('..')) fail(`entry ${name} climbs out of the archive`);
    // eslint-disable-next-line no-control-regex -- a NUL truncates the name in a C extractor and not in this one.
    if (/[\u0000-\u001f]/.test(name)) fail(`entry ${name} holds a control character`);
}
