/**
 * pkinative — conformance corpora
 * ===============================
 * THE pin table of the downloaded conformance corpora: one upstream commit
 * per corpus and one SHA-256 per file, the SHA-256 living in
 * `.github/checksums/<id>-<commit>.sha256` (the setup-verapdf pattern of
 * pdfnative). scripts/fetch-corpora.ts downloads the files into
 * `test-output/corpora/` and refuses any byte that does not match;
 * scripts/validate-certs.ts reads them; the `corpus-pin-parity` rule of
 * verify-docs holds the checksum files, THIRD-PARTY-NOTICES.md and
 * docs/assets/ecosystem.json to this table. Nothing here is committed data.
 *
 * @module scripts/lib/corpora
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface CorpusFile {
    /** The file name, as listed in the checksum file. */
    readonly name: string;
    /** The path inside the upstream repository. */
    readonly path: string;
}

export interface Corpus {
    readonly id: 'x509-limbo' | 'wycheproof';
    readonly title: string;
    readonly repository: string;
    /** The upstream commit every file is read at. */
    readonly commit: string;
    readonly licence: string;
    readonly files: readonly CorpusFile[];
}

export const CORPORA: readonly Corpus[] = [
    {
        id: 'x509-limbo',
        title: 'x509-limbo',
        repository: 'https://github.com/C2SP/x509-limbo',
        commit: '118721335e675edde10015df89b138cf292d7554',
        licence: 'Apache-2.0',
        files: [{ name: 'limbo.json', path: 'limbo.json' }],
    },
    {
        id: 'wycheproof',
        title: 'Project Wycheproof',
        repository: 'https://github.com/C2SP/wycheproof',
        commit: '3fa63dd0344abb611f1fb1d77e119938603ea230',
        licence: 'Apache-2.0',
        files: ['ecdsa_secp256r1_sha256_test.json', 'ecdsa_secp384r1_sha384_test.json', 'ecdsa_secp521r1_sha512_test.json']
            .map((name) => ({ name, path: `testvectors_v1/${name}` })),
    },
];

/** The immutable download URL of one file at the pinned commit. */
export function rawUrl(corpus: Corpus, file: CorpusFile): string {
    return `${corpus.repository.replace('https://github.com/', 'https://raw.githubusercontent.com/')}/${corpus.commit}/${file.path}`;
}

/** Repository-relative path of the checksum file of a corpus. */
export function checksumPath(corpus: Corpus): string {
    return `.github/checksums/${corpus.id}-${corpus.commit}.sha256`;
}

/** `sha256sum` output: `<64 hex>  <name>` per line (a `*` before the name is allowed). */
export function parseChecksums(text: string): Map<string, string> {
    const out = new Map<string, string>();
    for (const line of text.split('\n')) {
        const m = /^([0-9a-f]{64}) [ *](\S+)\s*$/.exec(line);
        if (m) out.set(m[2], m[1]);
    }
    return out;
}

/** Where the files of a corpus are downloaded (git-ignored). */
export function corpusDir(root: string, corpus: Corpus): string {
    return join(root, 'test-output', 'corpora', corpus.id, corpus.commit);
}

export function sha256Hex(bytes: Uint8Array): string {
    return createHash('sha256').update(bytes).digest('hex');
}

export interface CorpusState {
    readonly missing: readonly string[];
    readonly mismatched: readonly string[];
}

/** Compare the downloaded files of a corpus with its checksum file. */
export function checkCorpus(root: string, corpus: Corpus): CorpusState {
    const expected = parseChecksums(readFileSync(join(root, checksumPath(corpus)), 'utf8'));
    const missing: string[] = [];
    const mismatched: string[] = [];
    for (const file of corpus.files) {
        const path = join(corpusDir(root, corpus), file.name);
        if (!existsSync(path)) missing.push(file.name);
        else if (sha256Hex(readFileSync(path)) !== expected.get(file.name)) mismatched.push(file.name);
    }
    return { missing, mismatched };
}

/** True when every file of every corpus is downloaded and matches its pin. */
export function corporaReady(root: string): boolean {
    return CORPORA.every((corpus) => {
        const state = checkCorpus(root, corpus);
        return state.missing.length === 0 && state.mismatched.length === 0;
    });
}
