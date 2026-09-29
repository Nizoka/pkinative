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
    /**
     * The download URL, for a corpus that is not a git repository. A document
     * has no commit to put in a raw URL; its own SHA-256 is its identity, and
     * the checksum file refuses any other bytes from this address.
     */
    readonly url?: string | undefined;
}

/**
 * Where an archive corpus comes from, and which of its files are kept.
 *
 * An archive is pinned by its own SHA-256 — which is `commit`, because that is
 * the immutable identity of the upstream state whatever form it takes. That one
 * digest pins every byte, so the set of files inside it is pinned too; the
 * per-file checksum list is the **second** pin, and it defends against a bug in
 * this project's own ZIP reader rather than against a changed archive.
 */
export interface CorpusArchive {
    readonly url: string;
    /** Prefixes inside the archive whose files are extracted; everything else is left. */
    readonly include: readonly string[];
}

export interface Corpus {
    readonly id: 'x509-limbo' | 'wycheproof' | 'pkits' | 'rfc5280';
    readonly title: string;
    readonly repository: string;
    /**
     * The immutable identity of the upstream state: a git commit for a
     * repository, the archive's own SHA-256 for an archive.
     */
    readonly commit: string;
    readonly licence: string;
    /**
     * The files read at that identity. **Empty for an archive**, whose file set
     * is a property of the archive rather than a choice made here — the
     * checksum file is authoritative for which files were extracted, and the
     * archive's digest is authoritative for what was in it.
     */
    readonly files: readonly CorpusFile[];
    readonly archive?: CorpusArchive | undefined;
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
    {
        id: 'pkits',
        title: 'NIST Public Key Interoperability Test Suite (PKITS)',
        repository: 'https://csrc.nist.gov/projects/pki-testing',
        // The archive's own SHA-256. NIST publishes no version and no commit;
        // the digest is the only immutable identity the artefact has, and
        // pinning it is what makes "the same corpus" mean something.
        commit: '592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665',
        licence: 'US Government Work (17 U.S.C. §105), public domain',
        files: [],
        archive: {
            url: 'https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip',
            // The certificates and the revocation lists, and since 0.7 the 224
            // S/MIME messages: each is a detached CMS SignedData over a sample
            // text, signed by the end-entity certificate of the PKITS test of
            // the same name — so NIST's own expected result for the path is the
            // expected result for the signature, and L8 scores CMS against it.
            // The archive also holds PKCS#12 bundles, cross-certificate pairs and
            // an LDIF export of all of it; PKCS#12 is a container pkinative will
            // not read under the legacy KDF before 0.8.
            include: ['certs/', 'crls/', 'smime/'],
        },
    },
    {
        // The text L5 is held to. Conformance level L5 quotes RFC 5280 clause
        // by clause; without the RFC in the pin table, "a quote the RFC does
        // not contain" was a sentence in a comment rather than a check.
        // scripts/lib/rfc-requirements.ts extracts every requirement of §4.1
        // and §4.2 from exactly these bytes, and
        // scripts/data/rfc5280-requirements.json accounts for each one.
        id: 'rfc5280',
        title: 'RFC 5280, Internet X.509 PKI Certificate and CRL Profile (plain text)',
        repository: 'https://www.rfc-editor.org/rfc/rfc5280',
        // The file's own SHA-256. An RFC is never revised in place — errata
        // and updating RFCs are separate documents — but a proxy, a mirror or
        // a change of line endings would serve other bytes from the same URL,
        // and the digest is what makes "the text reviewed" a fixed thing.
        commit: 'a2f2628c0a83b873fc4786abd921f9b2c02395954b655d190bf16b831633345d',
        licence: 'Copyright (C) The IETF Trust (2008), BCP 78',
        files: [{ name: 'rfc5280.txt', path: 'rfc5280.txt', url: 'https://www.rfc-editor.org/rfc/rfc5280.txt' }],
    },
];

/** The immutable download URL of one file at the pinned commit. */
export function rawUrl(corpus: Corpus, file: CorpusFile): string {
    if (file.url !== undefined) return file.url;
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
