/**
 * pkinative — fetch the conformance corpora
 * =========================================
 * Downloads every file of scripts/lib/corpora.ts at its pinned commit into
 * `test-output/corpora/<id>/<commit>/`, and refuses to write a file whose
 * SHA-256 differs from `.github/checksums/<id>-<commit>.sha256`: an upstream
 * force-push or a tampered mirror fails here, never later as a confusing
 * conformance result. Files already present and matching are kept.
 *
 * Usage:
 *   npx tsx scripts/fetch-corpora.ts          # download what is missing
 *   npx tsx scripts/fetch-corpora.ts --check  # verify only, no network
 *
 * Exit: 0 when every file is present and matches, 1 otherwise.
 *
 * @module scripts/fetch-corpora
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CORPORA, checksumPath, corpusDir, parseChecksums, rawUrl, sha256Hex, type Corpus, type CorpusArchive } from './lib/corpora.js';
import { readZip } from './lib/zip.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const checkOnly = process.argv.includes('--check');

async function main(): Promise<number> {
    let failures = 0;
    for (const corpus of CORPORA) {
        const expected = parseChecksums(readFileSync(join(ROOT, checksumPath(corpus)), 'utf8'));
        const dir = corpusDir(ROOT, corpus);
        mkdirSync(dir, { recursive: true });
        if (corpus.archive !== undefined) {
            failures += await fetchArchive(corpus, corpus.archive, expected, dir);
            continue;
        }
        for (const file of corpus.files) {
            const want = expected.get(file.name);
            const dest = join(dir, file.name);
            const label = `${corpus.id}@${corpus.commit.slice(0, 12)} ${file.name}`;
            if (want === undefined) {
                console.error(`FAIL  ${label}: not listed in ${checksumPath(corpus)}`);
                failures++;
                continue;
            }
            if (existsSync(dest) && sha256Hex(readFileSync(dest)) === want) {
                console.log(`OK    ${label} (cached)`);
                continue;
            }
            if (checkOnly) {
                console.error(`FAIL  ${label}: missing or modified — run npx tsx scripts/fetch-corpora.ts`);
                failures++;
                continue;
            }
            const response = await fetch(rawUrl(corpus, file));
            if (!response.ok) {
                console.error(`FAIL  ${label}: HTTP ${response.status} from ${rawUrl(corpus, file)}`);
                failures++;
                continue;
            }
            const bytes = new Uint8Array(await response.arrayBuffer());
            const got = sha256Hex(bytes);
            if (got !== want) {
                console.error(`FAIL  ${label}: SHA-256 ${got} does not match the pin ${want} — nothing written`);
                failures++;
                continue;
            }
            writeFileSync(dest, bytes);
            console.log(`OK    ${label} (${bytes.length} bytes downloaded)`);
        }
    }
    return failures === 0 ? 0 : 1;
}

/**
 * An archive corpus: one download, two pins, and everything checked twice.
 *
 * The archive's own SHA-256 **is** `corpus.commit`, so a changed publication
 * fails before a single byte is read — which matters more here than for a
 * repository, because NIST publishes no version and would overwrite the same
 * URL. The per-file checksum list is the second pin, and it defends against a
 * different thing: a bug in `scripts/lib/zip.ts` that extracted the wrong bytes
 * from the right archive. One digest cannot catch that; the other cannot catch a
 * changed archive; together they do.
 *
 * Files already on disk and matching are kept, so re-running costs nothing —
 * and the network is touched only when something is actually missing.
 */
async function fetchArchive(
    corpus: Corpus,
    archive: CorpusArchive,
    expected: ReadonlyMap<string, string>,
    dir: string,
): Promise<number> {
    const label = `${corpus.id}@${corpus.commit.slice(0, 12)}`;
    if (expected.size === 0) {
        console.error(`FAIL  ${label}: ${checksumPath(corpus)} lists no file — an archive corpus is pinned twice, and this is the second pin`);
        return 1;
    }
    const stale = [...expected].filter(([name]) => !existsSync(join(dir, name)) || sha256Hex(readFileSync(join(dir, name))) !== expected.get(name));
    if (stale.length === 0) {
        console.log(`OK    ${label} (cached, ${String(expected.size)} files)`);
        return 0;
    }
    if (checkOnly) {
        console.error(`FAIL  ${label}: ${String(stale.length)} of ${String(expected.size)} files missing or modified — run npx tsx scripts/fetch-corpora.ts`);
        return 1;
    }

    const response = await fetch(archive.url);
    if (!response.ok) {
        console.error(`FAIL  ${label}: HTTP ${String(response.status)} from ${archive.url}`);
        return 1;
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    const got = sha256Hex(bytes);
    if (got !== corpus.commit) {
        console.error(`FAIL  ${label}: the archive hashes to ${got} and the pin is ${corpus.commit} — nothing extracted`);
        return 1;
    }

    let written = 0;
    let failures = 0;
    for (const entry of readZip(bytes)) {
        if (!archive.include.some((prefix) => entry.name.startsWith(prefix))) continue;
        // The name in the checksum file is the name inside the archive, so the
        // list reads as what it is: an inventory of that archive's contents.
        const want = expected.get(entry.name);
        if (want === undefined) {
            console.error(`FAIL  ${label} ${entry.name}: extracted and not listed in ${checksumPath(corpus)}`);
            failures += 1;
            continue;
        }
        const digest = sha256Hex(entry.bytes);
        if (digest !== want) {
            console.error(`FAIL  ${label} ${entry.name}: SHA-256 ${digest} does not match the pin ${want} — nothing written`);
            failures += 1;
            continue;
        }
        const dest = join(dir, entry.name);
        mkdirSync(dirname(dest), { recursive: true });
        writeFileSync(dest, entry.bytes);
        written += 1;
    }
    if (written !== expected.size) {
        console.error(`FAIL  ${label}: ${String(written)} files extracted, ${String(expected.size)} listed — the archive and the checksum file disagree`);
        failures += 1;
    }
    if (failures === 0) console.log(`OK    ${label} (${String(written)} files extracted from ${String(bytes.length)} archive bytes)`);
    return failures === 0 ? 0 : 1;
}

process.exitCode = await main();
