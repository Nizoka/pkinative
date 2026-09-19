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
import { CORPORA, checksumPath, corpusDir, parseChecksums, rawUrl, sha256Hex } from './lib/corpora.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const checkOnly = process.argv.includes('--check');

async function main(): Promise<number> {
    let failures = 0;
    for (const corpus of CORPORA) {
        const expected = parseChecksums(readFileSync(join(ROOT, checksumPath(corpus)), 'utf8'));
        const dir = corpusDir(ROOT, corpus);
        mkdirSync(dir, { recursive: true });
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

process.exitCode = await main();
