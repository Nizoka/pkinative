#!/usr/bin/env tsx
/**
 * pkinative — the output-byte baseline
 * ====================================
 * What pkinative *writes*, hashed, and held to a reviewed baseline.
 *
 * The conformance gate (L0–L4) answers the reading question: given these
 * bytes, does pkinative agree with everyone else about what they mean. It
 * says nothing about the other direction, which 0.3 opened: given this
 * description, which bytes does pkinative produce? An encoder can drift
 * without a single test going red — swap a `PrintableString` for a
 * `UTF8String`, emit an explicit `DEFAULT`, reorder a SET — and every
 * structural assertion still passes, because the structure is still right.
 * The bytes are what a relying party actually hashes.
 *
 * So each sample below is hashed and compared to `scripts/data/output-bytes.json`,
 * where every entry records the release its hash came from. A difference is
 * not a failure to be silenced: it is a diff a human reads, and the release
 * it moved in is the thing the file remembers.
 *
 * **Determinism, and why there is no key in this repository.** A signature
 * must be reproducible for a signed sample to have a stable hash, so every
 * signed sample uses Ed25519 (RFC 8032: deterministic by construction —
 * ECDSA and RSASSA-PSS are not, and are covered by the unsigned samples).
 * The key comes from a fixed 32-octet seed wrapped in the PKCS#8 prefix
 * here in this file, so nothing secret-looking is committed and the rule
 * "never commit what our own code can build" holds. `node:crypto` derives
 * the public half, which is why the sample certificates are genuinely
 * self-signed rather than merely well-formed.
 *
 * Usage:
 *   npx tsx scripts/verify-samples.ts
 *   npx tsx scripts/verify-samples.ts --json
 *   npx tsx scripts/verify-samples.ts --update-baseline   # then REVIEW the diff
 *
 * Exit: 0 every sample matches; 1 a sample moved, is new, or is gone.
 *
 * @module scripts/verify-samples
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { argv, exit, stdout } from 'node:process';
import { samples } from './lib/samples.js';

const BASELINE = 'scripts/data/output-bytes.json';

/** The release a new entry is recorded against. */
const VERSION = (JSON.parse(readFileSync('package.json', 'utf8')) as { version: string }).version;

interface Entry {
    readonly bytes: number;
    readonly sha256: string;
    readonly since: string;
}

interface Baseline {
    readonly $comment: string;
    readonly samples: Record<string, Entry>;
}

// ── The comparison ───────────────────────────────────────────────────

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

interface Difference {
    readonly name: string;
    readonly kind: 'moved' | 'new' | 'gone';
    readonly was?: Entry;
    readonly now?: Entry;
}

function compare(current: Map<string, Uint8Array>, baseline: Baseline): Difference[] {
    const out: Difference[] = [];
    for (const [name, bytes] of current) {
        const was = baseline.samples[name];
        const now: Entry = { bytes: bytes.length, sha256: sha256(bytes), since: was?.since ?? VERSION };
        if (was === undefined) out.push({ name, kind: 'new', now });
        else if (was.sha256 !== now.sha256) out.push({ name, kind: 'moved', was, now: { ...now, since: VERSION } });
    }
    for (const name of Object.keys(baseline.samples)) {
        if (!current.has(name)) out.push({ name, kind: 'gone', was: baseline.samples[name] });
    }
    return out;
}

async function main(): Promise<number> {
    const json = argv.includes('--json');
    const update = argv.includes('--update-baseline');
    const current = await samples();

    let baseline: Baseline;
    try {
        baseline = JSON.parse(readFileSync(BASELINE, 'utf8')) as Baseline;
    } catch {
        baseline = { $comment: '', samples: {} };
    }
    const differences = compare(current, baseline);

    if (update) {
        const next: Record<string, Entry> = {};
        for (const [name, bytes] of [...current].sort((a, b) => a[0].localeCompare(b[0]))) {
            const was = baseline.samples[name];
            const digest = sha256(bytes);
            next[name] = { bytes: bytes.length, sha256: digest, since: was !== undefined && was.sha256 === digest ? was.since : VERSION };
        }
        writeFileSync(BASELINE, `${JSON.stringify({ $comment: baseline.$comment || BASELINE_COMMENT, samples: next }, null, 2)}\n`, 'utf8');
        stdout.write(`verify-samples: baseline rewritten with ${String(current.size)} sample(s) — review every changed entry before committing\n`);
        return 0;
    }

    if (json) {
        stdout.write(`${JSON.stringify({ samples: current.size, differences }, null, 2)}\n`);
        return differences.length === 0 ? 0 : 1;
    }

    for (const d of differences) {
        if (d.kind === 'moved') stdout.write(`MOVED  ${d.name}: ${String(d.was?.bytes)} B ${String(d.was?.sha256).slice(0, 16)}… (since ${String(d.was?.since)}) → ${String(d.now?.bytes)} B ${String(d.now?.sha256).slice(0, 16)}…\n`);
        else if (d.kind === 'new') stdout.write(`NEW    ${d.name}: ${String(d.now?.bytes)} B ${String(d.now?.sha256).slice(0, 16)}…\n`);
        else stdout.write(`GONE   ${d.name}: was ${String(d.was?.bytes)} B since ${String(d.was?.since)}\n`);
    }
    if (differences.length === 0) {
        stdout.write(`verify-samples: ${String(current.size)} sample(s) byte for byte against the baseline.\n`);
        return 0;
    }
    stdout.write(`verify-samples: ${String(differences.length)} difference(s). If they are intended, run with --update-baseline and REVIEW every changed entry — these bytes are what a relying party hashes.\n`);
    return 1;
}

const BASELINE_COMMENT = 'What pkinative writes, hashed. Generated by `npx tsx scripts/verify-samples.ts --update-baseline` and never edited by hand; `since` records the release an entry last moved in. A difference here is a reviewed diff, not a failure to silence: these bytes are what a relying party hashes, and an encoder can drift without a single structural test going red.';

exit(await main());
