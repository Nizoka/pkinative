#!/usr/bin/env tsx
/**
 * pkinative — Tree-shaking gate
 * =============================
 * Bundles one import at a time from the built `dist/index.js` with esbuild
 * (the version tsup already pins, nothing new installed) and fails when the
 * bundle is over its byte budget or carries code that import does not need
 * (pdfnative 1.8.0 doctrine). `sideEffects: false` is a claim; this is its
 * proof — and the proof that the layer table keeps its promises: the
 * certificate parser ships no OID name registry and no hash, the PEM decoder
 * ships no ASN.1 decoder.
 *
 * Budgets are the minified size measured when the probe was added plus
 * 15 %: loose enough for a bug fix, tight enough that a module creeping into
 * a leaf import fails the gate.
 *
 * Usage:
 *   npm run build && npm run verify:bundle
 *   npx tsx scripts/verify-bundle.ts --json
 *
 * Exit: 0 every probe within budget and free of its markers; 1 otherwise;
 * 2 dist/ or esbuild missing.
 *
 * @module scripts/verify-bundle
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = resolve(REPO_ROOT, 'dist', 'index.js');

export interface Probe {
    /** What the consumer imports; `*` is the whole package. */
    readonly exports: readonly string[];
    /** Minified byte budget. */
    readonly maxBytes: number;
    /** Literals only the unwanted subsystem contains. */
    readonly mustNotContain: ReadonlyArray<readonly [label: string, marker: string]>;
}

/** Literals a subsystem cannot exist without. */
const MARKERS = {
    oidRegistry: ['OID name registry', 'jurisdictionStateOrProvinceName'],
    sha: ['SHA round constants', '1116352408'],
    pem: ['PEM boundaries', '-----BEGIN'],
    asn1Decoder: ['ASN.1 decoder', 'end-of-contents marker'],
    x509: ['X.509 parser', 'tbsCertificate'],
    webcrypto: ['Web Crypto bridge', 'RSASSA-PKCS1-v1_5'],
} as const;

/**
 * Measured 2026-09-20 (esbuild 0.28.1, minified ESM): 10.3, 8.6, 55.6,
 * 7.6, 14.6, 12.7 and 101.6 KB. Each budget is the measurement plus 15 %.
 *
 * The verification probe is the one that earns its place. AGENTS.md
 * §Architecture claims `crypto` never imports `x509`; this measures the
 * built artefact and finds neither the parser, nor the decoder, nor the
 * hashes in it — 12.7 KB to check a signature. The parser probe is the
 * same claim from the other side: reading a certificate ships no Web
 * Crypto bridge. A layer diagram is a drawing until something weighs it.
 */
export const PROBES: readonly Probe[] = [
    { exports: ['decodeAsn1'], maxBytes: 12 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem, MARKERS.x509, MARKERS.webcrypto] },
    { exports: ['decodePem', 'encodePem'], maxBytes: 10 * 1024, mustNotContain: [MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.x509, MARKERS.webcrypto] },
    { exports: ['parseCertificate', 'getExtension', 'formatDistinguishedName'], maxBytes: 64 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem, MARKERS.webcrypto] },
    { exports: ['computeFingerprint', 'formatFingerprint'], maxBytes: 9 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.webcrypto] },
    { exports: ['getOidName'], maxBytes: 17 * 1024, mustNotContain: [MARKERS.asn1Decoder, MARKERS.sha, MARKERS.x509, MARKERS.webcrypto] },
    { exports: ['verifyCertificateSignature', 'verifySelfSignature', 'canVerify'], maxBytes: 15 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // The builder from the same angle: writing a certificate ships no reader.
    // It carries the ASN.1 *encoders* by necessity, so the decoder marker is
    // the one that matters here — an app that only issues certificates must
    // not pay for the parser, the name registry or the hashes.
    { exports: ['createCertificate', 'createCertificationRequest', 'canSign'], maxBytes: 20 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    { exports: ['*'], maxBytes: 118 * 1024, mustNotContain: [] },
];

interface ProbeResult {
    readonly exports: readonly string[];
    readonly bytes: number;
    readonly maxBytes: number;
    readonly retained: readonly string[];
    readonly ok: boolean;
}

type Esbuild = { build: (options: Record<string, unknown>) => Promise<unknown> };

async function loadEsbuild(): Promise<Esbuild | null> {
    try {
        return await import(pathToFileURL(resolve(REPO_ROOT, 'node_modules', 'esbuild', 'lib', 'main.js')).href) as Esbuild;
    } catch {
        return null;
    }
}

async function main(): Promise<number> {
    const json = process.argv.includes('--json');
    if (!existsSync(DIST)) {
        console.error('verify-bundle: dist/index.js is missing — run `npm run build` first.');
        return 2;
    }
    const esbuild = await loadEsbuild();
    if (esbuild === null) {
        console.error('verify-bundle: esbuild is not installed — run `npm ci`.');
        return 2;
    }
    const work = mkdtempSync(join(tmpdir(), 'pkinative-bundle-'));
    const results: ProbeResult[] = [];
    try {
        for (const probe of PROBES) {
            const entry = join(work, 'entry.mjs');
            const out = join(work, 'out.mjs');
            const dist = DIST.replace(/\\/g, '/');
            writeFileSync(entry, probe.exports[0] === '*' ? `export * from '${dist}';\n` : `export { ${probe.exports.join(', ')} } from '${dist}';\n`);
            await esbuild.build({ entryPoints: [entry], bundle: true, format: 'esm', minify: true, outfile: out, logLevel: 'silent', platform: 'neutral', target: 'es2020' });
            const code = readFileSync(out, 'utf8');
            const retained = probe.mustNotContain.filter(([, marker]) => code.includes(marker)).map(([label]) => label);
            const bytes = Buffer.byteLength(code);
            results.push({ exports: probe.exports, bytes, maxBytes: probe.maxBytes, retained, ok: bytes <= probe.maxBytes && retained.length === 0 });
        }
    } finally {
        rmSync(work, { recursive: true, force: true });
    }
    const failed = results.filter((r) => !r.ok);
    if (json) {
        console.log(JSON.stringify({ ok: failed.length === 0, results }, null, 2));
    } else {
        for (const r of results) {
            const tail = r.retained.length > 0 ? ` — retained: ${r.retained.join(', ')}` : '';
            console.log(`${r.ok ? '✓' : '✗'} { ${r.exports.join(', ')} } → ${(r.bytes / 1024).toFixed(1)} KB (budget ${(r.maxBytes / 1024).toFixed(0)} KB)${tail}`);
        }
        console.log(failed.length === 0
            ? `verify-bundle: ${results.length} probes tree-shake within budget.`
            : `verify-bundle: ${failed.length} of ${results.length} probes are over budget or retain code they do not use.`);
    }
    return failed.length === 0 ? 0 : 1;
}

process.exitCode = await main();
