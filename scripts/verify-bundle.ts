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
 * Measured 2026-09-27 (esbuild 0.28.1, minified ESM): 12.1, 11.0, 57.3, 9.3,
 * 16.7, 14.7, 17.9, 16.7, 53.7 and 141.6 KB. Each budget is the measurement
 * plus roughly 15 %.
 *
 * **The `mustNotContain` markers are the invariant and are never relaxed** —
 * they are the only executable proof that `LAYERS` describes the artefact and
 * not just the diagram. The byte budgets are a different thing, and this
 * revision raised three leaves that did not change: `decodeAsn1`, `decodePem`
 * and `computeFingerprint` each grew about 1.5 KB when four named limits were
 * added, because `DEFAULT_PKI_LIMITS` is one frozen object and `resolveLimits`
 * validates against its key set — so every limit's name and default is in
 * every bundle that touches limits, which is all of them.
 *
 * That is the accepted cost of the closed enumeration: a `maxNode` typo is
 * caught instead of silently leaving a security bound at its default. The
 * roadmap expects the table to reach roughly 29 limits, so these leaves will
 * grow by another 3–4 KB on that account alone. Growth from *that* cause is
 * expected; growth from a marker appearing where it should not be is a
 * layering violation, and no budget change will make that pass.
 *
 * The verification probe is the one that earns its place. AGENTS.md
 * §Architecture claims `crypto` never imports `x509`; this measures the
 * built artefact and finds neither the parser, nor the decoder, nor the
 * hashes in it — 12.7 KB to check a signature. The parser probe is the
 * same claim from the other side: reading a certificate ships no Web
 * Crypto bridge. A layer diagram is a drawing until something weighs it.
 */
export const PROBES: readonly Probe[] = [
    { exports: ['decodeAsn1'], maxBytes: 14 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem, MARKERS.x509, MARKERS.webcrypto] },
    { exports: ['decodePem', 'encodePem'], maxBytes: 13 * 1024, mustNotContain: [MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.x509, MARKERS.webcrypto] },
    { exports: ['parseCertificate', 'getExtension', 'formatDistinguishedName'], maxBytes: 64 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem, MARKERS.webcrypto] },
    { exports: ['computeFingerprint', 'formatFingerprint'], maxBytes: 11 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.webcrypto] },
    { exports: ['getOidName'], maxBytes: 19 * 1024, mustNotContain: [MARKERS.asn1Decoder, MARKERS.sha, MARKERS.x509, MARKERS.webcrypto] },
    { exports: ['verifyCertificateSignature', 'verifySelfSignature', 'canVerify'], maxBytes: 17 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // The builder from the same angle: writing a certificate ships no reader.
    // It carries the ASN.1 *encoders* by necessity, so the decoder marker is
    // the one that matters here — an app that only issues certificates must
    // not pay for the parser, the name registry or the hashes.
    { exports: ['createCertificate', 'createCertificationRequest', 'canSign'], maxBytes: 20 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // "§6 is synchronous and pure", weighed. The Web Crypto marker is the one
    // that matters: signature verdicts reach `validateCertificatePath` as
    // data, so a bundle that retained the bridge would mean the claim had
    // quietly stopped being true. The ASN.1 decoder must be absent too — a
    // path validator that decodes anything is a layer upstream that failed to
    // expose it.
    //
    // 18 KB → 20 KB, measured at 18.5 KB: the name-constraint checker grew by
    // ~0.5 KB when x509-limbo scoring showed it accepting malformed names,
    // treating a URI constraint as a domain, ignoring a constrained form it
    // could not process, and comparing a wildcard as a string (CVE-2025-61727).
    // Every one of those was a bypass, so the bytes bought correctness rather
    // than features — and the headroom is named here so the next rise has to be
    // argued too.
    { exports: ['validateCertificatePath'], maxBytes: 20 * 1024, mustNotContain: [MARKERS.webcrypto, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // "Revocation is synchronous and carries no crypto", weighed. The Web
    // Crypto marker is the invariant: `checkRevocation` takes a signature
    // verdict rather than a key, and a bundle retaining the bridge would mean
    // that had quietly stopped being true.
    //
    // The 52 KB is a **known and reviewed cost**, not a small number: the CRL
    // parser reaches the x509 extension reader, whose decoder map references
    // all twenty certificate-extension decoders, so none of them can be
    // tree-shaken. A caller who reads only CRLs therefore pays for decoders a
    // CRL never uses. The trade was taken deliberately — an
    // `authorityKeyIdentifier` on a CRL decoded properly is worth more to
    // almost every caller than 35 KB they would save by reading every CRL
    // extension as `unknown` — and it is written here so the next person to
    // look at this number knows it was a choice.
    { exports: ['parseCertificateList', 'findRevocation', 'checkRevocation'], maxBytes: 58 * 1024, mustNotContain: [MARKERS.webcrypto, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // 156 KB → 164 KB, measured at 157.9 KB: the purpose check and the
    // composition layer. The roadmap's own projection for 1.0 is ~320 KB, so
    // this figure is on track; it is raised in the commit that measures it,
    // never ahead of one, which is what keeps it a budget rather than a ceiling
    // nobody reads.
    // The composition layer weighed, and the one probe here with **no**
    // `mustNotContain` by design: `verifyCertificateChain` reaches a key, a
    // parser and a verdict, which is precisely why it exists. What it is worth
    // measuring is that composing everything costs barely more than the parts —
    // a caller who wants the whole answer pays for the whole answer once.
    { exports: ['verifyCertificateChain'], maxBytes: 90 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.pem] },
    { exports: ['*'], maxBytes: 164 * 1024, mustNotContain: [] },
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
