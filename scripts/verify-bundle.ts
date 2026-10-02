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
    // Final review (2026-10-02): 14 KB → 15 KB, measured at 14.5 KB — every frame
    // now carries the bound no child may cross (an indefinite child held to its
    // definite parent, P-03).
    { exports: ['decodeAsn1'], maxBytes: 15 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem, MARKERS.x509, MARKERS.webcrypto] },
    { exports: ['decodePem', 'encodePem'], maxBytes: 13 * 1024, mustNotContain: [MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.x509, MARKERS.webcrypto] },
    // 1.0.0 audit: 64 KB → 70 KB, measured at 67.7 KB — the RFC 5280 Appendix A
    // name-syntax table and its two diagnostics, the X.690 §8.23 string checks,
    // and the subjectDirectoryAttributes decoder that makes "every RFC 5280
    // extension" true.
    // Final review (2026-10-02): 70 KB → 86 KB, measured at 84.2 KB — the 36 RFC 5280
    // §4.1–§4.2 profile diagnostics the L5 inventory recorded as not diagnosed,
    // the RFC 3986/4516 grammar they need (core/uri.ts), the EC-parameter and
    // RSA-exponent diagnostics and the control-character check on general names.
    { exports: ['parseCertificate', 'getExtension', 'formatDistinguishedName'], maxBytes: 86 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem, MARKERS.webcrypto] },
    // 1.0.0 audit: 11 KB → 12 KB, measured at 11.1 KB — the PkiError brand that
    // keeps instanceof true across the ESM and CJS builds.
    { exports: ['computeFingerprint', 'formatFingerprint'], maxBytes: 12 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.webcrypto] },
    { exports: ['getOidName'], maxBytes: 19 * 1024, mustNotContain: [MARKERS.asn1Decoder, MARKERS.sha, MARKERS.x509, MARKERS.webcrypto] },
    // 1.0.0 audit: 17 KB → 18 KB, measured at 17.4 KB — the RFC 4055 §1.2/§3.3
    // rules for id-RSASSA-PSS keys and the error brand.
    // Final review (2026-10-02): 18 KB → 19 KB, measured at 18.8 KB — the RSA public
    // exponent refused below 3 or even (RFC 8017 §3.1), and the RSASSA-PSS
    // parameter grammar enforced field by field.
    { exports: ['verifyCertificateSignature', 'verifySelfSignature', 'canVerify'], maxBytes: 19 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // The builder from the same angle: writing a certificate ships no reader.
    // It carries the ASN.1 *encoders* by necessity, so the decoder marker is
    // the one that matters here — an app that only issues certificates must
    // not pay for the parser, the name registry or the hashes.
    // 1.0.0 audit: 20 KB → 24 KB, measured at 22.6 KB — each name attribute
    // written in its Appendix A string type and held to its SIZE bounds, with the
    // messages that say which.
    { exports: ['createCertificate', 'createCertificationRequest', 'canSign'], maxBytes: 24 * 1024, mustNotContain: [MARKERS.x509, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
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
    //
    // 20 KB → 22 KB, measured at 20.5 KB in 0.9: two acceptance defects closed.
    // An excluded directoryName now also matches after RFC 5280 §7.1
    // preparation, and an rfc822Name constraint reaches the subject's
    // emailAddress when there is no subjectAltName (§4.2.1.10) — the second is
    // what let NIST's InvalidDNandRFC822nameConstraintsTest29 through since 0.5.
    // 1.0.0 audit: 22 KB → 25 KB, measured at 23.6 KB — the RFC 3986 host reader
    // for URI constraints and SmtpUTF8Mailbox under rfc822Name subtrees — two
    // constraint bypasses closed.
    // Final review (2026-10-02): 25 KB → 26 KB, measured at 25.1 KB — the anchor
    // matched by name and key, the §6.1.5 (g)(iii) intersection, v1/v2
    // intermediates refused and the implicit anchor counted.
    { exports: ['validateCertificatePath'], maxBytes: 26 * 1024, mustNotContain: [MARKERS.webcrypto, MARKERS.asn1Decoder, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
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
    //
    // 58 KB → 62 KB, measured at 60.0 KB when §5.2.5 landed: deciding whether a
    // list covers a certificate reads the certificate's `cRLDistributionPoints`
    // and compares GeneralNames, so the general-name reader is now reachable
    // from the CRL entry points. That is the cost of the answer being about
    // *this* certificate rather than about the CA, and it is not optional.
    //
    // 62 KB → 64 KB, measured at 62.1 KB when §5.2.4 landed: pairing a delta
    // with its base is a rule about two lists, and it lives beside the scope
    // decision rather than in the caller's head.
    // 1.0.0 audit: 64 KB → 72 KB, measured at 69.4 KB — REVOKED only from
    // authenticated, applicable evidence, plus the decoder and string-check
    // growth of the certificate parser it reaches.
    // Final review (2026-10-02): 72 KB → 87 KB, measured at 85.4 KB — the cursor
    // aligned with the decoder, the entry-extension walk of §5.3, the
    // distribution-point reasons mask, and the profile diagnostics the list's
    // issuer and extensions share with the certificate reader.
    { exports: ['parseCertificateList', 'findRevocation', 'checkRevocation'], maxBytes: 87 * 1024, mustNotContain: [MARKERS.webcrypto, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // 156 KB → 164 KB, measured at 157.9 KB: the purpose check and the
    // composition layer. The roadmap's own projection for 1.0 is ~320 KB, so
    // this figure is on track; it is raised in the commit that measures it,
    // never ahead of one, which is what keeps it a budget rather than a ceiling
    // nobody reads.
    // The composition layer weighed. It reaches a key, a parser and a verdict,
    // which is precisely why it exists — so the markers it must NOT retain are
    // only the two nothing here reads: the OID name registry and the PEM
    // envelope. Callers hand over DER.
    //
    // 90 KB → 120 KB, measured at 112.7 KB when OCSP joined: the response
    // decoder, and `parseCertificate` with both digests for the delegated
    // responder check. That is **70 % of the whole package**, and it is the
    // honest price of one call that asks every question — a caller who wants
    // only the parser still pays 61 KB, which is what the leaf probes above are
    // for. Recorded rather than hidden, and raised in the commit that measures
    // it.
    //
    // 120 KB → 124 KB, measured at 121.1 KB when delta CRLs and the CRL-signer
    // rules landed: the composition now pairs a delta with its base and judges
    // whether a delegated signer's own certificate is still good, which is a
    // second revocation question asked inside the first one.
    // 124 KB → 128 KB, measured at 124.6 KB in 0.9: the same two name-constraint
    // fixes, which the composition carries with the §6 walk.
    // 1.0.0 audit: 128 KB → 138 KB, measured at 133.3 KB — the path and
    // revocation fixes above, the commonName fallback held to dNSName
    // constraints, and the parser growth.
    // Final review (2026-10-02): 138 KB → 158 KB, measured at 156.1 KB — the sum
    // of the leaves above, plus the off-path CRL issuer validated with its own
    // links, the delegated responder's revocation, OCSP freshness and the
    // re-rooted reason paths.
    { exports: ['verifyCertificateChain'], maxBytes: 158 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.pem] },
    // The 0.7 band, weighed from four sides — measured 2026-09-29 at 70.5,
    // 35.2, 17.2 and 167.2 KB.
    //
    // "cms never imports crypto": reading a signed message or a timestamp
    // ships no Web Crypto bridge. It does ship the X.509 parser — a
    // SignedData carries certificates, and an ESS binding is checked against
    // one — which is most of the 70 KB.
    // 1.0.0 audit: 76 KB → 80 KB, measured at 76.4 KB — the parser growth it
    // inherits and the error brand.
    // Final review (2026-10-02): 80 KB → 92 KB, measured at 90.7 KB — the stricter
    // cursor, the PSS grammar, and the certificate reader's new diagnostics.
    { exports: ['parseSignedData', 'parseTimeStampToken', 'parseTimeStampResponse', 'parseTstInfo'], maxBytes: 92 * 1024, mustNotContain: [MARKERS.webcrypto, MARKERS.oidRegistry, MARKERS.pem] },
    // "build never imports x509": the signer's certificate enters as DER and
    // its issuer and serial are lifted from the encoding, never re-rendered.
    // The hashes are here by necessity — `messageDigest` is one.
    { exports: ['createSignedData', 'addTimeStampToken', 'createTimeStampRequest'], maxBytes: 40 * 1024, mustNotContain: [MARKERS.x509, MARKERS.oidRegistry, MARKERS.pem] },
    // The CMS signature on its own consumes a parsed SignerInfo and hashes
    // through Web Crypto, so it carries neither the parser nor the SHA code.
    // 1.0.0 audit: 19 KB → 20 KB, measured at 19.1 KB — the RFC 4055 rules,
    // shared with resolveCmsAlgorithm.
    // Final review (2026-10-02): 20 KB → 21 KB, measured at 20.5 KB — the RSA
    // exponent refusal and the RSASSA-PSS parameter grammar.
    { exports: ['verifySignerInfoSignature'], maxBytes: 21 * 1024, mustNotContain: [MARKERS.x509, MARKERS.oidRegistry, MARKERS.pem, MARKERS.sha] },
    // The two CMS verdicts are `verifyCertificateChain` plus the CMS layer,
    // which is exactly what they are: 121.7 + ~45 KB.
    // 1.0.0 audit: 176 KB → 190 KB, measured at 182.9 KB — everything
    // verifyCertificateChain gained, plus the CMS layer.
    // Final review (2026-10-02): 190 KB → 210 KB, measured at 206.0 KB — the chain
    // report's growth above, the SHA-1 imprint gate and the clock read once.
    { exports: ['verifySignedData', 'verifyTimeStampToken'], maxBytes: 210 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.pem] },
    // The 0.8 band, weighed from three sides — measured 2026-09-29 at 39.8,
    // 44.3 and 94.4 KB.
    //
    // "keys never imports x509", and more: describing a key file or a PKCS#12
    // ships neither the certificate parser nor the Web Crypto bridge. What a
    // file is protected with can be read before anyone types a password, on a
    // runtime with no crypto.subtle at all.
    { exports: ['parsePrivateKeyInfo', 'parseEncryptedPrivateKeyInfo', 'parsePkcs12'], maxBytes: 44 * 1024, mustNotContain: [MARKERS.x509, MARKERS.webcrypto, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // Opening them reaches the door and still no certificate parser: a key's
    // algorithm is named by the caller or, in openPkcs12, by its certificate.
    { exports: ['importPrivateKey', 'decryptPrivateKey', 'verifyPkcs12Mac', 'openSafeContents'], maxBytes: 50 * 1024, mustNotContain: [MARKERS.x509, MARKERS.oidRegistry, MARKERS.sha, MARKERS.pem] },
    // The one call parses every certificate the file carries, to match each
    // key to the one naming its algorithm: the certificate parser is the price.
    // Final review (2026-10-02): 104 KB → 120 KB, measured at 118.5 KB — the
    // certificate reader's profile diagnostics, which the bag's certificates
    // pass through, and the PBMAC1 key-length floor.
    { exports: ['openPkcs12'], maxBytes: 120 * 1024, mustNotContain: [MARKERS.oidRegistry, MARKERS.pem] },
    // 164 KB → 168 KB, measured at 165.4 KB with the CRL scope decision;
    // 168 KB → 172 KB, measured at 168.9 KB with delta CRLs and the signer rules;
    // 172 KB → 236 KB, measured at 225.3 KB with CMS and RFC 3161 — the largest
    // single rise so far, and the roadmap's ~320 KB projection for 1.0 still
    // holds with PKCS#8/#12 to come.
    // 236 KB → 272 KB, measured at 259.3 KB with PKCS#8, PKCS#12 and openPkcs12:
    // the last subsystem before 1.0, and within the ~320 KB projection.
    // 1.0.0 audit: 272 KB → 280 KB, measured at 272.9 KB — the whole of the
    // above; still under the ~320 KB projection for 1.0.
    // Final review (2026-10-02): 280 KB → 300 KB, measured at 296.3 KB — the sum of
    // the leaves above: 37 diagnostics and the checks behind them.
    { exports: ['*'], maxBytes: 300 * 1024, mustNotContain: [] },
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
