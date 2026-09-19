/**
 * pkinative — parser benchmarks (`npm run bench`)
 * ===============================================
 * The hot paths of performance.instructions.md over real certificates
 * (tests/fixtures/PROVENANCE.md): TLV decoding, certificate parsing with and
 * without extension decoding, PEM decoding of a bundle, SHA-256 fingerprints.
 * Numbers go to bench/RESULTS.md WITH their run context — numbers without
 * context are not evidence.
 */

import { bench, describe } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { computeFingerprint, decodeAsn1, decodePem, encodePem, parseCertificate } from '../src/index.js';

const dir = join(process.cwd(), 'tests', 'fixtures', 'certs');
const load = (name: string): Uint8Array => new Uint8Array(readFileSync(join(dir, `${name}.der`)));
const RSA_ROOT = load('isrg-root-x1');
const LEAF = load('letsencrypt-org-leaf');
const BUNDLE = readdirSync(dir).filter((f) => f.endsWith('.der')).map((f) => encodePem('CERTIFICATE', new Uint8Array(readFileSync(join(dir, f))))).join('');
const QUIET = { onDiagnostic: (): void => undefined };

describe('ASN.1', () => {
    bench('decodeAsn1 — ISRG Root X1 (1 391 B, RSA 4096)', () => { decodeAsn1(RSA_ROOT); });
    bench('decodeAsn1 — letsencrypt.org leaf (1 098 B)', () => { decodeAsn1(LEAF); });
});

describe('X.509', () => {
    bench('parseCertificate — ISRG Root X1', () => { parseCertificate(RSA_ROOT, QUIET); });
    bench('parseCertificate — letsencrypt.org leaf, 10 extensions', () => { parseCertificate(LEAF, QUIET); });
    bench('parseCertificate — leaf, decodeExtensions: false', () => { parseCertificate(LEAF, { ...QUIET, decodeExtensions: false }); });
});

describe('PEM and fingerprints', () => {
    bench('decodePem — 6-certificate bundle', () => { decodePem(BUNDLE); });
    bench('computeFingerprint SHA-256 — leaf', () => { computeFingerprint(LEAF, 'SHA-256'); });
});
