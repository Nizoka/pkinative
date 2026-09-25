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
import {
    canSign,
    computeFingerprint,
    createCertificate,
    decodeAsn1,
    decodePem,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtensions,
    encodeKeyUsage,
    encodePem,
    encodeSubjectAltName,
    parseCertificate,
    type ExtensionDescription,
    type NameDescription,
    type SigningKey,
} from '../src/index.js';

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

// ── Creation (0.3) ───────────────────────────────────────────────────
//
// The structural encoders are pkinative's own work and are measured alone.
// `createCertificate` is measured too, but read that row for what it is:
// an ECDSA P-256 signature dominates it, so it is a Web Crypto benchmark
// with a little encoding attached. It is here to catch an encoder that
// starts allocating per byte, not to compare runtimes — and it is labelled
// so nobody quotes it as pkinative's signing speed.

const SIGNER_NAME: NameDescription = [
    [{ type: '2.5.4.6', value: 'US', stringType: 'printable' }],
    [{ type: '2.5.4.3', value: 'pkinative benchmark issuer' }],
];
const EXTENSIONS: ExtensionDescription[] = [
    { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
    { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature', 'keyEncipherment']) },
    { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'bench.example' }, { kind: 'dNSName', value: 'www.bench.example' }]) },
];

// Top-level await: a `describe` callback is synchronous, and the key has to
// exist before the benchmark body runs. It is generated once for the whole
// file — generating one per iteration would measure key generation.
const material = await (async (): Promise<{ signer: SigningKey; spki: Uint8Array } | null> => {
    if (!canSign()) return null;
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return {
        signer: { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } },
        spki: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)),
    };
})();

describe('Creation', () => {
    bench('encodeDistinguishedName — 2 RDNs', () => { encodeDistinguishedName(SIGNER_NAME); });
    bench('encodeExtensions — 3 extensions', () => { encodeExtensions(EXTENSIONS); });

    if (material !== null) {
        bench('createCertificate — v3, 3 extensions (ECDSA P-256 sign dominates)', async () => {
            await createCertificate({
                serialNumber: 0x0123456789abcdefn,
                subject: [[{ type: '2.5.4.3', value: 'bench.example' }]],
                issuer: SIGNER_NAME,
                notBefore: 0,
                notAfter: 86_400_000,
                subjectPublicKey: material.spki,
                extensions: EXTENSIONS,
            }, material.signer);
        });
    }
});
