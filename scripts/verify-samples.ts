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

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { argv, exit, stdout } from 'node:process';
import {
    createCertificate,
    createCertificationRequest,
    encodeAlgorithmIdentifier,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeExtensions,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeValidity,
    parseCertificate,
    type SigningKey,
} from '../src/index.js';

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

// ── The deterministic signer ─────────────────────────────────────────

/** An Ed25519 PKCS#8 wrapper: version 0, the algorithm, then the seed in an OCTET STRING. */
const PKCS8_ED25519_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
/** Visibly not a real key: thirty-two 0x42 octets. */
const SEED = new Uint8Array(32).fill(0x42);

async function signer(): Promise<{ readonly signer: SigningKey; readonly spki: Uint8Array }> {
    const pkcs8 = new Uint8Array([...PKCS8_ED25519_PREFIX, ...SEED]);
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
    // Web Crypto cannot give the public half of a private key, and pkinative
    // is not allowed to compute it (that is scalar multiplication on secret
    // material). node:crypto can, and scripts/ may use node:.
    const spki = new Uint8Array(createPublicKey(createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }));
    return { signer: { key, algorithm: { name: 'Ed25519' } }, spki };
}

// ── The catalogue ────────────────────────────────────────────────────

const CN = '2.5.4.3';
const C = '2.5.4.6';
const KEY_ID = new Uint8Array(20).fill(0xab);

/** Every sample is named for what would break if its bytes moved. */
async function samples(): Promise<Map<string, Uint8Array>> {
    const out = new Map<string, Uint8Array>();
    const { signer: key, spki } = await signer();

    // AlgorithmIdentifier: the absent-versus-NULL parameter, which is the
    // single most common way a hand-written encoder produces a signature
    // that verifies nowhere while every field still reads correctly.
    out.set('algid/rsa-sha256-with-null', encodeAlgorithmIdentifier('1.2.840.113549.1.1.11'));
    out.set('algid/ecdsa-sha256-no-params', encodeAlgorithmIdentifier('1.2.840.10045.4.3.2'));
    out.set('algid/ed25519-no-params', encodeAlgorithmIdentifier('1.3.101.112'));

    // Names: the string-type chooser, and RDN ordering.
    out.set('name/attribute-utf8', encodeNameAttribute({ type: CN, value: 'Ünicode Authority' }));
    out.set('name/attribute-printable', encodeNameAttribute({ type: C, value: 'FR', stringType: 'printable' }));
    out.set('name/two-rdns', encodeDistinguishedName([[{ type: C, value: 'FR', stringType: 'printable' }], [{ type: CN, value: 'pkinative sample' }]]));
    out.set('name/multi-valued-rdn', encodeDistinguishedName([[{ type: C, value: 'FR', stringType: 'printable' }, { type: CN, value: 'a' }]]));

    // Validity: RFC 5280 §4.1.2.5 switches representation at 2050, and the
    // two encodings differ in length as well as in tag.
    out.set('validity/utctime-both', encodeValidity(Date.UTC(2026, 0, 1), Date.UTC(2027, 0, 1)));
    out.set('validity/utctime-to-generalized', encodeValidity(Date.UTC(2049, 11, 31), Date.UTC(2050, 0, 1)));

    // Extension values, one per encoder.
    out.set('ext/basic-constraints-ca', encodeBasicConstraints({ cA: true, pathLenConstraint: 3 }));
    out.set('ext/basic-constraints-leaf', encodeBasicConstraints({ cA: false }));
    out.set('ext/key-usage-ca', encodeKeyUsage(['keyCertSign', 'cRLSign']));
    out.set('ext/key-usage-leaf', encodeKeyUsage(['digitalSignature', 'keyEncipherment']));
    out.set('ext/key-usage-decipher-only', encodeKeyUsage(['decipherOnly']));
    out.set('ext/extended-key-usage', encodeExtendedKeyUsage(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']));
    out.set('ext/subject-key-identifier', encodeSubjectKeyIdentifier(KEY_ID));
    out.set('ext/authority-key-identifier', encodeAuthorityKeyIdentifier(KEY_ID));
    out.set('ext/subject-alt-name', encodeSubjectAltName([
        { kind: 'dNSName', value: 'sample.example' },
        { kind: 'rfc822Name', value: 'pki@sample.example' },
        { kind: 'uniformResourceIdentifier', value: 'https://sample.example/' },
        // 192.0.2.1 (RFC 5737 documentation range) and 2001:db8::1
        // (RFC 3849), in network byte order.
        { kind: 'iPAddress', value: Uint8Array.of(192, 0, 2, 1) },
        { kind: 'iPAddress', value: Uint8Array.of(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) },
        { kind: 'registeredID', value: '1.3.6.1.4.1.99999.1' },
    ]));
    out.set('ext/sequence-of-three', encodeExtensions([
        { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
        { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
        { oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(KEY_ID) },
    ]));

    // Whole structures, signed with the deterministic key.
    const root = await createCertificate({
        serialNumber: 0x0123456789abcdefn,
        subject: [[{ type: C, value: 'FR', stringType: 'printable' }], [{ type: CN, value: 'pkinative sample root' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2036, 0, 1),
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: true, pathLenConstraint: 0 }) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['keyCertSign', 'cRLSign']) },
            { oid: '2.5.29.14', value: encodeSubjectKeyIdentifier(KEY_ID) },
        ],
    }, key);
    out.set('cert/v3-ed25519-root', root);

    out.set('cert/v1-no-extensions', await createCertificate({
        serialNumber: Uint8Array.of(0x01),
        subject: [[{ type: CN, value: 'pkinative sample v1' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2027, 0, 1),
        subjectPublicKey: spki,
    }, key));

    out.set('cert/v3-leaf-issued-by-root', await createCertificate({
        serialNumber: 2n,
        issuerDer: parseCertificate(root, { onDiagnostic: () => undefined }).subject.der,
        subject: [[{ type: CN, value: 'sample.example' }]],
        notBefore: Date.UTC(2026, 0, 1),
        notAfter: Date.UTC(2026, 3, 1),
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.19', critical: true, value: encodeBasicConstraints({ cA: false }) },
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'sample.example' }]) },
            { oid: '2.5.29.35', value: encodeAuthorityKeyIdentifier(KEY_ID) },
        ],
    }, key));

    out.set('csr/no-attributes', await createCertificationRequest({
        subject: [[{ type: CN, value: 'sample.example' }]],
        subjectPublicKey: spki,
    }, key));

    out.set('csr/with-requested-extensions', await createCertificationRequest({
        subject: [[{ type: C, value: 'FR', stringType: 'printable' }], [{ type: CN, value: 'sample.example' }]],
        subjectPublicKey: spki,
        extensions: [
            { oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: 'sample.example' }, { kind: 'dNSName', value: 'www.sample.example' }]) },
            { oid: '2.5.29.15', critical: true, value: encodeKeyUsage(['digitalSignature']) },
        ],
    }, key));

    return out;
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
