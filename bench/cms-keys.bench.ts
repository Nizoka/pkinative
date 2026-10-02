/**
 * pkinative — CMS, timestamp and key-container benchmarks (`npm run bench`)
 * ========================================================================
 * The 0.7 and 0.8 one-call reports over a small real PKI: a signed message
 * attached and detached, a timestamp token, a PKCS#12 opened, a PKCS#8 key
 * imported plain and under PBES2. Every row that verifies a signature or
 * derives a key is Web Crypto plus pkinative, and is labelled so; the
 * `openPkcs12` row is a PBKDF2 benchmark (2 048 iterations, what OpenSSL 3
 * writes by default) with a little decoding attached, and nobody should
 * quote it as pkinative's speed. Numbers go to bench/RESULTS.md WITH their
 * run context — numbers without context are not evidence.
 */

import { webcrypto } from 'node:crypto';
import { bench, describe } from 'vitest';
import {
    decryptPrivateKey,
    importPrivateKey,
    openPkcs12,
    parseSignedData,
    verifySignedData,
    verifyTimeStampToken,
} from '../src/index.js';
import {
    authenticatedSafe,
    certBag,
    dataInfo,
    encryptedSafeContents,
    localKeyId,
    pbmac1MacData,
    pfx,
    safeContents,
    shroudedKeyBag,
    shroudKey,
} from '../tests/helpers/pkcs12-builder.js';
import { createSignedData } from '../src/build/build-signed-data.js';
import { AT, issue, issueTsa, makeRoot, makeToken, sha, tstInfo } from '../tests/verify/_cms-pki.js';

const QUIET = { onDiagnostic: (): undefined => undefined };
const DATA = new TextEncoder().encode('the bytes a signer committed to, measured a few thousand times');
const PASSWORD = 'correct horse battery staple';
const KEY_ID = Uint8Array.of(0x4b, 0x45, 0x59, 0x31);

// Top-level await: the PKI and every container exist once for the whole
// file, so no row measures key generation, issuance or encryption.
const world = await (async () => {
    const root = await makeRoot('Bench CMS Root');
    const signer = await issue(root, { subject: 'Bench Signer' });
    const tsa = await issueTsa(root);
    const attached = await createSignedData({ content: DATA, certificate: signer.certificate }, signer.signer);
    const detached = await createSignedData({ content: DATA, detached: true, certificate: signer.certificate }, signer.signer);
    const imprint = await sha('SHA-256', DATA);
    const token = await makeToken(tsa, tstInfo({ imprint }));
    const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', signer.pair.privateKey as never));
    const shrouded = await shroudKey(pkcs8, PASSWORD);
    const certs = safeContents(certBag(signer.certificate.der, [localKeyId(KEY_ID)]), certBag(root.certificate.der));
    const keys = safeContents(shroudedKeyBag(shrouded, [localKeyId(KEY_ID)]));
    const authSafe = authenticatedSafe(await encryptedSafeContents(certs, PASSWORD), dataInfo(keys));
    const pkcs12 = pfx({ authSafe, macData: await pbmac1MacData(authSafe, PASSWORD) });
    return { root: root.certificate, attached, detached, token, imprint, pkcs8, shrouded, pkcs12 };
})();

const ECDSA = { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } as const;

describe('CMS', () => {
    bench('parseSignedData — one signer, one certificate', () => { parseSignedData(world.attached, QUIET); });
    bench('verifySignedData — attached, one ECDSA P-256 signer under a root (verify dominates)', async () => {
        await verifySignedData({ signedData: world.attached, trustAnchors: [world.root], at: AT });
    });
    bench('verifySignedData — detached, content supplied', async () => {
        await verifySignedData({ signedData: world.detached, content: DATA, trustAnchors: [world.root], at: AT });
    });
    bench('verifyTimeStampToken — token against its imprint, TSA under a root', async () => {
        await verifyTimeStampToken({ token: world.token, imprint: world.imprint, trustAnchors: [world.root], at: AT });
    });
});

describe('Keys', () => {
    bench('importPrivateKey — PKCS#8 ECDSA P-256', async () => { await importPrivateKey(world.pkcs8, { algorithm: ECDSA }); });
    bench('decryptPrivateKey — PBES2, PBKDF2 2 048 iterations, AES-256-CBC (PBKDF2 dominates)', async () => {
        await decryptPrivateKey(world.shrouded, { password: PASSWORD, algorithm: ECDSA });
    });
    bench('openPkcs12 — PBMAC1, one shrouded key, two certificates (three PBKDF2 runs dominate)', async () => {
        await openPkcs12(world.pkcs12, { password: PASSWORD });
    });
});
