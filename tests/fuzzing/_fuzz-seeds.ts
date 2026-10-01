/**
 * Seeds for the ClusterFuzzLite targets in `fuzz/`, one list per target.
 *
 * A coverage-guided fuzzer started from random bytes spends its first days
 * rediscovering the tag-length header; started from a structure that parses,
 * it is inside the grammar on its first mutation. The committed fixtures are
 * certificates only, and an OCSP response or a PFX is far from a
 * certificate in mutation distance — so the seeds of the grammars that are
 * not X.509 are **built**, here, every signature real, and never committed
 * (tests/fixtures/PROVENANCE.md: "never commit what our own code can build").
 *
 * Two consumers, one list:
 *   - `tests/fuzzing/targets.test.ts` feeds every seed, truncated and
 *     mutated, to its target on every gate run;
 *   - `.clusterfuzzlite/build.sh` runs this file as a script
 *     (`npx tsx tests/fuzzing/_fuzz-seeds.ts <dir>`), which writes
 *     `<dir>/<target>/<n>.der` for the build step to zip into each target's
 *     seed corpus.
 */

import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { createSignedData } from '../../src/build/build-signed-data.js';
import { contentInfo as cmsContentInfo } from '../helpers/cms-signed-data-builder.js';
import {
    authenticatedSafe,
    certBag,
    dataInfo,
    encryptedSafeContents,
    friendlyName,
    localKeyId,
    pbmac1MacData,
    pfx,
    safeContents,
    shroudKey,
    shroudedKeyBag,
} from '../helpers/pkcs12-builder.js';
import { ascii, sequence, tlv, universal } from '../helpers/raw-der-builder.js';
import { issue, issueTsa, makeCrl, makeRoot, makeToken, sha, tstInfo } from '../verify/_cms-pki.js';

/** The target names, as `fuzz/<name>.js`. */
export type FuzzTarget = 'asn1' | 'cms' | 'crl' | 'ocsp' | 'pem' | 'pkcs12' | 'tsp' | 'x509';

const PASSWORD = 'fuzz-seed';

/** The committed certificates: foreign DER, the seed every target shares. */
export function fixtureSeeds(): Uint8Array[] {
    return readdirSync('tests/fixtures/certs')
        .filter((f) => f.endsWith('.der'))
        .sort()
        .map((f) => new Uint8Array(readFileSync(`tests/fixtures/certs/${f}`)));
}

/** An RFC 6960 §4.2.1 response, built field by field: `successful`, one `good` answer, responder by key hash. */
function ocspResponse(): Uint8Array {
    const generalized = (text: string): Uint8Array => universal(24, ascii(text));
    const certId = sequence(
        sequence(universal(6, [0x2b, 0x0e, 0x03, 0x02, 0x1a]), universal(5, [])),
        universal(4, new Array<number>(20).fill(0xaa)),
        universal(4, new Array<number>(20).fill(0xbb)),
        universal(2, [0x2a]),
    );
    const single = sequence(certId, tlv(2, false, 0, []), generalized('20260501000000Z'), tlv(2, true, 0, generalized('20260508000000Z')));
    const tbs = sequence(
        tlv(2, true, 2, universal(4, new Array<number>(20).fill(0xcc))),
        generalized('20260501000000Z'),
        sequence(single),
    );
    const basic = sequence(tbs, sequence(universal(6, [0x2b, 0x65, 0x70])), universal(3, [0x00, 0xde, 0xad]));
    const basicOid = universal(6, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]);
    return sequence(universal(10, [0]), tlv(2, true, 0, sequence(basicOid, universal(4, basic))));
}

/** Every target's seeds. Keys are generated, so two calls give different bytes of the same shapes. */
export async function fuzzSeeds(): Promise<Readonly<Record<FuzzTarget, readonly Uint8Array[]>>> {
    const fixtures = fixtureSeeds();
    const root = await makeRoot('Fuzz Seed Root');
    const signer = await issue(root, { subject: 'Fuzz Seed Signer', serial: 2n });
    const tsa = await issueTsa(root);

    // CMS: one SignedData this library wrote, one assembled without it.
    const signed = await createSignedData({ content: Uint8Array.from(ascii('fuzz seed')), certificate: signer.certificate }, signer.signer);

    // RFC 3161: the TSTInfo, the token around it, the response around that.
    const info = tstInfo({ imprint: await sha('SHA-256', Uint8Array.from(ascii('fuzz seed'))), nonce: 0x1234n });
    const token = await makeToken(tsa, info);
    const response = sequence(sequence(universal(2, [0])), token);

    // PKCS#12: a certificate and a shrouded key in a plain SafeContents, the
    // same certificate in an encrypted one, and a PBMAC1 over the lot.
    const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', signer.pair.privateKey as never));
    const shrouded = await shroudKey(pkcs8, PASSWORD);
    const keyId = localKeyId([1, 2, 3, 4]);
    const plain = dataInfo(safeContents(
        certBag(signer.certificate.der, [friendlyName('fuzz'), keyId]),
        shroudedKeyBag(shrouded, [keyId]),
    ));
    const encrypted = await encryptedSafeContents(safeContents(certBag(root.certificate.der)), PASSWORD);
    const authSafe = authenticatedSafe(plain, encrypted);
    const p12 = pfx({ authSafe, macData: await pbmac1MacData(authSafe, PASSWORD) });

    const pem = new TextEncoder().encode(`-----BEGIN CERTIFICATE-----\n${Buffer.from(signer.certificate.der).toString('base64').replace(/.{64}/g, '$&\n')}\n-----END CERTIFICATE-----\n`);

    return {
        asn1: [...fixtures, signed],
        x509: [...fixtures, signer.certificate.der, tsa.certificate.der],
        pem: [pem],
        cms: [signed, cmsContentInfo()],
        crl: [await makeCrl(root, [signer.certificate]), await makeCrl(root)],
        ocsp: [ocspResponse(), sequence(universal(10, [3]))],
        tsp: [response, token, info],
        pkcs12: [p12, pkcs8, shrouded],
    };
}

/** `npx tsx tests/fuzzing/_fuzz-seeds.ts <dir>`: write `<dir>/<target>/<n>.der`. */
async function main(argv: readonly string[]): Promise<number> {
    const dir = argv[0];
    if (dir === undefined || argv.length !== 1) {
        process.stderr.write('usage: npx tsx tests/fuzzing/_fuzz-seeds.ts <output directory>\n');
        return 2;
    }
    const seeds = await fuzzSeeds();
    for (const [target, list] of Object.entries(seeds)) {
        mkdirSync(join(dir, target), { recursive: true });
        list.forEach((seed, i) => { writeFileSync(join(dir, target, `${i}.der`), seed); });
        process.stdout.write(`${target}: ${list.length} seed(s)\n`);
    }
    return 0;
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
    main(process.argv.slice(2)).then((code) => process.exit(code), (err: unknown) => {
        process.stderr.write(`fuzz-seeds: ${(err as Error).stack ?? String(err)}\n`);
        process.exit(1);
    });
}
