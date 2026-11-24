import { readFileSync, readdirSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import * as api from '../../src/index.js';
import {
    PkiError,
    createCertificationRequest,
    createOcspRequest,
    createTimeStampRequest,
    decodeAsn1,
    decodeAsn1Sequence,
    decodeExtensionValue,
    decodePem,
    encodeInteger,
    encodePem,
    encodeSequence,
    openSafeContents,
    parseAttributeCertificate,
    parseCertificate,
    parseCertificateList,
    parseCertificationRequest,
    parseEncryptedPrivateKeyInfo,
    parseOcspRequest,
    parseOcspResponse,
    parsePkcs12,
    parsePrivateKeyInfo,
    parseSignedData,
    parseTimeStampRequest,
    parseTimeStampResponse,
    parseTimeStampToken,
    parseTstInfo,
} from '../../src/index.js';
import { attributeCertificate } from '../helpers/attribute-certificate-builder.js';
import { bitString, utf8 } from '../helpers/cert-builder.js';
import { authenticatedSafe, certBag, dataInfo, friendlyName, keyBag, pfx, safeContents, shroudKey } from '../helpers/pkcs12-builder.js';
import { issue, issueTsa, keyPair, makeCrl, makeOcspResponse, makeRoot, makeToken, quiet, sha, spkiOf, tstInfo } from '../verify/_cms-pki.js';

/**
 * What a reader returns cannot be changed by who receives it.
 *
 * A decoded value is shared: the certificate a caller parsed once is the one
 * its path builder, its revocation check and its report all hold. Every reader
 * therefore freezes what it returns, to the last nested list — and the empty
 * list is where that is forgotten, because `[]` written inline is a new,
 * open array each time while its non-empty counterpart went through the
 * function that freezes.
 *
 * Each reader of the entry point is called on an input built here, and every
 * object and array reachable from its result is asserted frozen. The readers
 * are read from the entry point: one added later fails the first test until
 * it has an input in the table.
 */

/** Readers whose result has nothing to freeze, each with why. */
const NOTHING_TO_FREEZE: Readonly<Record<string, string>> = {
    decodeOid: 'returns a string',
};

/** Every object and array reachable from `value` that is not frozen, by path. */
function openPaths(value: unknown, path: string, seen = new Set<unknown>()): string[] {
    if (typeof value !== 'object' || value === null || ArrayBuffer.isView(value) || seen.has(value)) return [];
    seen.add(value);
    const here = Object.isFrozen(value) ? [] : [`${path}${Array.isArray(value) ? ` (array of ${String(value.length)})` : ''}`];
    return here.concat(Object.entries(value).flatMap(([key, member]) => openPaths(member, Array.isArray(value) ? `${path}[${key}]` : `${path}.${key}`, seen)));
}

/** The public certificates of the fixture tree, whatever envelope each came in. */
function fixtureCertificates(): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const entry of readdirSync('tests/fixtures', { recursive: true })) {
        const file = `tests/fixtures/${String(entry)}`;
        if (!/\.(der|crt|cer|pem)$/i.test(file)) continue;
        const raw = readFileSync(file);
        if (raw.subarray(0, 5).toString('latin1') !== '-----') {
            out.push(new Uint8Array(raw));
            continue;
        }
        for (const block of decodePem(raw.toString('latin1'), { mode: 'lax' })) {
            if (block.label === 'CERTIFICATE') out.push(block.bytes);
        }
    }
    return out;
}

describe('property — what a reader returns is frozen', () => {
    /** Reader name → the results to walk, each with a label for the failure message. */
    const results = new Map<string, Array<readonly [string, unknown]>>();
    const record = (reader: string, label: string, value: unknown): void => {
        results.set(reader, [...(results.get(reader) ?? []), [label, value]]);
    };

    beforeAll(async () => {
        const root = await makeRoot();
        const leaf = await issue(root);
        const tsa = await issueTsa(root);
        const hash = await sha('SHA-256', Uint8Array.of(1, 2, 3));
        const leafDer = leaf.certificate.der;

        record('parseCertificate', 'an issued certificate', parseCertificate(leafDer, quiet));
        record('parseCertificate', 'with extensions left undecoded', parseCertificate(leafDer, { ...quiet, decodeExtensions: false }));
        for (const [index, der] of fixtureCertificates().entries()) {
            // The tree also holds what is not a certificate; a refusal is not a result.
            try {
                record('parseCertificate', `fixture ${String(index)}`, parseCertificate(der, quiet));
            } catch (error) {
                if (!(error instanceof PkiError)) throw error;
            }
        }
        for (const extension of leaf.certificate.extensions) {
            record('decodeExtensionValue', extension.oid, decodeExtensionValue(extension.oid, extension.valueDer, quiet));
        }
        record('decodeAsn1', 'a certificate', decodeAsn1(leafDer));
        record('decodeAsn1Sequence', 'two certificates', decodeAsn1Sequence(Uint8Array.from([...leafDer, ...root.certificate.der])));
        record('decodePem', 'two blocks', decodePem(encodePem('CERTIFICATE', leafDer) + encodePem('CERTIFICATE', root.certificate.der)));

        record('parseCertificateList', 'an empty list', parseCertificateList(await makeCrl(root), quiet));
        record('parseCertificateList', 'one entry', parseCertificateList(await makeCrl(root, [leaf.certificate]), quiet));
        record('parseOcspResponse', 'good', parseOcspResponse(await makeOcspResponse(root, leaf.certificate, 'good'), quiet));
        record('parseOcspResponse', 'revoked', parseOcspResponse(await makeOcspResponse(root, leaf.certificate, 'revoked'), quiet));
        // malformedRequest: a response with a status and no body.
        record('parseOcspResponse', 'no body', parseOcspResponse(encodeSequence([Uint8Array.of(0x0a, 0x01, 0x01)]), quiet));
        record('parseOcspRequest', 'bare', parseOcspRequest(createOcspRequest(leaf.certificate, root.certificate), quiet));
        record('parseOcspRequest', 'with a nonce', parseOcspRequest(createOcspRequest(leaf.certificate, root.certificate, { nonce: new Uint8Array(16).fill(7) }), quiet));

        record('parseTimeStampRequest', 'bare', parseTimeStampRequest(createTimeStampRequest(hash), quiet));
        record('parseTimeStampRequest', 'with a nonce, a policy and certReq', parseTimeStampRequest(createTimeStampRequest(hash, { nonce: 5n, policy: '1.2.3.4', certReq: true }), quiet));
        const info = tstInfo({ imprint: hash });
        const token = await makeToken(tsa, info);
        record('parseTstInfo', 'minimal', parseTstInfo(info, quiet));
        record('parseTstInfo', 'with a nonce and ordering', parseTstInfo(tstInfo({ imprint: hash, nonce: 9n, ordering: true }), quiet));
        record('parseTimeStampToken', 'a token', parseTimeStampToken(token, quiet));
        record('parseSignedData', 'a token', parseSignedData(token, quiet));
        record('parseTimeStampResponse', 'granted', parseTimeStampResponse(encodeSequence([encodeSequence([encodeInteger(0)]), token]), quiet));
        record('parseTimeStampResponse', 'rejected', parseTimeStampResponse(encodeSequence([encodeSequence([encodeInteger(2)])]), quiet));
        // PKIStatusInfo with its two optional lists: one statusString, and failInfo bit 0 (badAlg).
        record('parseTimeStampResponse', 'rejected, saying why', parseTimeStampResponse(
            encodeSequence([encodeSequence([encodeInteger(2), encodeSequence([utf8('no')]), bitString([0x80], 7)])]), quiet));

        record('parseCertificationRequest', 'a request', parseCertificationRequest(
            await createCertificationRequest({ subject: [[{ type: '2.5.4.3', value: 'frozen' }]], subjectPublicKey: await spkiOf(leaf.pair) }, leaf.signer), quiet));
        record('parseAttributeCertificate', 'the builder\'s default', parseAttributeCertificate(attributeCertificate(), quiet));

        const pair = await keyPair('ECDSA');
        const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey as never));
        record('parsePrivateKeyInfo', 'an exported key', parsePrivateKeyInfo(pkcs8, quiet));
        record('parseEncryptedPrivateKeyInfo', 'a shrouded key', parseEncryptedPrivateKeyInfo(await shroudKey(pkcs8, 'password'), quiet));
        const pkcs12 = parsePkcs12(pfx({ authSafe: authenticatedSafe(dataInfo(safeContents(certBag(leafDer, [friendlyName('leaf')]), keyBag(pkcs8)))) }), quiet);
        record('parsePkcs12', 'a certificate and a key, unencrypted', pkcs12);
        record('parsePkcs12', 'no content', parsePkcs12(pfx({ authSafe: authenticatedSafe() }), quiet));
        for (const contents of pkcs12.contents) record('openSafeContents', 'unencrypted', await openSafeContents(contents, 'password', quiet));
    });

    it('should have an input for every reader of the entry point', () => {
        const readers = Object.keys(api).filter((name) => /^(parse|decode)[A-Z]/.test(name) || name === 'openSafeContents').sort();
        expect([...results.keys(), ...Object.keys(NOTHING_TO_FREEZE)].sort()).toEqual(readers);
    });

    it('should freeze every object and every list, the empty ones included', () => {
        const open = [...results].flatMap(([reader, values]) => values.flatMap(([label, value]) => openPaths(value, `${reader}(${label})`)));
        expect(open, open.join('\n')).toEqual([]);
    });
});
