import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CORPORA } from '../../scripts/lib/corpora.js';
import { expectationOfName } from '../../scripts/lib/pkits.js';
import { reasonLayer, reasonsBeyondPath, splitPkitsMessage, testsOfSigner } from '../../scripts/lib/pkits-smime.js';
import * as pki from '../../src/index.js';

/**
 * Taking a PKITS `multipart/signed` message apart, without the corpus.
 *
 * The one rule this must get exactly right is which line break belongs to the
 * content. RFC 2046 §5.1.1 gives the break before a delimiter to the
 * delimiter; PKITS writes its envelope with bare LF and its signed part with
 * CRLF. Measured on all 224 messages of the pinned archive before this was
 * written: the content the signer hashed ends with the part's own CRLF, and
 * the bare LF after it is the delimiter's.
 */

const encoder = new TextEncoder();
const SIGNATURE = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01]);

function message(boundary: string, signedPart: string): Uint8Array {
    return encoder.encode([
        'To: recipient@testcertificates.gov',
        `Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"; boundary="${boundary}"`,
        '',
        'This is an S/MIME signed message',
        '',
        `--${boundary}`,
        signedPart,
        `--${boundary}`,
        'Content-Type: application/pkcs7-signature; name="smime.p7s"',
        'Content-Transfer-Encoding: base64',
        '',
        btoa(String.fromCharCode(...SIGNATURE)),
        '',
        `--${boundary}--`,
        '',
    ].join('\n'));
}

describe('splitPkitsMessage', () => {
    it('should keep the part\'s own CRLF and give the envelope\'s LF to the delimiter', () => {
        const signed = 'Content-Type: text/plain\r\n\r\nThis is a sample signed message.\r\n';
        const split = splitPkitsMessage('smime/SignedValidSignaturesTest1.eml', message('----B', signed));
        expect(new TextDecoder().decode(split.content)).toBe(signed);
        expect(split.signature).toEqual(SIGNATURE);
        expect(split.test).toBe('ValidSignaturesTest1');
    });

    it('should give a CRLF before the delimiter to the delimiter too', () => {
        // Every bare LF of the envelope made CRLF; the part's own CRLF left alone.
        const bytes = encoder.encode(new TextDecoder().decode(message('----B', 'Content-Type: text/plain\r\n\r\nbody')).replace(/(?<!\r)\n/g, '\r\n'));
        expect(new TextDecoder().decode(splitPkitsMessage('smime/SignedValidTest2.eml', bytes).content)).toBe('Content-Type: text/plain\r\n\r\nbody');
    });

    it('should hand back a view of the input, not a re-encoding of it', () => {
        const bytes = message('----B', 'Content-Type: text/plain\r\n\r\nbody\r\n');
        expect(splitPkitsMessage('smime/SignedValidTest3.eml', bytes).content.buffer).toBe(bytes.buffer);
    });

    it.each([
        ['names no boundary', encoder.encode('To: x\n\nplain text\n')],
        ['has one part only', encoder.encode('Content-Type: multipart/signed; boundary="B"\n\n--B\nbody\n--B--\n')],
    ])('should refuse a message that %s', (_, bytes) => {
        expect(() => splitPkitsMessage('smime/SignedValidTest4.eml', bytes)).toThrow(/pkits-smime/);
    });

    it('should refuse a file name that does not follow the PKITS convention', () => {
        expect(() => splitPkitsMessage('smime/other.eml', message('----B', 'x\r\n'))).toThrow(/naming/);
    });
});

describe('testsOfSigner', () => {
    const root = pki.parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/isrg-root-x1.der')), { onDiagnostic: () => undefined });
    const leaf = pki.parseCertificate(new Uint8Array(readFileSync('tests/fixtures/certs/letsencrypt-org-leaf.der')), { onDiagnostic: () => undefined });
    const tests = new Map([['ValidRootTest1', root], ['ValidLeafTest2', leaf]]);

    it('should link an issuerAndSerialNumber signer to the one certificate it names', () => {
        const sid = { kind: 'issuerAndSerialNumber', issuer: leaf.issuer, serialNumber: leaf.serialNumber } as const;
        expect(testsOfSigner(pki, sid, tests)).toEqual(['ValidLeafTest2']);
    });

    it('should not link on the issuer alone', () => {
        // Same issuer, another serial: a different certificate.
        const serialNumber = { ...leaf.serialNumber, bytes: Uint8Array.of(1) };
        expect(testsOfSigner(pki, { kind: 'issuerAndSerialNumber', issuer: leaf.issuer, serialNumber }, tests)).toEqual([]);
    });

    it('should link a subjectKeyIdentifier signer through the certificate\'s own extension', () => {
        const keyIdentifier = pki.getExtension(root, 'subjectKeyIdentifier')?.keyIdentifier ?? new Uint8Array();
        expect(testsOfSigner(pki, { kind: 'subjectKeyIdentifier', keyIdentifier }, tests)).toEqual(['ValidRootTest1']);
        expect(testsOfSigner(pki, { kind: 'subjectKeyIdentifier', keyIdentifier: Uint8Array.of(1, 2, 3) }, tests)).toEqual([]);
    });
});

describe('reasonLayer', () => {
    it.each([
        ['signerInfos[0].chain', 'chain'],
        ['signerInfos[0].chain.crl', 'chain'],
        ['signerInfos[12].chain.path[0]', 'chain'],
        ['signerInfos[0]', 'cms'],
        ['signerInfos[0].signature', 'cms'],
        ['signerInfos[0].unsignedAttrs.timeStampToken[0]', 'cms'],
        ['signerInfos[0].chainless', 'cms'],
        ['signedData', 'cms'],
    ])('should put %s in the %s layer', (path, layer) => {
        expect(reasonLayer(path)).toBe(layer);
    });
});

describe('reasonsBeyondPath', () => {
    it('should compare sets, so a list supplied twice is not a new reason', () => {
        expect(reasonsBeyondPath(['PKI_REASON_REVOKED', 'PKI_REASON_REVOKED'], ['PKI_REASON_REVOKED'])).toEqual([]);
    });

    it('should accept a message refused for fewer of the path\'s reasons', () => {
        // L7's bag holds cross-certificates a message does not carry; the
        // detour they cost there is not a reason the message must repeat.
        expect(reasonsBeyondPath(['PKI_REASON_NAME_NOT_PERMITTED'], ['PKI_REASON_SIGNATURE_INVALID', 'PKI_REASON_NAME_NOT_PERMITTED'])).toEqual([]);
    });

    it('should name every reason the path is not refused for, once and sorted', () => {
        expect(reasonsBeyondPath(['PKI_REASON_REVOKED', 'PKI_REASON_EXPIRED', 'PKI_REASON_EXPIRED'], [])).toEqual(['PKI_REASON_EXPIRED', 'PKI_REASON_REVOKED']);
    });
});

/**
 * The L8 baseline, held to the discipline of L6 and L7 without the corpus:
 * every accepted difference carries a sentence someone wrote, the canaries are
 * set, and the claims keep their shape.
 */
interface SmimeBaseline {
    readonly corpus: string;
    readonly commit: string;
    readonly canaries: { readonly mustSucceed: string; readonly mustFail: string };
    readonly totals: { readonly messages: number; readonly intact: number; readonly scored: number; readonly agree: number; readonly deviations: number; readonly skipped: number };
    readonly notIntact: Readonly<Record<string, { readonly reasons: string; readonly why: string }>>;
    readonly deviations: Readonly<Record<string, { readonly test: string; readonly expected: string; readonly why: string }>>;
    readonly pathDisagreements: Readonly<Record<string, { readonly test: string; readonly why: string }>>;
    readonly reasons: Readonly<Record<string, string>>;
}

interface PathBaseline {
    readonly deviations: Readonly<Record<string, { readonly expected: string }>>;
}

describe('the NIST PKITS S/MIME score baseline', () => {
    const baseline = JSON.parse(readFileSync('scripts/data/pkits-smime-score.json', 'utf8')) as SmimeBaseline;
    const paths = JSON.parse(readFileSync('scripts/data/pkits-score.json', 'utf8')) as PathBaseline;
    const ecosystem = JSON.parse(readFileSync('docs/assets/ecosystem.json', 'utf8')) as { declared: { pkits: Record<string, number> } };
    const deviations = Object.keys(baseline.deviations);
    const reviewed = [
        ...Object.values(baseline.notIntact),
        ...Object.values(baseline.deviations),
        ...Object.values(baseline.pathDisagreements),
    ];

    it('should be pinned to the archive the gate fetches', () => {
        expect(baseline.corpus).toBe('pkits');
        expect(baseline.commit).toBe(CORPORA.find((c) => c.id === 'pkits')?.commit);
    });

    it('should carry a written reason, not a placeholder, for every reviewed entry', () => {
        expect(reviewed.filter((entry) => entry.why.trim().length < 120)).toEqual([]);
    });

    it('should deviate from NIST only where L7 deviates on the signer\'s own test', () => {
        // Claim (b), in the one form a diff can show: a message verdict that
        // differs from NIST while its path verdict does not would need a
        // reviewed path disagreement, and there is none to hide behind.
        for (const [name, entry] of Object.entries(baseline.deviations)) {
            if (Object.hasOwn(baseline.pathDisagreements, name)) continue;
            expect(paths.deviations[entry.test]?.expected, name).toBe(entry.expected);
        }
    });

    it('should name two canaries whose names say what they expect, and neither a deviation', () => {
        const { mustSucceed, mustFail } = baseline.canaries;
        expect(expectationOfName(mustSucceed)).toBe(true);
        expect(expectationOfName(mustFail)).toBe(false);
        expect(deviations).not.toContain(mustSucceed);
        expect(deviations).not.toContain(mustFail);
        expect(Object.keys(baseline.notIntact)).not.toContain(mustSucceed);
    });

    it('should review every signer the CMS layer does not find intact on a CMS-layer code', () => {
        for (const [name, entry] of Object.entries(baseline.notIntact)) {
            expect(entry.reasons, name).toMatch(/^PKI_REASON_[A-Z_]+(?:,PKI_REASON_[A-Z_]+)*$/);
        }
    });

    it('should pin messages on their reason codes without pinning a deviation', () => {
        const pins = Object.keys(baseline.reasons);
        expect(pins.length).toBeGreaterThan(20);
        expect(pins.filter((name) => deviations.includes(name))).toEqual([]);
        for (const [name, codes] of Object.entries(baseline.reasons)) {
            for (const code of codes.split(',')) expect(code, name).toMatch(/^PKI_REASON_[A-Z_]+$/);
        }
    });

    it('should keep the totals self-consistent and equal to the declared canaries', () => {
        const { totals } = baseline;
        expect(totals.agree + totals.deviations).toBe(totals.scored);
        expect(totals.scored + totals.skipped).toBe(totals.messages);
        expect(totals.deviations).toBe(deviations.length);
        expect(totals.messages - totals.intact).toBe(Object.keys(baseline.notIntact).length);
        expect(ecosystem.declared.pkits['messages']).toBe(totals.messages);
        expect(ecosystem.declared.pkits['messagesIntact']).toBe(totals.intact);
        expect(ecosystem.declared.pkits['messagesAgree']).toBe(totals.agree);
    });
});
