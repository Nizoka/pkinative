import { describe, it, expect } from 'vitest';
import { parseCertificate } from '../../src/x509/x509-certificate.js';
import { PkiError } from '../../src/types/pki-errors.js';
import { BASIC_CONSTRAINTS_CA, certificate, context, explicit, extension, octetString, rsaKey } from '../helpers/cert-builder.js';
import { sequence } from '../helpers/raw-der-builder.js';

const QUIET = { onDiagnostic: (): void => undefined };

/** A certificate, or the code of the PkiError it ends in; any other exception fails the suite. */
function outcome(bytes: Uint8Array): string {
    try {
        parseCertificate(bytes, QUIET);
        return 'ok';
    } catch (error) {
        if (error instanceof PkiError) return error.code;
        throw error;
    }
}

const SAMPLES: ReadonlyArray<readonly [string, Uint8Array]> = [
    ['an EC certificate', certificate()],
    ['an RSA certificate with unique identifiers and two extensions', certificate({
        subjectPublicKeyInfo: rsaKey([0x00, 0xc1, 0x02, 0x03, 0x04]),
        trailing: [
            context(1, false, [0x00, 0xaa]),
            context(2, false, [0x00, 0xbb]),
            explicit(3, sequence(BASIC_CONSTRAINTS_CA, extension('2.5.29.14', octetString([1, 2, 3])))),
        ],
    })],
];

describe('parseCertificate under truncation', () => {
    it.each(SAMPLES)('should refuse every proper prefix of %s with a PkiError', (_, der) => {
        for (let length = 0; length < der.length; length++) {
            expect(outcome(der.subarray(0, length)), `prefix of ${length} octets`).not.toBe('ok');
        }
    });
});

describe('parseCertificate under single-octet mutation', () => {
    it.each(SAMPLES)('should end every mutation of %s in a certificate or a PkiError', (_, der) => {
        const outcomes = new Set<string>();
        for (let i = 0; i < der.length; i++) {
            for (const value of [0x00, 0x80, 0xff, (der[i] ?? 0) ^ 0x01]) {
                const mutated = der.slice();
                mutated[i] = value;
                outcomes.add(outcome(mutated));
            }
        }
        expect(outcomes.has('ok')).toBe(true);
        expect(outcomes.size).toBeGreaterThan(5);
    });
});
