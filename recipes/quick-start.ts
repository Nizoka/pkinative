/**
 * Recipe: the README quick start — read PEM certificates and print what a
 * person checks first: who, issued by whom, valid when, for which names, and
 * the fingerprint. The block between the quick-start markers is the README
 * code block, character for character (tests/docs/recipes.test.ts).
 */
import { encodePem } from 'pkinative';
import { fixture } from './_fixtures.ts';

// quick-start:begin
import { computeFingerprint, decodePem, formatDistinguishedName, formatFingerprint, getExtension, parseCertificate } from 'pkinative';

export function describeCertificates(pemText: string): string[] {
    const lines: string[] = [];
    for (const { bytes } of decodePem(pemText, { label: 'CERTIFICATE' })) {
        const cert = parseCertificate(bytes);
        const names = getExtension(cert, 'subjectAltName')?.names ?? [];
        const iso = (ms: number): string => new Date(ms).toISOString();
        lines.push(
            `subject: ${formatDistinguishedName(cert.subject)}`,
            `issuer:  ${formatDistinguishedName(cert.issuer)}`,
            `valid:   ${iso(cert.validity.notBefore.epochMilliseconds)} → ${iso(cert.validity.notAfter.epochMilliseconds)}`,
            `names:   ${names.map((n) => (n.kind === 'dNSName' ? n.value : n.kind)).join(', ')}`,
            `sha-256: ${formatFingerprint(computeFingerprint(bytes, 'SHA-256'))}`,
        );
    }
    return lines;
}
// quick-start:end

export default function run(): Record<string, string> {
    const lines = describeCertificates(encodePem('CERTIFICATE', fixture('letsencrypt-org-leaf')));
    return {
        subject: lines[0] ?? '',
        issuer: lines[1] ?? '',
        valid: lines[2] ?? '',
        firstName: (lines[3] ?? '').split(', ')[0] ?? '',
        fingerprint: lines[4] ?? '',
    };
}
