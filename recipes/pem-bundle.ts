/**
 * Recipe: read a CA bundle — many PEM certificates in one text — and link
 * each certificate to its issuer by key identifier (a root is its own). The `label` option makes
 * a private key slipped into the bundle an error instead of a certificate.
 * pkinative exports no PEM-to-certificate shortcut: decodePem and
 * parseCertificate compose, as encoding/pem and crypto/x509 do in Go.
 */
import { decodePem, encodePem, formatDistinguishedName, getExtension, parseCertificate, PkiError } from 'pkinative';
import { FIXTURE_NAMES, fixture } from './_fixtures.ts';

const hex = (bytes: Uint8Array | undefined): string => [...(bytes ?? [])].map((b) => b.toString(16).padStart(2, '0')).join('');

export default function run(): Record<string, string> {
    const bundle = FIXTURE_NAMES.map((name) => encodePem('CERTIFICATE', fixture(name))).join('\n');

    const certificates = decodePem(bundle, { label: 'CERTIFICATE' }).map((block) => parseCertificate(block.bytes, { onDiagnostic: () => undefined }));
    const bySubjectKey = new Map(certificates.map((c) => [hex(getExtension(c, 'subjectKeyIdentifier')?.keyIdentifier), c]));

    const links = certificates.map((cert) => {
        // A root carries no authorityKeyIdentifier: its issuer name is its own subject, byte for byte.
        const selfIssued = hex(cert.issuer.der) === hex(cert.subject.der);
        const issuer = selfIssued ? cert : bySubjectKey.get(hex(getExtension(cert, 'authorityKeyIdentifier')?.keyIdentifier));
        return `${formatDistinguishedName(cert.subject).split(',')[0]} <- ${issuer === undefined ? '?' : formatDistinguishedName(issuer.subject).split(',')[0]}`;
    });

    let refused = '';
    try {
        decodePem(`${bundle}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n`, { label: 'CERTIFICATE' });
    } catch (error) {
        refused = error instanceof PkiError ? error.code : 'unexpected';
    }

    return {
        count: String(certificates.length),
        links: links.join('; '),
        privateKey: refused,
    };
}
