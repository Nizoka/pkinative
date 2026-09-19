/**
 * Recipe: walk every extension of a certificate — the decoded ones by kind,
 * the critical flags, the profile diagnostics — then keep one extension raw
 * and decode it on demand, the way an inspection tool reads certificates it
 * must not reject.
 */
import { decodeExtensionValue, getExtension, getOidName, parseCertificate, type PkiDiagnostic } from 'pkinative';
import { fixture } from './_fixtures.ts';

export default function run(): Record<string, string> {
    const der = fixture('letsencrypt-org-leaf');
    const cert = parseCertificate(der);

    const kinds = cert.extensions.map((e) => `${e.kind}${e.critical ? '!' : ''}`);
    const policies = getExtension(cert, 'certificatePolicies')?.policies.map((p) => getOidName(p.policyIdentifier) ?? p.policyIdentifier) ?? [];
    const crl = getExtension(cert, 'crlDistributionPoints')?.points[0]?.fullName?.[0];

    // Tools that must show a certificate even when an extension is malformed
    // parse with decodeExtensions: false, then decode what they need.
    const raw = parseCertificate(der, { decodeExtensions: false });
    const keyUsage = raw.extensions.find((e) => e.oid === '2.5.29.15');
    const decoded = keyUsage === undefined ? undefined : decodeExtensionValue(keyUsage.oid, keyUsage.valueDer, { critical: keyUsage.critical });

    // The RFC 8410 example encodes DEFAULT values explicitly: read, and reported.
    const seen: PkiDiagnostic[] = [];
    parseCertificate(fixture('rfc8410-x25519'), { onDiagnostic: (d) => { seen.push(d); } });

    return {
        extensions: kinds.join(','),
        policy: policies.join(','),
        crl: crl?.kind === 'uniformResourceIdentifier' ? crl.value : '',
        rawKinds: [...new Set(raw.extensions.map((e) => e.kind))].join(','),
        onDemand: decoded?.kind === 'keyUsage' ? decoded.usages.join(',') : '',
        diagnostics: seen.map((d) => `${d.code}@${d.path}`).join(' '),
    };
}
