/**
 * Recipe: the docs/agent-brief.md sample — compose `decodePem` and
 * `parseCertificate` (there is no `parsePemCertificates`) and read the host
 * names out of subjectAltName. The block between the agent-brief markers is
 * the brief's code block, character for character (tests/docs/recipes.test.ts),
 * so an agent that copies it gets code that runs.
 */
import { encodePem } from 'pkinative';
import { fixture } from './_fixtures.ts';

// agent-brief:begin
import { decodePem, getExtension, parseCertificate } from 'pkinative';

export function hostNames(pemText: string): string[] {
    const names: string[] = [];
    for (const { bytes } of decodePem(pemText, { label: 'CERTIFICATE' })) {
        const cert = parseCertificate(bytes);
        for (const name of getExtension(cert, 'subjectAltName')?.names ?? []) {
            if (name.kind === 'dNSName') names.push(name.value);
        }
    }
    return names;
}
// agent-brief:end

export default function run(): Record<string, string> {
    const pemText = encodePem('CERTIFICATE', fixture('letsencrypt-org-leaf'));
    return { names: hostNames(pemText).join(',') };
}
