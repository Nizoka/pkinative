/**
 * pkinative — the interoperability matrix, read direction: signed structures
 * ==========================================================================
 * Foreign tools writing what pkinative verifies: CMS SignedData, RFC 3161
 * tokens, OCSP responses, CRLs — each made by the tool from keys it generated
 * itself, and each with the verdict pkinative must reach written down in
 * `READ_CASES` (scripts/lib/interop.ts). The oracle is the tool: it signed,
 * so the signature is good, the revocation it recorded is the revocation, the
 * imprint it stamped is the imprint.
 *
 * Everything pkinative is handed is DER the tool itself wrote — PEM is
 * unwrapped here with a regular expression and Buffer, never with pkinative's
 * own decoder, so a defect there cannot hide one here.
 *
 * A case the installed tool cannot write is a skip when the tool is not the
 * reference build (OpenSSL before 3.0, LibreSSL), and a failure when it is:
 * there, a command that fails is a defect of this runner, and a green run that
 * skipped it would be green about nothing.
 *
 * @module scripts/lib/interop-reads
 */

import { X509Certificate } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    parseCertificate,
    PkiError,
    verifyCertificateChain,
    verifySignedData,
    verifyTimeStampToken,
    type Certificate,
} from '../../src/index.js';
import { READ_CASES } from './interop.js';
import { firstLine, locate, type Host, type Ran } from './interop-host.js';

const PROGRAMS = join(dirname(fileURLToPath(import.meta.url)), '..', 'validators');

export interface ReadRun {
    readonly checks: number;
    readonly lines: readonly string[];
    readonly failures: readonly string[];
    readonly skips: readonly string[];
}

/** One case's evaluation: the messages that make it fail, empty when pkinative decided as declared. */
type Evaluate = () => Promise<string[]>;

interface Written {
    readonly cases: ReadonlyMap<string, Evaluate>;
    readonly skipped: ReadonlyMap<string, string>;
    /** Commands that failed on a reference build. */
    readonly failures: readonly string[];
}

// ── Helpers ─────────────────────────────────────────────────────────

/** Every PEM block of `label` in a file, as DER — Buffer's base64, not pkinative's decoder. */
export function pemBlocks(text: string, label: string): Uint8Array[] {
    const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`, 'g');
    return [...text.matchAll(re)].map((m) => new Uint8Array(Buffer.from((m[1] ?? '').replace(/\s+/g, ''), 'base64')));
}

const read = (path: string): Uint8Array => new Uint8Array(readFileSync(path));
const cert = (der: Uint8Array): Certificate => parseCertificate(der, { onDiagnostic: () => undefined });
const certPem = (path: string): Certificate => cert(new Uint8Array(new X509Certificate(readFileSync(path)).raw));
const codes = (reasons: readonly { readonly code: string }[]): string => reasons.map((r) => r.code).join(', ') || 'no reason';

/** `valid`, or the reasons it is not. */
function expectValid(what: string, report: { readonly valid: boolean; readonly reasons: readonly { readonly code: string }[] }): string[] {
    return report.valid ? [] : [`${what}: not valid (${codes(report.reasons)})`];
}

function expectReason(what: string, report: { readonly valid: boolean; readonly reasons: readonly { readonly code: string }[] }, code: string): string[] {
    if (report.valid) return [`${what}: valid, expected ${code}`];
    return report.reasons.some((r) => r.code === code) ? [] : [`${what}: refused with ${codes(report.reasons)}, expected ${code}`];
}

/** Run each command in turn; the first failure stops and is returned. */
function steps(host: Host, commands: readonly (readonly string[])[], options: { readonly cwd?: string } = {}): Ran | null {
    for (const args of commands) {
        const r = host.run(args, options);
        if (r.status !== 0) return { ...r, stderr: `${args.slice(0, 2).join(' ')}: ${firstLine(r)}` };
    }
    return null;
}

// ── OpenSSL ─────────────────────────────────────────────────────────

function opensslConfig(dir: string): string {
    const d = dir.replace(/\\/g, '/');
    return `[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = unused
[ v3_root ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier = hash
[ v3_signer ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
extendedKeyUsage = emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_leaf ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_tsa ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_ocsp ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,OCSPSigning
noCheck = ignored
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ${d}
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/root.pem
private_key = $dir/root.key
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_days = 30
default_crl_days = 7
policy = policy_any
unique_subject = no
copy_extensions = none
crl_extensions = crl_ext
[ policy_any ]
commonName = supplied
[ crl_ext ]
authorityKeyIdentifier = keyid:always
[ tsa ]
default_tsa = tsa_rsa
[ tsa_rsa ]
dir = ${d}
serial = $dir/tsaserial
crypto_device = builtin
signer_cert = $dir/tsa.pem
certs = $dir/root.pem
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.3.1
digests = sha256, sha384, sha512
accuracy = secs:1
ess_cert_id_alg = sha256
`;
}

const KEYS: Readonly<Record<string, readonly string[]>> = {
    rsa: ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    p384: ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384'],
    p256: ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'],
    ed25519: ['-algorithm', 'ED25519'],
};

/** Everything OpenSSL writes for the `openssl:*` cases, and the evaluations. */
function opensslWrites(o: Host, dir: string, reference: boolean): Written {
    const cases = new Map<string, Evaluate>();
    const skipped = new Map<string, string>();
    const failures: string[] = [];
    const ids = READ_CASES.filter((c) => c.tool === 'openssl').map((c) => c.id);
    const giveUp = (which: readonly string[], r: Ran): void => {
        for (const id of which) {
            if (reference) failures.push(`${id}: ${o.command} could not write it (${firstLine(r)}) — on a reference build that is a defect of this runner`);
            else skipped.set(id, `this openssl cannot write it (${firstLine(r)})`);
        }
    };
    const f = (name: string): string => join(dir, name);
    const cnf = f('openssl.cnf');
    writeFileSync(cnf, opensslConfig(dir));
    mkdirSync(f('newcerts'), { recursive: true });
    writeFileSync(f('index.txt'), '');
    writeFileSync(f('serial'), '1000\n');
    writeFileSync(f('crlnumber'), '01\n');
    writeFileSync(f('tsaserial'), '01\n');
    const data = new TextEncoder().encode('pkinative interop, signed by OpenSSL\n');
    writeFileSync(f('data.txt'), data);

    const issue = (name: string, key: string, extensions: string): (readonly string[])[] => [
        ['genpkey', ...(KEYS[key] ?? []), '-out', f(`${name}.key`)],
        ['req', '-new', '-key', f(`${name}.key`), '-subj', `/CN=${name}.example.com`, '-config', cnf, '-out', f(`${name}.csr`)],
        ['ca', '-batch', '-config', cnf, '-extensions', extensions, '-in', f(`${name}.csr`), '-out', f(`${name}.pem`), '-notext'],
    ];
    const setup = steps(o, [
        ['genpkey', ...(KEYS['rsa'] ?? []), '-out', f('root.key')],
        ['req', '-x509', '-new', '-key', f('root.key'), '-subj', '/CN=pkinative interop openssl root', '-days', '30', '-sha256', '-config', cnf, '-extensions', 'v3_root', '-out', f('root.pem')],
        ...issue('signer-rsa', 'rsa', 'v3_signer'),
        ...issue('signer-p384', 'p384', 'v3_signer'),
        ...issue('signer-ed25519', 'ed25519', 'v3_signer'),
        ...issue('tsa', 'rsa', 'v3_tsa'),
        ...issue('ocsp', 'p256', 'v3_ocsp'),
        ...issue('good', 'p256', 'v3_leaf'),
        ...issue('revoked1', 'p256', 'v3_leaf'),
        ...issue('revoked2', 'p256', 'v3_leaf'),
    ]);
    if (setup !== null) { giveUp(ids, setup); return { cases, skipped, failures }; }
    const root = (): Certificate => certPem(f('root.pem'));
    const leaf = (name: string): Certificate => certPem(f(`${name}.pem`));

    // CMS SignedData.
    const sign = (out: string, signer: string, extra: readonly string[]): readonly string[] =>
        ['cms', '-sign', '-in', f('data.txt'), '-binary', '-signer', f(`${signer}.pem`), '-inkey', f(`${signer}.key`), '-outform', 'DER', '-out', f(out), ...extra];
    const cms: readonly [string, readonly string[], boolean][] = [
        ['openssl:cms-rsa', sign('cms-rsa.der', 'signer-rsa', ['-nodetach']), false],
        ['openssl:cms-rsa-pss', sign('cms-rsa-pss.der', 'signer-rsa', ['-keyopt', 'rsa_padding_mode:pss']), true],
        ['openssl:cms-ecdsa', sign('cms-ecdsa.der', 'signer-p384', ['-nodetach', '-md', 'sha384']), false],
        // RFC 8419 §3.1: SHA-512 with Ed25519; OpenSSL 3.5 has no default digest for it.
        ['openssl:cms-ed25519', sign('cms-ed25519.der', 'signer-ed25519', ['-md', 'sha512']), true],
    ];
    for (const [id, args, detached] of cms) {
        const r = o.run(args);
        if (r.status !== 0) { giveUp([id], r); continue; }
        const out = args[args.indexOf('-out') + 1] ?? '';
        cases.set(id, async () => expectValid(id, await verifySignedData({ signedData: read(out), ...(detached ? { content: data } : {}), trustAnchors: [root()] })));
    }
    const stream = o.run(sign('cms-ber.der', 'signer-rsa', ['-nodetach', '-stream']));
    if (stream.status !== 0) giveUp(['openssl:cms-ber-stream'], stream);
    else {
        cases.set('openssl:cms-ber-stream', async () => {
            const out: string[] = [];
            const signedData = read(f('cms-ber.der'));
            try {
                const strict = await verifySignedData({ signedData, trustAnchors: [root()] });
                if (strict.valid) out.push('openssl:cms-ber-stream: valid under the default DER rules, which an indefinite length breaks');
            } catch (error) {
                const message = error instanceof Error ? error.message : String(error);
                if (!(error instanceof PkiError) || !message.includes("'ber'")) out.push(`openssl:cms-ber-stream: refused under DER without naming the remedy encodingRules: 'ber' (${message.slice(0, 160)})`);
            }
            out.push(...expectValid('openssl:cms-ber-stream with encodingRules ber', await verifySignedData({ signedData, trustAnchors: [root()], encodingRules: 'ber' })));
            return out;
        });
    }
    if (cases.has('openssl:cms-rsa')) {
        // One content octet changed after signing: "interop" → "interOp".
        const bytes = read(f('cms-rsa.der'));
        const at = Buffer.from(bytes).indexOf('interop');
        if (at < 0) failures.push('openssl:cms-tampered: the content was not found in the attached SignedData');
        else {
            bytes[at + 5] = 0x4f;
            writeFileSync(f('cms-tampered.der'), bytes);
            cases.set('openssl:cms-tampered', async () => expectReason('openssl:cms-tampered', await verifySignedData({ signedData: bytes, trustAnchors: [root()] }), 'PKI_REASON_CMS_DIGEST_MISMATCH'));
        }
    } else skipped.set('openssl:cms-tampered', 'no attached SignedData to tamper with');

    // RFC 3161.
    const ts = steps(o, [
        ['ts', '-query', '-data', f('data.txt'), '-sha256', '-cert', '-out', f('q.tsq')],
        ['ts', '-reply', '-config', cnf, '-section', 'tsa_rsa', '-queryfile', f('q.tsq'), '-out', f('r.tsr')],
    ]);
    if (ts !== null) giveUp(['openssl:tsp-reply'], ts);
    else {
        cases.set('openssl:tsp-reply', async () => {
            const input = { response: read(f('r.tsr')), request: read(f('q.tsq')), trustAnchors: [root()] };
            return [
                ...expectValid('openssl:tsp-reply', await verifyTimeStampToken({ ...input, data })),
                ...expectReason('openssl:tsp-reply against other data', await verifyTimeStampToken({ ...input, data: new TextEncoder().encode('other data') }), 'PKI_REASON_TSP_IMPRINT_MISMATCH'),
            ];
        });
    }

    // Revocation: one certificate revoked, a CRL; a second revoked, the next
    // CRL and the delta between them; OCSP answers from the same index.
    const revocation = steps(o, [
        ['ca', '-config', cnf, '-revoke', f('revoked1.pem'), '-crl_reason', 'keyCompromise'],
        ['ca', '-config', cnf, '-gencrl', '-out', f('crl1.pem')],
        ['ocsp', '-issuer', f('root.pem'), '-cert', f('good.pem'), '-reqout', f('req-good.der')],
        ['ocsp', '-index', f('index.txt'), '-CA', f('root.pem'), '-rsigner', f('ocsp.pem'), '-rkey', f('ocsp.key'), '-reqin', f('req-good.der'), '-respout', f('resp-good.der'), '-ndays', '7'],
        ['ocsp', '-issuer', f('root.pem'), '-cert', f('revoked1.pem'), '-reqout', f('req-revoked.der')],
        ['ocsp', '-index', f('index.txt'), '-CA', f('root.pem'), '-rsigner', f('ocsp.pem'), '-rkey', f('ocsp.key'), '-reqin', f('req-revoked.der'), '-respout', f('resp-revoked.der'), '-ndays', '7'],
    ]);
    if (revocation !== null) {
        giveUp(['openssl:ocsp-good', 'openssl:ocsp-revoked', 'openssl:crl-base', 'openssl:crl-delta'], revocation);
        return { cases, skipped, failures };
    }
    const chain = (name: string, extra: { crls?: Uint8Array[]; ocspResponses?: Uint8Array[] }): ReturnType<typeof verifyCertificateChain> =>
        verifyCertificateChain({ leaf: leaf(name), trustAnchors: [root()], requireRevocation: true, ...extra });
    const crl = (name: string): Uint8Array => pemBlocks(readFileSync(f(name), 'utf8'), 'X509 CRL')[0] ?? new Uint8Array(0);
    cases.set('openssl:ocsp-good', async () => expectValid('openssl:ocsp-good', await chain('good', { ocspResponses: [read(f('resp-good.der'))] })));
    cases.set('openssl:ocsp-revoked', async () => expectReason('openssl:ocsp-revoked', await chain('revoked1', { ocspResponses: [read(f('resp-revoked.der'))] }), 'PKI_REASON_REVOKED'));
    cases.set('openssl:crl-base', async () => [
        ...expectReason('openssl:crl-base, the revoked certificate', await chain('revoked1', { crls: [crl('crl1.pem')] }), 'PKI_REASON_REVOKED'),
        ...expectValid('openssl:crl-base, the other', await chain('good', { crls: [crl('crl1.pem')] })),
    ]);
    const delta = steps(o, [
        ['ca', '-config', cnf, '-revoke', f('revoked2.pem'), '-crl_reason', 'superseded'],
        ['ca', '-config', cnf, '-gencrl', '-out', f('crl2.pem')],
        // -sha256: without it the delta is signed with SHA-1, which pkinative
        // rightly does not take as evidence — and a delta nobody can verify
        // is not applied, so the case would test the digest, not the delta.
        ['crl', '-in', f('crl1.pem'), '-gendelta', f('crl2.pem'), '-key', f('root.key'), '-sha256', '-out', f('delta.pem')],
    ]);
    if (delta !== null) giveUp(['openssl:crl-delta'], delta);
    else {
        cases.set('openssl:crl-delta', async () => [
            // Without the delta the base list says nothing about it: the delta is what is read.
            ...expectValid('openssl:crl-delta, the base alone', await chain('revoked2', { crls: [crl('crl1.pem')] })),
            ...expectReason('openssl:crl-delta, base and delta', await chain('revoked2', { crls: [crl('crl1.pem'), crl('delta.pem')] }), 'PKI_REASON_REVOKED'),
        ]);
    }
    return { cases, skipped, failures };
}

// ── GnuTLS certtool ─────────────────────────────────────────────────

function certtoolWrites(c: Host, dir: string): Written {
    const cases = new Map<string, Evaluate>();
    const failures: string[] = [];
    const f = (name: string): string => join(dir, name);
    const p = (name: string): string => c.path(f(name));
    writeFileSync(f('ca.tmpl'), 'cn = "pkinative interop certtool CA"\nca\ncert_signing_key\ncrl_signing_key\nexpiration_days = 30\n');
    for (const name of ['listed', 'other']) {
        writeFileSync(f(`${name}.tmpl`), `cn = "${name}.example.com"\ndns_name = "${name}.example.com"\ntls_www_server\nsigning_key\nexpiration_days = 30\n`);
    }
    writeFileSync(f('crl.tmpl'), 'crl_next_update = 7\ncrl_number = 1\n');
    const failed = steps(c, [
        ['--generate-privkey', '--key-type', 'ecdsa', '--outfile', p('ca.key')],
        ['--generate-self-signed', '--load-privkey', p('ca.key'), '--template', p('ca.tmpl'), '--outfile', p('ca.pem')],
        ...['listed', 'other'].flatMap((name) => [
            ['--generate-privkey', '--key-type', 'ecdsa', '--outfile', p(`${name}.key`)],
            ['--generate-certificate', '--load-privkey', p(`${name}.key`), '--load-ca-certificate', p('ca.pem'), '--load-ca-privkey', p('ca.key'), '--template', p(`${name}.tmpl`), '--outfile', p(`${name}.pem`)],
        ]),
        ['--generate-crl', '--load-ca-privkey', p('ca.key'), '--load-ca-certificate', p('ca.pem'), '--load-certificate', p('listed.pem'), '--template', p('crl.tmpl'), '--outfile', p('crl.pem')],
    ]);
    if (failed !== null) {
        failures.push(`gnutls-certtool:crl: certtool could not write it (${firstLine(failed)})`);
        return { cases, skipped: new Map(), failures };
    }
    cases.set('gnutls-certtool:crl', async () => {
        const crls = pemBlocks(readFileSync(f('crl.pem'), 'utf8'), 'X509 CRL');
        const anchor = certPem(f('ca.pem'));
        const chain = (name: string): ReturnType<typeof verifyCertificateChain> => verifyCertificateChain({ leaf: certPem(f(`${name}.pem`)), trustAnchors: [anchor], crls, requireRevocation: true });
        return [
            ...expectReason('gnutls-certtool:crl, the listed certificate', await chain('listed'), 'PKI_REASON_REVOKED'),
            ...expectValid('gnutls-certtool:crl, the other', await chain('other')),
        ];
    });
    return { cases, skipped: new Map(), failures };
}

// ── gpgsm ───────────────────────────────────────────────────────────

function gpgsmWrites(g: Host, conf: Host, o: Host, dir: string): Written {
    const cases = new Map<string, Evaluate>();
    const failures: string[] = [];
    const f = (name: string): string => join(dir, name);
    const home = f('gnupg');
    mkdirSync(home, { recursive: true });
    writeFileSync(f('openssl.cnf'), '[ req ]\ndistinguished_name = dn\nprompt = no\n[ dn ]\nCN = unused\n[ v3_root ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n[ v3_signer ]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,nonRepudiation\nextendedKeyUsage = emailProtection\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\nsubjectAltName = email:gpgsm@example.com\n');
    writeFileSync(f('data.txt'), 'pkinative interop, signed by gpgsm\n');
    writeFileSync(join(home, 'gpg-agent.conf'), 'allow-loopback-pinentry\n');
    writeFileSync(join(home, 'gpgsm.conf'), 'disable-crl-checks\ndisable-trusted-cert-crl-check\nno-common-certs-import\n');
    const password = 'pkinative interop';
    // OpenSSL makes the key and its certificate, and packs them the way gpgsm imports them.
    const made = steps(o, [
        ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', f('root.key')],
        ['req', '-x509', '-new', '-key', f('root.key'), '-subj', '/CN=pkinative interop gpgsm root', '-days', '30', '-sha256', '-config', f('openssl.cnf'), '-extensions', 'v3_root', '-out', f('root.pem')],
        ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', f('signer.key')],
        ['req', '-new', '-key', f('signer.key'), '-subj', '/CN=pkinative interop gpgsm signer', '-config', f('openssl.cnf'), '-out', f('signer.csr')],
        ['x509', '-req', '-in', f('signer.csr'), '-CA', f('root.pem'), '-CAkey', f('root.key'), '-CAcreateserial', '-days', '30', '-sha256', '-extfile', f('openssl.cnf'), '-extensions', 'v3_signer', '-out', f('signer.pem')],
        ['pkcs12', '-export', '-in', f('signer.pem'), '-inkey', f('signer.key'), '-out', f('signer.p12'), '-passout', `pass:${password}`],
    ]);
    if (made !== null) {
        failures.push(`gpgsm:cms-*: OpenSSL could not make the signer gpgsm imports (${firstLine(made)})`);
        return { cases, skipped: new Map(), failures };
    }
    const H = g.path(home);
    conf.run(['--homedir', H, '--create-socketdir']);
    const G = (args: readonly string[], input?: string): Ran =>
        g.run(['--homedir', H, '--batch', '--disable-dirmngr', '--pinentry-mode', 'loopback', ...(input === undefined ? [] : ['--passphrase-fd', '0']), ...args], input === undefined ? {} : { input: `${input}\n` });
    const signed = ((): Ran | null => {
        for (const [args, input] of [
            [['--import', g.path(f('root.pem'))], undefined],
            [['--import', g.path(f('signer.p12'))], password],
        ] as const) {
            const r = G(args, input);
            if (r.status !== 0) return r;
        }
        const fpr = /^fpr:+([0-9A-F]{40}):/m.exec(G(['--with-colons', '--list-keys', 'pkinative interop gpgsm root']).stdout)?.[1];
        writeFileSync(join(home, 'trustlist.txt'), `${fpr ?? ''} S relax\n`);
        for (const [args, input] of [
            [['--local-user', 'pkinative interop gpgsm signer', '--detach-sign', '--output', g.path(f('detached.p7s')), g.path(f('data.txt'))], password],
            [['--local-user', 'pkinative interop gpgsm signer', '--sign', '--output', g.path(f('attached.p7m')), g.path(f('data.txt'))], password],
        ] as const) {
            const r = G(args, input);
            if (r.status !== 0) return r;
        }
        return null;
    })();
    conf.run(['--homedir', H, '--kill', 'gpg-agent']);
    if (signed !== null) {
        failures.push(`gpgsm:cms-*: gpgsm could not sign (${firstLine(signed)})`);
        return { cases, skipped: new Map(), failures };
    }
    const root = (): Certificate => certPem(f('root.pem'));
    cases.set('gpgsm:cms-detached', async () => expectValid('gpgsm:cms-detached', await verifySignedData({ signedData: read(f('detached.p7s')), content: read(f('data.txt')), trustAnchors: [root()] })));
    cases.set('gpgsm:cms-attached', async () => expectValid('gpgsm:cms-attached', await verifySignedData({ signedData: read(f('attached.p7m')), trustAnchors: [root()], encodingRules: 'ber' })));
    return { cases, skipped: new Map(), failures };
}

// ── .NET ────────────────────────────────────────────────────────────

function dotnetWrites(pwsh: Host, dir: string): Written {
    const cases = new Map<string, Evaluate>();
    const r = pwsh.run(['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(PROGRAMS, 'dotnet-sign.ps1'), dir]);
    if (r.status !== 0 || !r.stdout.includes('WROTE')) return { cases, skipped: new Map(), failures: [`dotnet:cms-*: .NET could not sign (${firstLine(r)})`] };
    const f = (name: string): string => join(dir, name);
    const root = (): Certificate => cert(read(f('root.cer')));
    const content = read(f('content.bin'));
    for (const [id, file, detached] of [
        ['dotnet:cms-rsa', 'cms-rsa.p7s', true],
        ['dotnet:cms-rsa-ski', 'cms-rsa-ski.p7m', false],
        ['dotnet:cms-rsa-pss', 'cms-rsa-pss.p7s', true],
        ['dotnet:cms-ecdsa', 'cms-ecdsa.p7s', true],
    ] as const) {
        cases.set(id, async () => expectValid(id, await verifySignedData({ signedData: read(f(file)), ...(detached ? { content } : {}), trustAnchors: [root()] })));
    }
    return { cases, skipped: new Map(), failures: [] };
}

// ── The reading ─────────────────────────────────────────────────────

/** What the runner knows about a located tool. */
export interface ReadTool { readonly host: Host; readonly reference: boolean }

/**
 * Have `toolId` write every case it declares, and hand each to pkinative.
 * `null` when the tool declares no read case.
 */
export async function readSignedStructures(toolId: string, tool: ReadTool, openssl: ReadTool | null, dir: string): Promise<ReadRun | null> {
    const declared = READ_CASES.filter((c) => c.tool === toolId).map((c) => c.id);
    if (declared.length === 0) return null;
    mkdirSync(dir, { recursive: true });
    let written: Written;
    if (toolId === 'openssl') written = opensslWrites(tool.host, dir, tool.reference);
    else if (toolId === 'gnutls-certtool') written = certtoolWrites(tool.host, dir);
    else if (toolId === 'dotnet') written = dotnetWrites(tool.host, dir);
    else if (toolId === 'gpgsm') {
        const conf = locate(['gpgconf'], ['--version'], { allowWsl: true, allowNative: tool.host.via === 'native' });
        if (openssl === null || conf === null) {
            return { checks: 0, lines: [], failures: [], skips: declared.map((id) => `${id} not written: gpgsm needs ${openssl === null ? 'OpenSSL to make its signer' : 'gpgconf'}`) };
        }
        written = gpgsmWrites(tool.host, conf, openssl.host, dir);
    } else {
        return { checks: 0, lines: [], failures: [`${toolId}: READ_CASES declares cases for it and scripts/lib/interop-reads.ts has no writer`], skips: [] };
    }

    const failures = [...written.failures];
    const skips = [...written.skipped].map(([id, why]) => `${id} not written: ${why}`);
    const lines: string[] = [];
    let checks = 0;
    for (const [id, evaluate] of written.cases) {
        if (!declared.includes(id)) { failures.push(`${id}: produced by ${toolId} and not declared in READ_CASES — an undeclared case is one the guide cannot describe`); continue; }
        let messages: string[];
        try {
            messages = await evaluate();
        } catch (error) {
            messages = [`${id}: threw ${error instanceof PkiError ? error.code : ''} ${error instanceof Error ? error.message.slice(0, 200) : String(error)}`];
        }
        checks += 1;
        failures.push(...messages);
        lines.push(`${id}: ${messages.length === 0 ? (READ_CASES.find((c) => c.id === id)?.expect ?? 'as declared') : 'DISAGREES'}`);
    }
    for (const id of declared) {
        if (!written.cases.has(id) && !written.skipped.has(id) && !written.failures.some((m) => m.startsWith(id) || m.startsWith(`${toolId}:cms-*`))) {
            failures.push(`${id}: declared in READ_CASES and neither written nor skipped with a reason by ${toolId}`);
        }
    }
    return { checks, lines, failures, skips };
}

