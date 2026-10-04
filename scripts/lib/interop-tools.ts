/**
 * pkinative — the interoperability matrix, write direction: the readers
 * =====================================================================
 * Every foreign tool that reads what pkinative writes, and how it is asked.
 *
 * A tool answers in **checks**: one per artefact and per question —
 * `cert.read`, `cert.pem`, `chain.verify`, `chain.webpki`, `csr.verify`,
 * `csr.pem`, `cms.verify`, `cms.certificates`, `ocsp.request`, `tsq.read`,
 * `cert.import`, and for the linters `lint.cert` and `lint.chain`. A check
 * either succeeded, with the facts the tool read, or did not, with the
 * tool's own words. Nothing is judged here: `scripts/run-interop.ts` compares
 * every fact to the one pkinative wrote, applies the reviewed limitations
 * and waivers, and decides. A command-line tool is parsed here; a library is
 * driven by a small program in `scripts/validators/` that writes NDJSON, so
 * what is compared is the library's API values, never its rendering.
 *
 * What is extracted from a command line is a value with one spelling — a
 * serial as an integer, a name attribute after RFC 4514 unescaping — never a
 * rendered line, and a parse that finds nothing is `unreadable`, which is a
 * defect of this runner and never evidence about the artefact.
 *
 * @module scripts/lib/interop-tools
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { platform } from 'node:process';
import { fileURLToPath } from 'node:url';
import type { Artefact, ArtefactSet, Facts } from './interop-artefacts.js';
import { firstLine, locate, type Host, type Ran } from './interop-host.js';

const PROGRAMS = join(dirname(fileURLToPath(import.meta.url)), '..', 'validators');

// ── The vocabulary ──────────────────────────────────────────────────

export interface LintFinding {
    readonly lint: string;
    /** Normalised: `error` (error, fatal), `warning` (warn, warning, notice) or `info`. */
    readonly severity: 'error' | 'warning' | 'info';
}

export interface CheckResult {
    readonly artefact: string;
    readonly check: string;
    readonly ok: boolean;
    readonly facts?: Facts;
    readonly error?: string;
    /** The tool's own statement that it cannot do this, honoured only where TOOL_LIMITATIONS allows it. */
    readonly unsupported?: string;
    /** The tool succeeded and this runner could not read its answer: a defect here, never about the artefact. */
    readonly unreadable?: boolean;
    readonly findings?: readonly LintFinding[];
}

export interface Located {
    readonly version: string;
    /**
     * Whether this build is one the matrix holds to agreement on refusals.
     * OpenSSL before 3.0 and LibreSSL are not: a refusal from them is
     * reported as not applicable — the L3 rule for the same builds — while
     * every fact they do read must still agree.
     */
    readonly reference: boolean;
}

export interface WriteTool {
    readonly id: string;
    /** Where it comes from, for the report and for anyone reproducing this. */
    readonly provenance: string;
    /** Probe the tool. `null` when it is not installed here. */
    locate(): Located | null;
    /** The command `locate` found, for the read direction to write with. */
    host(): Host | null;
    /** Ask every question this tool can answer about the set. */
    check(set: ArtefactSet, work: string): readonly CheckResult[];
}

// ── Shared readers ──────────────────────────────────────────────────

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

/**
 * RFC 4514 attribute values by upper-case type, first occurrence wins:
 * `CN=a\,b,L=Paris+OU=Ingénierie` gives CN `a,b`, L `Paris`, OU `Ingénierie`.
 * `\XX` pairs are UTF-8 octets; a `#`-prefixed value (hex DER) is skipped.
 */
export function parseRfc4514(text: string): Map<string, string> {
    const out = new Map<string, string>();
    let i = 0;
    const s = text.trim();
    while (i < s.length) {
        let type = '';
        while (i < s.length && s[i] !== '=') type += s[i++];
        i++;
        const octets: number[] = [];
        const flush = (chunk: string): void => { for (const b of Buffer.from(chunk, 'utf8')) octets.push(b); };
        let hexValue = s[i] === '#';
        while (i < s.length && s[i] !== ',' && s[i] !== '+') {
            if (s[i] === '\\' && i + 1 < s.length) {
                const pair = s.slice(i + 1, i + 3);
                if (/^[0-9A-Fa-f]{2}$/.test(pair)) { octets.push(parseInt(pair, 16)); i += 3; continue; }
                flush(s[i + 1] ?? '');
                i += 2;
                continue;
            }
            flush(s[i] ?? '');
            i++;
        }
        i++;
        const key = type.trim().toUpperCase();
        if (!hexValue && key !== '' && !out.has(key)) out.set(key, Buffer.from(octets).toString('utf8').trim());
        hexValue = false;
    }
    return out;
}

/** The facts a name gives, in the vocabulary of interop-artefacts.ts. */
function nameFacts(names: ReadonlyMap<string, string>): Record<string, string> {
    const facts: Record<string, string> = { commonName: names.get('CN') ?? '' };
    const o = names.get('O');
    const ou = names.get('OU');
    const l = names.get('L');
    if (o !== undefined) facts['organization'] = o;
    if (ou !== undefined) facts['organizationalUnit'] = ou;
    if (l !== undefined) facts['locality'] = l;
    return facts;
}

/** An integer's hex the way every tool is compared on it: lowercase, no leading zeros. */
export const intHex = (hex: string): string => BigInt(`0x${hex.replace(/[^0-9A-Fa-f]/g, '') || '0'}`).toString(16);

const refusal = (artefact: string, check: string, r: Ran): CheckResult => ({ artefact, check, ok: false, error: firstLine(r) });
const unreadable = (artefact: string, check: string, what: string): CheckResult => ({ artefact, check, ok: false, unreadable: true, error: what });

/** Run a program that reads the manifest and writes NDJSON check records. */
function runProgram(host: Host, args: readonly string[], set: ArtefactSet, work: string, tool: string, extraEnv: Readonly<Record<string, string>> = {}): CheckResult[] {
    // The manifest as this host must read it: every path translated.
    const translated = JSON.parse(readFileSync(set.manifest, 'utf8')) as { artefacts: Record<string, unknown>[] };
    for (const a of translated.artefacts) {
        for (const key of ['der', 'pem', 'content']) if (typeof a[key] === 'string') a[key] = host.path(a[key] as string);
    }
    mkdirSync(work, { recursive: true });
    const manifest = join(work, `manifest-${tool}.json`);
    const out = join(work, `${tool}.ndjson`);
    writeFileSync(manifest, JSON.stringify(translated));
    const r = host.run([...args, host.path(manifest), host.path(out)], { env: extraEnv, timeoutMs: 900_000 });
    let text = '';
    try { text = readFileSync(out, 'utf8'); } catch { /* reported below */ }
    const lines = text.split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l) as Record<string, unknown>);
    const footer = lines.at(-1);
    if (r.status !== 0 || footer?.['t'] !== 'footer' || footer['count'] !== lines.length - 2) {
        return [{ artefact: '*', check: 'program', ok: false, unreadable: true, error: `${tool}: the program did not complete (exit ${String(r.status)}): ${firstLine(r)}` }];
    }
    const results: CheckResult[] = [];
    for (const l of lines.slice(1, -1)) {
        const findings = Array.isArray(l['findings'])
            ? (l['findings'] as { lint: string; severity: string }[]).map((f) => ({ lint: f.lint, severity: normaliseSeverity(f.severity) }))
            : undefined;
        results.push({
            artefact: String(l['id']), check: String(l['check']), ok: l['ok'] === true,
            ...(l['facts'] === undefined ? {} : { facts: l['facts'] as Facts }),
            ...(typeof l['error'] === 'string' ? { error: l['error'] } : {}),
            ...(typeof l['unsupported'] === 'string' ? { unsupported: l['unsupported'] } : {}),
            ...(findings === undefined ? {} : { findings }),
        });
    }
    return results;
}

/** The header line of a program's output, for its version. */
function programVersion(work: string, tool: string): string | undefined {
    try {
        const first = readFileSync(join(work, `${tool}.ndjson`), 'utf8').split('\n')[0] ?? '';
        return (JSON.parse(first) as { version?: string }).version;
    } catch {
        return undefined;
    }
}

export function normaliseSeverity(s: string): LintFinding['severity'] {
    const lower = s.toLowerCase();
    if (lower === 'error' || lower === 'fatal') return 'error';
    if (lower === 'warn' || lower === 'warning' || lower === 'notice') return 'warning';
    return 'info';
}

const certs = (set: ArtefactSet): Artefact[] => set.artefacts.filter((a) => a.kind === 'cert');
const byId = (set: ArtefactSet): Map<string, Artefact> => new Map(set.artefacts.map((a) => [a.id, a]));
/** The frozen samples of scripts/lib/samples.ts, profile `sample`: never linted, chains not held to the Web PKI purpose. */
const isSample = (a: Artefact): boolean => a.profile === 'sample';

// ── OpenSSL ─────────────────────────────────────────────────────────

const HASH_OIDS: Readonly<Record<string, string>> = {
    sha1: '1.3.14.3.2.26', sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3',
};

/** `openssl ts -query -text`, as facts. */
export function parseTsQueryText(text: string): Facts | undefined {
    const hash = /Hash Algorithm:\s*(\S+)/.exec(text)?.[1]?.toLowerCase();
    const dump = [...text.matchAll(/^\s*[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -]){1,16})/gim)].map((m) => (m[1] ?? '').replace(/[ -]/g, '')).join('');
    const policy = /Policy OID:\s*(\S+)/.exec(text)?.[1];
    const nonce = /Nonce:\s*(\S+)/.exec(text)?.[1];
    const certReq = /Certificate required:\s*(yes|no)/.exec(text)?.[1];
    if (hash === undefined || dump === '' || certReq === undefined) return undefined;
    return {
        hashOid: HASH_OIDS[hash] ?? hash,
        imprint: dump.toLowerCase(),
        policy: policy === undefined || policy === 'unspecified' ? '' : policy,
        nonce: nonce === undefined || nonce === 'unspecified' ? '' : intHex(nonce.replace(/^0x/i, '')),
        certReq: certReq === 'yes' ? 'true' : 'false',
    };
}

/** `openssl ocsp -req_text`, as facts. The nonce is printed with its inner OCTET STRING header, which is stripped. */
export function parseOcspReqText(text: string): Facts | undefined {
    const name = /Issuer Name Hash:\s*([0-9A-F]+)/i.exec(text)?.[1];
    const key = /Issuer Key Hash:\s*([0-9A-F]+)/i.exec(text)?.[1];
    const serial = /Serial Number:\s*([0-9A-F]+)/i.exec(text)?.[1];
    if (name === undefined || key === undefined || serial === undefined) return undefined;
    const raw = /OCSP Nonce:\s*\n?\s*([0-9A-F]+)/i.exec(text)?.[1]?.toLowerCase() ?? '';
    const nonce = raw.startsWith('04') && raw.length >= 4 && parseInt(raw.slice(2, 4), 16) * 2 === raw.length - 4 ? raw.slice(4) : raw;
    return { issuerNameHash: name.toLowerCase(), issuerKeyHash: key.toLowerCase(), serial: intHex(serial), nonce };
}

/** `openssl version` → whether it is a reference build: OpenSSL 3.0 or later. */
export function opensslReference(version: string): boolean {
    const m = /^OpenSSL (\d+)\./.exec(version);
    return m !== null && Number(m[1]) >= 3;
}

/**
 * Why this openssl cannot sign a CMS SignedData with Ed25519 itself, or
 * undefined when it can. OpenSSL 3.0 refuses every digest for EdDSA in CMS
 * ("eddsa_digest_signverify_init: invalid digest"), so it can verify no
 * Ed25519 SignedData either, whoever wrote it.
 */
export function opensslCmsEddsa(o: Host, work: string): string | undefined {
    const f = (name: string): string => join(work, `openssl-eddsa-probe-${name}`);
    writeFileSync(f('data.txt'), 'probe');
    for (const args of [
        ['genpkey', '-algorithm', 'ED25519', '-out', f('key.pem')],
        ['req', '-x509', '-new', '-key', f('key.pem'), '-subj', '/CN=pkinative eddsa probe', '-days', '1', '-out', f('cert.pem')],
        ['cms', '-sign', '-binary', '-in', f('data.txt'), '-signer', f('cert.pem'), '-inkey', f('key.pem'), '-md', 'sha512', '-outform', 'DER', '-out', f('cms.der')],
    ]) {
        const r = o.run(args);
        if (r.status !== 0) return `this openssl cannot sign a CMS SignedData with Ed25519 itself (${firstLine(r)})`;
    }
    return undefined;
}

function opensslTool(): WriteTool {
    let host: Host | null = null;
    return {
        id: 'openssl',
        provenance: 'the OpenSSL command-line tool, a lineage independent of everything else here',
        host: () => host,
        locate() {
            host = locate(['openssl'], ['version']);
            if (host === null) return null;
            const version = host.run(['version']).stdout.trim();
            return { version, reference: opensslReference(version) };
        },
        check(set, work) {
            const o = host as Host;
            const out: CheckResult[] = [];
            const ids = byId(set);
            const nameopt = ['-nameopt', 'RFC2253,-esc_msb'];
            const noCmsEddsa = opensslCmsEddsa(o, work);
            for (const a of set.artefacts) {
                if (a.kind === 'cert') {
                    const r = o.run(['x509', '-inform', 'DER', '-in', a.der, '-noout', '-serial', '-subject', ...nameopt, '-ext', 'subjectAltName']);
                    if (r.status !== 0) out.push(refusal(a.id, 'cert.read', r));
                    else {
                        const serial = /serial=([0-9A-Fa-f]+)/.exec(r.stdout)?.[1];
                        const subject = /subject=(.*)/.exec(r.stdout)?.[1];
                        if (serial === undefined || subject === undefined) out.push(unreadable(a.id, 'cert.read', `no serial or subject in ${JSON.stringify(r.stdout.slice(0, 120))}`));
                        else out.push({ artefact: a.id, check: 'cert.read', ok: true, facts: { serial: intHex(serial), ...nameFacts(parseRfc4514(subject)), dnsNames: [...r.stdout.matchAll(/DNS:([^\s,]+)/g)].map((m) => m[1] ?? '').sort().join(',') } });
                    }
                    const p = o.run(['x509', '-in', a.pem, '-noout', '-serial']);
                    const ps = /serial=([0-9A-Fa-f]+)/.exec(p.stdout)?.[1];
                    out.push(p.status !== 0 ? refusal(a.id, 'cert.pem', p) : ps === undefined ? unreadable(a.id, 'cert.pem', 'no serial') : { artefact: a.id, check: 'cert.pem', ok: true, facts: { serial: intHex(ps) } });
                    if (a.shape === 'ca' || a.shape === undefined) continue;
                    const issuer = ids.get(a.issuer ?? '');
                    if (issuer === undefined) continue;
                    // -partial_chain is never used: the CA must be a trust
                    // anchor in its own right, which is what it claims to be.
                    const v = o.run(['verify',
                        ...(isSample(a) ? [] : ['-x509_strict', '-purpose', 'sslserver']),
                        ...(a.serverName === undefined ? [] : ['-verify_hostname', a.serverName]),
                        ...(a.verifyAt === undefined ? [] : ['-attime', String(Math.floor(a.verifyAt / 1000))]),
                        '-CAfile', issuer.pem, a.pem]);
                    out.push(v.status === 0 ? { artefact: a.id, check: 'chain.verify', ok: true } : refusal(a.id, 'chain.verify', v));
                } else if (a.kind === 'csr') {
                    const r = o.run(['req', '-inform', 'DER', '-in', a.der, '-noout', '-verify', '-subject', ...nameopt]);
                    const subject = /subject=(.*)/.exec(r.stdout)?.[1];
                    out.push(r.status !== 0 ? refusal(a.id, 'csr.verify', r) : subject === undefined ? unreadable(a.id, 'csr.verify', 'no subject') : { artefact: a.id, check: 'csr.verify', ok: true, facts: { commonName: parseRfc4514(subject).get('CN') ?? '' } });
                    const p = o.run(['req', '-in', a.pem, '-noout', '-verify']);
                    out.push(p.status === 0 ? { artefact: a.id, check: 'csr.pem', ok: true } : refusal(a.id, 'csr.pem', p));
                } else if (a.kind === 'cms') {
                    const issuer = ids.get(a.issuer ?? '');
                    const content = join(work, `openssl-${a.id.replace('/', '-')}.out`);
                    const r = o.run(['cms', '-verify', '-binary', '-inform', 'DER', '-in', a.der, ...(a.detached === true && a.content !== undefined ? ['-content', a.content] : []), '-CAfile', issuer?.pem ?? '', '-purpose', 'any', '-out', content]);
                    if (r.status !== 0) out.push({ ...refusal(a.id, 'cms.verify', r), ...(noCmsEddsa !== undefined && a.profile === 'ed25519' ? { unsupported: noCmsEddsa } : {}) });
                    else out.push({ artefact: a.id, check: 'cms.verify', ok: true, facts: { contentSha256: sha256(new Uint8Array(readFileSync(content))) } });
                } else if (a.kind === 'ocsp-request') {
                    const r = o.run(['ocsp', '-reqin', a.der, '-req_text']);
                    const facts = parseOcspReqText(r.stdout);
                    out.push(r.status !== 0 ? refusal(a.id, 'ocsp.request', r) : facts === undefined ? unreadable(a.id, 'ocsp.request', r.stdout.slice(0, 120)) : { artefact: a.id, check: 'ocsp.request', ok: true, facts });
                } else if (a.kind === 'tsq') {
                    const r = o.run(['ts', '-query', '-in', a.der, '-text']);
                    const facts = parseTsQueryText(r.stdout);
                    out.push(r.status !== 0 ? refusal(a.id, 'tsq.read', r) : facts === undefined ? unreadable(a.id, 'tsq.read', r.stdout.slice(0, 120)) : { artefact: a.id, check: 'tsq.read', ok: true, facts });
                }
            }
            return out;
        },
    };
}

// ── GnuTLS certtool ─────────────────────────────────────────────────

/**
 * The DNS names of the subjectAltName block of `certtool --certificate-info`,
 * sorted and joined. Only that block: name constraints print `DNSname:`
 * lines too, and a CA constrained to example.com has no DNS name.
 */
export function certtoolSanDns(text: string): string {
    const lines = text.split(/\r?\n/);
    const indent = (l: string): number => (/^\s*/.exec(l)?.[0] ?? '').replace(/\t/g, '        ').length;
    const at = lines.findIndex((l) => /Subject Alternative Name/.test(l));
    if (at < 0) return '';
    const names: string[] = [];
    for (const line of lines.slice(at + 1)) {
        if (line.trim() === '' || indent(line) <= indent(lines[at] ?? '')) break;
        const m = /^\s*DNSname:\s*(\S+)/.exec(line);
        if (m !== null) names.push(m[1] ?? '');
    }
    return names.sort().join(',');
}

function certtoolTool(): WriteTool {
    let host: Host | null = null;
    return {
        id: 'gnutls-certtool',
        provenance: 'GnuTLS certtool, the second-most-deployed TLS stack, sharing no code with OpenSSL',
        host: () => host,
        locate() {
            host = locate(['certtool'], ['--version'], { allowWsl: true, accept: (r) => /GnuTLS/i.test(r.stdout) });
            if (host === null) return null;
            return { version: `${(host.run(['--version']).stdout.split('\n')[0] ?? '').trim()}${host.via === 'wsl' ? ' (WSL)' : ''}`, reference: true };
        },
        check(set) {
            const h = host as Host;
            const out: CheckResult[] = [];
            const ids = byId(set);
            for (const a of set.artefacts) {
                if (a.kind === 'cert') {
                    const r = h.run(['--certificate-info', '--inder', '--infile', h.path(a.der)]);
                    const serial = /Serial Number \(hex\):\s*([0-9a-fA-F]+)/.exec(r.stdout)?.[1];
                    const subject = /^\s*Subject:\s*(.*)$/m.exec(r.stdout)?.[1];
                    if (r.status !== 0) out.push(refusal(a.id, 'cert.read', r));
                    else if (serial === undefined || subject === undefined) out.push(unreadable(a.id, 'cert.read', r.stdout.slice(0, 120)));
                    else out.push({ artefact: a.id, check: 'cert.read', ok: true, facts: { serial: intHex(serial), ...nameFacts(parseRfc4514(subject)), dnsNames: certtoolSanDns(r.stdout) } });
                    const p = h.run(['--certificate-info', '--infile', h.path(a.pem)]);
                    const ps = /Serial Number \(hex\):\s*([0-9a-fA-F]+)/.exec(p.stdout)?.[1];
                    out.push(p.status !== 0 ? refusal(a.id, 'cert.pem', p) : ps === undefined ? unreadable(a.id, 'cert.pem', 'no serial') : { artefact: a.id, check: 'cert.pem', ok: true, facts: { serial: intHex(ps) } });
                    if (a.shape === 'ca' || a.shape === undefined) continue;
                    const issuer = ids.get(a.issuer ?? '');
                    if (issuer === undefined) continue;
                    const v = h.run(['--verify', '--load-ca-certificate', h.path(issuer.pem), '--infile', h.path(a.pem),
                        ...(a.serverName === undefined ? [] : [`--verify-hostname=${a.serverName}`]),
                        ...(isSample(a) ? [] : ['--verify-purpose=1.3.6.1.5.5.7.3.1']),
                        ...(a.verifyAt === undefined ? [] : [`--attime=${new Date(a.verifyAt).toISOString().slice(0, 19).replace('T', ' ')}`])]);
                    out.push(v.status === 0 && /Chain verification output: Verified/.test(v.stdout) ? { artefact: a.id, check: 'chain.verify', ok: true } : { artefact: a.id, check: 'chain.verify', ok: false, error: /Chain verification output: (.*)/.exec(v.stdout)?.[1] ?? firstLine(v) });
                } else if (a.kind === 'csr') {
                    for (const [check, args] of [['csr.verify', ['--inder', '--infile', h.path(a.der)]], ['csr.pem', ['--infile', h.path(a.pem)]]] as const) {
                        const r = h.run(['--crq-info', ...args]);
                        const subject = /^\s*Subject:\s*(.*)$/m.exec(r.stdout)?.[1];
                        if (r.status !== 0) out.push(refusal(a.id, check, r));
                        else if (!/Self signature: verified/.test(r.stdout)) out.push({ artefact: a.id, check, ok: false, error: /Self signature: (.*)/.exec(r.stdout)?.[1] ?? 'no self-signature verdict' });
                        else out.push({ artefact: a.id, check, ok: true, facts: { commonName: parseRfc4514(subject ?? '').get('CN') ?? '' } });
                    }
                }
            }
            return out;
        },
    };
}

// ── The JDK: CertificateFactory, PKIX, and keytool for PKCS #10 ─────

function javaTool(): WriteTool {
    let java: Host | null = null;
    let keytool: Host | null = null;
    const home = process.env['JAVA_HOME'];
    const candidates = (name: string): string[] => [...(home === undefined ? [] : [join(home, 'bin', name)]), name];
    return {
        id: 'java-keytool',
        provenance: 'the JDK\'s CertificateFactory, PKIX CertPathValidator and keytool — what every Java service reads with',
        host: () => java,
        locate() {
            // `--version` is JDK 9+; a JDK 8 on PATH fails it and is passed
            // over, since the reader is a single-file source program (JDK 11+).
            java = locate(candidates('java'), ['--version']);
            keytool = locate(candidates('keytool'), ['-help']);
            if (java === null || keytool === null) return null;
            return { version: (java.run(['--version']).stdout.split('\n')[0] ?? '').trim(), reference: true };
        },
        check(set, work) {
            const out = runProgram(java as Host, [join(PROGRAMS, 'java', 'Interop.java')], set, work, 'java-keytool');
            const eddsa = !/"eddsa":false/.test(readFileSync(join(work, 'java-keytool.ndjson'), 'utf8').split('\n')[0] ?? '');
            for (const a of set.artefacts.filter((x) => x.kind === 'csr')) {
                // keytool reads PKCS #10 in PEM only, and parsing verifies the signature.
                const r = (keytool as Host).run(['-printcertreq', '-file', a.pem]);
                const subject = /^Subject:\s*(.*)$/m.exec(r.stdout)?.[1];
                // The frozen samples are Ed25519 too.
                const ed25519 = a.profile === 'ed25519' || a.profile === 'sample';
                if (r.status !== 0) out.push({ ...refusal(a.id, 'csr.verify', r), ...(!eddsa && ed25519 ? { unsupported: 'this JDK has no EdDSA (JEP 339 arrived in JDK 15)' } : {}) });
                // keytool prints X.500 keyword form, separators ", " and " + ".
                else out.push({ artefact: a.id, check: 'csr.verify', ok: true, facts: { commonName: parseRfc4514((subject ?? '').replace(/, /g, ',').replace(/ \+ /g, '+')).get('CN') ?? '' } });
            }
            return out;
        },
    };
}

// ── Programs over a library ─────────────────────────────────────────

function pythonHost(): Host | null {
    // `py -3` is the Windows launcher; a `python3` that is the Store stub
    // fails the probe, which imports cryptography for exactly that reason.
    for (const command of platform === 'win32' ? ['py', 'python', 'python3'] : ['python3', 'python']) {
        const host = locate([command], ['-c', 'import cryptography'], { allowWsl: false });
        if (host !== null) return host;
    }
    return null;
}

function pythonTool(): WriteTool {
    let host: Host | null = null;
    return {
        id: 'python-cryptography',
        provenance: 'pyca/cryptography — Rust (rust-asn1, cryptography-x509), the library most Python PKI tooling embeds',
        host: () => host,
        locate() {
            host = pythonHost();
            if (host === null) return null;
            return { version: `cryptography ${host.run(['-c', 'import cryptography; print(cryptography.__version__)']).stdout.trim()}`, reference: true };
        },
        check(set, work) {
            return runProgram(host as Host, [join(PROGRAMS, 'python-cryptography.py'), 'interop'], set, work, 'python-cryptography', { PYTHONIOENCODING: 'utf-8' });
        },
    };
}

/** Go, natively or through WSL. */
export function goHost(): Host | null {
    return locate(['go'], ['version'], { allowWsl: true });
}

function goTool(): WriteTool {
    let host: Host | null = null;
    return {
        id: 'go-x509',
        provenance: 'Go crypto/x509 — Go\'s own ASN.1, no C underneath',
        host: () => host,
        locate() {
            host = goHost();
            if (host === null) return null;
            return { version: `${host.run(['version']).stdout.trim()}${host.via === 'wsl' ? ' (WSL)' : ''}`, reference: true };
        },
        check(set, work) {
            const h = host as Host;
            return runProgram(h, ['run', h.path(join(PROGRAMS, 'go-x509', 'main.go')), 'interop'], set, work, 'go-x509', { CGO_ENABLED: '0' });
        },
    };
}

function dotnetTool(): WriteTool {
    let host: Host | null = null;
    return {
        id: 'dotnet',
        provenance: '.NET\'s managed readers — X509Certificate2, CertificateRequest, SignedCms, Rfc3161TimestampRequest — through PowerShell 7; on Windows X509Chain is CryptoAPI\'s chain engine',
        host: () => host,
        locate() {
            // Spawned, never looked for on disk: PowerShell 7 from the Store
            // is an App Execution Alias that `stat` cannot open.
            host = locate(['pwsh'], ['-NoProfile', '-NonInteractive', '-Command', 'if ([Environment]::Version.Major -lt 7) { exit 1 }']);
            if (host === null) return null;
            const v = host.run(['-NoProfile', '-NonInteractive', '-Command', '"PowerShell $($PSVersionTable.PSVersion) on $([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)"']).stdout.trim();
            return { version: v, reference: true };
        },
        check(set, work) {
            return runProgram(host as Host, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(PROGRAMS, 'dotnet.ps1')], set, work, 'dotnet');
        },
    };
}

// ── Windows CryptoAPI through Windows PowerShell 5.1 ────────────────

function cryptoapiTool(): WriteTool {
    let host: Host | null = null;
    return {
        id: 'windows-cryptoapi',
        provenance: 'Microsoft CryptoAPI through .NET Framework\'s X509Certificate2 under Windows PowerShell — a lineage with nothing in common with OpenSSL',
        host: () => host,
        locate() {
            if (platform !== 'win32') return null;
            host = locate(['powershell'], ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()']);
            if (host === null) return null;
            return { version: `Windows PowerShell ${host.run(['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()']).stdout.trim()}`, reference: true };
        },
        check(set) {
            // One process for every certificate. `SerialNumber` and
            // `GetNameInfo` are API values, the same in every locale; the SAN
            // is not reachable without X509Extension.Format(), whose output
            // is translated, so it is not supplied.
            const list = certs(set).map((a) => `'${a.id.replace(/'/g, "''")}|${a.der.replace(/'/g, "''")}'`).join(',');
            const script = [
                `foreach ($entry in @(${list})) {`,
                '  $id, $path = $entry -split "\\|", 2',
                '  try { $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[System.IO.File]::ReadAllBytes($path))',
                '    "OK|$id|$($c.SerialNumber)|$($c.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false))" }',
                '  catch { "NO|$id|$($_.Exception.Message -replace "\\s+", " ")" } }',
            ].join('\n');
            const r = (host as Host).run(['-NoProfile', '-NonInteractive', '-Command', script]);
            const out: CheckResult[] = [];
            const seen = new Map<string, string>();
            for (const line of r.stdout.split(/\r?\n/)) {
                const [state, id, ...rest] = line.split('|');
                if (id !== undefined && (state === 'OK' || state === 'NO')) seen.set(id, `${state}|${rest.join('|')}`);
            }
            for (const a of certs(set)) {
                const answer = seen.get(a.id);
                if (answer === undefined) { out.push(unreadable(a.id, 'cert.read', `no answer from Windows PowerShell (${firstLine(r)})`)); continue; }
                const [state, serial, cn] = answer.split('|');
                if (state === 'NO') out.push({ artefact: a.id, check: 'cert.read', ok: false, error: serial ?? '' });
                // GetNameInfo(SimpleName) falls back to other attributes when
                // there is no CN, so it is the commonName only where one exists.
                else out.push({ artefact: a.id, check: 'cert.read', ok: true, facts: { serial: intHex(serial ?? ''), commonName: cn ?? '' } });
            }
            return out;
        },
    };
}

// ── gpgsm ───────────────────────────────────────────────────────────

/** `gpgsm --status-fd 1 --verify`: a good signature from a fully trusted chain. */
export const gpgsmVerified = (status: string): boolean => /\[GNUPG:\] GOODSIG\b/.test(status) && /\[GNUPG:\] VALIDSIG\b/.test(status) && /\[GNUPG:\] TRUST_FULLY\b/.test(status);

function gpgsmTool(): WriteTool {
    let host: Host | null = null;
    let conf: Host | null = null;
    return {
        id: 'gpgsm',
        provenance: 'GnuPG\'s gpgsm over libksba and libgcrypt — the S/MIME reader of the GNU stack, sharing no code with OpenSSL',
        host: () => host,
        locate() {
            // Git for Windows ships an MSYS gpgsm that rewrites every path
            // and cannot start its agent from a temporary directory, so on
            // Windows only the WSL one is used.
            const native = platform !== 'win32';
            host = locate(['gpgsm'], ['--version'], { allowWsl: true, allowNative: native });
            conf = locate(['gpgconf'], ['--version'], { allowWsl: true, allowNative: native });
            if (host === null || conf === null) return null;
            return { version: `${(host.run(['--version']).stdout.split('\n')[0] ?? '').trim()}${host.via === 'wsl' ? ' (WSL)' : ''}`, reference: true };
        },
        check(set, work) {
            const g = host as Host;
            const home = join(work, 'gnupg');
            mkdirSync(home, { recursive: true });
            writeFileSync(join(home, 'gpgsm.conf'), 'disable-crl-checks\ndisable-trusted-cert-crl-check\nno-common-certs-import\n');
            const H = g.path(home);
            (conf as Host).run(['--homedir', H, '--create-socketdir']);
            // The CA's critical nameConstraints is an extension gpgsm does not
            // implement; it is told to ignore it rather than refuse every
            // chain, which tests what gpgsm does implement.
            const G = (args: readonly string[]): Ran => g.run(['--homedir', H, '--batch', '--disable-dirmngr', '--status-fd', '1', '--ignore-cert-extension', '2.5.29.30', ...args]);
            const out: CheckResult[] = [];
            const trust: string[] = [];
            for (const a of certs(set).filter((x) => !isSample(x))) {
                const r = G(['--import', g.path(a.der)]);
                const imported = /IMPORT_OK/.test(r.stdout);
                // gpgsm logs this for every multi-valued RDN; 2.4.4 then exits 2, after IMPORT_OK.
                const multiValuedRdn = imported && /no subject found in certificate/.test(`${r.stdout}\n${r.stderr}`)
                    ? { unsupported: 'gpgsm imported it (IMPORT_OK), then exited non-zero on "no subject found in certificate", which it logs for a multi-valued RDN' }
                    : {};
                out.push(r.status === 0 && imported ? { artefact: a.id, check: 'cert.import', ok: true } : { ...refusal(a.id, 'cert.import', r), ...multiValuedRdn });
                if (a.shape !== 'ca') continue;
                const listed = G(['--with-colons', '--list-keys', a.expect['commonName'] ?? '']);
                const fpr = /^fpr:+([0-9A-F]{40}):/m.exec(listed.stdout)?.[1];
                if (fpr !== undefined) trust.push(`${fpr} S relax`);
            }
            writeFileSync(join(home, 'trustlist.txt'), `${trust.join('\n')}\n`);
            // The agent the imports started read an empty trust list; it
            // reads the new one only when it starts again.
            (conf as Host).run(['--homedir', H, '--kill', 'gpg-agent']);
            for (const a of set.artefacts.filter((x) => x.kind === 'cms')) {
                const r = G(['--verify', g.path(a.der), ...(a.detached === true && a.content !== undefined ? [g.path(a.content)] : [])]);
                out.push(r.status === 0 && gpgsmVerified(r.stdout) ? { artefact: a.id, check: 'cms.verify', ok: true } : { artefact: a.id, check: 'cms.verify', ok: false, error: (r.stderr.trim().split('\n').at(-1) ?? '') || firstLine(r) });
            }
            (conf as Host).run(['--homedir', H, '--kill', 'gpg-agent']);
            return out;
        },
    };
}

// ── The linters ─────────────────────────────────────────────────────

/**
 * Which zlint sources judge a certificate. The CA/Browser Forum, Mozilla,
 * Chrome and Apple profiles apply to a certificate shaped for the Web PKI in
 * a signature family it admits; the rich leaf carries, on purpose, what the
 * Web PKI forbids (a reserved IP address, an e-mail address, a URI, an OU, a
 * BMPString, a multi-valued RDN), and P-521 and Ed25519 are outside its
 * allow-lists — those are judged by the RFC sources and zlint's community
 * lints alone. The S/MIME, code-signing, EV and ETSI profiles are never ours.
 */
export function zlintSources(a: Artefact): readonly string[] {
    return a.shape !== 'rich' && a.webpki === true
        ? ['-excludeSources', 'CABF_EV,CABF_SMIME_BR,CABF_CS_BR,ETSI_ESI']
        : ['-includeSources', 'RFC5280,RFC5480,RFC5891,RFC3279,RFC8813,Community'];
}

/** One line of zlint's output, as findings: every result other than pass, NA and NE. */
export function zlintFindings(line: string): LintFinding[] {
    const results = JSON.parse(line) as Record<string, { result: string }>;
    return Object.entries(results)
        .filter(([, v]) => !['pass', 'NA', 'NE'].includes(v.result))
        .map(([lint, v]) => ({ lint, severity: normaliseSeverity(v.result) }));
}

function zlintTool(): WriteTool {
    let host: Host | null = null;
    return {
        id: 'zlint',
        provenance: 'zlint v3, the certificate linter of the Web PKI (CA/Browser Forum, Mozilla, Chrome, Apple and the RFCs)',
        host: () => host,
        locate() {
            host = locate(['zlint'], ['-list-lints-source'], { allowWsl: true });
            if (host === null) return null;
            const listed = host.run(['-list-lints-json']).stdout.split('\n').filter((l) => l.startsWith('{')).length;
            return { version: `zlint (${String(listed)} lints)${host.via === 'wsl' ? ' (WSL)' : ''}`, reference: true };
        },
        check(set) {
            const h = host as Host;
            const out: CheckResult[] = [];
            // One process per set of sources: zlint takes many files and
            // prints one JSON object per file, in order.
            const groups = new Map<string, Artefact[]>();
            for (const a of certs(set).filter((x) => !isSample(x))) {
                const key = zlintSources(a).join(' ');
                groups.set(key, [...(groups.get(key) ?? []), a]);
            }
            for (const [key, members] of groups) {
                const r = h.run([...key.split(' '), '-format', 'der', ...members.map((a) => h.path(a.der))]);
                const lines = r.stdout.split('\n').filter((l) => l.startsWith('{'));
                if (r.status !== 0 || lines.length !== members.length) {
                    for (const a of members) out.push(unreadable(a.id, 'lint.cert', `zlint printed ${String(lines.length)} results for ${String(members.length)} files (${firstLine(r)})`));
                    continue;
                }
                members.forEach((a, i) => out.push({ artefact: a.id, check: 'lint.cert', ok: true, findings: zlintFindings(lines[i] ?? '{}') }));
            }
            return out;
        },
    };
}

function pkilintTool(): WriteTool {
    let host: Host | null = null;
    return {
        id: 'pkilint',
        provenance: 'DigiCert pkilint — lint_pkix_cert and lint_pkix_signer_signee_cert_chain, RFC 5280 profile',
        host: () => host,
        locate() {
            for (const command of platform === 'win32' ? ['py', 'python', 'python3'] : ['python3', 'python']) {
                host = locate([command], ['-c', 'import pkilint.bin.lint_pkix_cert']);
                if (host !== null) break;
            }
            if (host === null) return null;
            return { version: `pkilint ${host.run(['-c', 'from importlib.metadata import version; print(version("pkilint"))']).stdout.trim()}`, reference: true };
        },
        check(set, work) {
            // The frozen samples are not linted: they are minimal on purpose
            // (a v1 certificate, a root with no key identifier method) and
            // verify:samples already holds every byte of them.
            const fresh: ArtefactSet = { ...set, artefacts: set.artefacts.filter((a) => !isSample(a)) };
            const manifest = join(work, 'manifest-lint.json');
            mkdirSync(work, { recursive: true });
            writeFileSync(manifest, JSON.stringify({ artefacts: fresh.artefacts }));
            return runProgram(host as Host, [join(PROGRAMS, 'pkilint-driver.py')], { ...fresh, manifest }, work, 'pkilint', { PYTHONIOENCODING: 'utf-8' });
        },
    };
}

/** Every write-direction tool, in the order the report lists them. */
export function writeTools(): readonly WriteTool[] {
    return [opensslTool(), cryptoapiTool(), dotnetTool(), certtoolTool(), goTool(), pythonTool(), javaTool(), gpgsmTool(), zlintTool(), pkilintTool()];
}

/** The version a program printed in its header, after a run. */
export { programVersion };
