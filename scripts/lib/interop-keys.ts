/**
 * pkinative — the interoperability matrix, read direction: key containers
 * =======================================================================
 * Foreign tools writing what pkinative reads.
 *
 * pkinative never writes a PKCS#8 or a PKCS#12: it may not encrypt or wrap a
 * key, by policy. For key containers the arrow of the write-direction matrix
 * therefore points back inward, and the oracle is the same — the foreign tool
 * itself. Each writer produces a key and a self-signed certificate, packs them
 * the way the tool does by default and the ways it can be asked to, and
 * pkinative must make of each file exactly what the case declares:
 *
 * - **what was written is agreed on.** The tool says what it wrote — OpenSSL
 *   through `pkcs12 -info`, a command through the scheme it was asked for,
 *   Windows through facts observed once and written down beside each writer —
 *   and `parsePkcs12` / `parseEncryptedPrivateKeyInfo` must read the same MAC
 *   construction and the same encryption schemes, in one spelling.
 * - **a file pkinative can open, it opens:** `openPkcs12` reports the integrity
 *   the case promises, the certificate byte-identical to the one the tool
 *   holds, and a key that signs data the certificate's public key verifies —
 *   verified by the tool where it can (`openssl dgst` / `pkeyutl`), by
 *   node:crypto otherwise, never by pkinative.
 * - **a file pkinative refuses, it reports and never throws for:** the reason
 *   codes are exact and every refused scheme is named.
 *
 * A case the installed tool cannot write — OpenSSL before 3.4 has no PBMAC1,
 * LibreSSL has no `-legacy`, a legacy provider that will not load — is a SKIP
 * with its reason, never a pass.
 *
 * @module scripts/lib/interop-keys
 */

import { spawnSync } from 'node:child_process';
import { X509Certificate, verify as nodeVerify, webcrypto } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join } from 'node:path';
import { env, platform } from 'node:process';
import {
    decryptPrivateKey,
    parseEncryptedPrivateKeyInfo,
    parsePkcs12,
    PkiError,
    openPkcs12,
    type Pkcs12,
    type OpenPkcs12Report,
    type SignatureAlgorithm,
    type SigningKey,
} from '../../src/index.js';
import { KEY_CONTAINER_CASES } from './interop.js';

// ── The vocabulary ───────────────────────────────────────────────────

type KeyKind = 'ec-p256' | 'rsa-2048' | 'ed25519';

/** What each kind of key signs with — the algorithm `decryptPrivateKey` is told, and the one `openPkcs12` derives from the certificate (for RSA, from `OPEN`'s `rsaAlgorithm`). */
const SIGNING: Readonly<Record<KeyKind, SignatureAlgorithm>> = {
    'ec-p256': { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' },
    'rsa-2048': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    ed25519: { name: 'Ed25519' },
};

/** What every `openPkcs12` call here adds to the password: the RSA scheme, which a certificate does not name and pkinative does not guess. */
const OPEN = { rsaAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } } as const;

/**
 * What a container is protected with, in one spelling for every tool: `mac`
 * is `pbmac1`, `appendix-b/<digest>` or `absent`; each scheme is
 * `pbes2/aes-<bits>-cbc/hmac-<digest>` or the name of a PKCS#12 scheme with
 * its punctuation removed. `mac` is `undefined` when the writer cannot say.
 */
interface Protection {
    readonly mac: string | undefined;
    readonly schemes: readonly string[];
}

type Expectation =
    /** `openPkcs12` valid, integrity verified, one key that signs, the certificate byte-identical. */
    | { readonly kind: 'opens' }
    /** Refused for integrity alone; valid with `allowUnverifiedIntegrity`, one key that signs. */
    | { readonly kind: 'opens-unverified' }
    /** Reported, never thrown: exactly these reason codes, each refused scheme named. */
    | { readonly kind: 'reports'; readonly codes: readonly string[]; readonly naming: readonly string[]; readonly integrity: OpenPkcs12Report['integrity'] }
    /** `decryptPrivateKey` returns a key that signs. */
    | { readonly kind: 'decrypts' }
    /** `decryptPrivateKey` throws this code, naming the scheme. */
    | { readonly kind: 'refused'; readonly code: string; readonly naming: string };

/** One file a foreign tool wrote. */
interface ForeignContainer {
    readonly caseId: string;
    readonly key: KeyKind;
    readonly format: 'pkcs12' | 'pkcs8';
    readonly bytes: Uint8Array;
    /** The password pkinative is given — not always the one it was written with. */
    readonly password: string;
    /** The certificate as the tool holds it, DER. */
    readonly certificateDer: Uint8Array;
    /** What the tool says it wrote. */
    readonly wrote: Protection;
    readonly expect: Expectation;
}

interface Written {
    readonly containers: readonly ForeignContainer[];
    readonly skipped: readonly { readonly caseId: string; readonly why: string }[];
    /** A step the tool should have been able to take and did not — documented commands, above all. */
    readonly failures?: readonly string[];
}

interface Writer {
    write(dir: string): Written;
    /** Verify a signature with the certificate's public key as the tool itself does it; `null` when it cannot. */
    verify?(dir: string, certificateDer: Uint8Array, key: KeyKind, data: Uint8Array, signature: Uint8Array): boolean | null;
    /** Who verified, for the report. */
    readonly verifier?: string;
}

const PASSWORD = 'pkinative interop';
const PKCS12_INTEGRITY = 'PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED';
const PKCS12_UNSUPPORTED = 'PKI_REASON_PKCS12_ENCRYPTION_UNSUPPORTED';

/** Letters and digits only, lower case, and OpenSSL's `SHA1And` spelled as RFC 7292's `SHAAnd`. */
const squash = (text: string): string => text.toLowerCase().replace(/[^a-z0-9]/g, '').replace(/sha1and/g, 'shaand');

/** The RFC 7292 Appendix C names, the spelling a PKCS#12 scheme is reported in. */
const PKCS12_SCHEMES: readonly string[] = [
    'pbeWithSHAAnd128BitRC4', 'pbeWithSHAAnd40BitRC4', 'pbeWithSHAAnd3-KeyTripleDES-CBC',
    'pbeWithSHAAnd2-KeyTripleDES-CBC', 'pbeWithSHAAnd128BitRC2-CBC', 'pbeWithSHAAnd40BitRC2-CBC',
];

/**
 * A scheme in the one spelling: OpenSSL's `PBES2, PBKDF2, AES-256-CBC,
 * Iteration 2048, PRF hmacWithSHA256` and pkinative's `PBES2 (PBKDF2 with
 * HMAC-SHA-256, AES-256-CBC)` both become `pbes2/aes-256-cbc/hmac-sha256`;
 * OpenSSL's `pbeWithSHA1And40BitRC2-CBC, Iteration 2048` becomes RFC 7292's
 * `pbeWithSHAAnd40BitRC2-CBC`.
 */
function schemeToken(text: string): string {
    const lower = text.toLowerCase();
    if (!lower.includes('pbes2')) {
        // OpenSSL appends `, Iteration 2048`; the scheme is what precedes it.
        const name = squash(text.split(',')[0] ?? text);
        return PKCS12_SCHEMES.find((s) => squash(s) === name) ?? name;
    }
    const bits = /aes-?(\d+)-?cbc/.exec(lower)?.[1] ?? '?';
    // PBKDF2's PRF defaults to HMAC-SHA-1, which OpenSSL then does not print.
    const prf = /hmac(?:with|-)(sha-?\d+)/.exec(lower)?.[1]?.replace('-', '') ?? 'sha1';
    return `pbes2/aes-${bits}-cbc/hmac-${prf}`;
}

const DIGESTS: ReadonlyMap<string, string> = new Map([
    ['1.3.14.3.2.26', 'sha1'],
    ['2.16.840.1.101.3.4.2.1', 'sha256'],
    ['2.16.840.1.101.3.4.2.2', 'sha384'],
    ['2.16.840.1.101.3.4.2.3', 'sha512'],
]);

/** What pkinative reads a PKCS#12 as protected with: its MAC, the encryption of every SafeContents, and of every key in the plain ones. */
function protectionRead(p: Pkcs12): Protection {
    const mac = p.mac === undefined ? 'absent'
        : p.mac.kind === 'pbmac1' ? 'pbmac1'
            : `appendix-b/${DIGESTS.get(p.mac.algorithm.oid) ?? p.mac.algorithm.oid}`;
    const schemes: string[] = [];
    for (const contents of p.contents) {
        if (contents.encryption !== undefined) schemes.push(schemeToken(contents.encryption.scheme));
        for (const bag of contents.bags) {
            if (bag.encryptedKey !== undefined) schemes.push(schemeToken(bag.encryptedKey.encryption.scheme));
        }
    }
    return { mac, schemes };
}

const describe = (p: Protection): string =>
    `MAC ${p.mac ?? 'not stated'}; ${p.schemes.length === 0 ? 'nothing encrypted' : p.schemes.join(' + ')}`;

/**
 * What pkinative must make of a PKCS#12, decided by what the tool says it
 * wrote: every PBES2 opens, every other scheme is named in a reason, and an
 * Appendix B MAC is integrity pkinative cannot verify.
 */
function expectationFor(p: Protection): Expectation {
    const refused = p.schemes.filter((s) => !s.startsWith('pbes2/'));
    if (refused.length === 0) return p.mac === 'pbmac1' ? { kind: 'opens' } : { kind: 'opens-unverified' };
    return {
        kind: 'reports',
        codes: [...(p.mac === 'pbmac1' ? [] : [PKCS12_INTEGRITY]), ...refused.map(() => PKCS12_UNSUPPORTED)],
        naming: refused,
        integrity: 'unverified',
    };
}

// ── The shell ────────────────────────────────────────────────────────

interface Ran { readonly status: number; readonly stdout: string; readonly stderr: string }

function run(command: string, args: readonly string[], extraEnv: Readonly<Record<string, string>> = {}): Ran {
    const r = spawnSync(command, [...args], { encoding: 'utf8', windowsHide: true, env: { ...env, ...extraEnv } });
    return { status: r.status ?? -1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const firstLine = (r: Ran): string => (r.stderr.trim() || r.stdout.trim()).split(/\r?\n/)[0] ?? `exit ${String(r.status)}`;

/** The directory holding an executable found on PATH, or `undefined`. */
function onPath(name: string): string | undefined {
    const files = platform === 'win32' ? [`${name}.exe`, name] : [name];
    for (const dir of (env.PATH ?? env.Path ?? '').split(delimiter)) {
        if (dir !== '' && files.some((f) => existsSync(join(dir, f)))) return dir;
    }
    return undefined;
}

// ── OpenSSL ──────────────────────────────────────────────────────────

const GENPKEY: Readonly<Record<KeyKind, readonly string[]>> = {
    'ec-p256': ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'],
    'rsa-2048': ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    ed25519: ['-algorithm', 'ED25519'],
};

/**
 * The environment under which OpenSSL loads its legacy provider, or why it
 * cannot. The provider is a separate module that installers put in different
 * places — the Windows build next to `openssl.exe` while its compiled-in
 * MODULESDIR points elsewhere — so the places are tried in turn, and each is
 * proved by loading the provider rather than by finding a file.
 */
function legacyProvider(): { readonly env: Readonly<Record<string, string>> } | { readonly why: string } {
    const loads = (extra: Readonly<Record<string, string>>): boolean => run('openssl', ['list', '-providers', '-provider', 'legacy'], extra).status === 0;
    if (loads({})) return { env: {} };
    const candidates = new Set<string>();
    const modulesDir = /MODULESDIR:\s*"([^"]+)"/.exec(run('openssl', ['version', '-m']).stdout)?.[1];
    if (modulesDir !== undefined) candidates.add(modulesDir);
    const bin = onPath('openssl');
    if (bin !== undefined) {
        candidates.add(bin);
        candidates.add(join(dirname(bin), 'lib', 'ossl-modules'));
        candidates.add(join(dirname(bin), 'lib64', 'ossl-modules'));
    }
    for (const dir of candidates) {
        if (!['legacy.dll', 'legacy.so', 'legacy.dylib'].some((f) => existsSync(join(dir, f)))) continue;
        if (loads({ OPENSSL_MODULES: dir })) return { env: { OPENSSL_MODULES: dir } };
    }
    return { why: `the legacy provider does not load (looked in ${[...candidates].join(', ') || 'no directory'}) — RC2 is only there` };
}

/** Parse `openssl pkcs12 -info -noout`: the MAC line and every encrypted item. */
function opensslProtection(text: string): Protection | undefined {
    const lines = text.split(/\r?\n/).map((l) => l.trim());
    const macLine = lines.find((l) => l.startsWith('MAC: '))?.slice(5);
    const mac = macLine === undefined ? undefined
        : /^PBMAC1/i.test(macLine) ? 'pbmac1' : `appendix-b/${(/^([A-Za-z0-9-]+)/.exec(macLine)?.[1] ?? macLine).toLowerCase().replace('-', '')}`;
    const schemes = lines.flatMap((l) => {
        const m = /^(?:PKCS7 Encrypted data|Shrouded Keybag): (.+)$/.exec(l);
        return m?.[1] === undefined ? [] : [schemeToken(m[1])];
    });
    return schemes.length === 0 && mac === undefined ? undefined : { mac, schemes };
}

/** An IEEE P1363 ECDSA signature — what Web Crypto produces — as the DER `Ecdsa-Sig-Value` OpenSSL verifies. */
function p1363ToDer(signature: Uint8Array): Uint8Array {
    const half = signature.length / 2;
    const integer = (bytes: Uint8Array): number[] => {
        let i = 0;
        while (i < bytes.length - 1 && bytes[i] === 0) i += 1;
        const body = [...bytes.subarray(i)];
        if ((body[0] ?? 0) >= 0x80) body.unshift(0);
        return [0x02, body.length, ...body];
    };
    const content = [...integer(signature.subarray(0, half)), ...integer(signature.subarray(half))];
    return Uint8Array.from([0x30, content.length, ...content]);
}

const OPENSSL_WRITER: Writer = {
    verifier: 'openssl verifies',
    write(dir) {
        const containers: ForeignContainer[] = [];
        const skipped: { caseId: string; why: string }[] = [];
        const failures: string[] = [];
        const file = (name: string): string => join(dir, name);
        const help = run('openssl', ['pkcs12', '-help']);
        const helpText = `${help.stdout}\n${help.stderr}`;
        const pbmac1 = helpText.includes('-pbmac1_pbkdf2');
        const legacyFlag = helpText.includes('-legacy');
        const legacy = legacyFlag ? legacyProvider() : { why: 'this openssl has no -legacy option (LibreSSL, or OpenSSL before 3.0, whose default export is the legacy one)' };
        const noPbmac1 = 'this openssl cannot write PBMAC1 (-pbmac1_pbkdf2 needs OpenSSL 3.4 or later)';

        /** `openssl pkcs12 -info` on a file, as a Protection, or a skip. */
        const info = (path: string, extra: readonly string[] = [], extraEnv: Readonly<Record<string, string>> = {}): Protection | string => {
            const r = run('openssl', ['pkcs12', '-info', '-noout', '-in', path, '-passin', `pass:${PASSWORD}`, ...extra], extraEnv);
            const described = opensslProtection(`${r.stdout}\n${r.stderr}`);
            return described ?? `openssl cannot describe the file it wrote (${firstLine(r)})`;
        };

        const pkcs12Case = (caseId: string, key: KeyKind, path: string, cert: Uint8Array, described: Protection | string, expect?: Expectation, password = PASSWORD): void => {
            if (typeof described === 'string') { skipped.push({ caseId, why: `${key}: ${described}` }); return; }
            containers.push({ caseId, key, format: 'pkcs12', bytes: new Uint8Array(readFileSync(path)), password, certificateDer: cert, wrote: described, expect: expect ?? expectationFor(described) });
        };

        for (const key of ['ec-p256', 'rsa-2048', 'ed25519'] as const) {
            const keyPem = file(`${key}.key.pem`);
            const certPem = file(`${key}.cert.pem`);
            const certDer = file(`${key}.cert.der`);
            const made = run('openssl', ['genpkey', ...GENPKEY[key], '-out', keyPem]);
            const signed = made.status === 0
                ? run('openssl', ['req', '-new', '-x509', '-key', keyPem, '-out', certPem, '-subj', `/CN=pkinative interop ${key}`, '-days', '30'])
                : made;
            const exported = signed.status === 0 ? run('openssl', ['x509', '-in', certPem, '-outform', 'DER', '-out', certDer]) : signed;
            if (exported.status !== 0) {
                for (const c of KEY_CONTAINER_CASES.filter((c) => c.tool === 'openssl')) skipped.push({ caseId: c.id, why: `${key}: this openssl cannot make the key and certificate (${firstLine(exported)})` });
                continue;
            }
            const cert = new Uint8Array(readFileSync(certDer));
            const exportArgs = (out: string): string[] => ['pkcs12', '-export', '-in', certPem, '-inkey', keyPem, '-out', out, '-passout', `pass:${PASSWORD}`];

            // PBMAC1, and — for one key — the same file under the wrong password.
            const pb = file(`${key}.pbmac1.p12`);
            const pbr = pbmac1 ? run('openssl', [...exportArgs(pb), '-pbmac1_pbkdf2']) : undefined;
            const pbWhy = pbr === undefined ? noPbmac1 : pbr.status !== 0 ? firstLine(pbr) : undefined;
            const pbCases = key === 'ec-p256' ? ['openssl:pkcs12-pbmac1', 'openssl:pkcs12-wrong-password'] : ['openssl:pkcs12-pbmac1'];
            if (pbWhy !== undefined) {
                for (const caseId of pbCases) skipped.push({ caseId, why: `${key}: ${pbWhy}` });
            } else {
                const described = info(pb);
                pkcs12Case('openssl:pkcs12-pbmac1', key, pb, cert, described);
                if (key === 'ec-p256') {
                    pkcs12Case('openssl:pkcs12-wrong-password', key, pb, cert, described,
                        { kind: 'reports', codes: ['PKI_REASON_PKCS12_MAC_MISMATCH'], naming: [], integrity: 'mismatch' }, 'not the password');
                }
            }

            // The default: what `openssl pkcs12 -export` writes with no option,
            // which differs by version — so the tool's own -info decides.
            const def = file(`${key}.default.p12`);
            const r = run('openssl', exportArgs(def));
            if (r.status !== 0) skipped.push({ caseId: 'openssl:pkcs12-default', why: `${key}: ${firstLine(r)}` });
            else pkcs12Case('openssl:pkcs12-default', key, def, cert, info(def, legacyFlag && 'env' in legacy ? ['-legacy'] : [], 'env' in legacy ? legacy.env : {}));

            // PKCS#8 under PBES2, for every key.
            const p8 = file(`${key}.pbes2.p8.der`);
            const p8r = run('openssl', ['pkcs8', '-topk8', '-v2', 'aes-256-cbc', '-v2prf', 'hmacWithSHA256', '-in', keyPem, '-outform', 'DER', '-out', p8, '-passout', `pass:${PASSWORD}`]);
            if (p8r.status !== 0) skipped.push({ caseId: 'openssl:pkcs8-pbes2', why: `${key}: ${firstLine(p8r)}` });
            else containers.push({ caseId: 'openssl:pkcs8-pbes2', key, format: 'pkcs8', bytes: new Uint8Array(readFileSync(p8)), password: PASSWORD, certificateDer: cert, wrote: { mac: undefined, schemes: ['pbes2/aes-256-cbc/hmac-sha256'] }, expect: { kind: 'decrypts' } });

            if (key !== 'ec-p256') continue;

            // PKCS#8 under a PKCS#12 scheme: 3DES keyed by Appendix B.
            const v1 = file(`${key}.pbes1.p8.der`);
            const v1r = run('openssl', ['pkcs8', '-topk8', '-v1', 'PBE-SHA1-3DES', '-in', keyPem, '-outform', 'DER', '-out', v1, '-passout', `pass:${PASSWORD}`]);
            if (v1r.status !== 0) skipped.push({ caseId: 'openssl:pkcs8-pbes1', why: `${key}: ${firstLine(v1r)}` });
            else {
                const scheme = 'pbeWithSHAAnd3-KeyTripleDES-CBC';
                containers.push({ caseId: 'openssl:pkcs8-pbes1', key, format: 'pkcs8', bytes: new Uint8Array(readFileSync(v1)), password: PASSWORD, certificateDer: cert, wrote: { mac: undefined, schemes: [scheme] }, expect: { kind: 'refused', code: 'PKI_KEY_ENCRYPTION_UNSUPPORTED', naming: scheme } });
            }

            // -legacy, and the conversion SECURITY.md and errors.json document.
            if (!('env' in legacy)) {
                skipped.push({ caseId: 'openssl:pkcs12-legacy', why: legacy.why });
                skipped.push({ caseId: 'openssl:pkcs12-converted', why: legacy.why });
                continue;
            }
            const leg = file(`${key}.legacy.p12`);
            const lr = run('openssl', [...exportArgs(leg), '-legacy'], legacy.env);
            if (lr.status !== 0) {
                skipped.push({ caseId: 'openssl:pkcs12-legacy', why: firstLine(lr) });
                skipped.push({ caseId: 'openssl:pkcs12-converted', why: 'no legacy file to convert' });
                continue;
            }
            pkcs12Case('openssl:pkcs12-legacy', key, leg, cert, info(leg, ['-legacy'], legacy.env));
            if (!pbmac1) { skipped.push({ caseId: 'openssl:pkcs12-converted', why: noPbmac1 }); continue; }
            const bundle = file('bundle.pem');
            const modern = file('modern.p12');
            const pemPass = 'pem pass phrase';
            const step1 = run('openssl', ['pkcs12', '-in', leg, '-legacy', '-out', bundle, '-passin', `pass:${PASSWORD}`, '-passout', `pass:${pemPass}`], legacy.env);
            const step2 = step1.status === 0
                ? run('openssl', ['pkcs12', '-export', '-in', bundle, '-pbmac1_pbkdf2', '-out', modern, '-passin', `pass:${pemPass}`, '-passout', `pass:${PASSWORD}`])
                : step1;
            if (step2.status !== 0) {
                // The documented commands failing is a finding about the
                // documentation, not a tool that cannot do something.
                failures.push(`openssl:pkcs12-converted: the conversion SECURITY.md and docs/data/errors.json document fails on this openssl (${firstLine(step2)})`);
            } else {
                pkcs12Case('openssl:pkcs12-converted', key, modern, cert, info(modern), { kind: 'opens' });
            }
        }
        return { containers, skipped, failures };
    },
    verify(dir, certificateDer, key, data, signature) {
        const cert = join(dir, 'verify-cert.der');
        const pub = join(dir, 'verify-pub.pem');
        const dataPath = join(dir, 'verify-data.bin');
        const sigPath = join(dir, 'verify-sig.bin');
        writeFileSync(cert, certificateDer);
        writeFileSync(dataPath, data);
        writeFileSync(sigPath, key === 'ec-p256' ? p1363ToDer(signature) : signature);
        const extracted = run('openssl', ['x509', '-inform', 'DER', '-in', cert, '-pubkey', '-noout']);
        if (extracted.status !== 0) return null;
        writeFileSync(pub, extracted.stdout);
        const r = key === 'ed25519'
            ? run('openssl', ['pkeyutl', '-verify', '-pubin', '-inkey', pub, '-rawin', '-in', dataPath, '-sigfile', sigPath])
            : run('openssl', ['dgst', '-sha256', '-verify', pub, '-signature', sigPath, dataPath]);
        // A tool too old for the option cannot verify here; that is not a "no".
        if (r.status !== 0 && /unknown option|unrecognized|invalid command/i.test(r.stderr)) return null;
        return r.status === 0;
    },
};

// ── Windows ──────────────────────────────────────────────────────────

/**
 * The PowerShell that makes an EC P-256 and an RSA 2048 key and certificate
 * in memory — `CertificateRequest.CreateSelfSigned`, no certificate store
 * touched — and exports each with `exportCall`.
 */
function windowsScript(dir: string, exportCall: string, guard: string): string {
    const at = dir.replace(/'/g, "''");
    return [
        "$ErrorActionPreference = 'Stop'",
        guard,
        "$X = 'System.Security.Cryptography.X509Certificates'",
        '$now = [DateTimeOffset]::UtcNow',
        '$sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256',
        "$ec = New-Object \"$X.CertificateRequest\" 'CN=pkinative interop windows ec-p256', ([System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)), $sha256",
        "$rsa = New-Object \"$X.CertificateRequest\" 'CN=pkinative interop windows rsa-2048', ([System.Security.Cryptography.RSA]::Create(2048)), $sha256, ([System.Security.Cryptography.RSASignaturePadding]::Pkcs1)",
        "foreach ($pair in @(@('ec-p256', $ec), @('rsa-2048', $rsa))) { $c = $pair[1].CreateSelfSigned($now.AddMinutes(-5), $now.AddDays(30)); "
            + `[IO.File]::WriteAllBytes((Join-Path '${at}' ($pair[0] + '.cer')), $c.RawData); `
            + `[IO.File]::WriteAllBytes((Join-Path '${at}' ($pair[0] + '.pfx')), ${exportCall}) }`,
        "'WROTE ' + [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription",
    ].join('\n');
}

const TRIPLE_DES = 'pbeWithSHAAnd3-KeyTripleDES-CBC';
const PBES2_AES256_SHA256 = 'pbes2/aes-256-cbc/hmac-sha256';

const WINDOWS_WRITER: Writer = {
    write(dir) {
        const containers: ForeignContainer[] = [];
        const skipped: { caseId: string; why: string }[] = [];
        const collect = (caseId: string, sub: string, wrote: Protection): void => {
            for (const key of ['ec-p256', 'rsa-2048'] as const) {
                containers.push({
                    caseId, key, format: 'pkcs12',
                    bytes: new Uint8Array(readFileSync(join(sub, `${key}.pfx`))), password: PASSWORD,
                    certificateDer: new Uint8Array(readFileSync(join(sub, `${key}.cer`))),
                    wrote, expect: expectationFor(wrote),
                });
            }
        };

        // Windows PowerShell 5.1: .NET Framework, whose Export hands the store
        // to CryptoAPI's PFXExportCertStoreEx. Observed on Windows 11 26100
        // (.NET Framework 4.8.1), and the same from PowerShell 7 on .NET 10:
        //  - MAC: HMAC-SHA-1 keyed with RFC 7292 Appendix B, 2000 iterations,
        //    a 20-byte salt — integrity pkinative cannot verify;
        //  - the key: a pkcs8ShroudedKeyBag under pbeWithSHAAnd3-KeyTripleDES-CBC,
        //    in a plain SafeContents that comes FIRST;
        //  - the certificate: an encrypted SafeContents, also 3DES — so
        //    nothing opens, and the report names 3DES twice;
        //  - DER throughout at every level parsePkcs12 reads: no encodingRules
        //    'ber' needed, although openPkcs12 documents Windows as a BER writer.
        const exported = join(dir, 'export');
        mkdirSync(exported, { recursive: true });
        const r = run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
            windowsScript(exported, `$c.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, '${PASSWORD}')`, '')]);
        if (r.status !== 0 || !r.stdout.includes('WROTE')) skipped.push({ caseId: 'windows-cryptoapi:pfx-export', why: `Windows PowerShell could not export a PFX (${firstLine(r)})` });
        else collect('windows-cryptoapi:pfx-export', exported, { mac: 'appendix-b/sha1', schemes: [TRIPLE_DES, TRIPLE_DES] });

        // PowerShell 7 on .NET 9 or later, asked for PBES2 explicitly.
        // Observed with .NET 10.0 on Windows 11 26100:
        //  - MAC: HMAC-SHA-256, still keyed with Appendix B (2000 iterations,
        //    20-byte salt) — .NET has no PBMAC1, so integrity stays unverified;
        //  - the key and the certificate's SafeContents both under PBES2 with
        //    PBKDF2/HMAC-SHA-256 and AES-256-CBC, 2000 iterations;
        //  - the same layout as the 3DES export (key first), DER throughout.
        const pbes2 = join(dir, 'pbes2');
        mkdirSync(pbes2, { recursive: true });
        if (onPath('pwsh') === undefined) {
            skipped.push({ caseId: 'windows-cryptoapi:pfx-pbes2', why: 'PowerShell 7 (pwsh) is not installed, and Windows PowerShell 5.1 has no ExportPkcs12' });
        } else {
            const p = run('pwsh', ['-NoProfile', '-NonInteractive', '-Command', windowsScript(pbes2,
                `$c.ExportPkcs12([System.Security.Cryptography.X509Certificates.Pkcs12ExportPbeParameters]::Pbes2Aes256Sha256, '${PASSWORD}')`,
                "if (-not ('System.Security.Cryptography.X509Certificates.Pkcs12ExportPbeParameters' -as [type])) { 'NO-PBES2 ' + [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription; exit 0 }")]);
            if (p.stdout.includes('NO-PBES2')) skipped.push({ caseId: 'windows-cryptoapi:pfx-pbes2', why: `PowerShell 7 runs on ${p.stdout.replace('NO-PBES2', '').trim()}, which has no ExportPkcs12 — it arrived in .NET 9` });
            else if (p.status !== 0 || !p.stdout.includes('WROTE')) skipped.push({ caseId: 'windows-cryptoapi:pfx-pbes2', why: `PowerShell 7 could not export a PFX (${firstLine(p)})` });
            else collect('windows-cryptoapi:pfx-pbes2', pbes2, { mac: 'appendix-b/sha256', schemes: [PBES2_AES256_SHA256, PBES2_AES256_SHA256] });
        }
        return { containers, skipped };
    },
};

/** The writers, by the tool id of scripts/lib/interop.ts. */
const WRITERS: ReadonlyMap<string, Writer> = new Map([
    ['openssl', OPENSSL_WRITER],
    ['windows-cryptoapi', WINDOWS_WRITER],
]);

// ── The reading ──────────────────────────────────────────────────────

export interface KeyContainerRun {
    readonly checks: number;
    readonly containers: number;
    /** One line per container: what the tool wrote, and what pkinative read. */
    readonly lines: readonly string[];
    readonly failures: readonly string[];
    readonly skips: readonly string[];
}

const sameBytes = (a: Uint8Array | undefined, b: Uint8Array): boolean =>
    a !== undefined && a.length === b.length && a.every((v, i) => v === b[i]);

const codesOf = (r: OpenPkcs12Report): string => r.reasons.map((x) => x.code).sort().join(',');

/**
 * Hand every container a tool writes to pkinative, and compare. `null` when
 * the tool writes no key container.
 */
export async function readKeyContainers(toolId: string, dir: string): Promise<KeyContainerRun | null> {
    const writer = WRITERS.get(toolId);
    if (writer === undefined) return null;
    mkdirSync(dir, { recursive: true });
    const failures: string[] = [];
    const skips: string[] = [];
    const lines: string[] = [];
    let checks = 0;
    const written = writer.write(dir);
    const declared = KEY_CONTAINER_CASES.filter((c) => c.tool === toolId).map((c) => c.id);
    const seen = new Set<string>();
    failures.push(...written.failures ?? []);
    for (const f of written.failures ?? []) seen.add(f.split(':').slice(0, 2).join(':'));

    for (const s of written.skipped) {
        seen.add(s.caseId);
        skips.push(`${s.caseId} not written: ${s.why}`);
    }

    /** Sign with a key pkinative handed back, and have someone other than pkinative verify it. */
    const signs = async (c: ForeignContainer, signingKey: SigningKey | undefined): Promise<string> => {
        if (signingKey === undefined) { failures.push(`${c.caseId} ${c.key}: pkinative handed back no signing key`); return 'no key'; }
        const data = new TextEncoder().encode(`signed with the key ${c.caseId} held`);
        const a = signingKey.algorithm;
        const params = a.name === 'ECDSA' ? { name: 'ECDSA', hash: a.hash } : a.name === 'RSA-PSS' ? { name: 'RSA-PSS', saltLength: 32 } : { name: a.name };
        const signature = new Uint8Array(await webcrypto.subtle.sign(params, signingKey.key as unknown as webcrypto.CryptoKey, data));
        let by = writer.verifier ?? 'node:crypto verifies';
        let ok = writer.verify?.(dir, c.certificateDer, c.key, data, signature) ?? null;
        if (ok === null) {
            by = 'node:crypto verifies';
            ok = nodeVerify(c.key === 'ed25519' ? null : 'sha256', data, { key: new X509Certificate(c.certificateDer).publicKey, dsaEncoding: 'ieee-p1363' }, signature);
        }
        checks += 1;
        if (!ok) failures.push(`${c.caseId} ${c.key}: the key pkinative opened signs data its certificate's public key does not verify (${by.replace(' verifies', '')})`);
        return `the key signs (${by})`;
    };

    /** The one key a container holds: its certificate byte-identical, and a signature that verifies. */
    const holdsKey = async (c: ForeignContainer, r: OpenPkcs12Report): Promise<string> => {
        checks += 1;
        if (r.keys.length !== 1) { failures.push(`${c.caseId} ${c.key}: ${String(r.keys.length)} keys reported, one written`); return 'wrong key count'; }
        const [held] = r.keys;
        if (!sameBytes(held?.certificate?.der, c.certificateDer)) failures.push(`${c.caseId} ${c.key}: the key's certificate is not byte-identical to the one the tool wrote`);
        return signs(c, held?.signingKey);
    };

    for (const c of written.containers) {
        seen.add(c.caseId);
        if (!declared.includes(c.caseId)) {
            failures.push(`${c.caseId}: produced by ${toolId} and not declared in scripts/lib/interop.ts KEY_CONTAINER_CASES — an undeclared case is one the guide cannot describe`);
            continue;
        }
        const label = `${c.caseId} ${c.key}`;
        let read: string;
        try {
            // ── What was written, agreed on ──
            if (c.format === 'pkcs12') {
                let parsed: Pkcs12 | undefined;
                try { parsed = parsePkcs12(c.bytes); } catch (error) {
                    failures.push(`${label}: parsePkcs12 refused what ${toolId} wrote (${error instanceof Error ? error.message : String(error)})`);
                }
                if (parsed !== undefined) {
                    const got = protectionRead(parsed);
                    checks += 1;
                    if (c.wrote.mac !== undefined && got.mac !== c.wrote.mac) failures.push(`${label}: ${toolId} wrote MAC ${c.wrote.mac}, pkinative read ${got.mac ?? '?'}`);
                    if ([...got.schemes].sort().join(',') !== [...c.wrote.schemes].sort().join(',')) failures.push(`${label}: ${toolId} wrote ${c.wrote.schemes.join(' + ')}, pkinative read ${got.schemes.join(' + ')}`);
                }
            } else {
                const got = schemeToken(parseEncryptedPrivateKeyInfo(c.bytes).encryption.scheme);
                checks += 1;
                if (got !== c.wrote.schemes[0]) failures.push(`${label}: ${toolId} wrote ${c.wrote.schemes[0] ?? '?'}, pkinative read ${got}`);
            }

            // ── What pkinative makes of it ──
            const e = c.expect;
            switch (e.kind) {
                case 'opens': {
                    const r = await openPkcs12(c.bytes, { ...OPEN, password: c.password });
                    checks += 1;
                    if (!r.valid || r.integrity !== 'verified') failures.push(`${label}: openPkcs12 says valid=${String(r.valid)}, integrity=${r.integrity} (${codesOf(r) || 'no reason'}); expected valid and verified`);
                    read = `valid, integrity verified, ${await holdsKey(c, r)}`;
                    break;
                }
                case 'opens-unverified': {
                    const strict = await openPkcs12(c.bytes, { ...OPEN, password: c.password });
                    checks += 1;
                    if (strict.valid || strict.integrity !== 'unverified' || codesOf(strict) !== PKCS12_INTEGRITY) {
                        failures.push(`${label}: openPkcs12 says valid=${String(strict.valid)}, integrity=${strict.integrity}, reasons ${codesOf(strict) || 'none'}; expected ${PKCS12_INTEGRITY} alone`);
                    }
                    const waived = await openPkcs12(c.bytes, { ...OPEN, password: c.password, allowUnverifiedIntegrity: true });
                    checks += 1;
                    if (!waived.valid) failures.push(`${label}: with allowUnverifiedIntegrity openPkcs12 is still not valid (${codesOf(waived)})`);
                    read = `${PKCS12_INTEGRITY}; with allowUnverifiedIntegrity valid, ${await holdsKey(c, waived)}`;
                    break;
                }
                case 'reports': {
                    const r = await openPkcs12(c.bytes, { ...OPEN, password: c.password });
                    checks += 1;
                    const want = [...e.codes].sort().join(',');
                    if (r.valid || codesOf(r) !== want || r.integrity !== e.integrity) {
                        failures.push(`${label}: openPkcs12 says valid=${String(r.valid)}, integrity=${r.integrity}, reasons ${codesOf(r) || 'none'}; expected ${want}, integrity ${e.integrity}`);
                    }
                    for (const scheme of e.naming) {
                        checks += 1;
                        if (!r.reasons.some((x) => x.code === PKCS12_UNSUPPORTED && squash(x.message).includes(squash(scheme)))) failures.push(`${label}: no ${PKCS12_UNSUPPORTED} names ${scheme}`);
                    }
                    if (e.integrity === 'mismatch' && r.keys.length !== 0) failures.push(`${label}: a MAC mismatch decrypted ${String(r.keys.length)} key(s) anyway`);
                    read = `reported, not thrown: ${[...new Set(r.reasons.map((x) => x.code))].join(' + ')}`;
                    break;
                }
                case 'decrypts': {
                    const key = await decryptPrivateKey(c.bytes, { password: c.password, algorithm: SIGNING[c.key] });
                    read = `decryptPrivateKey: ${await signs(c, key)}`;
                    break;
                }
                case 'refused': {
                    checks += 1;
                    try {
                        await decryptPrivateKey(c.bytes, { password: c.password, algorithm: SIGNING[c.key] });
                        failures.push(`${label}: decryptPrivateKey opened a key it must refuse`);
                        read = 'opened';
                    } catch (error) {
                        const code = error instanceof PkiError ? error.code : 'not a PkiError';
                        if (code !== e.code) failures.push(`${label}: decryptPrivateKey threw ${code}, expected ${e.code}`);
                        if (!(error instanceof Error) || !squash(error.message).includes(squash(e.naming))) failures.push(`${label}: the refusal does not name ${e.naming}`);
                        read = `decryptPrivateKey throws ${code}`;
                    }
                    break;
                }
            }
        } catch (error) {
            // openPkcs12 must never throw for the file's sake, and a key the
            // case says opens must open: either way the finding is pkinative's.
            failures.push(`${label}: threw ${error instanceof PkiError ? error.code : ''} ${error instanceof Error ? error.message : String(error)}`);
            read = 'threw';
        }
        lines.push(`${label}: wrote ${c.format === 'pkcs8' ? `EncryptedPrivateKeyInfo under ${c.wrote.schemes.join(' + ')}` : describe(c.wrote)} — read ${read}`);
    }

    for (const id of declared) {
        if (!seen.has(id)) failures.push(`${id}: declared in KEY_CONTAINER_CASES and neither written nor skipped with a reason by ${toolId}`);
    }
    if (written.containers.length > 0 && checks === 0) failures.push(`${toolId}: key containers compared nothing`);
    return { checks, containers: written.containers.length, lines, failures, skips };
}
