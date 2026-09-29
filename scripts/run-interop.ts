#!/usr/bin/env tsx
/**
 * pkinative — the interoperability matrix
 * =======================================
 * Foreign tools reading what pkinative writes — and, for key containers,
 * which pkinative reads and never writes, pkinative reading what they write
 * (`scripts/lib/interop-keys.ts`, the `KEYS` lines).
 *
 * The conformance gate's L1–L5 all point one way: bytes someone else produced,
 * read by pkinative. From 0.3 the arrow also points outward, and that
 * direction has no corpus — nobody publishes a set of certificates a library
 * is supposed to have written. The only oracle available is the tools
 * themselves, so this runner hands each artefact to every tool it can find and
 * requires them to agree on facts that have exactly one right answer: the
 * serial number, the subject common name, the DNS names, and — for the chain —
 * whether the signature verifies.
 *
 * What is compared is never rendered text where a fact would do. Every tool
 * prints a distinguished name its own way, and comparing those would test
 * formatting. What the table below extracts is the *value*, in one spelling,
 * from each tool's own output.
 *
 * **Three states, not two.** A tool that is absent is a SKIP, which
 * `--require-all` turns into a failure: on the reference platform every
 * declared tool must be there. A tool that is present and *refuses* an
 * artefact is a **failure** — unlike the read direction, where a foreign
 * acceptance policy stricter than ours is not our defect, here the artefact
 * is ours, and a tool refusing it is exactly the finding this runner exists
 * to produce.
 *
 * Usage:
 *   npx tsx scripts/run-interop.ts
 *   npx tsx scripts/run-interop.ts --require-all
 *   npx tsx scripts/run-interop.ts --json
 *
 * Exit: 0 every present tool agreed; 1 a disagreement, a refusal, or a
 * missing tool under `--require-all`.
 *
 * @module scripts/run-interop
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { argv, exit, stdout } from 'node:process';
import { PENDING_TOOLS } from './lib/interop.js';
import { readKeyContainers } from './lib/interop-keys.js';
import { EXPECTED, samples } from './lib/samples.js';

/**
 * What a tool can say about a certificate. Every field is optional and each
 * tool declares in `supplies` which it can produce, the same contract the
 * read-direction validators already follow: a tool that cannot reach a field
 * says so instead of being special-cased, and a field nobody supplies is not
 * silently compared against nothing.
 */
interface Facts {
    /** The serial as an unsigned integer. Tools print it in several widths and cases; the value has one spelling. */
    readonly serial?: bigint;
    readonly commonName?: string;
    readonly dnsNames?: readonly string[];
}

type FactField = 'serial' | 'commonName' | 'dnsNames';

/**
 * Three outcomes, and conflating the last two is how a gate ends up red in
 * one language and green in another.
 *
 * - `facts` — the tool read the artefact.
 * - `refused` — the tool exited non-zero: it will not accept these bytes, and
 *   since the bytes are ours that is a finding about pkinative.
 * - `unreadable` — the tool succeeded and this runner could not parse what it
 *   printed. That is a defect **here**, never evidence about the artefact.
 *   Windows `certutil` found this the first time it ran: its `-dump` output is
 *   localised, so "Numéro de série" did not match a regex expecting "Serial
 *   Number", and a runner with two states would have reported a perfectly
 *   good certificate as refused.
 */
type Reading =
    | { readonly kind: 'facts'; readonly facts: Facts }
    | { readonly kind: 'refused'; readonly detail: string }
    | { readonly kind: 'unreadable'; readonly detail: string };

interface Tool {
    readonly id: string;
    /** Where it comes from, for the report and for anyone reproducing this. */
    readonly provenance: string;
    /** The fields this tool can supply in a stable, locale-independent form. */
    readonly supplies: readonly FactField[];
    /** The version string, or null when the tool is not installed here. */
    version(): string | null;
    read(path: string): Reading;
    /** Verify a leaf against a root, both DER. `null` means "cannot do this". */
    verifyChain?(leaf: string, root: string): boolean | null;
    /** Read a DER PKCS#10 request and check its self-signature. */
    readRequest?(path: string): boolean | null;
}

const run = (command: string, args: readonly string[]): { status: number; stdout: string; stderr: string } => {
    const r = spawnSync(command, [...args], { encoding: 'utf8', windowsHide: true });
    return { status: r.status ?? -1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
};

const dnsFrom = (text: string): string[] => [...text.matchAll(/DNS:([^\s,]+)/g)].map((m) => m[1] as string).sort();

// ── The tools ────────────────────────────────────────────────────────

const OPENSSL: Tool = {
    id: 'openssl',
    provenance: 'the OpenSSL command-line tool, a lineage independent of everything else here',
    supplies: ['serial', 'commonName', 'dnsNames'],
    version() {
        const r = run('openssl', ['version']);
        return r.status === 0 ? r.stdout.trim() : null;
    },
    read(path) {
        const r = run('openssl', ['x509', '-inform', 'DER', '-in', path, '-noout', '-serial', '-subject', '-ext', 'subjectAltName']);
        if (r.status !== 0) return { kind: 'refused', detail: r.stderr.trim().split('\n')[0] ?? `exit ${String(r.status)}` };
        const serial = /serial=([0-9A-Fa-f]+)/.exec(r.stdout)?.[1];
        const commonName = /CN\s*=\s*([^,\n/]+)/.exec(r.stdout)?.[1]?.trim();
        if (serial === undefined || commonName === undefined) return { kind: 'unreadable', detail: `no serial or CN in ${JSON.stringify(r.stdout.slice(0, 120))}` };
        return { kind: 'facts', facts: { serial: BigInt(`0x${serial}`), commonName, dnsNames: dnsFrom(r.stdout) } };
    },
    verifyChain(leaf, root) {
        // -partial_chain is not used: the root must be a trust anchor in its
        // own right, which is what the sample claims to be.
        const r = run('openssl', ['verify', '-no_check_time', '-CAfile', root, leaf]);
        return r.status === 0;
    },
    readRequest(path) {
        const r = run('openssl', ['req', '-inform', 'DER', '-in', path, '-noout', '-verify']);
        return r.status === 0;
    },
};

const WINDOWS_CRYPTOAPI: Tool = {
    id: 'windows-cryptoapi',
    provenance: 'Microsoft CryptoAPI through .NET X509Certificate2 — a lineage with nothing in common with OpenSSL',
    // `SerialNumber` and `Subject` are API values and the same in every
    // locale. The SAN is not: reaching it from Windows PowerShell means
    // `X509Extension.Format()`, whose output is translated, so this tool does
    // not supply dnsNames rather than comparing a French string to an English
    // one. `EnumerateDnsNames()` would fix it and needs .NET 5+, which
    // Windows PowerShell 5.1 does not have.
    supplies: ['serial', 'commonName'],
    version() {
        if (process.platform !== 'win32') return null;
        const r = run('powershell', ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()']);
        return r.status === 0 ? `Windows PowerShell ${r.stdout.trim()}` : null;
    },
    read(path) {
        const script = [
            `$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('${path.replace(/'/g, "''")}')`,
            '"SERIAL=" + $c.SerialNumber; "SUBJECT=" + $c.Subject',
        ].join('; ');
        const r = run('powershell', ['-NoProfile', '-NonInteractive', '-Command', script]);
        if (r.status !== 0) return { kind: 'refused', detail: r.stderr.trim().split('\n')[0] ?? `exit ${String(r.status)}` };
        const serial = /SERIAL=([0-9A-Fa-f]+)/.exec(r.stdout)?.[1];
        const commonName = /CN=([^,\r\n]+)/.exec(r.stdout)?.[1]?.trim();
        if (serial === undefined || commonName === undefined) return { kind: 'unreadable', detail: `no SERIAL or CN in ${JSON.stringify(r.stdout.slice(0, 120))}` };
        return { kind: 'facts', facts: { serial: BigInt(`0x${serial}`), commonName } };
    },
};

const TOOLS: readonly Tool[] = [OPENSSL, WINDOWS_CRYPTOAPI];

// ── The run ──────────────────────────────────────────────────────────

const failures: string[] = [];
const skips: string[] = [];
const lines: string[] = [];
let toolsRun = 0;

/**
 * Compare only the fields the tool declared it supplies, and count them: a
 * tool that supplies nothing must not be able to pass by comparing nothing.
 */
function compare(tool: Tool, sample: string, got: Facts, want: { commonName: string; serialHex: string; dnsNames: readonly string[] }): number {
    let compared = 0;
    if (tool.supplies.includes('serial')) {
        compared += 1;
        const wanted = BigInt(`0x${want.serialHex}`);
        if (got.serial !== wanted) failures.push(`${tool.id} read ${sample} serial as ${String(got.serial)}, pkinative wrote ${String(wanted)}`);
    }
    if (tool.supplies.includes('commonName')) {
        compared += 1;
        if (got.commonName !== want.commonName) failures.push(`${tool.id} read ${sample} CN as ${JSON.stringify(got.commonName)}, pkinative wrote ${JSON.stringify(want.commonName)}`);
    }
    if (tool.supplies.includes('dnsNames')) {
        compared += 1;
        const wanted = [...want.dnsNames].sort().join(',');
        const read = (got.dnsNames ?? []).join(',');
        if (read !== wanted) failures.push(`${tool.id} read ${sample} DNS names as ${JSON.stringify(read)}, pkinative wrote ${JSON.stringify(wanted)}`);
    }
    return compared;
}

async function main(): Promise<number> {
    const requireAll = argv.includes('--require-all');
    const json = argv.includes('--json');
    const work = mkdtempSync(join(tmpdir(), 'pkinative-interop-'));
    const catalogue = await samples();

    const paths = new Map<string, string>();
    for (const [name, bytes] of catalogue) {
        if (!name.startsWith('cert/') && !name.startsWith('csr/')) continue;
        const file = join(work, `${name.replace('/', '-')}.der`);
        writeFileSync(file, bytes);
        paths.set(name, file);
    }

    try {
        for (const tool of TOOLS) {
            const version = tool.version();
            if (version === null) {
                skips.push(`${tool.id} is not installed on this platform (${process.platform})`);
                continue;
            }
            let checks = 0;
            for (const [name, want] of Object.entries(EXPECTED)) {
                const path = paths.get(name);
                if (path === undefined) { failures.push(`${tool.id}: the catalogue has no sample named ${name}`); continue; }
                const reading = tool.read(path);
                if (reading.kind === 'refused') {
                    // The artefact is ours. A tool refusing it is the finding.
                    failures.push(`${tool.id} REFUSED ${name}, a certificate pkinative wrote (${reading.detail}) — the bytes are ours, so this is our defect until proven otherwise`);
                    continue;
                }
                if (reading.kind === 'unreadable') {
                    // Never blamed on the artefact: the tool was happy and
                    // this runner could not read it.
                    failures.push(`${tool.id} accepted ${name} and run-interop could not parse its output (${reading.detail}) — a defect in this runner, not in the certificate`);
                    continue;
                }
                checks += compare(tool, name, reading.facts, want);
            }
            if (checks === 0) {
                // Anti-vacuity, the same guard the read direction carries: a
                // tool that compared nothing is not a cross-check.
                failures.push(`${tool.id} compared nothing — a tool that supplies no field agrees with everything`);
            }

            const leaf = paths.get('cert/v3-leaf-issued-by-root');
            const root = paths.get('cert/v3-ed25519-root');
            if (tool.verifyChain !== undefined && leaf !== undefined && root !== undefined) {
                const verified = tool.verifyChain(leaf, root);
                if (verified === false) failures.push(`${tool.id} could not verify the leaf against the root pkinative wrote — a chain that does not build is a chain nobody can use`);
                if (verified !== null) checks += 1;
            }
            const csr = paths.get('csr/with-requested-extensions');
            if (tool.readRequest !== undefined && csr !== undefined) {
                const ok = tool.readRequest(csr);
                if (ok === false) failures.push(`${tool.id} rejected the PKCS#10 request pkinative wrote, or its self-signature`);
                if (ok !== null) checks += 1;
            }
            lines.push(`OK    ${tool.id} (${version}): ${checks} check(s) agree — ${tool.provenance}`);
            toolsRun += 1;

            // The read direction: key containers the tool writes, read by
            // pkinative, which never writes one (scripts/lib/interop-keys.ts).
            const keys = await readKeyContainers(tool.id, join(work, `keys-${tool.id}`));
            if (keys !== null) {
                lines.push(`KEYS  ${tool.id} → pkinative: ${String(keys.checks)} check(s) over ${String(keys.containers)} key container(s) it wrote`);
                for (const line of keys.lines) lines.push(`      ${line}`);
                failures.push(...keys.failures);
                skips.push(...keys.skips);
            }
        }

        for (const pending of PENDING_TOOLS) {
            if (pending.platform === 'all' || pending.platform === process.platform) {
                skips.push(`${pending.id} is declared and not implemented: ${pending.why}`);
            }
        }
    } finally {
        rmSync(work, { recursive: true, force: true });
    }

    if (json) {
        stdout.write(`${JSON.stringify({ tools: TOOLS.map((t) => t.id), pending: PENDING_TOOLS.map((t) => t.id), failures, skips }, null, 2)}\n`);
    } else {
        for (const line of lines) stdout.write(`${line}\n`);
        for (const skip of skips) stdout.write(`SKIP  ${skip}\n`);
        for (const f of failures) stdout.write(`FAIL  ${f}\n`);
    }

    if (failures.length > 0) {
        stdout.write(`run-interop: ${String(failures.length)} disagreement(s). A foreign tool that cannot read what pkinative writes, or a key container a foreign tool writes that pkinative misreads, is pkinative's problem, not the tool's.\n`);
        return 1;
    }
    if (requireAll && skips.length > 0) {
        stdout.write(`run-interop: ${String(skips.length)} tool(s) unavailable and --require-all was given — on the reference platform every declared tool must run.\n`);
        return 1;
    }
    stdout.write(`run-interop: ${String(toolsRun)} tool(s) agree on every artefact, in both directions${skips.length > 0 ? `, ${String(skips.length)} skipped` : ''}.\n`);
    return 0;
}

exit(await main());
