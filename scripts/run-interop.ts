#!/usr/bin/env tsx
/**
 * pkinative — the interoperability matrix
 * =======================================
 * Foreign tools reading what pkinative writes, and pkinative reading what
 * foreign tools write.
 *
 * The conformance gate's L1–L8 all point one way: bytes someone else
 * produced, read by pkinative. From 0.3 the arrow also points outward, and
 * that direction has no corpus — nobody publishes a set of certificates a
 * library is supposed to have written. The only oracle available is the tools
 * themselves, the way veraPDF is the oracle of a PDF writer: every artefact
 * goes to every tool this platform has, and each must agree on facts with
 * exactly one right answer.
 *
 * **Write direction** (scripts/lib/interop-tools.ts). Two sets: the frozen
 * Ed25519 samples verify:samples hashes (scripts/lib/samples.ts), and a set
 * generated afresh — certificates, CSRs, CMS, an OCSP request and RFC 3161
 * requests in every signature family the API writes, keys made by this
 * harness (scripts/lib/interop-artefacts.ts). Readers are OpenSSL, Windows
 * CryptoAPI, .NET, GnuTLS, Go, pyca/cryptography, the JDK and gpgsm; zlint
 * and pkilint lint every created certificate. A refusal of our bytes is a
 * failure; a lint error is a failure; a lint warning must be reviewed in
 * scripts/data/lint-waivers.json (scripts/lib/interop-judge.ts).
 *
 * **Read direction.** Key containers (scripts/lib/interop-keys.ts, the `KEYS`
 * lines), and signed structures — CMS, timestamps, OCSP, CRLs — written by
 * OpenSSL, GnuTLS, gpgsm and .NET and verified by pkinative with the verdict
 * READ_CASES declares (scripts/lib/interop-reads.ts, the `READS` lines).
 *
 * **Which tools must be there.** `--require-all` — or
 * PKINATIVE_INTEROP_REQUIRE_ALL=1, which is how the release gate passes it —
 * fails the run when a tool of REQUIRED_TOOLS for this platform is missing,
 * or when one of its cases was skipped. Every other tool runs where it is
 * found and is held to the same agreement when it does.
 *
 * Usage:
 *   npx tsx scripts/run-interop.ts
 *   npx tsx scripts/run-interop.ts --require-all
 *   npx tsx scripts/run-interop.ts --json
 *   npx tsx scripts/run-interop.ts --keep <dir>   # leave the artefacts there
 *
 * Exit: 0 every present tool agreed; 1 a disagreement, a refusal, a stale
 * review, or a missing required tool under `--require-all`.
 *
 * @module scripts/run-interop
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { argv, env, exit, platform, stdout } from 'node:process';
import { fileURLToPath } from 'node:url';
import { encodePem } from '../src/index.js';
import { IMPLEMENTED_TOOLS, PENDING_TOOLS, REQUIRED_TOOLS, TOOL_LIMITATIONS, TOOL_PLATFORMS } from './lib/interop.js';
import { buildArtefacts, type Artefact, type ArtefactSet } from './lib/interop-artefacts.js';
import { judge, type LintWaiver } from './lib/interop-judge.js';
import { readKeyContainers } from './lib/interop-keys.js';
import { readSignedStructures, type ReadTool } from './lib/interop-reads.js';
import { writeTools } from './lib/interop-tools.js';
import { EXPECTED, samples } from './lib/samples.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WAIVERS = join(ROOT, 'scripts', 'data', 'lint-waivers.json');

/** The frozen samples, as artefacts of the set: written beside the fresh ones and added to the manifest. */
async function withSamples(set: ArtefactSet): Promise<ArtefactSet> {
    const catalogue = await samples();
    const extra: Artefact[] = [];
    for (const [name, spec] of Object.entries(EXPECTED)) {
        const bytes = catalogue.get(name);
        if (bytes === undefined) throw new Error(`run-interop: the catalogue has no sample named ${name}`);
        const base = join(set.dir, `sample-${name.replace('/', '-')}`);
        writeFileSync(`${base}.der`, bytes);
        writeFileSync(`${base}.pem`, encodePem(spec.kind === 'cert' ? 'CERTIFICATE' : 'CERTIFICATE REQUEST', bytes));
        extra.push({
            id: `sample/${name}`, profile: 'sample', kind: spec.kind, der: `${base}.der`, pem: `${base}.pem`, expect: spec.facts,
            ...('shape' in spec ? { shape: spec.shape, issuer: `sample/${spec.issuer}` } : {}),
            ...('serverName' in spec ? { serverName: spec.serverName, verifyAt: spec.verifyAt } : {}),
        });
    }
    const artefacts = [...set.artefacts, ...extra];
    writeFileSync(set.manifest, JSON.stringify({ artefacts }, null, 1));
    return { ...set, artefacts };
}

function loadWaivers(): LintWaiver[] {
    const file = JSON.parse(readFileSync(WAIVERS, 'utf8')) as { waivers?: LintWaiver[] };
    return file.waivers ?? [];
}

async function main(): Promise<number> {
    const requireAll = argv.includes('--require-all') || env['PKINATIVE_INTEROP_REQUIRE_ALL'] === '1';
    const json = argv.includes('--json');
    const keepAt = argv.indexOf('--keep');
    const keep = keepAt >= 0 ? argv[keepAt + 1] : undefined;
    const work = keep ?? mkdtempSync(join(tmpdir(), 'pkinative-interop-'));
    mkdirSync(work, { recursive: true });
    const required = REQUIRED_TOOLS[platform as keyof typeof REQUIRED_TOOLS] ?? [];

    const failures: string[] = [];
    /** Required tools that are absent: failures under --require-all. */
    const requiredSkips: string[] = [];
    const skips: string[] = [];
    const notApplicable: string[] = [];
    const lines: string[] = [];
    let toolsRun = 0;

    try {
        const set = await withSamples(await buildArtefacts(join(work, 'artefacts')));
        lines.push(`SET   ${String(set.artefacts.length)} artefacts: ${String(set.artefacts.filter((a) => a.kind === 'cert').length)} certificates, ${String(set.artefacts.filter((a) => a.kind === 'csr').length)} CSRs, ${String(set.artefacts.filter((a) => a.kind === 'cms').length)} SignedData, ${String(set.artefacts.filter((a) => a.kind === 'ocsp-request').length)} OCSP requests, ${String(set.artefacts.filter((a) => a.kind === 'tsq').length)} TimeStampReqs`);
        const waivers = loadWaivers();
        const located = new Map<string, ReadTool>();

        for (const tool of writeTools()) {
            if (!IMPLEMENTED_TOOLS.includes(tool.id)) { failures.push(`${tool.id}: run by run-interop and not declared in IMPLEMENTED_TOOLS`); continue; }
            if (!(TOOL_PLATFORMS[tool.id] ?? []).includes(platform)) { notApplicable.push(`${tool.id} has not been proved on ${platform} (TOOL_PLATFORMS), so it is not run here`); continue; }
            const found = tool.locate();
            if (found === null) {
                const why = `${tool.id} is not installed on this ${platform} machine`;
                if (required.includes(tool.id)) requiredSkips.push(`${why}, and REQUIRED_TOOLS requires it here`);
                else notApplicable.push(why);
                continue;
            }
            const host = tool.host();
            if (host !== null) located.set(tool.id, { host, reference: found.reference });
            const toolWork = join(work, tool.id);
            mkdirSync(toolWork, { recursive: true });
            const started = Date.now();
            const results = tool.check(set, toolWork);
            const seconds = ((Date.now() - started) / 1000).toFixed(1);
            const verdict = judge(tool.id, results, set.artefacts, found.reference, TOOL_LIMITATIONS, waivers);
            failures.push(...verdict.failures);
            notApplicable.push(...verdict.notApplicable);
            lines.push(`${verdict.failures.length === 0 ? 'OK  ' : 'FAIL'}  ${tool.id} (${found.version}${found.reference ? '' : ', not the reference build'}): ${String(verdict.agreed)} check(s), ${String(verdict.compared)} fact(s) agree in ${seconds} s — ${tool.provenance}`);
            toolsRun += 1;
        }

        // The read direction: key containers.
        for (const id of ['openssl', 'windows-cryptoapi']) {
            if (!located.has(id)) continue;
            const keys = await readKeyContainers(id, join(work, `keys-${id}`));
            if (keys === null) continue;
            lines.push(`KEYS  ${id} → pkinative: ${String(keys.checks)} check(s) over ${String(keys.containers)} key container(s) it wrote`);
            for (const line of keys.lines) lines.push(`      ${line}`);
            failures.push(...keys.failures);
            // A case the installed build cannot write (no PBMAC1 before
            // OpenSSL 3.4, no legacy provider) is a skip with its reason;
            // --require-all is about the tool being there, not every build
            // having every feature.
            skips.push(...keys.skips);
        }

        // The read direction: signed structures.
        for (const id of ['openssl', 'gnutls-certtool', 'gpgsm', 'dotnet']) {
            const tool = located.get(id);
            if (tool === undefined) continue;
            const reads = await readSignedStructures(id, tool, located.get('openssl') ?? null, join(work, `reads-${id}`));
            if (reads === null) continue;
            lines.push(`READS ${id} → pkinative: ${String(reads.checks)} case(s) it wrote`);
            for (const line of reads.lines) lines.push(`      ${line}`);
            failures.push(...reads.failures);
            skips.push(...reads.skips);
        }

        for (const pending of PENDING_TOOLS) {
            if (pending.platform === 'all' || pending.platform === platform) notApplicable.push(`${pending.id} is declared and not implemented: ${pending.why}`);
        }
    } finally {
        if (keep === undefined) rmSync(work, { recursive: true, force: true });
    }

    const failed = failures.length > 0 || (requireAll && requiredSkips.length > 0);
    if (json) {
        stdout.write(`${JSON.stringify({ platform, required, tools: IMPLEMENTED_TOOLS, pending: PENDING_TOOLS.map((t) => t.id), failures, requiredSkips, skips, notApplicable }, null, 2)}\n`);
    } else {
        for (const line of lines) stdout.write(`${line}\n`);
        for (const n of notApplicable) stdout.write(`N/A   ${n}\n`);
        for (const s of [...requiredSkips, ...skips]) stdout.write(`SKIP  ${s}\n`);
        for (const f of failures) stdout.write(`FAIL  ${f}\n`);
    }
    if (failures.length > 0) {
        stdout.write(`run-interop: ${String(failures.length)} failure(s). A foreign tool that cannot read what pkinative writes, or a structure a foreign tool writes that pkinative misreads, is pkinative's problem, not the tool's.\n`);
    } else if (failed) {
        stdout.write(`run-interop: ${String(requiredSkips.length)} required tool(s) or case(s) unavailable on ${platform} and --require-all was given — REQUIRED_TOOLS says this platform must run them.\n`);
    } else {
        stdout.write(`run-interop: ${String(toolsRun)} tool(s) agree on every artefact they read or write${requiredSkips.length + skips.length > 0 ? `, ${String(requiredSkips.length + skips.length)} skipped` : ''}${requireAll ? ' (--require-all)' : ''}.\n`);
    }
    return failed ? 1 : 0;
}

exit(await main());
