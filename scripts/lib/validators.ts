/**
 * pkinative — cross-implementation validators (conformance level L4)
 * ==================================================================
 * There is no veraPDF for the PKI: no single reference implementation a
 * parser can be held to. The honest equivalent is confrontation — have the
 * same certificates read by implementations written by other people, in
 * other languages, and require agreement.
 *
 * Five decisions make that workable rather than a formatting swamp:
 *
 * 1. **Compare fingerprints of DER slices, never rendered text.** Every
 *    implementation prints a distinguished name its own way (RFC 4514, X.500,
 *    its own), and chasing that is endless and proves nothing. `SHA-256` of
 *    the subject's *encoded bytes* is both simpler and stricter, and every
 *    implementation can produce it.
 * 2. **A self-declared field mask.** A validator announces in its header what
 *    it can supply; only those fields are compared. A tool that cannot reach
 *    the SubjectPublicKeyInfo says so instead of being special-cased here.
 * 3. **A footer that proves completeness.** A validator that stops halfway is
 *    caught by the contract itself, not by a heuristic about output length.
 * 4. **Canaries against complacency.** A positive canary every validator must
 *    read, so one that rejects everything is unmasked; negative canaries no
 *    implementation can accept, so one that accepts everything is unmasked.
 *    Both verdicts are outside the disagreement allowlist by construction.
 * 5. **Disagreements are reviewed data.** A real difference between two
 *    implementations is recorded in `scripts/data/validator-disagreements.json`
 *    with its reason, the way `limbo-refusals.json` records refusals — never
 *    silently tolerated, never a permanent red.
 *
 * Certificates reach a validator through a blob file, never stdin: tens of
 * thousands of writes to a pipe deadlock as soon as the child stops draining
 * it, and Windows builds read stdin in text mode, which corrupts DER.
 *
 * @module scripts/lib/validators
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Bumped when the record contract changes; a validator declaring another is refused. */
export const SCHEMA = 1;

const BLOB_MAGIC = 'PKIBLOB1';

/**
 * Every field a validator may declare. The value is always a lowercase hex
 * SHA-256 of an exact DER slice, or an exact identifier — never rendered
 * text, so there is nothing to normalise and nothing to argue about.
 */
export const FIELDS: Readonly<Record<string, string>> = Object.freeze({
    subjectFp256: 'SHA-256 of the encoded subject Name, tag and length included',
    issuerFp256: 'SHA-256 of the encoded issuer Name, tag and length included',
    spkiKeyFp256: 'SHA-256 of the subjectPublicKey BIT STRING content, padding octet excluded',
    tbsFp256: 'SHA-256 of the encoded tbsCertificate — the bytes a signature covers',
    keyAlgOid: 'The SubjectPublicKeyInfo algorithm OID, in dotted notation',
    version: 'The certificate version as a number: 1, 2 or 3',
});

/** What a validator reports for one certificate. */
export interface CertRecord {
    readonly t: 'cert';
    readonly i: number;
    readonly ok: boolean;
    readonly error?: string;
    readonly [field: string]: unknown;
}

export interface HeaderRecord {
    readonly t: 'header';
    readonly schema: number;
    readonly tool: string;
    readonly version: string;
    readonly fields: readonly string[];
}

export interface FooterRecord {
    readonly t: 'footer';
    readonly count: number;
}

/** A validator's whole answer, once the stream has been checked. */
export interface ValidatorStream {
    readonly header: HeaderRecord;
    readonly certs: readonly CertRecord[];
}

/** One implementation pkinative is confronted with. */
export interface ValidatorSpec {
    readonly id: string;
    /** The implementation family, so two entries of one lineage are not mistaken for two opinions. */
    readonly lineage: string;
    /** `process.platform` values this validator can run on. */
    readonly platforms: readonly string[];
    /** Its version string, or null when the toolchain is not installed. */
    readonly probe: () => string | null;
    /** Read `blobPath`, write NDJSON to `outPath`. */
    readonly emit: (blobPath: string, outPath: string) => { ok: boolean; stderr: string };
}

// ── Transport ────────────────────────────────────────────────────────

/**
 * `PKIBLOB1`, a 4-octet big-endian count, then each certificate as a 4-octet
 * big-endian length and its bytes. Length-framed rather than delimited,
 * because DER contains every byte value.
 */
export function writeBlob(path: string, certs: readonly Uint8Array[]): void {
    let total = BLOB_MAGIC.length + 4;
    for (const cert of certs) total += 4 + cert.length;
    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);
    for (let i = 0; i < BLOB_MAGIC.length; i++) out[i] = BLOB_MAGIC.charCodeAt(i);
    view.setUint32(BLOB_MAGIC.length, certs.length);
    let at = BLOB_MAGIC.length + 4;
    for (const cert of certs) {
        view.setUint32(at, cert.length);
        out.set(cert, at + 4);
        at += 4 + cert.length;
    }
    writeFileSync(path, out);
}

// ── The record contract ──────────────────────────────────────────────

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Parse and check a validator's NDJSON.
 *
 * Every deviation is a failure of the validator, not of the certificates:
 * a missing header, an unknown schema, a gap in the indices, a missing
 * footer, a count that disagrees. A validator that stops halfway through the
 * corpus and exits 0 is exactly what this catches.
 *
 * @returns The stream, or the reasons it is not usable.
 */
export function parseStream(text: string, expected: number): ValidatorStream | { errors: readonly string[] } {
    const errors: string[] = [];
    const lines = text.replace(/\r\n/g, '\n').split('\n').filter((l) => l.trim() !== '');
    const records: unknown[] = [];
    for (const [index, line] of lines.entries()) {
        try {
            records.push(JSON.parse(line));
        } catch {
            errors.push(`line ${index + 1} is not JSON: ${line.slice(0, 80)}`);
        }
    }
    if (errors.length > 0) return { errors };

    const head = records[0];
    if (!isObject(head) || head['t'] !== 'header') return { errors: ['the stream does not open with a header record'] };
    const schema = head['schema'];
    const tool = head['tool'];
    const toolVersion = head['version'];
    const fields = head['fields'];
    if (schema !== SCHEMA) errors.push(`the header declares schema ${String(schema)}; this runner speaks ${String(SCHEMA)}`);
    if (typeof tool !== 'string' || typeof toolVersion !== 'string') errors.push('the header must carry a string `tool` and `version`');
    if (!Array.isArray(fields) || fields.length === 0) errors.push('the header must declare a non-empty `fields` mask');
    else for (const field of fields) {
        if (typeof field !== 'string' || !(field in FIELDS)) errors.push(`the header declares the unknown field ${JSON.stringify(field)}`);
    }

    const tail = records[records.length - 1];
    if (!isObject(tail) || tail['t'] !== 'footer') errors.push('the stream does not end with a footer record — a validator that stopped halfway looks identical without it');
    else if (tail['count'] !== expected) errors.push(`the footer counts ${String(tail['count'])} certificates; ${expected} were submitted`);

    const certs: CertRecord[] = [];
    for (const [offset, record] of records.slice(1, -1).entries()) {
        if (!isObject(record) || record['t'] !== 'cert') { errors.push(`record ${offset + 1} is neither a cert nor the footer`); continue; }
        if (record['i'] !== offset) { errors.push(`record ${offset + 1} is certificate ${String(record['i'])}; the stream must be in submission order with no gap`); continue; }
        if (typeof record['ok'] !== 'boolean') { errors.push(`certificate ${String(record['i'])} declares no boolean \`ok\``); continue; }
        certs.push(record as unknown as CertRecord);
    }
    if (errors.length === 0 && certs.length !== expected) errors.push(`the stream holds ${certs.length} certificate records; ${expected} were submitted`);
    if (errors.length > 0) return { errors };
    return { header: head as unknown as HeaderRecord, certs };
}

// ── Comparison ───────────────────────────────────────────────────────

/** What pkinative says about one certificate, in the vocabulary of `FIELDS`. */
export type Expected = Readonly<Record<string, string | number>>;

/**
 * Compare one record against pkinative, over the fields the validator
 * declared it can supply and pkinative also knows.
 *
 * @returns One message per field that disagrees.
 */
export function compareRecord(expected: Expected, actual: CertRecord, mask: readonly string[]): string[] {
    const out: string[] = [];
    for (const field of mask) {
        const mine = expected[field];
        if (mine === undefined) continue;
        const theirs = actual[field];
        if (theirs === undefined || theirs === null || theirs === '') { out.push(`${field}: absent, though the header declares it`); continue; }
        if (String(theirs) !== String(mine)) out.push(`${field}: ${String(theirs)} against ${String(mine)}`);
    }
    return out;
}

// ── Canaries ─────────────────────────────────────────────────────────

/**
 * Bytes no implementation can accept as a certificate, derived by rule from a
 * real one — never committed, because our own code can build them (the
 * fixture policy of testing.instructions.md).
 *
 * They are deliberately *structurally* broken rather than merely
 * profile-invalid: a certificate one implementation refuses and another reads
 * is a difference of policy, and belongs in the disagreement file. A
 * validator that reads a truncated DER value is not lenient, it is lying.
 */
export function negativeCanaries(real: Uint8Array): ReadonlyArray<{ readonly why: string; readonly bytes: Uint8Array }> {
    const truncated = real.subarray(0, Math.max(8, real.length >> 1));
    const empty = new Uint8Array(0);
    const notDer = Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    const overlong = Uint8Array.from([0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01, 0x00]);
    return [
        { why: 'a certificate cut in half', bytes: truncated },
        { why: 'no bytes at all', bytes: empty },
        { why: 'eight 0xFF octets, which are not ASN.1', bytes: notDer },
        { why: 'a SEQUENCE whose declared length runs past the input', bytes: overlong },
    ];
}

// ── Helpers for the validator programs ───────────────────────────────

export const sha256Hex = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

/** Run a command, capturing everything, and never throw. */
export function run(command: string, args: readonly string[], timeoutMs = 900_000): { status: number | null; stdout: string; stderr: string } {
    const result = spawnSync(command, [...args], { encoding: 'utf8', windowsHide: true, timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 });
    return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? (result.error?.message ?? '') };
}

/** Read a validator's output file, or an empty string when it wrote none. */
export function readOutput(path: string): string {
    try {
        return readFileSync(path, 'utf8');
    } catch {
        return '';
    }
}

// ── The registry ─────────────────────────────────────────────────────

const EMITTERS = join(dirname(fileURLToPath(import.meta.url)), '..', 'validators');

/**
 * The implementations pkinative is confronted with.
 *
 * The rule for membership is that the toolchain is **already on the runner**:
 * nothing here is downloaded, vendored, cached or checksum-pinned, so the
 * conformance gate adds no supply-chain surface of its own. A lineage that
 * needs an install is not worth what it would cost.
 *
 * Still to come, each one entry plus one small program, and each deliberately
 * absent until it can be run and proved rather than written blind: Go's
 * `crypto/x509`, Java's `CertificateFactory`, and .NET's own reader on Linux
 * and macOS — three lineages independent of both OpenSSL and CryptoAPI.
 */
export const VALIDATORS: readonly ValidatorSpec[] = [
    {
        id: 'windows-cryptoapi',
        lineage: 'Microsoft CryptoAPI, through .NET X509Certificate2',
        platforms: ['win32'],
        probe: () => {
            const probe = run('powershell', ['-NoProfile', '-Command', '$PSVersionTable.PSVersion.ToString()'], 60_000);
            return probe.status === 0 && probe.stdout.trim() !== '' ? `Windows PowerShell ${probe.stdout.trim()}` : null;
        },
        emit: (blobPath, outPath) => {
            const result = run('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(EMITTERS, 'windows-cryptoapi.ps1'), blobPath, outPath]);
            return { ok: result.status === 0, stderr: result.stderr };
        },
    },
];
