/* ═══════════════════════════════════════════════════════════════
   pkinative.dev — MCP tool explorer

   One card per pkinative-mcp 1.0.0 tool, in tools/list order: what
   the tool is for, a prompt that makes an assistant reach for it, the
   `tools/call` arguments it would send, and a Run button that performs
   the engine call behind the tool on the published pkinative build
   (load-engine.js, held by the `cdn-pin` rule). The arguments shown are
   the server's own schema — every one of them validates against the
   zod schema of the matching src/tools/<name>.ts at the v1.0.0 tag.

   What a browser cannot do is said, not faked: reading the operator's
   sandbox, the cache, the operator ceilings, a password from the
   environment, the governance drafter. Those answers are labelled
   BROWSER_LIMITATION — this page's own label, never one of the
   server's codes — and say what the server does instead.

   ── The keys on this page ────────────────────────────────────
   The creation tools need a signing key. pkinative never generates
   one, and neither does the server. This page does, with
   `crypto.subtle.generateKey`: two ECDSA P-256 keys, non-extractable,
   alive only in this tab. The page exports the PUBLIC half once
   (`exportKey('spki')`, the one line pkinative's documentation asks a
   caller to write) and hands the private CryptoKey to the engine as a
   SigningKey. No key byte is ever read, shown or stored.

   ── One rule, without exception ──────────────────────────────
   Everything that reaches the page goes through textContent. innerHTML
   is never used — not for input, not for engine output, not for the
   static notes either.
   ═══════════════════════════════════════════════════════════════ */

import { loadEngine, ENGINE_VERSION } from './load-engine.js';
import { SAMPLES } from './samples.js';

/** The published package, once loadEngine() answered. */
let E = null;

/** Hand the engine module over (the browser boot, or the repository's own Node check). */
export function setEngine(mod) {
    E = mod;
}

// ── Facts about the server, from pkinative-mcp at the v1.0.0 tag ──

const SERVER = /*#__PURE__*/ Object.freeze({
    name: 'pkinative-mcp',
    version: '1.0.0',
    toolApiVersion: '1.0.0',
    protocol: 'MCP 2026-07-28 + legacy 2024/2025 initialize',
    toolCount: 34,
});

/** The operator ceilings at their defaults (src/limits.ts); an operator moves them with three variables. */
const CEILINGS = /*#__PURE__*/ Object.freeze({
    maxInputBytes: 67108864,
    maxKdfIterations: 10000000,
    maxPathsExplored: 1000,
    env: ['PKINATIVE_MCP_MAX_INPUT_BYTES', 'PKINATIVE_MCP_MAX_KDF_ITERATIONS', 'PKINATIVE_MCP_MAX_PATHS_EXPLORED'],
});

/** The server's own refusal codes (src/wrapper-codes.ts), with the condition each one names. */
const WRAPPER_CODES = /*#__PURE__*/ Object.freeze([
    ['VALIDATION_ERROR', 'The input fails the schema: a wrong type, bound or enum, an unknown key at any depth, none or several of the exclusive members, SHA-1 without allowSha1, a password given twice.'],
    ['INPUT_TOO_LARGE', 'A decoded inline input, the sum of inline inputs, or a sandbox file exceeds its cap.'],
    ['INPUT_NOT_FOUND', 'A path input does not exist in the sandbox, or is not a regular file.'],
    ['INVALID_PATH', 'A path member is empty or not a string.'],
    ['INVALID_EXTENSION', 'A path input or outputPath does not end in an allowed extension.'],
    ['SECURITY_VIOLATION', 'File I/O without a sandbox; an absolute, drive, UNC or escaping path; a link whose real path leaves the sandbox; a key-bearing outputPath; an attempt to extract, dump or serve private-key material.'],
    ['OUTPUT_TOO_LARGE', 'An artefact above its inline, hex, file or resource cap.'],
    ['OUTPUT_EXISTS', 'The target file already exists — the server never overwrites.'],
    ['MISSING_OUTPUT_PATH', "outputMode: 'file' without outputPath."],
    ['IO_ERROR', 'A filesystem operation failed; the message carries the errno, never an absolute path.'],
    ['LIMIT_CEILING_EXCEEDED', 'A limits.* value above its operator ceiling (data.env names the variable).'],
    ['UNKNOWN_RESOURCE', 'resources/read outside pkinative://output/, or of a missing file — a JSON-RPC -32602.'],
    ['GOVERNANCE_VIOLATION', 'A draft_governance_issue draft breaks the AI-governance contract.'],
    ['SECRET_REQUIRED', 'An encrypted key, a PKCS#12 or a MAC check needs a password and none was given.'],
    ['KEY_TYPE_REQUIRED', 'An encrypted PKCS#8 key whose type nothing names.'],
    ['RSA_SCHEME_REQUIRED', 'An RSA key without rsaScheme: there is no default RSA signature scheme.'],
    ['KEY_MISMATCH', 'The signing key does not belong to the certificate, issuer or public key it was paired with.'],
    ['UNSUPPORTED_KEY', 'A key algorithm Web Crypto cannot sign with on this host.'],
    ['NOT_FOUND', 'A named element is absent: an extension, a nodePath step, a signerIndex, an extractIndex, a code.'],
    ['ENGINE_VERDICT', 'A one-call engine operation (opening a PKCS#12 to sign) came back negative; data.reasons carries the PKI_REASON_* codes.'],
    ['ENGINE_ERROR', 'The engine threw something that is not a PkiError: a bug, to report with a reproduction.'],
]);

const AT = '2026-10-01T00:00:00Z';
const PAGE_TEXT = 'Signed in the browser by the pkinative MCP explorer.';

// ── Small DOM helpers ─────────────────────────────────────────

/** An element with text and optional classes. Text always via textContent. */
function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
}

function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
}

/**
 * Static prose with `code` spans: the text is split on backticks and each
 * odd segment becomes a <code>. Still textContent all the way down.
 */
function prose(parent, text) {
    String(text).split('`').forEach((part, i) => {
        if (part === '') return;
        parent.appendChild(i % 2 === 1 ? el('code', part) : document.createTextNode(part));
    });
    return parent;
}

// ── Bytes ─────────────────────────────────────────────────────

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function fromHex(text) {
    const compact = String(text).replace(/^0x/i, '').replace(/[\s:]/g, '');
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(compact)) throw fail('VALIDATION_ERROR', `not hexadecimal: ${String(text).slice(0, 40)}`);
    const out = new Uint8Array(compact.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(compact.slice(i * 2, i * 2 + 2), 16);
    return out;
}

function toBase64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
}

function fromBase64(text) {
    if (/^data:/i.test(text) || /-----BEGIN/.test(text)) throw fail('VALIDATION_ERROR', 'derBase64 is the DER as base64, once — not a data: URI and not PEM (pass PEM as pem).');
    const bin = atob(String(text).replace(/\s/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

const utf8 = (text) => new TextEncoder().encode(text);
const iso = (ms) => new Date(ms).toISOString();

// ── Refusals ──────────────────────────────────────────────────

/** A refusal with a code, the shape a tool result carries in _meta.error. */
function fail(code, message, data) {
    return Object.assign(new Error(message), { code, data });
}

/** What this page cannot reproduce, with what the server does instead. */
function limitation(why, onTheServer) {
    return Object.assign(new Error(why), { code: 'BROWSER_LIMITATION', onTheServer });
}

// ── The wire form (ADR 0018): bigint as decimal, bytes as hex ─

function toWire(value) {
    if (typeof value === 'bigint') return value.toString(10);
    if (typeof value === 'number') return Number.isFinite(value) ? value : String(value);
    if (value === null || typeof value !== 'object') return typeof value === 'string' || typeof value === 'boolean' ? value : null;
    if (value instanceof Uint8Array) return hex(value);
    if (Array.isArray(value)) return value.map((v) => (v === undefined ? null : toWire(v)));
    if (typeof CryptoKey !== 'undefined' && value instanceof CryptoKey) {
        return { type: value.type, algorithm: value.algorithm.name, extractable: value.extractable, usages: [...value.usages] };
    }
    const out = {};
    for (const [k, v] of Object.entries(value)) {
        if (v === undefined || typeof v === 'function') continue;
        out[k] = toWire(v);
    }
    return out;
}

const RAW_KEYS = new Set(['der', 'tbsDer', 'valueDer', 'raw']);

/** toWire with every raw DER echo removed, as the server's views do. */
function stripRaw(value) {
    const walk = (w) => {
        if (Array.isArray(w)) return w.map(walk);
        if (w !== null && typeof w === 'object') {
            const out = {};
            for (const [k, v] of Object.entries(w)) if (!RAW_KEYS.has(k)) out[k] = walk(v);
            return out;
        }
        return w;
    };
    return walk(toWire(value));
}

const timeView = (t) => ({ type: t.type, epochMilliseconds: t.epochMilliseconds, iso: iso(t.epochMilliseconds), text: t.text });
const algorithmView = (a) => ({ oid: a.oid, name: E.getOidName(a.oid) ?? null, hasParameters: a.parameters !== undefined });

function dn(name) {
    const text = E.formatDistinguishedName(name);
    return text === '' ? '(empty)' : text;
}

function nameView(name) {
    return {
        string: dn(name),
        rdns: name.rdns.map((rdn) => rdn.map((atv) => ({
            type: atv.type,
            name: E.getOidName(atv.type) ?? null,
            value: atv.value?.value ?? null,
            stringType: atv.value?.stringType ?? null,
        }))),
    };
}

function spkiView(spki) {
    const base = { kind: spki.kind, algorithm: algorithmView(spki.algorithm), publicKeyBits: spki.publicKey.bytes.length * 8 - spki.publicKey.unusedBits };
    if (spki.kind === 'rsa' || spki.kind === 'rsa-pss') return { ...base, modulusBits: spki.modulusBits, publicExponent: spki.publicExponent.toString(10) };
    if (spki.kind === 'ec') return { ...base, curve: spki.curve ?? null, namedCurve: spki.namedCurve ?? null, pointFormat: spki.pointFormat };
    if (spki.kind === 'unknown') return base;
    return { ...base, keyBytes: spki.key ? spki.key.length : null };
}

const extensionView = (e) => ({ kind: e.kind, oid: e.oid, name: E.getOidName(e.oid) ?? null, critical: e.critical, ...stripRaw(e) });

function certificateView(cert) {
    return {
        version: cert.version,
        serialNumber: { hex: cert.serialNumber.hex, decimal: cert.serialNumber.value.toString(10) },
        signatureAlgorithm: algorithmView(cert.signatureAlgorithm),
        issuer: nameView(cert.issuer),
        subject: nameView(cert.subject),
        validity: { notBefore: timeView(cert.validity.notBefore), notAfter: timeView(cert.validity.notAfter) },
        subjectPublicKeyInfo: spkiView(cert.subjectPublicKeyInfo),
        extensions: cert.extensions.map(extensionView),
        selfIssued: hex(cert.issuer.der) === hex(cert.subject.der),
        sizeBytes: cert.der.length,
    };
}

const certificateRef = (c) => ({ subject: dn(c.subject), issuer: dn(c.issuer), serialNumber: c.serialNumber.hex, notAfter: iso(c.validity.notAfter.epochMilliseconds) });

const reasonsView = (reasons) => reasons.map((r) => ({
    code: r.code, message: r.message, standard: r.standard, path: r.path,
    ...(r.errorCode !== undefined ? { errorCode: r.errorCode } : {}),
    ...(r.limit !== undefined ? { limit: r.limit } : {}),
}));

// ── The diagnostics sink, as every result carries it ──────────

/** De-duplicated by code and path, capped at 200, with per-code counts. */
function makeSink() {
    const rows = [];
    const seen = new Set();
    const counts = {};
    let truncated = false;
    return {
        onDiagnostic(d) {
            counts[d.code] = (counts[d.code] ?? 0) + 1;
            const key = `${d.code}\u0000${d.path}`;
            if (seen.has(key)) return;
            seen.add(key);
            if (rows.length >= 200) { truncated = true; return; }
            rows.push({ code: d.code, severity: d.severity, message: d.message, standard: d.standard, path: d.path, ...(d.offset !== undefined ? { offset: d.offset } : {}) });
        },
        report() {
            return { diagnostics: rows, diagnosticCounts: counts, ...(truncated ? { diagnosticsTruncated: true } : {}) };
        },
    };
}

/** The PARSE fragment (encodingRules, strict, limits) as the server hands it to the engine. */
function parseOptions(args, sink) {
    return {
        onDiagnostic: sink.onDiagnostic,
        ...(args.encodingRules ? { encodingRules: args.encodingRules } : {}),
        ...(args.strict ? { strict: true } : {}),
        ...(args.limits ? { limits: args.limits } : {}),
    };
}

// ── Projection: verbosity and fields, applied after the tool ──

function pick(value, segments) {
    if (segments.length === 0) return value;
    if (Array.isArray(value)) return value.map((v) => pick(v, segments));
    if (value !== null && typeof value === 'object') {
        const [head, ...rest] = segments;
        if (!Object.prototype.hasOwnProperty.call(value, head)) return undefined;
        const inner = pick(value[head], rest);
        return inner === undefined ? undefined : { [head]: inner };
    }
    return undefined;
}

function merge(a, b) {
    if (b === undefined) return a;
    if (a === undefined) return b;
    if (Array.isArray(a) && Array.isArray(b)) return a.map((x, i) => merge(x, b[i]));
    if (a && b && typeof a === 'object' && typeof b === 'object') {
        const out = { ...a };
        for (const [k, v] of Object.entries(b)) out[k] = k in out ? merge(out[k], v) : v;
        return out;
    }
    return b;
}

function project(full, summary, args) {
    const base = args.verbosity === 'summary' && summary ? summary : full;
    const fields = Array.isArray(args.fields) ? args.fields : [];
    if (fields.length === 0) return base;
    let result;
    const unmatched = [];
    for (const f of fields) {
        const got = pick(base, f.split('.'));
        if (got === undefined) unmatched.push(f);
        else result = merge(result, got);
    }
    return { ...(result ?? {}), ...(unmatched.length > 0 ? { _meta: { unmatchedFields: unmatched, availableFields: Object.keys(base) } } : {}) };
}

// ── Inputs: PKI_INPUT, bundles, content, the page's own sandbox ─

const CERT_LABELS = ['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'];
const SECRET_LABEL = /PRIVATE KEY|PKCS12|PFX/;

/**
 * The bytes of one PKI_INPUT. `path` is looked up in the page sandbox — the
 * handful of files this page made or you dropped; anything else is the
 * operator's directory, which only the server can read.
 */
function inputBytes(input, what, ctx, labels) {
    const forms = input && typeof input === 'object' ? ['pem', 'derBase64', 'path'].filter((k) => input[k] !== undefined) : [];
    if (forms.length !== 1) throw fail('VALIDATION_ERROR', `${what}: exactly one of pem, derBase64 or path`);
    if (input.pem !== undefined) {
        const blocks = E.decodePem(input.pem);
        if (labels && !blocks.some((b) => labels.includes(b.label))) {
            throw fail('PKI_PEM_UNEXPECTED_LABEL', `${what} holds no ${labels.join(' or ')} PEM block (labels present: ${blocks.map((b) => b.label).join(', ')}).`, { path: what, remedy: "convert_pem mode:'decode' (lists the labels present)" });
        }
        if (blocks.length !== 1) throw fail('VALIDATION_ERROR', `${what}: the PEM text holds ${String(blocks.length)} blocks where one object is expected — pick one with convert_pem extractIndex, or pass a bundle.`);
        return { der: blocks[0].bytes, label: blocks[0].label };
    }
    if (input.derBase64 !== undefined) return { der: fromBase64(input.derBase64), label: null };
    const entry = ctx.vfs.get(input.path);
    if (!entry || !entry.der) {
        throw limitation(`${what}.path names ${input.path}, a file of the operator's PKINATIVE_MCP_OUTPUT_DIR sandbox — this page has no filesystem.`, 'The server reads the file from the sandbox (relative path, allow-listed extension, real path held inside). Pass pem or derBase64 to run it here.');
    }
    return { der: entry.der, label: entry.label ?? null };
}

/** A PKI_BUNDLE: every block of every item, in order. */
function bundleBytes(list, what, ctx) {
    const out = [];
    (list ?? []).forEach((item, i) => {
        if (item.pem !== undefined) for (const b of E.decodePem(item.pem)) out.push(b.bytes);
        else out.push(inputBytes(item, `${what}[${String(i)}]`, ctx).der);
    });
    return out;
}

const certificateOf = (input, what, ctx, o) => E.parseCertificate(inputBytes(input, what, ctx, CERT_LABELS).der, o);
const certificatesOf = (list, what, ctx, o) => bundleBytes(list, what, ctx).map((der) => E.parseCertificate(der, o));

/** CONTENT_INPUT: text, base64 or a sandbox path. */
function contentBytes(input, what, ctx) {
    if (input.text !== undefined) return utf8(input.text);
    if (input.base64 !== undefined) return fromBase64(input.base64);
    return inputBytes({ path: input.path }, what, ctx).der;
}

/** `at`: ISO 8601, epoch milliseconds or 'now'; omitted, the clock. */
function resolveAt(at) {
    if (at === undefined || at === 'now') { const ms = Date.now(); return { ms, iso: iso(ms), source: 'clock' }; }
    const ms = /^\d+$/.test(at) ? Number(at) : Date.parse(at);
    if (!Number.isFinite(ms)) throw fail('VALIDATION_ERROR', `at: not an ISO 8601 instant or epoch milliseconds (${at})`);
    return { ms, iso: iso(ms), source: 'input' };
}

/** A KeyPurposeId by name or dotted OID. */
function purposeOid(name) {
    if (name === 'any') return E.ANY_EXTENDED_KEY_USAGE;
    if (E.KEY_PURPOSES[name] !== undefined) return E.KEY_PURPOSES[name];
    if (/^\d+(\.\d+)+$/.test(name)) return name;
    throw fail('VALIDATION_ERROR', `purpose: ${name} is neither a purpose name nor a dotted OID`);
}

/** The signer: on this page, only the keys it generated itself. */
function signerOf(signer, ctx) {
    const entry = signer && signer.key && signer.key.path !== undefined ? ctx.vfs.get(signer.key.path) : undefined;
    if (!entry || !entry.signingKey) {
        throw limitation('This page signs only with the two keys it generated in this tab (keys/page-ca.key.pem, keys/page-leaf.key.pem). It never asks for yours.', 'The server reads a PKCS#8 key or a PKCS#12 from the sandbox (or inline), imports it as a non-extractable Web Crypto key, signs, and verifies the result before the bytes return.');
    }
    return entry;
}

// ── Artefacts: delivered once, never duplicated into structuredContent ─

const MIME = { pem: 'application/x-pem-file', hex: 'application/octet-stream' };

function artefact(der, args, defaults, summary, sink) {
    const encoding = args.encoding ?? defaults.encoding;
    const out = {
        encoding,
        sizeBytes: der.length,
        sha256: hex(E.computeFingerprint(der, 'SHA-256')),
        mode: 'base64',
        ...(encoding === 'hex' ? { hex: hex(der) } : {}),
        mimeType: encoding === 'der' ? defaults.mime : MIME[encoding],
        ...(summary ? { summary } : {}),
        ...(sink ? sink.report() : {}),
    };
    // The bytes themselves: the server sends them ONCE, as an embedded
    // resource block beside structuredContent. Shown here under _resource.
    if (encoding === 'pem') out._resource = { mimeType: MIME.pem, text: E.encodePem(defaults.label, der) };
    if (encoding === 'der') out._resource = { mimeType: defaults.mime, blob: toBase64(der) };
    return out;
}

// ── Specs → engine descriptions (the fields these payloads use) ─

const NAME_OIDS = [['C', '2.5.4.6', 'printable'], ['ST', '2.5.4.8'], ['L', '2.5.4.7'], ['O', '2.5.4.10'], ['OU', '2.5.4.11'], ['CN', '2.5.4.3']];

function nameOf(spec) {
    const known = new Set(NAME_OIDS.map(([k]) => k));
    for (const k of Object.keys(spec)) if (!known.has(k)) throw limitation(`name attribute ${k} is not reproduced on this page`, 'The server accepts every attribute of its name spec (C, ST, L, O, OU, CN, emailAddress, serialNumber, dotted OIDs …).');
    return NAME_OIDS.filter(([k]) => spec[k] !== undefined).map(([k, oid, stringType]) => [{ type: oid, value: spec[k], ...(stringType ? { stringType } : {}) }]);
}

function ipBytes(text) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(text)) return new Uint8Array(text.split('.').map(Number));
    const [head, tail] = text.split('::');
    const parts = (s) => (s ? s.split(':').map((h) => parseInt(h, 16)) : []);
    const h = parts(head), t = tail === undefined ? [] : parts(tail);
    const groups = tail === undefined ? h : [...h, ...new Array(8 - h.length - t.length).fill(0), ...t];
    if (groups.length !== 8 || groups.some((g) => !(g >= 0 && g <= 0xffff))) throw fail('VALIDATION_ERROR', `not an IP address: ${text}`);
    return new Uint8Array(groups.flatMap((g) => [g >> 8, g & 0xff]));
}

function generalNames(spec) {
    return [
        ...(spec.dns ?? []).map((value) => ({ kind: 'dNSName', value })),
        ...(spec.email ?? []).map((value) => ({ kind: 'rfc822Name', value })),
        ...(spec.uri ?? []).map((value) => ({ kind: 'uniformResourceIdentifier', value })),
        ...(spec.ip ?? []).map((value) => ({ kind: 'iPAddress', value: ipBytes(value) })),
    ];
}

/** The subjectPublicKey BIT STRING of a SubjectPublicKeyInfo — what a key identifier hashes. */
const spkiKeyBits = (spki) => E.readBitString(E.decodeAsn1(spki).children[1]).bytes;

function extensionsOf(ext, ids) {
    const out = [];
    const listOf = (v, key) => (Array.isArray(v) ? { items: v, critical: undefined } : { items: v[key], critical: v.critical });
    if (ext.basicConstraints) {
        out.push({ oid: '2.5.29.19', critical: ext.basicConstraints.critical ?? true, value: E.encodeBasicConstraints({ cA: ext.basicConstraints.ca, ...(ext.basicConstraints.pathLen !== undefined ? { pathLenConstraint: ext.basicConstraints.pathLen } : {}) }) });
    }
    if (ext.keyUsage) { const l = listOf(ext.keyUsage, 'usages'); out.push({ oid: '2.5.29.15', critical: l.critical ?? true, value: E.encodeKeyUsage(l.items) }); }
    if (ext.extendedKeyUsage) { const l = listOf(ext.extendedKeyUsage, 'purposes'); out.push({ oid: '2.5.29.37', critical: l.critical ?? false, value: E.encodeExtendedKeyUsage(l.items.map(purposeOid)) }); }
    if (ext.subjectAltName) out.push({ oid: '2.5.29.17', critical: ext.subjectAltName.critical ?? false, value: E.encodeSubjectAltName(generalNames(ext.subjectAltName)) });
    if (ids.ski) out.push({ oid: '2.5.29.14', critical: false, value: E.encodeSubjectKeyIdentifier(E.computeKeyIdentifier(ids.ski)) });
    if (ids.aki) out.push({ oid: '2.5.29.35', critical: false, value: E.encodeAuthorityKeyIdentifier(ids.aki) });
    return out;
}

function keyIdOf(cert) {
    const ski = E.getExtension(cert, 'subjectKeyIdentifier');
    return ski ? ski.keyIdentifier : E.computeKeyIdentifier(cert.subjectPublicKeyInfo.publicKey.bytes);
}

/** encode_asn1's node spec, for the node types these payloads use. */
function encodeSpec(spec, path) {
    switch (spec.type) {
        case 'sequence': return E.encodeSequence(spec.children.map((c, i) => encodeSpec(c, `${path}.children[${String(i)}]`)));
        case 'set': return E.encodeSet(spec.children.map((c, i) => encodeSpec(c, `${path}.children[${String(i)}]`)));
        case 'set-of': return E.encodeSetOf(spec.children.map((c, i) => encodeSpec(c, `${path}.children[${String(i)}]`)));
        case 'oid': return E.encodeObjectIdentifier(spec.value);
        case 'integer': return E.encodeInteger(BigInt(spec.value));
        case 'boolean': return E.encodeBoolean(spec.value);
        case 'null': return E.encodeNull();
        case 'octet-string': return E.encodeOctetString(fromHex(spec.hex ?? spec.value));
        case 'string': return E.encodeString(spec.stringType, spec.value);
        case 'explicit': return E.encodeExplicit(spec.tag, encodeSpec(spec.inner, `${path}.inner`), { tagClass: spec.class ?? 'context' });
        case 'implicit': return E.encodeImplicit(spec.tag, encodeSpec(spec.inner, `${path}.inner`), { tagClass: spec.class ?? 'context' });
        default: throw limitation(`${path}: node type ${String(spec.type)} is not reproduced on this page`, 'The server encodes every node type of its spec: boolean, integer, bit-string, octet-string, oid, string, time, sequence, set, set-of, explicit, implicit, tlv, der.');
    }
}

const UNIVERSAL = {
    1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL', 6: 'OBJECT IDENTIFIER', 10: 'ENUMERATED',
    12: 'UTF8String', 13: 'RELATIVE-OID', 16: 'SEQUENCE', 17: 'SET', 18: 'NumericString', 19: 'PrintableString', 20: 'TeletexString',
    22: 'IA5String', 23: 'UTCTime', 24: 'GeneralizedTime', 26: 'VisibleString', 28: 'UniversalString', 30: 'BMPString',
};

function tagName(node) {
    if (node.tagClass === 'universal') return UNIVERSAL[node.tagNumber] ?? `[UNIVERSAL ${String(node.tagNumber)}]`;
    return `[${node.tagClass === 'context' ? '' : node.tagClass.toUpperCase() + ' '}${String(node.tagNumber)}]`;
}

function countNodes(node) {
    let n = 1;
    for (const c of node.children) n += countNodes(c);
    return n;
}

// ── The page's own sandbox ────────────────────────────────────
//
// `path` arguments resolve here. Two keys and the artefacts the creation
// cards made from them, plus the files you dropped. Nothing else exists.

const page = {
    vfs: new Map(),
    dropped: [],
    pemText: null,
    certId: 'letsencrypt-org-leaf',
    password: '',
    pki: null,
    loadRegistry: null,
};

/** A dropped certificate or a sample, as `{ id, label, pem, der }`. */
function knownCertificates() {
    const samples = SAMPLES.map((s) => ({ id: s.id, label: s.label, pem: s.pem, der: E.decodePem(s.pem)[0].bytes }));
    return [...page.dropped.filter((f) => f.kind === 'certificate'), ...samples];
}

const sample = (id) => ({ pem: SAMPLES.find((s) => s.id === id).pem });
const droppedOf = (kind) => page.dropped.filter((f) => f.kind === kind).at(-1);
const inputOf = (file) => (file.pem !== undefined ? { pem: file.pem } : { derBase64: toBase64(file.der) });

/** The certificate under test: a sample, or one you dropped. */
function certUnderTest() {
    const all = knownCertificates();
    return all.find((c) => c.id === page.certId) ?? all[0];
}

/** The issuer of `der` among every certificate the page knows, matched by encoded name. */
function issuerOf(issuerNameDer) {
    const want = hex(issuerNameDer);
    return knownCertificates().find((c) => hex(E.parseCertificate(c.der, { onDiagnostic() { /* sniffing */ } }).subject.der) === want);
}

const quiet = { onDiagnostic() { /* the card's own run reports them */ } };

// ── The tool catalogue, in tools/list order ───────────────────
//
// `args(ctx)` builds the arguments the assistant would send; `run(args, ctx)`
// performs the engine call behind the tool on exactly those arguments.

const TOOLS = [{
    id: 'convert_pem',
    group: 'Encodings', cls: 'writes', kind: 'read',
    purpose: 'Lists every block of a PEM text — label, DER size, offset, SHA-256 — and delivers one as DER, PEM or hex. A private-key block is listed, never extracted.',
    prompt: 'What is inside this PEM file? Give me the first certificate as hex.',
    args: (ctx) => ({ mode: 'decode', input: { pem: ctx.pemText }, extractIndex: 0, encoding: 'hex' }),
    note: 'Runs `decodePem` and `computeFingerprint` on the PEM of the certificate under test — or on the PEM file you dropped, bundles included. `mode: \'encode\'` wraps one DER value into a strict RFC 7468 block.',
    run(args, ctx) {
        const sink = makeSink();
        if (args.mode !== 'decode') {
            const { der } = inputBytes(args.input, 'input', ctx);
            if (!args.label) throw fail('VALIDATION_ERROR', 'encode: label is required');
            if (SECRET_LABEL.test(args.label)) throw fail('SECURITY_VIOLATION', `label '${args.label}' names private-key material: this server never produces a private key.`);
            return { mode: 'encode', artefact: artefact(der, { encoding: args.encoding ?? 'pem' }, { encoding: 'pem', label: args.label, mime: 'application/octet-stream' }), ...sink.report() };
        }
        if (args.input.pem === undefined) throw fail('VALIDATION_ERROR', "decode reads PEM text: pass input.pem (derBase64 is for mode 'encode')");
        const blocks = E.decodePem(args.input.pem, { ...(args.pemMode ? { mode: args.pemMode } : {}) });
        const listed = blocks.map((b, index) => ({ index, label: b.label, sizeBytes: b.bytes.length, offset: b.offset, headers: b.headers.map(([n, v]) => [n, v]), sha256: hex(E.computeFingerprint(b.bytes, 'SHA-256')) }))
            .filter((b) => !args.label || b.label === args.label);
        const out = { mode: 'decode', blocks: listed, count: listed.length };
        if (args.extractIndex !== undefined) {
            const block = blocks[args.extractIndex];
            if (!block) throw fail('NOT_FOUND', `extractIndex ${String(args.extractIndex)}: the text holds ${String(blocks.length)} block(s)`);
            if (SECRET_LABEL.test(block.label)) throw fail('SECURITY_VIOLATION', `block ${String(args.extractIndex)} is '${block.label}': a private key is listed, never extracted.`);
            out.extracted = { index: args.extractIndex, label: block.label };
            out.artefact = artefact(block.bytes, args, { encoding: 'der', label: block.label, mime: 'application/octet-stream' });
        }
        return { ...out, ...sink.report() };
    },
}, {
    id: 'resolve_oid',
    group: 'Encodings', cls: 'readOnly', kind: 'read',
    purpose: 'Object identifiers in one call: registered names (up to 1000 per call), X.660 validation, the engine registry paged, dotted to hex, hex to dotted.',
    prompt: 'What are 1.2.840.113549.1.1.11, 2.5.29.17 and 1.3.6.1.5.5.7.3.1?',
    args: () => ({ mode: 'name', oids: ['1.2.840.113549.1.1.11', '1.2.840.10045.4.3.3', '2.5.29.17', '1.3.6.1.5.5.7.3.1', '1.2.3.4'] }),
    variants: [{ label: 'Run decode', args: () => ({ mode: 'decode', hex: '06062a864886f70d', form: 'tlv' }) }],
    note: 'Runs `getOidName`, `isValidOid`, `decodeOid` / `readObjectIdentifier` and `encodeOid` / `encodeObjectIdentifier` — the registry lookups are local to the engine, nothing is fetched.',
    run(args) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        switch (args.mode) {
            case 'name': return { mode: 'name', oids: args.oids.map((oid) => ({ oid, name: E.getOidName(oid) ?? null })), ...sink.report() };
            case 'validate': return { mode: 'validate', oids: args.oids.map((oid) => ({ oid, valid: E.isValidOid(oid) })), ...sink.report() };
            case 'encode': return { mode: 'encode', oids: args.oids.map((oid) => ({ oid, hex: hex(args.form === 'tlv' ? E.encodeObjectIdentifier(oid) : E.encodeOid(oid)) })), ...sink.report() };
            case 'decode': {
                const bytes = fromHex(args.hex);
                const oid = args.form === 'tlv' ? E.readObjectIdentifier(E.decodeAsn1(bytes, o), o) : E.decodeOid(bytes, o);
                return { mode: 'decode', oid, name: E.getOidName(oid) ?? null, ...sink.report() };
            }
            default: {
                const all = E.OID_REGISTRY.filter((e) => !args.filter || e.oid.includes(args.filter) || e.name.includes(args.filter));
                const offset = args.offset ?? 0, limit = args.limit ?? 200;
                return { mode: 'list', entries: all.slice(offset, offset + limit).map((e) => ({ oid: e.oid, name: e.name, standard: e.standard })), total: all.length, hasMore: offset + limit < all.length, ...sink.report() };
            }
        }
    },
}, {
    id: 'compute_fingerprint',
    group: 'Encodings', cls: 'readOnly', kind: 'read',
    purpose: 'The digest of the exact DER (SHA-256 by default), the RFC 5280 key identifier of a public key, or SHAKE256 output. No input byte is returned.',
    prompt: 'Give me the SHA-256 fingerprint of this certificate, colon-separated.',
    args: (ctx) => ({ input: ctx.cert }),
    variants: [{ label: 'Run key-id', args: (ctx) => ({ input: ctx.cert, mode: 'key-id', fields: ['hex', 'from'] }) }],
    note: 'Runs `computeFingerprint` and `formatFingerprint`; `key-id` runs `computeKeyIdentifier` on the public key of a certificate, CSR or PUBLIC KEY — hashing public data only.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der, label } = inputBytes(args.input, 'input', ctx);
        const mode = args.mode ?? 'fingerprint';
        if (mode === 'shake256') {
            const digest = E.shake256(der, args.outputLength ?? 32);
            return { mode, algorithm: 'SHAKE256', hex: hex(digest), formatted: E.formatFingerprint(digest), sizeBytes: der.length, label, ...sink.report() };
        }
        if (mode === 'key-id') {
            let bits, from;
            if (label === 'PUBLIC KEY') { bits = spkiKeyBits(der); from = 'public-key'; }
            else if (label === 'CERTIFICATE REQUEST' || label === 'NEW CERTIFICATE REQUEST') { bits = E.parseCertificationRequest(der, o).subjectPublicKeyInfo.publicKey.bytes; from = 'request'; }
            else { bits = E.parseCertificate(der, o).subjectPublicKeyInfo.publicKey.bytes; from = 'certificate'; }
            const algorithm = args.algorithm ?? 'SHA-1';
            const id = E.computeKeyIdentifier(bits, algorithm);
            return { mode, algorithm, hex: hex(id), formatted: E.formatFingerprint(id), sizeBytes: bits.length, label, from, ...sink.report() };
        }
        const algorithm = args.algorithm ?? 'SHA-256';
        const digest = E.computeFingerprint(der, algorithm);
        const formatted = E.formatFingerprint(digest, { ...(args.separator !== undefined ? { separator: args.separator } : {}), ...(args.letterCase ? { letterCase: args.letterCase } : {}) });
        return { mode, algorithm, hex: hex(digest), formatted, sizeBytes: der.length, label, ...sink.report() };
    },
}, {
    id: 'decode_asn1',
    group: 'Encodings', cls: 'readOnly', kind: 'read',
    purpose: 'The X.690 node tree of any DER (BER on request): offsets, tags, previews, OID names; `nodePath` narrows to a subtree and `read` applies a typed reader. Refuses a private key or a PKCS#12.',
    prompt: 'Read the serial number field of this certificate straight from the DER.',
    args: (ctx) => ({ input: ctx.cert, nodePath: '0.1', read: 'integer' }),
    variants: [{ label: 'Run tree', args: (ctx) => ({ input: ctx.cert, fields: ['nodes.path', 'nodes.tagName', 'nodes.oidName', 'nodeCount'] }) }],
    note: 'Runs `decodeAsn1` and the typed readers (`readInteger`, `readObjectIdentifier`, `readTime` …). Previews stop at 32 bytes, the tree at 20 000 nodes, as on the server.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der, label } = inputBytes(args.input, 'input', ctx);
        if (label && SECRET_LABEL.test(label)) throw fail('SECURITY_VIOLATION', `input is '${label}': decode_asn1 never dumps private-key material — use inspect_private_key or inspect_pkcs12.`);
        const roots = args.sequence ? E.decodeAsn1Sequence(der, o) : [E.decodeAsn1(der, o)];
        let start = { node: roots[0], root: 0, path: '' };
        if (args.nodePath) {
            let node = roots[0];
            for (const step of args.nodePath.split('.')) {
                node = node.children[Number(step)];
                if (!node) throw fail('NOT_FOUND', `nodePath ${args.nodePath}: step ${step} does not exist`);
            }
            start = { node, root: 0, path: args.nodePath };
        }
        const maxPreview = args.maxPreviewBytes ?? 32;
        const nodes = [];
        let truncated = false;
        const walk = (node, path, depth, root) => {
            if (nodes.length >= 20000) { truncated = true; return; }
            const row = { root, path, depth, offset: node.offset, headerLength: node.headerLength, contentLength: node.contentLength, indefinite: node.indefinite, tagClass: node.tagClass, tagNumber: node.tagNumber, tagName: tagName(node), constructed: node.constructed, childCount: node.children.length };
            if (!node.constructed) row.preview = hex(node.content.subarray(0, maxPreview));
            if (node.tagClass === 'universal' && node.tagNumber === 6) { const oid = E.decodeOid(node.content, o); row.oid = oid; row.oidName = E.getOidName(oid) ?? null; }
            nodes.push(row);
            node.children.forEach((c, i) => walk(c, path === '' ? String(i) : `${path}.${String(i)}`, depth + 1, root));
        };
        if (args.nodePath) walk(start.node, start.path, 0, 0);
        else roots.forEach((r, i) => walk(r, '', 0, i));
        const out = { label, sizeBytes: der.length, nodes, nodeCount: nodes.length, truncated };
        if (args.read) {
            const n = start.node;
            const reads = {
                'boolean': () => E.readBoolean(n, o), 'integer': () => E.readInteger(n, o), 'small-integer': () => E.readSmallInteger(n), 'enumerated': () => E.readEnumerated(n, o),
                'null': () => E.readNull(n), 'bit-string': () => E.readBitString(n, o), 'octet-string': () => E.readOctetString(n, o), 'oid': () => E.readObjectIdentifier(n, o),
                'relative-oid': () => E.readRelativeOid(n, o), 'string': () => E.readString(n, o), 'time': () => timeView(E.readTime(n, o)),
            };
            out.value = { type: args.read, value: toWire(reads[args.read]()) };
        }
        return { ...out, ...sink.report() };
    },
}, {
    id: 'encode_asn1',
    group: 'Encodings', cls: 'writes', kind: 'artefact',
    purpose: 'A JSON node spec encoded to DER through the engine\'s own encoders — deterministic, the inverse of `decode_asn1`.',
    prompt: 'Encode an AlgorithmIdentifier for ecdsa-with-SHA256 and give me the hex.',
    args: () => ({ spec: { type: 'sequence', children: [{ type: 'oid', value: '1.2.840.10045.4.3.2' }] }, encoding: 'hex' }),
    note: 'Runs `encodeSequence`, `encodeObjectIdentifier`, `encodeImplicit` … The page interprets the node types its payloads use; the server takes every type of the spec, `tlv` and `der` included.',
    run(args) {
        const der = encodeSpec(args.spec, 'spec');
        const root = E.decodeAsn1(der);
        return artefact(der, args, { encoding: 'der', label: args.label ?? 'ASN.1', mime: 'application/octet-stream' }, { rootTag: tagName(root), nodeCount: countNodes(root), sizeBytes: der.length }, makeSink());
    },
}, {
    id: 'inspect_certificate',
    group: 'Certificates and requests', cls: 'readOnly', kind: 'read',
    purpose: 'The RFC 5280 report of one certificate: serial, algorithms, names, validity, public key, every extension decoded, fingerprints, diagnostics; `issuer` adds one signature check — which is not trust.',
    prompt: 'What is this certificate? Who issued it, until when, and what may it do?',
    args: (ctx) => ({ certificate: ctx.cert }),
    variants: [{ label: 'Run with issuer', args: () => ({ certificate: sample('lets-encrypt-r12'), issuer: sample('isrg-root-x1'), fields: ['subjectString', 'issuerString', 'signature'] }) }],
    note: 'Runs `parseCertificate`, `computeFingerprint`, `formatFingerprint`; with `issuer`, `verifyCertificateSignature` in Web Crypto. The variant checks R12 against ISRG Root X1.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const cert = certificateOf(args.certificate, 'certificate', ctx, o);
        const view = certificateView(cert);
        const out = {
            ...view,
            ...(args.extension ? { extensions: view.extensions.filter((e) => e.kind === args.extension) } : {}),
            subjectString: dn(cert.subject),
            issuerString: dn(cert.issuer),
            fingerprints: Object.fromEntries((args.fingerprints ?? ['SHA-256']).map((a) => [a, E.formatFingerprint(E.computeFingerprint(cert.der, a))])),
        };
        if (args.issuer) {
            const issuer = certificateOf(args.issuer, 'issuer', ctx, o);
            out.signature = { checked: 'issuer', valid: await E.verifyCertificateSignature(cert, issuer, { allowSha1: args.allowSha1 ?? false }), issuerSubject: dn(issuer.subject) };
        } else if (args.checkSelfSignature) {
            out.signature = { checked: 'self', valid: await E.verifySelfSignature(cert, { allowSha1: args.allowSha1 ?? false }) };
        }
        return { ...out, ...sink.report() };
    },
}, {
    id: 'create_certificate',
    group: 'Certificates and requests', cls: 'produces', kind: 'artefact',
    purpose: 'Issues an X.509 v3 certificate from a JSON spec, signed by a non-extractable Web Crypto key: a self-signed CA, or a leaf issued from a certificate, CSR or PUBLIC KEY. Verified against the issuer before the bytes return.',
    prompt: 'Make me a test CA valid for ten years, then issue a leaf for page-leaf.example.test from this CSR.',
    args: () => CA_SPEC_ARGS,
    variants: [{ label: 'Run leaf from CSR', args: () => LEAF_SPEC_ARGS }],
    note: 'Runs `createCertificate`, then `verifySelfSignature` or `verifyCertificateSignature`. The signer is a key THIS PAGE generated with `crypto.subtle.generateKey` (ECDSA P-256, non-extractable, gone when the tab closes) — pkinative generated nothing. The server reads your key from the sandbox instead.',
    async run(args, ctx) {
        const sink = makeSink();
        const signer = signerOf(args.signer, ctx);
        const spec = args.spec;
        let issuer, spki = signer.spki, publicKeyFrom = 'signer';
        if (args.issuerCertificate) issuer = certificateOf(args.issuerCertificate, 'issuerCertificate', ctx, quiet);
        if (args.subjectPublicKey) {
            const { der, label } = inputBytes(args.subjectPublicKey, 'subjectPublicKey', ctx);
            spki = label === 'PUBLIC KEY' ? der : (label && label.includes('REQUEST') ? E.parseCertificationRequest(der, quiet) : E.parseCertificate(der, quiet)).subjectPublicKeyInfo.der;
            publicKeyFrom = label && label.includes('REQUEST') ? 'request' : label === 'PUBLIC KEY' ? 'public-key' : 'certificate';
        }
        const notBefore = resolveAt(spec.notBefore);
        const notAfter = notBefore.ms + (spec.validityDays ?? 365) * 86400000;
        const random = spec.serialNumber === undefined || spec.serialNumber === 'random';
        const serial = random ? crypto.getRandomValues(new Uint8Array(16)).map((b, i) => (i === 0 ? (b & 0x7f) | 0x40 : b)) : BigInt(spec.serialNumber);
        const description = {
            serialNumber: serial,
            subject: nameOf(spec.subject),
            ...(issuer ? { issuerDer: issuer.subject.der } : {}),
            notBefore: notBefore.ms,
            notAfter,
            subjectPublicKey: spki,
            extensions: extensionsOf(spec.extensions ?? {}, { ski: spkiKeyBits(spki), aki: issuer ? keyIdOf(issuer) : E.computeKeyIdentifier(spkiKeyBits(spki)) }),
        };
        const der = await E.createCertificate(description, signer.signingKey);
        const cert = E.parseCertificate(der, { onDiagnostic: sink.onDiagnostic });
        const verified = issuer ? await E.verifyCertificateSignature(cert, issuer) : await E.verifySelfSignature(cert);
        const summary = {
            serialNumber: cert.serialNumber.hex, randomSerial: random, subject: dn(cert.subject), issuer: dn(cert.issuer), selfSigned: !issuer,
            signatureAlgorithm: algorithmView(cert.signatureAlgorithm), notBefore: iso(notBefore.ms), notAfter: iso(notAfter), notBeforeSource: notBefore.source,
            extensions: cert.extensions.map((e) => e.kind), signatureVerified: verified, publicKeyFrom,
        };
        return artefact(der, args, { encoding: 'pem', label: 'CERTIFICATE', mime: 'application/pkix-cert' }, summary, sink);
    },
}, {
    id: 'encode_x509_structure',
    group: 'Certificates and requests', cls: 'writes', kind: 'artefact',
    purpose: 'One X.509 building block — a name, a validity, an SPKI, an extension, a SAN, a key identifier, a signature AlgorithmIdentifier — encoded deterministically from a closed spec. Nothing here signs.',
    prompt: 'Encode a subjectAltName with svc.example.test, a wildcard and 192.0.2.1.',
    args: () => ({ structure: 'subject-alt-name', spec: { dns: ['svc.example.test', '*.wild.example.test'], ip: ['192.0.2.1'] } }),
    variants: [{ label: 'Run key-usage', args: () => ({ structure: 'key-usage', spec: ['digitalSignature', 'keyCertSign'] }) }],
    note: 'Runs `encodeSubjectAltName`, `encodeKeyUsage`, `encodeExtendedKeyUsage` or `encodeBasicConstraints`; the server covers fifteen structures, this page the four its payloads use.',
    run(args) {
        const encoders = {
            'subject-alt-name': () => E.encodeSubjectAltName(generalNames(args.spec)),
            'key-usage': () => E.encodeKeyUsage(Array.isArray(args.spec) ? args.spec : args.spec.usages),
            'extended-key-usage': () => E.encodeExtendedKeyUsage((Array.isArray(args.spec) ? args.spec : args.spec.purposes).map(purposeOid)),
            'basic-constraints': () => E.encodeBasicConstraints({ cA: args.spec.ca, ...(args.spec.pathLen !== undefined ? { pathLenConstraint: args.spec.pathLen } : {}) }),
        };
        if (!encoders[args.structure]) throw limitation(`structure '${args.structure}' is not reproduced on this page`, 'The server encodes name, name-attribute, validity, spki, algorithm-identifier, attribute, extension(s), the four above, the key identifiers and signature-algorithm.');
        const der = encoders[args.structure]();
        return artefact(der, args, { encoding: 'hex', label: 'X509 STRUCTURE', mime: 'application/octet-stream' }, { structure: args.structure, sizeBytes: der.length }, makeSink());
    },
}, {
    id: 'decode_extension',
    group: 'Certificates and requests', cls: 'readOnly', kind: 'read',
    purpose: 'One extnValue decoded by its OID exactly as `inspect_certificate` would; `critical` is checked against the RFC 5280 rule for the kind — a diagnostic, not a refusal.',
    prompt: 'What does the extension value 30030101ff under 2.5.29.19 say?',
    args: () => ({ oid: '2.5.29.19', valueHex: '30030101ff', critical: true }),
    variants: [{ label: 'Run EKU', args: () => ({ oid: '2.5.29.37', valueHex: '300a06082b06010505070301', fields: ['kind', 'decoded.purposes'] }) }],
    note: 'Runs `decodeExtensionValue`.',
    run(args) {
        const sink = makeSink();
        const value = fromHex(args.valueHex);
        const ext = E.decodeExtensionValue(args.oid, value, { ...parseOptions(args, sink), ...(args.critical !== undefined ? { critical: args.critical } : {}) });
        const decoded = stripRaw(ext);
        for (const k of ['kind', 'oid', 'critical']) delete decoded[k];
        return { kind: ext.kind, oid: ext.oid, name: E.getOidName(ext.oid) ?? null, critical: ext.critical, sizeBytes: value.length, decoded, ...sink.report() };
    },
}, {
    id: 'check_certificate_name',
    group: 'Certificates and requests', cls: 'readOnly', kind: 'verdict',
    purpose: 'The RFC 6125 identity verdict: a certificate and a host or IP (SAN dNSName / iPAddress, wildcards, an opt-in CN fallback), or the match form `presented` + `reference` with no certificate.',
    prompt: 'Is this certificate valid for www.letsencrypt.org?',
    args: (ctx) => ({ certificate: ctx.cert, host: 'www.letsencrypt.org' }),
    variants: [{ label: 'Run match form', args: () => ({ presented: '*.example.test', reference: 'a.example.test' }) }],
    note: 'Runs `checkServerName`, or `matchDnsName` for the match form. Pick another certificate above and the same call answers `valid: false` with `PKI_REASON_NAME_MISMATCH` — a verdict, never an error.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        if (args.presented !== undefined) {
            const match = E.matchDnsName(args.presented, args.reference, { ...(args.allowWildcards !== undefined ? { allowWildcards: args.allowWildcards } : {}) });
            return { form: 'match', valid: match, reasons: [], reference: { kind: 'dns', value: args.reference }, presented: args.presented, match, ...sink.report() };
        }
        const cert = certificateOf(args.certificate, 'certificate', ctx, o);
        const reference = args.ip !== undefined ? { kind: 'ip', value: ipBytes(args.ip) } : { kind: 'dns', value: args.host };
        const reasons = E.checkServerName(cert, reference, {
            ...(args.allowCommonNameFallback ? { allowCommonNameFallback: true, path: [cert, ...certificatesOf(args.chain, 'chain', ctx, o)] } : {}),
            ...(args.allowWildcards !== undefined ? { allowWildcards: args.allowWildcards } : {}),
        });
        return { form: 'certificate', valid: reasons.length === 0, reasons: reasonsView(reasons), reference: { kind: reference.kind, value: args.ip ?? args.host }, subject: dn(cert.subject), ...sink.report() };
    },
}, {
    id: 'check_certificate_purpose',
    group: 'Certificates and requests', cls: 'readOnly', kind: 'verdict',
    purpose: 'May the certificate be used for a purpose (serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, ocspSigning, any, or an OID) along its chain? A CA\'s own EKU applies to what it issued.',
    prompt: 'May this certificate sign code?',
    args: (ctx) => ({ certificate: ctx.cert, purpose: 'codeSigning' }),
    variants: [{ label: 'Run serverAuth', args: (ctx) => ({ certificate: ctx.cert, purpose: 'serverAuth' }) }],
    note: 'Runs `checkExtendedKeyUsage`. A purpose the certificate does not permit is `valid: false` with `PKI_REASON_PURPOSE_NOT_PERMITTED` in `reasons[]`.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const cert = certificateOf(args.certificate, 'certificate', ctx, o);
        const path = [cert, ...certificatesOf(args.chain, 'chain', ctx, o)];
        const oid = purposeOid(args.purpose);
        const reasons = E.checkExtendedKeyUsage(path, oid, { restrictIssuers: args.restrictIssuers ?? true, requireExplicitPurpose: args.requireExplicitPurpose ?? false });
        return { valid: reasons.length === 0, reasons: reasonsView(reasons), purpose: args.purpose, purposeOid: oid, purposeName: E.getOidName(oid) ?? null, subject: dn(cert.subject), pathLength: path.length, ...sink.report() };
    },
}, {
    id: 'inspect_csr',
    group: 'Certificates and requests', cls: 'readOnly', kind: 'read',
    purpose: 'The RFC 2986 report of one PKCS#10 request: subject, key, attributes, the extensions requested, whether a challengePassword is present (never its text), and the proof of possession.',
    prompt: 'What does this request ask for, and did its own key sign it?',
    args: (ctx) => ({ request: ctx.csr }),
    note: 'Runs `parseCertificationRequest` and `verifyCertificationRequest`. The request is the one you dropped, else the one the `create_csr` card built in this tab.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der } = inputBytes(args.request, 'request', ctx, ['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST']);
        const csr = E.parseCertificationRequest(der, o);
        const out = {
            version: csr.version, subject: nameView(csr.subject), subjectPublicKeyInfo: spkiView(csr.subjectPublicKeyInfo),
            attributes: csr.attributes.map((a) => ({ oid: a.oid, name: E.getOidName(a.oid) ?? null, valueCount: a.values.length })),
            extensions: csr.extensions === undefined ? null : csr.extensions.map(extensionView),
            challengePassword: csr.challengePassword !== undefined, signatureAlgorithm: algorithmView(csr.signatureAlgorithm), sizeBytes: csr.der.length, subjectString: dn(csr.subject),
        };
        if (args.verify !== false) {
            const v = await E.verifyCertificationRequest(csr, { allowSha1: args.allowSha1 ?? false });
            out.signature = { valid: v.valid, reasons: reasonsView(v.reasons), signatureVerifications: v.signatureVerifications };
        }
        return { ...out, ...sink.report() };
    },
}, {
    id: 'create_csr',
    group: 'Certificates and requests', cls: 'produces', kind: 'artefact',
    purpose: 'A PKCS#10 request from a JSON spec, signed by a non-extractable key; the public key is derived from the signer. The proof of possession is verified before the bytes return.',
    prompt: 'Draft a CSR for page-leaf.example.test with a SAN, for S/MIME signing.',
    args: () => CSR_SPEC_ARGS,
    note: 'Runs `createCertificationRequest`, then `verifyCertificationRequest`. The key is the page-generated `keys/page-leaf.key.pem` (ECDSA P-256, non-extractable, this tab only).',
    async run(args, ctx) {
        const sink = makeSink();
        const signer = signerOf(args.signer, ctx);
        const der = await E.createCertificationRequest({ subject: nameOf(args.spec.subject), subjectPublicKey: signer.spki, extensions: extensionsOf(args.spec.extensions ?? {}, {}) }, signer.signingKey);
        const csr = E.parseCertificationRequest(der, { onDiagnostic: sink.onDiagnostic });
        const v = await E.verifyCertificationRequest(csr);
        return artefact(der, args, { encoding: 'pem', label: 'CERTIFICATE REQUEST', mime: 'application/pkcs10' }, {
            subject: dn(csr.subject), signatureAlgorithm: algorithmView(csr.signatureAlgorithm), extensions: (csr.extensions ?? []).map((e) => e.kind), signatureVerified: v.valid, publicKeyFrom: 'signer',
        }, sink);
    },
}, {
    id: 'verify_certificate_chain',
    group: 'Paths, CRLs and OCSP', cls: 'readOnly', kind: 'verdict',
    purpose: 'The one-call trust verdict: a path from the leaf through the candidates to one of your anchors, every signature verified, RFC 5280 §6 at `at`, the server name, the purposes, and revocation from the CRL / OCSP bytes you supply.',
    prompt: 'Does R12 chain to ISRG Root X1 for TLS server use on 1 October 2026?',
    args: () => ({ leaf: sample('lets-encrypt-r12'), trustAnchors: [sample('isrg-root-x1')], at: AT, purposes: ['serverAuth'] }),
    variants: [
        { label: 'Run summary', args: () => ({ leaf: sample('lets-encrypt-r12'), trustAnchors: [sample('isrg-root-x1')], at: AT, purposes: ['serverAuth'], verbosity: 'summary' }) },
        { label: 'Run wrong anchor', args: () => ({ leaf: sample('lets-encrypt-e7'), trustAnchors: [sample('isrg-root-x1')], at: AT }) },
    ],
    note: 'Runs `verifyCertificateChain` — path building, every signature in Web Crypto, §6 validation, purposes, revocation evidence. "Wrong anchor" is E7 against ISRG Root X1: `valid: false`, `PKI_REASON_NO_TRUST_ANCHOR`, and still not an error.',
    summary: (r) => ({ valid: r.valid, reasonCodes: r.reasons.map((x) => x.code), pathLength: r.pathLength, evaluatedAt: r.evaluatedAt, revocationEvidence: r.revocationEvidence, diagnosticCount: r.diagnostics.length }),
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const at = resolveAt(args.at);
        const leaf = certificateOf(args.leaf, 'leaf', ctx, o);
        const crls = bundleBytes(args.crls, 'crls', ctx);
        const ocspResponses = bundleBytes(args.ocspResponses, 'ocspResponses', ctx);
        const report = await E.verifyCertificateChain({
            leaf, candidates: certificatesOf(args.candidates, 'candidates', ctx, o), trustAnchors: certificatesOf(args.trustAnchors, 'trustAnchors', ctx, o), at: at.ms,
            ...(args.serverName ? { serverName: args.serverName.ip !== undefined ? { kind: 'ip', value: ipBytes(args.serverName.ip) } : { kind: 'dns', value: args.serverName.host } } : {}),
            ...(args.purposes ? { purposes: args.purposes.map(purposeOid) } : {}),
            crls, ocspResponses, requireRevocation: args.requireRevocation ?? false, allowSha1: args.allowSha1 ?? false, onDiagnostic: sink.onDiagnostic,
        });
        return {
            valid: report.valid, reasons: reasonsView(report.reasons), path: report.path.map(certificateRef), pathLength: report.path.length, explored: report.explored,
            signatureVerifications: report.signatureVerifications, evaluatedAt: at.iso, evaluatedAtSource: at.source,
            revocationEvidence: { crls: crls.length, ocspResponses: ocspResponses.length, required: args.requireRevocation ?? false }, ...sink.report(),
        };
    },
}, {
    id: 'build_certificate_path',
    group: 'Paths, CRLs and OCSP', cls: 'readOnly', kind: 'verdict',
    purpose: 'Path discovery only: which intermediates lead from the leaf to an anchor under the structural rules at `at`. No signature is checked — `valid` is always false; read `found` and `structuralReasons`.',
    prompt: 'From this bag of intermediates and roots, which path leads from E7 to a root?',
    args: () => ({ leaf: sample('lets-encrypt-e7'), candidates: [sample('lets-encrypt-r12')], trustAnchors: [sample('isrg-root-x1'), sample('isrg-root-x2')], at: AT, purposes: ['serverAuth'] }),
    note: 'Runs `buildCertificatePath` with no signature verdicts, which is the point: `PKI_REASON_SIGNATURE_NOT_CHECKED` always, and the structural answer beside it.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const at = resolveAt(args.at);
        const report = E.buildCertificatePath({
            leaf: certificateOf(args.leaf, 'leaf', ctx, o), candidates: certificatesOf(args.candidates, 'candidates', ctx, o), trustAnchors: certificatesOf(args.trustAnchors, 'trustAnchors', ctx, o),
            at: at.ms, ...(args.purposes ? { purposes: args.purposes.map(purposeOid) } : {}),
        });
        const structural = report.reasons.filter((r) => r.code !== 'PKI_REASON_SIGNATURE_NOT_CHECKED');
        return {
            found: structural.length === 0 && report.path.length > 0, valid: report.valid, reasons: reasonsView(report.reasons), structuralReasons: reasonsView(structural),
            path: report.path.map(certificateRef), pathLength: report.path.length, explored: report.explored, signaturesChecked: false, evaluatedAt: at.iso, evaluatedAtSource: at.source, ...sink.report(),
        };
    },
}, {
    id: 'validate_certificate_path',
    group: 'Paths, CRLs and OCSP', cls: 'readOnly', kind: 'verdict',
    purpose: 'RFC 5280 §6.1 validation of a path you ordered (leaf first) against your anchors at `at`; every link signature verified first. No revocation here.',
    prompt: 'Validate exactly this path — R12, then ISRG Root X1 — as of 1 October 2026.',
    args: () => ({ path: [sample('lets-encrypt-r12')], trustAnchors: [sample('isrg-root-x1')], at: AT }),
    note: 'Runs `verifyCertificateSignature` on every link, then `validateCertificatePath` with those verdicts — signatures arrive precomputed, as the engine\'s layering requires.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const at = resolveAt(args.at);
        const path = certificatesOf(args.path, 'path', ctx, o);
        const anchors = certificatesOf(args.trustAnchors, 'trustAnchors', ctx, o);
        const results = [], rows = [];
        if (args.checkSignatures !== false) {
            for (let i = 0; i < path.length; i++) {
                const cert = path[i];
                const issuer = path[i + 1] ?? anchors.find((a) => hex(a.subject.der) === hex(cert.issuer.der));
                if (!issuer) continue;
                const verdict = (await E.verifyCertificateSignature(cert, issuer, { allowSha1: args.allowSha1 ?? false })) ? 'valid' : 'invalid';
                results.push({ certificate: cert, issuer, verdict });
                rows.push({ index: i, subject: dn(cert.subject), issuer: dn(issuer.subject), verdict });
            }
        }
        const report = E.validateCertificatePath({ path, trustAnchors: anchors, at: at.ms, signatures: results });
        const failing = args.checkSignatures === false ? report.reasons.filter((r) => r.code !== 'PKI_REASON_SIGNATURE_NOT_CHECKED') : report.reasons;
        return {
            valid: report.valid, reasons: reasonsView(report.reasons), failingReasons: reasonsView(failing), path: report.path.map(certificateRef), pathLength: report.path.length,
            signaturesChecked: args.checkSignatures !== false, signatures: rows, evaluatedAt: at.iso, evaluatedAtSource: at.source, ...sink.report(),
        };
    },
}, {
    id: 'inspect_crl',
    group: 'Paths, CRLs and OCSP', cls: 'readOnly', kind: 'read',
    purpose: 'The RFC 5280 §5 report of one CRL: issuer, updates, CRL number, delta indicator, entry count (walked, never all decoded), extensions; `issuer` adds one signature check.',
    prompt: 'When was this CRL issued, when is the next one due, and how many entries does it hold?',
    needs: 'crl',
    args: (ctx) => (ctx.crl ? { crl: ctx.crl.input, ...(ctx.crl.issuer ? { issuer: ctx.crl.issuer } : {}) } : { crl: { path: 'crls/issuer.crl' } }),
    note: 'Runs `parseCertificateList` and, when the page knows a certificate whose subject is the CRL\'s issuer, `verifyCrlSignature`. Drop a .crl above — the page has none of its own: pkinative writes no CRL, by doctrine.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der } = inputBytes(args.crl, 'crl', ctx);
        const crl = E.parseCertificateList(der, o);
        const out = {
            version: crl.version, issuer: nameView(crl.issuer), issuerString: dn(crl.issuer), signatureAlgorithm: algorithmView(crl.signatureAlgorithm),
            thisUpdate: timeView(crl.thisUpdate), nextUpdate: crl.nextUpdate ? timeView(crl.nextUpdate) : null,
            crlNumber: crl.crlNumber === undefined ? null : crl.crlNumber.toString(10), isDelta: crl.isDelta,
            baseCrlNumber: crl.baseCrlNumber === undefined ? null : crl.baseCrlNumber.toString(10),
            issuingDistributionPoint: crl.issuingDistributionPoint ? stripRaw(crl.issuingDistributionPoint) : null,
            entryCount: crl.entryCount, extensions: crl.extensions.map(extensionView), sizeBytes: der.length,
        };
        if (args.issuer) {
            const issuer = certificateOf(args.issuer, 'issuer', ctx, o);
            out.signature = { valid: await E.verifyCrlSignature(crl, issuer, { allowSha1: args.allowSha1 ?? false }), issuerSubject: dn(issuer.subject) };
        }
        return { ...out, ...sink.report() };
    },
}, {
    id: 'check_crl_revocation',
    group: 'Paths, CRLs and OCSP', cls: 'readOnly', kind: 'verdict',
    purpose: 'One certificate against one base CRL (and an optional delta) you fetched, at `at`: scope, freshness, the signature verified against the issuer, the serial looked up.',
    prompt: 'Is this certificate revoked according to the CRL I downloaded?',
    needs: 'crl',
    args: (ctx) => (ctx.crl ? { certificate: ctx.cert, crl: ctx.crl.input, issuer: ctx.crl.issuer ?? { path: 'certs/crl-issuer.crt' } } : { certificate: ctx.cert, crl: { path: 'crls/issuer.crl' }, issuer: { path: 'certs/crl-issuer.crt' } }),
    note: 'Runs `verifyCrlSignature`, then `checkRevocation` on the certificate under test. The issuer is found among the samples and the certificates you dropped, by encoded name; `at` is omitted, so the clock decides — pin it for a reproducible verdict.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const at = resolveAt(args.at);
        const certificate = certificateOf(args.certificate, 'certificate', ctx, o);
        const { der } = inputBytes(args.crl, 'crl', ctx);
        const crl = E.parseCertificateList(der, o);
        const issuer = certificateOf(args.issuer, 'issuer', ctx, o);
        const signatureVerified = await E.verifyCrlSignature(crl, issuer, { allowSha1: args.allowSha1 ?? false });
        const reasons = E.checkRevocation({ certificate, crl, crlDer: der, at: at.ms, signatureVerified, ...(args.staleTolerance !== undefined ? { staleTolerance: args.staleTolerance } : {}), onDiagnostic: sink.onDiagnostic });
        return {
            valid: reasons.length === 0, reasons: reasonsView(reasons), signatureVerified, evaluatedAt: at.iso, evaluatedAtSource: at.source,
            crlNumber: crl.crlNumber === undefined ? null : crl.crlNumber.toString(10), isDelta: crl.isDelta, ...sink.report(),
        };
    },
}, {
    id: 'create_ocsp_request',
    group: 'Paths, CRLs and OCSP', cls: 'produces', kind: 'artefact',
    purpose: 'The DER OCSPRequest (RFC 6960) for a certificate under its issuer: CertID with SHA-1 (default) or SHA-256, an RFC 8954 nonce. You POST the bytes to the responder; the server never does.',
    prompt: 'Build the OCSP request for R12 with a SHA-256 CertID and a fresh nonce — I will send it myself.',
    args: () => ({ certificate: sample('lets-encrypt-r12'), issuer: sample('isrg-root-x1'), hashAlgorithm: 'SHA-256', nonce: 'random', encoding: 'hex' }),
    note: 'Runs `encodeOcspCertId` and `createOcspRequest`. The nonce is 16 bytes from `crypto.getRandomValues` in this page, as the server draws it in the wrapper — the engine generates no randomness.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const certificate = certificateOf(args.certificate, 'certificate', ctx, o);
        const issuer = certificateOf(args.issuer, 'issuer', ctx, o);
        const hashAlgorithm = args.hashAlgorithm ?? 'SHA-1';
        const nonce = args.nonce === undefined ? undefined : args.nonce === 'random' ? crypto.getRandomValues(new Uint8Array(16)) : fromHex(args.nonce);
        const der = E.createOcspRequest(certificate, issuer, { hashAlgorithm, ...(nonce ? { nonce } : {}) });
        return artefact(der, args, { encoding: 'der', label: 'OCSP REQUEST', mime: 'application/ocsp-request' }, {
            certIdHex: hex(E.encodeOcspCertId(certificate, issuer, hashAlgorithm)), hashAlgorithm, nonceHex: nonce ? hex(nonce) : null, randomNonce: args.nonce === 'random',
            certIdOnly: args.certIdOnly ?? false, serialNumber: certificate.serialNumber.hex, subject: dn(certificate.subject), issuer: dn(issuer.subject), sizeBytes: der.length,
        }, sink);
    },
}, {
    id: 'inspect_ocsp_response',
    group: 'Paths, CRLs and OCSP', cls: 'readOnly', kind: 'read',
    purpose: 'The RFC 6960 report of one response: status, responder id, producedAt, every SingleResponse, extensions, embedded certificates, nonce presence; the signature checked against the embedded certificates.',
    prompt: 'What does this OCSP response say, and who signed it?',
    needs: 'ocsp',
    args: (ctx) => (ctx.ocsp ? { response: ctx.ocsp.input } : { response: { path: 'ocsp/response.ocsp' } }),
    note: 'Runs `parseOcspResponse` and `verifyOcspSignature` against each embedded certificate. Drop an OCSP response above (`openssl ocsp … -respout`); the page builds none — pkinative has no OCSP-response writer.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der } = inputBytes(args.response, 'response', ctx);
        const response = E.parseOcspResponse(der, o);
        const basic = response.basicResponse;
        const out = { status: response.status, basicResponse: null, noncePresent: false, sizeBytes: der.length };
        if (basic) {
            const embedded = basic.certificates.map((c) => E.parseCertificate(c, o));
            out.basicResponse = {
                responderId: stripRaw(basic.responderId), producedAt: timeView(basic.producedAt),
                responses: basic.responses.map((r) => ({
                    certId: { hashAlgorithm: algorithmView(r.certId.hashAlgorithm), issuerNameHash: hex(r.certId.issuerNameHash), issuerKeyHash: hex(r.certId.issuerKeyHash), serialNumber: r.certId.serialNumber.hex },
                    status: stripRaw(r.status), thisUpdate: timeView(r.thisUpdate), nextUpdate: r.nextUpdate ? timeView(r.nextUpdate) : null, extensions: r.extensions.map(extensionView),
                })),
                extensions: basic.extensions.map(extensionView), certificates: embedded.map(certificateRef), signatureAlgorithm: algorithmView(basic.signatureAlgorithm),
            };
            out.noncePresent = basic.extensions.some((e) => e.oid === E.OCSP_NONCE_OID);
            let signer;
            for (const c of embedded) if (await E.verifyOcspSignature(basic, c)) { signer = c; break; }
            out.signature = { valid: signer !== undefined, signer: signer ? dn(signer.subject) : null, source: signer ? 'embedded' : null };
        }
        return { ...out, ...sink.report() };
    },
}, {
    id: 'check_ocsp_status',
    group: 'Paths, CRLs and OCSP', cls: 'readOnly', kind: 'verdict',
    purpose: 'One response for one certificate: the CertID recomputed from the issuer, the signature verified, the signer authorised (RFC 6960 §4.2.2.2), status, freshness at `at`, nonce.',
    prompt: 'Is this certificate good according to the OCSP response I fetched?',
    needs: 'ocsp',
    args: (ctx) => (ctx.ocsp ? { response: ctx.ocsp.input, certificate: ctx.cert, issuer: ctx.certIssuer ?? { path: 'certs/issuer.crt' } } : { response: { path: 'ocsp/response.ocsp' }, certificate: ctx.cert, issuer: { path: 'certs/issuer.crt' } }),
    note: 'Runs `encodeOcspCertId`, `verifyOcspSignature`, `verifyCertificateSignature` and `checkExtendedKeyUsage` (the responder\'s authority), then `checkOcspStatus` — on the certificate under test and its issuer, found among the samples and your files.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der } = inputBytes(args.response, 'response', ctx);
        const response = E.parseOcspResponse(der, o);
        const certificate = certificateOf(args.certificate, 'certificate', ctx, o);
        const issuer = certificateOf(args.issuer, 'issuer', ctx, o);
        const basic = response.basicResponse;
        const answered = basic?.responses.find((r) => r.certId.serialNumber.hex === certificate.serialNumber.hex);
        const byOid = { '1.3.14.3.2.26': 'SHA-1', '2.16.840.1.101.3.4.2.1': 'SHA-256' };
        const hash = args.hashAlgorithm ?? (answered ? byOid[answered.certId.hashAlgorithm.oid] : undefined) ?? 'SHA-1';
        const certId = E.encodeOcspCertId(certificate, issuer, hash);
        const node = E.decodeAsn1(certId);
        const find = async (cands) => { for (const c of cands) if (await E.verifyOcspSignature(basic, c)) return c; return undefined; };
        let signer, source = null;
        if (basic) {
            signer = await find(basic.certificates.map((c) => E.parseCertificate(c, o)));
            if (signer) source = 'embedded';
            else { signer = await find([issuer]); source = signer ? 'issuer' : null; }
        }
        let authorized;
        if (signer) {
            authorized = args.responderTrusted === true || hex(signer.der) === hex(issuer.der)
                || ((await E.verifyCertificateSignature(signer, issuer)) && E.checkExtendedKeyUsage([signer], E.KEY_PURPOSES.ocspSigning, { restrictIssuers: false, requireExplicitPurpose: true }).length === 0);
        }
        const at = resolveAt(args.at);
        const reasons = E.checkOcspStatus({
            response, expected: { issuerNameHash: E.readOctetString(node.children[1]), issuerKeyHash: E.readOctetString(node.children[2]), serialNumber: certificate.serialNumber.bytes },
            at: at.ms, ...(basic ? { signatureVerified: signer !== undefined } : {}), ...(authorized !== undefined ? { responderAuthorized: authorized } : {}), ...(signer ? { signer } : {}),
            ...(args.nonce ? { nonce: fromHex(args.nonce) } : {}), requireNonce: args.requireNonce ?? false, onDiagnostic: sink.onDiagnostic,
        });
        return {
            valid: reasons.length === 0, reasons: reasonsView(reasons), status: answered ? answered.status.kind : null, signatureVerified: signer !== undefined, responderAuthorized: authorized ?? false,
            responder: signer ? dn(signer.subject) : null, responderSource: source, hashAlgorithm: hash, certIdHex: hex(certId), evaluatedAt: at.iso, evaluatedAtSource: at.source, ...sink.report(),
        };
    },
}, {
    id: 'sign_cms',
    group: 'CMS and time-stamps', cls: 'produces', kind: 'artefact',
    purpose: 'An RFC 5652 SignedData over content (attached or detached) or a precomputed digest, signed attributes always written (contentType, messageDigest, signingTime, SigningCertificateV2, CMSAlgorithmProtection), verified before the bytes return.',
    prompt: 'Sign this text with my leaf certificate, attached, signing time pinned.',
    args: () => CMS_SPEC_ARGS,
    note: 'Runs `createSignedData`, then `parseSignedData` and `verifySignerInfoSignature`. Certificate and key are the page\'s own: `page-leaf.crt.pem`, issued by the page CA, and `keys/page-leaf.key.pem`, generated in this tab.',
    async run(args, ctx) {
        const sink = makeSink();
        const signer = signerOf(args.signer, ctx);
        const certificate = certificateOf(args.certificate, 'certificate', ctx, quiet);
        const content = args.content ? contentBytes(args.content, 'content', ctx) : undefined;
        const signingTime = args.signingTime === 'none' ? undefined : resolveAt(args.signingTime);
        const der = await E.createSignedData({
            ...(content ? { content } : { contentDigest: fromHex(args.contentDigest) }), detached: args.detached ?? false, certificate,
            ...(args.chain ? { certificates: bundleBytes(args.chain, 'chain', ctx) } : {}), ...(signingTime ? { signingTime: Math.floor(signingTime.ms / 1000) * 1000 } : {}),
            signingCertificateV2: args.signingCertificateV2 ?? true, algorithmProtection: args.algorithmProtection ?? true,
        }, signer.signingKey);
        const sd = E.parseSignedData(der, { onDiagnostic: sink.onDiagnostic });
        const si = sd.signerInfos[0];
        return artefact(der, args, { encoding: 'der', label: 'CMS', mime: 'application/pkcs7-signature' }, {
            detached: args.detached ?? false, contentType: sd.contentType, signerSubject: dn(certificate.subject), signerSerial: certificate.serialNumber.hex, sid: args.sid ?? 'issuerAndSerialNumber',
            digestAlgorithm: algorithmView(si.digestAlgorithm), signatureAlgorithm: algorithmView(si.signatureAlgorithm), signingTime: signingTime ? iso(Math.floor(signingTime.ms / 1000) * 1000) : null,
            signingTimeSource: signingTime ? signingTime.source : 'none', certificatesEmbedded: sd.certificates.length, crlsEmbedded: sd.crls.length, signedAttributes: si.signedAttributes.length,
            unsignedAttributes: si.unsignedAttributes ? si.unsignedAttributes.length : 0, signatureVerified: await E.verifySignerInfoSignature(si, certificate), contentBytes: content ? content.length : 0,
        }, sink);
    },
}, {
    id: 'verify_cms',
    group: 'CMS and time-stamps', cls: 'readOnly', kind: 'verdict',
    purpose: 'The one-call verdict on a SignedData: for every signer the signed attributes, the content digest, the signature, the chain to your anchors at `at`, every counter time-stamp, and revocation from the bytes you supply.',
    prompt: 'Is this signed message intact, and does its signer chain to my root?',
    args: (ctx) => (ctx.cms ? { signedData: ctx.cms.input, trustAnchors: ctx.cms.anchors, at: ctx.cms.at, ...(ctx.cms.purposes ? { purposes: ctx.cms.purposes } : {}) } : { signedData: { path: 'signed/message.p7s' }, trustAnchors: [{ path: 'certs/root.crt' }] }),
    note: 'Runs `verifySignedData`. With no file of yours it verifies the SignedData the `sign_cms` card built in this tab against the page CA — drop a .p7s / .p7m and a root certificate to judge your own.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const at = resolveAt(args.at);
        const report = await E.verifySignedData({
            signedData: inputBytes(args.signedData, 'signedData', ctx).der, ...(args.content ? { content: contentBytes(args.content, 'content', ctx) } : {}),
            trustAnchors: certificatesOf(args.trustAnchors, 'trustAnchors', ctx, o), certificates: certificatesOf(args.candidates, 'candidates', ctx, o),
            crls: bundleBytes(args.crls, 'crls', ctx), ocspResponses: bundleBytes(args.ocspResponses, 'ocspResponses', ctx), at: at.ms,
            ...(args.purposes ? { purposes: args.purposes.map(purposeOid) } : {}), atTimeStamp: args.atTimeStamp ?? false, requireRevocation: args.requireRevocation ?? false, allowSha1: args.allowSha1 ?? false,
        });
        const chainView = (c) => (c ? { valid: c.valid, path: c.path.map(certificateRef), reasons: reasonsView(c.reasons) } : null);
        return {
            valid: report.valid, reasons: reasonsView(report.reasons),
            signers: report.signers.map((s) => ({
                index: s.index, valid: s.valid, intact: s.intact, certificate: s.certificate ? certificateRef(s.certificate) : null, signingTime: s.signingTime ? iso(s.signingTime.epochMilliseconds) : null,
                timeStamps: (s.timeStamps ?? []).map((t) => ({ valid: t.valid, genTime: t.genTime ? iso(t.genTime.epochMilliseconds) : null, reasons: reasonsView(t.reasons ?? []) })),
                chain: chainView(s.chain), reasons: reasonsView(s.reasons),
            })),
            signerCount: report.signers.length, signatureVerifications: report.signatureVerifications, evaluatedAt: at.iso, evaluatedAtSource: at.source, atTimeStamp: args.atTimeStamp ?? false, ...sink.report(),
        };
    },
}, {
    id: 'inspect_cms',
    group: 'CMS and time-stamps', cls: 'readOnly', kind: 'read',
    purpose: 'The RFC 5652 report: content type and length, digest algorithms, embedded certificates, every signer (identifier, algorithms, signing time as claimed, attributes, time-stamp count, the signature value a counter time-stamp stamps).',
    prompt: 'Who signed this, when do they claim, and with which algorithm?',
    args: (ctx) => (ctx.cms ? { signedData: ctx.cms.input } : { signedData: { path: 'signed/message.p7s' } }),
    note: 'Runs `parseSignedData`. Parsing proves nothing — `signingTime` is what the signer claims; `verify_cms` is the verdict.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der } = inputBytes(args.signedData, 'signedData', ctx);
        const sd = E.parseSignedData(der, o);
        const attrs = (list) => list.map((a) => ({ oid: a.oid, name: E.getOidName(a.oid) ?? null, valueCount: a.values.length }));
        return {
            version: sd.version, contentType: { oid: sd.contentType, name: E.getOidName(sd.contentType) ?? null }, contentLength: sd.content ? sd.content.length : null,
            digestAlgorithms: sd.digestAlgorithms.map(algorithmView), certificates: sd.certificates.map((c) => certificateRef(E.parseCertificate(c, o))),
            crlCount: sd.crls.length, ocspResponseCount: sd.ocspResponses.length,
            signerInfos: sd.signerInfos.map((s, index) => ({
                index, version: s.version,
                sid: s.sid.kind === 'issuerAndSerialNumber' ? { kind: s.sid.kind, issuer: dn(s.sid.issuer), serialNumber: s.sid.serialNumber.hex ?? toWire(s.sid.serialNumber) } : toWire(s.sid),
                digestAlgorithm: algorithmView(s.digestAlgorithm), signatureAlgorithm: algorithmView(s.signatureAlgorithm),
                signingTime: s.signingTime ? iso(s.signingTime.epochMilliseconds) : null, signingCertificate: s.signingCertificate ? stripRaw(s.signingCertificate) : null,
                algorithmProtection: s.algorithmProtection ? stripRaw(s.algorithmProtection) : null, signedAttributes: s.signedAttributes ? attrs(s.signedAttributes) : null,
                unsignedAttributes: s.unsignedAttributes ? attrs(s.unsignedAttributes) : null, timeStampTokens: s.timeStampTokens.length, signature: hex(s.signature),
            })),
            sizeBytes: der.length, ...sink.report(),
        };
    },
}, {
    id: 'amend_cms',
    group: 'CMS and time-stamps', cls: 'writes', kind: 'artefact',
    purpose: 'The one edit a signed message legitimately receives afterwards: an unsigned attribute, or an RFC 3161 counter time-stamp on a signer — every signed octet unchanged, the token\'s imprint checked first.',
    prompt: 'Add this unsigned attribute to the first signer, and give me the result as PEM.',
    args: (ctx) => ({ signedData: ctx.cms ? ctx.cms.input : { path: 'signed/message.p7s' }, operation: 'add-unsigned-attribute', attribute: '300d06032a0304310606042a030405', encoding: 'pem' }),
    note: 'Runs `addUnsignedAttribute` (`addTimeStampToken` for `add-timestamp`, after `verifyTimeStampToken` checks the imprint). The attribute is a private OID 1.2.3.4 holding one OID value — the server\'s own example.',
    run(args, ctx) {
        const sink = makeSink();
        const { der } = inputBytes(args.signedData, 'signedData', ctx);
        const index = args.signerIndex ?? 0;
        if (args.operation !== 'add-unsigned-attribute') throw limitation('add-timestamp needs a TimeStampToken from a TSA; this page has none to add.', 'The server checks the token\'s imprint against the signature value with verifyTimeStampToken, then adds it with addTimeStampToken.');
        const out = E.addUnsignedAttribute(der, index, fromHex(args.attribute));
        const si = E.parseSignedData(out, { onDiagnostic: sink.onDiagnostic }).signerInfos[index];
        return artefact(out, args, { encoding: 'der', label: 'CMS', mime: 'application/pkcs7-signature' }, {
            operation: args.operation, signerIndex: index, unsignedAttributes: si.unsignedAttributes ? si.unsignedAttributes.length : 0, timeStampTokens: si.timeStampTokens.length, tokenGenTime: null, sizeBytesBefore: der.length,
        }, sink);
    },
}, {
    id: 'create_timestamp_request',
    group: 'CMS and time-stamps', cls: 'produces', kind: 'artefact',
    purpose: 'The RFC 3161 TimeStampReq you POST to a TSA yourself: an imprint over the data or a digest (SHA-256 / 384 / 512), a nonce, a policy, certReq.',
    prompt: 'Prepare a time-stamp request for this text with a random nonce.',
    args: () => ({ data: { text: PAGE_TEXT }, nonce: 'random', encoding: 'hex' }),
    note: 'Runs `computeFingerprint` over the data (public bytes) and `createTimeStampRequest`. The 64-bit nonce comes from `crypto.getRandomValues` here — the engine draws no randomness.',
    run(args, ctx) {
        const hashAlgorithm = args.hashAlgorithm ?? 'SHA-256';
        const data = args.data ? contentBytes(args.data, 'data', ctx) : undefined;
        const imprint = data ? E.computeFingerprint(data, hashAlgorithm) : fromHex(args.digestHex);
        const random = args.nonce === 'random';
        const nonce = args.nonce === undefined ? undefined : random ? new DataView(crypto.getRandomValues(new Uint8Array(8)).buffer).getBigUint64(0) : /^\d+$/.test(args.nonce) ? BigInt(args.nonce) : BigInt(`0x${args.nonce}`);
        const der = E.createTimeStampRequest(imprint, { hashAlgorithm, ...(nonce !== undefined ? { nonce } : {}), ...(args.policy ? { policy: args.policy } : {}), certReq: args.certReq ?? true });
        return artefact(der, args, { encoding: 'der', label: 'TIMESTAMP REQUEST', mime: 'application/timestamp-query' }, {
            hashAlgorithm, imprintHex: hex(imprint), nonce: nonce === undefined ? null : nonce.toString(10), randomNonce: random, policy: args.policy ?? null, certReq: args.certReq ?? true, dataBytes: data ? data.length : null,
        }, makeSink());
    },
}, {
    id: 'inspect_timestamp',
    group: 'CMS and time-stamps', cls: 'readOnly', kind: 'read',
    purpose: 'A TimeStampResp, a TimeStampToken or a bare TSTInfo (auto-detected): status, policy, imprint, serial, genTime, accuracy, nonce, the TSA name as stated. Parsing proves nothing.',
    prompt: 'What did the TSA answer, and when does the token say the data existed?',
    needs: 'timestamp',
    args: (ctx) => (ctx.timestamp ? { input: ctx.timestamp.input } : { input: { path: 'tsa/response.tsr' } }),
    note: 'Runs `parseTimeStampResponse`, else `parseTimeStampToken`, else `parseTstInfo`. Drop a .tsr or .tst above (`openssl ts -reply` writes them); the page cannot ask a TSA — neither can the server, which has no network.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der } = inputBytes(args.input, 'input', ctx);
        const tstView = (t) => ({
            version: t.version, policy: { oid: t.policy, name: E.getOidName(t.policy) ?? null },
            messageImprint: { hashAlgorithm: algorithmView(t.messageImprint.hashAlgorithm), hashedMessage: hex(t.messageImprint.hashedMessage) },
            serialNumber: { hex: t.serialNumber.hex, decimal: t.serialNumber.value.toString(10) }, genTime: timeView(t.genTime), accuracy: t.accuracy ? toWire(t.accuracy) : null,
            ordering: t.ordering, nonce: t.nonce === undefined ? null : t.nonce.toString(10), tsa: t.tsa ? { kind: t.tsa.kind, name: t.tsa.name ? dn(t.tsa.name) : toWire(t.tsa.value ?? null) } : null,
            extensions: t.extensions.map(extensionView),
        });
        const tokenView = (tok) => ({ tstInfo: tstView(tok.tstInfo), signerInfos: tok.signedData.signerInfos.length, certificates: tok.signedData.certificates.map((c) => certificateRef(E.parseCertificate(c, o))) });
        const tries = [
            ['response', () => { const r = E.parseTimeStampResponse(der, o); return { status: { status: r.status, statusStrings: r.statusStrings, failInfo: r.failInfo }, token: r.token ? tokenView(r.token) : null }; }],
            ['token', () => ({ token: tokenView(E.parseTimeStampToken(der, o)) })],
            ['tstinfo', () => ({ tstInfo: tstView(E.parseTstInfo(der, o)) })],
        ].filter(([as]) => !args.as || as === args.as);
        let last;
        for (const [as, parse] of tries) {
            try { return { as, ...parse(), sizeBytes: der.length, ...sink.report() }; } catch (error) { last = error; }
        }
        throw last;
    },
}, {
    id: 'verify_timestamp',
    group: 'CMS and time-stamps', cls: 'readOnly', kind: 'verdict',
    purpose: 'A token or response judged against what you say was stamped (the request, the data or a digest), the TSA signature, its chain to your anchors at `at` with a critical timeStamping EKU, and revocation from the bytes you supply.',
    prompt: 'Is this time-stamp genuine, from a TSA I trust, and over my document?',
    needs: 'timestamp',
    args: (ctx) => (ctx.timestamp ? ctx.timestamp.verifyArgs : { response: { path: 'tsa/response.tsr' }, data: { path: 'document.pdf' }, trustAnchors: [{ path: 'certs/tsa-root.crt' }] }),
    note: 'Runs `verifyTimeStampToken`. The page passes the token\'s own imprint as `digestHex`, so the imprint check is trivially true here — in real use pass the data or the request you sent. The anchors are the certificates you dropped.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const at = resolveAt(args.at);
        const anchors = certificatesOf(args.trustAnchors, 'trustAnchors', ctx, o);
        if (anchors.length === 0) throw fail('VALIDATION_ERROR', 'trustAnchors: at least one certificate — drop the TSA\'s root certificate above.');
        const report = await E.verifyTimeStampToken({
            ...(args.token ? { token: inputBytes(args.token, 'token', ctx).der } : {}), ...(args.response ? { response: inputBytes(args.response, 'response', ctx).der } : {}),
            ...(args.request ? { request: inputBytes(args.request, 'request', ctx).der } : {}), ...(args.data ? { data: contentBytes(args.data, 'data', ctx) } : {}),
            ...(args.digestHex ? { imprint: fromHex(args.digestHex) } : {}), trustAnchors: anchors, certificates: certificatesOf(args.candidates, 'candidates', ctx, o),
            crls: bundleBytes(args.crls, 'crls', ctx), ocspResponses: bundleBytes(args.ocspResponses, 'ocspResponses', ctx), at: at.ms, allowSha1: args.allowSha1 ?? false, onDiagnostic: sink.onDiagnostic,
        });
        return {
            valid: report.valid, reasons: reasonsView(report.reasons), genTime: report.genTime ? iso(report.genTime.epochMilliseconds) : null,
            earliest: report.earliest === undefined ? null : iso(report.earliest), latest: report.latest === undefined ? null : iso(report.latest),
            tsa: report.tsaCertificate ? certificateRef(report.tsaCertificate) : null, chain: report.chain ? { valid: report.chain.valid, path: report.chain.path.map(certificateRef), reasons: reasonsView(report.chain.reasons) } : null,
            signatureVerifications: report.signatureVerifications, evaluatedAt: at.iso, evaluatedAtSource: at.source, ...sink.report(),
        };
    },
}, {
    id: 'inspect_private_key',
    group: 'Keys', cls: 'readOnly', kind: 'read',
    purpose: 'Describes a PKCS#8 key without its password: format, kind, curve, algorithm, the PBES2 parameters of an encrypted key (or the legacy scheme pkinative refuses). No result ever carries a key byte.',
    prompt: 'What is this key file protected with? Do not decrypt it.',
    needs: 'key',
    args: () => ({ key: { path: 'keys/your.key' } }),
    note: 'Runs `parseEncryptedPrivateKeyInfo`, else `parsePrivateKeyInfo`, and reports an allow-list of fields. The arguments name a sandbox path on purpose: a key belongs in the operator\'s sandbox, never in a model transcript. Here, the path resolves to the TEST key you dropped — it stays in this tab.',
    run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der } = inputBytes(args.key, 'key', ctx);
        let enc;
        try { enc = E.parseEncryptedPrivateKeyInfo(der, quiet); } catch { enc = undefined; }
        if (enc) {
            const p = enc.encryption.pbes2;
            return {
                format: 'encrypted-pkcs8',
                encryption: { scheme: enc.encryption.scheme, algorithm: enc.encryption.algorithm.oid, ...(p ? { pbes2: { iterations: p.iterations, prf: p.prf, keyBits: p.keyBits, cipher: E.getOidName(p.cipherOid) ?? p.cipherOid, saltBytes: p.salt.length } } : {}) },
                encryptedBytes: enc.encryptedData.length, encrypted: true, sizeBytes: der.length, ...sink.report(),
            };
        }
        const key = E.parsePrivateKeyInfo(der, o);
        return { format: 'pkcs8', version: key.version, kind: key.kind, ...(key.curve ? { curve: key.curve } : {}), algorithm: algorithmView(key.algorithm), attributes: key.attributes.length, encrypted: false, sizeBytes: der.length, ...sink.report() };
    },
}, {
    id: 'inspect_pkcs12',
    group: 'Keys', cls: 'readOnly', kind: 'read',
    purpose: 'Describes a .p12 / .pfx without its password: MAC construction (PBMAC1 or the legacy MAC), every SafeContents and its scheme, the bags of the plain ones; with a password, the MAC verified and every bag described.',
    prompt: 'What is in this .p12, and how is it protected?',
    needs: 'p12',
    args: () => ({ pkcs12: { path: 'keys/your.p12' } }),
    note: 'Runs `parsePkcs12`; with the password field above, `verifyPkcs12Mac` and `openSafeContents` too. The password never enters the arguments: on the server it is `PKINATIVE_MCP_PASSWORD`, kept out of the transcript.',
    async run(args, ctx) {
        const sink = makeSink();
        const o = parseOptions(args, sink);
        const { der } = inputBytes(args.pkcs12, 'pkcs12', ctx);
        const p12 = E.parsePkcs12(der, o);
        const bagView = (b) => ({ path: b.path, kind: b.kind, oid: b.oid, friendlyName: b.friendlyName ?? null, localKeyId: b.localKeyId ? hex(b.localKeyId) : null, ...(b.certificateDer ? { certificate: certificateRef(E.parseCertificate(b.certificateDer, quiet)) } : {}) });
        const encView = (e) => (e ? { scheme: e.scheme, algorithm: e.algorithm.oid, ...(e.pbes2 ? { pbes2: { iterations: e.pbes2.iterations, prf: e.pbes2.prf, keyBits: e.pbes2.keyBits, cipher: E.getOidName(e.pbes2.cipherOid) ?? e.pbes2.cipherOid, saltBytes: e.pbes2.salt.length } } : {}) } : null);
        const out = {
            version: p12.version,
            mac: p12.mac ? { kind: p12.mac.kind, algorithm: p12.mac.algorithm.oid, iterations: p12.mac.iterations, ...(p12.mac.pbmac1 ? { pbmac1: { iterations: p12.mac.pbmac1.iterations, prf: p12.mac.pbmac1.prf, hmac: p12.mac.pbmac1.hmac, keyLength: p12.mac.pbmac1.keyLength } } : {}) } : null,
            contents: p12.contents.map((c) => ({ path: c.path, encrypted: c.encrypted, encryption: encView(c.encryption), bags: c.bags.map(bagView) })),
            bagCount: p12.contents.reduce((n, c) => n + c.bags.length, 0), sizeBytes: der.length,
        };
        if (ctx.password) {
            out.macVerified = p12.mac ? await E.verifyPkcs12Mac(p12, ctx.password) : null;
            out.opened = [];
            for (const c of p12.contents) out.opened.push({ path: c.path, bags: (await E.openSafeContents(c, ctx.password, quiet)).map(bagView) });
        }
        return { ...out, ...sink.report() };
    },
}, {
    id: 'open_pkcs12',
    group: 'Keys', cls: 'writes', kind: 'verdict',
    purpose: 'Opens a PKCS#12 in one call: MAC verified, PBES2 SafeContents decrypted, every key unwrapped straight into a non-extractable Web Crypto key (described, never exported), certificates parsed; optionally a PEM bundle of the certificates — never a key.',
    prompt: 'Open this .p12 and give me its certificate chain as PEM.',
    needs: 'p12',
    args: () => ({ pkcs12: { path: 'keys/your.p12' }, exportCertificates: true }),
    note: 'Runs `openPkcs12` with the password field above (on the server: `PKINATIVE_MCP_PASSWORD`). The keys become non-extractable CryptoKey handles inside this tab and are described by their algorithm and usages only.',
    async run(args, ctx) {
        const sink = makeSink();
        const { der } = inputBytes(args.pkcs12, 'pkcs12', ctx);
        if (!ctx.password) throw fail('SECRET_REQUIRED', 'Opening a PKCS#12 needs its password: type it in the password field above (the server reads PKINATIVE_MCP_PASSWORD or the per-call password).');
        const report = await E.openPkcs12(der, { password: ctx.password, ...(args.allowUnverifiedIntegrity ? { allowUnverifiedIntegrity: true } : {}), ...(args.rsaScheme ? { rsaAlgorithm: args.rsaScheme === 'pss' ? { name: 'RSA-PSS', hash: args.hash ?? 'SHA-256' } : { name: 'RSASSA-PKCS1-v1_5', hash: args.hash ?? 'SHA-256' } } : {}), onDiagnostic: sink.onDiagnostic });
        const out = {
            valid: report.valid, integrity: report.integrity, reasons: reasonsView(report.reasons),
            keys: report.keys.map((k) => ({ path: k.path, friendlyName: k.friendlyName ?? null, localKeyId: k.localKeyId ? hex(k.localKeyId) : null, certificate: k.certificate ? certificateRef(k.certificate) : null, signingKey: k.signingKey ? { algorithm: toWire(k.signingKey.algorithm), key: toWire(k.signingKey.key) } : null })),
            certificates: report.certificates.map(certificateRef), keyCount: report.keys.length, certificateCount: report.certificates.length, crlCount: report.crls.length,
        };
        if (args.exportCertificates) {
            const pem = [...report.certificates.map((c) => E.encodePem('CERTIFICATE', c.der)), ...report.crls.map((c) => E.encodePem('X509 CRL', c.der ?? c))].join('');
            out.artefact = { encoding: 'pem', sizeBytes: pem.length, sha256: hex(E.computeFingerprint(utf8(pem), 'SHA-256')), mimeType: MIME.pem, summary: { certificates: report.certificates.length, crls: report.crls.length }, mode: 'base64', _resource: { mimeType: MIME.pem, text: pem } };
        }
        return { ...out, ...sink.report() };
    },
}, {
    id: 'describe_engine',
    group: 'Meta', cls: 'readOnly', kind: 'engine',
    purpose: 'Offline preflight: versions, the host\'s Web Crypto capabilities, the engine\'s 22 default limits, the operator ceilings, every server cap, sandbox / cache / pinned-instant state, the code vocabularies, the doctrine refusals. `network` is always \'none\'.',
    prompt: 'Before I send anything: which limits and ceilings apply on this server, and can it verify and sign?',
    args: () => ({ fields: ['server', 'engine', 'capabilities', 'defaultLimits', 'ceilings', 'network'] }),
    note: 'The engine half is live: `ENGINE_VERSION`, `DEFAULT_PKI_LIMITS`, `canVerify()`, `canSign()`, `canDecrypt()`, `OID_REGISTRY` — answered by this browser. The server half (`server`, `ceilings` at their defaults, `network`) is reproduced from the 1.0.0 source and listed in `_static`; the operator\'s environment moves the ceilings, the sandbox and the pinned instant.',
    run(args) {
        const full = {
            server: { ...SERVER },
            engine: { name: 'pkinative', version: ENGINE_VERSION },
            capabilities: { canVerify: E.canVerify(), canSign: E.canSign(), canDecrypt: E.canDecrypt(), platform: 'browser' },
            randomness: { engine: 'none', wrapper: 'crypto.getRandomValues (this page)' },
            defaultLimits: { ...E.DEFAULT_PKI_LIMITS },
            ceilings: { ...CEILINGS, env: [...CEILINGS.env] },
            sandbox: { enabled: false, cacheEnabled: false, pinnedInstant: null },
            network: 'none',
            registries: { wrapperCodes: WRAPPER_CODES.map(([c]) => c), purposes: [...Object.keys(E.KEY_PURPOSES), 'any'], keyUsageBits: [...E.KEY_USAGE_BITS.keys()], oidRegistryCount: E.OID_REGISTRY.length, ocspNonceOid: E.OCSP_NONCE_OID, anyExtendedKeyUsage: E.ANY_EXTENDED_KEY_USAGE },
            _static: ['server', 'ceilings (defaults; PKINATIVE_MCP_MAX_* move them)', 'sandbox (none on this page)', 'network', 'registries.wrapperCodes'],
            _notOnThisPage: ['caps (every byte and count bound of the wrapper)', 'refusals (the doctrine, each line with its remedy)', 'unexposed (the engine surface JSON cannot carry)', 'registries.errorCodes / reasonCodes / diagnosticCodes', 'capabilities.node / nodeFloorSatisfied', 'sandbox extension allow-lists'],
        };
        return project(full, { server: full.server, engine: full.engine, capabilities: full.capabilities, sandbox: full.sandbox, network: full.network }, { verbosity: args.verbosity });
    },
}, {
    id: 'explain_code',
    group: 'Meta', cls: 'readOnly', kind: 'explain',
    purpose: 'Any code this server can emit — a PKI_* error, a PKI_REASON_* reason, a PKI_DIAG_* diagnostic or a wrapper code — explained: class, standard, CWE, the version that brought it, the remedy.',
    prompt: 'Why did my chain come back with PKI_REASON_NO_TRUST_ANCHOR, and what do I change?',
    args: () => ({ code: 'PKI_REASON_NO_TRUST_ANCHOR' }),
    variants: [{ label: 'Run list wrapper', args: () => ({ list: true, kind: 'wrapper', fields: ['codes.code', 'count'] }) }],
    note: 'Reads the site\'s own registries — errors.json, reasons.json, diagnostics.json, the files the engine is held to — and the server\'s wrapper table. The server answers from the same registries vendored at the v1.0.0 tag, and adds the MCP input that lifts each code.',
    async run(args, ctx) {
        const [errors, reasons, diagnostics] = await Promise.all(['errors', 'reasons', 'diagnostics'].map((n) => ctx.loadRegistry(n)));
        const entries = [
            ...errors.errors.map((e) => ({ code: e.code, kind: 'error', summary: e.raisedWhen, standard: e.standard, engineClass: e.class, cwe: e.cwe, since: e.since, remedy: { engine: e.remedy } })),
            ...reasons.reasons.map((e) => ({ code: e.code, kind: 'reason', summary: e.returnedWhen, standard: e.standard, since: e.since, remedy: { engine: e.remedy } })),
            ...diagnostics.diagnostics.map((e) => ({ code: e.code, kind: 'diagnostic', summary: e.raisedWhen, standard: e.standard, severity: e.severity, since: e.since, remedy: { engine: e.remedy } })),
            ...WRAPPER_CODES.map(([code, summary]) => ({ code, kind: 'wrapper', summary })),
        ];
        if (args.list) {
            const codes = entries.filter((e) => !args.kind || e.kind === args.kind).map(({ code, kind, summary }) => ({ code, kind, summary }));
            return { codes, count: codes.length };
        }
        const hit = entries.find((e) => e.code === args.code);
        if (!hit) throw fail('NOT_FOUND', `${String(args.code)} is not a code this server emits — explain_code { list: true } enumerates them.`);
        return hit;
    },
}, {
    id: 'draft_governance_issue',
    group: 'Meta', cls: 'writes', kind: 'governance',
    purpose: 'A local GitHub issue draft plus a compliance report, for pkinative, pkinative-cli or pkinative-mcp — never submitted; a human files it under their own identity.',
    prompt: 'The engine refuses an empty delta CRL. Draft the bug report — I will file it myself.',
    args: () => ({
        title: 'parseCertificateList refuses a delta CRL with an empty revokedCertificates list',
        summary: 'A delta CRL (deltaCRLIndicator present) whose revokedCertificates SEQUENCE is absent is refused with PKI_X509_STRUCTURE_INVALID although RFC 5280 makes the field OPTIONAL.',
        issueType: 'bug', targetRepo: 'pkinative',
        reproduction: { command: 'inspect_crl { crl: { path: "fixtures/empty-delta.crl" } }', result: 'PKI_X509_STRUCTURE_INVALID at revokedCertificates' },
        expectedBehavior: 'The delta CRL parses with entryCount 0.', affectedPackages: ['pkinative', 'pkinative-mcp'], duplicateSearchPerformed: true,
    }),
    note: 'These arguments are the server\'s own `_meta.examples` entry. Copy them into your client: the drafter is the server\'s policy engine, not an engine call.',
    run() {
        throw limitation('draft_governance_issue is the server\'s own policy engine — there is no pkinative call behind it to run here.', 'The server renders the Markdown draft, checks it against the AI-governance contract (no runtime dependency, a reproduction, a duplicate search, no secret) and returns it with a compliance report — or writes it into the sandbox. It never contacts GitHub; a human reviews and files it.');
    },
}];

/** The arguments of the page's own PKI, shared by the creation cards and the boot sequence. */
const CA_SPEC_ARGS = {
    spec: { serialNumber: 1, subject: { O: 'pkinative explorer', CN: 'Page Test CA' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 3650, extensions: { basicConstraints: { ca: true, pathLen: 0 }, keyUsage: ['keyCertSign', 'cRLSign'] } },
    signer: { key: { path: 'keys/page-ca.key.pem' } },
};
const CSR_SPEC_ARGS = {
    spec: { subject: { O: 'pkinative explorer', CN: 'page-leaf.example.test' }, extensions: { subjectAltName: { email: ['page-leaf@example.test'] }, keyUsage: ['digitalSignature'], extendedKeyUsage: ['emailProtection'] } },
    signer: { key: { path: 'keys/page-leaf.key.pem' } },
};
const LEAF_SPEC_ARGS = {
    spec: { serialNumber: 2, subject: { O: 'pkinative explorer', CN: 'page-leaf.example.test' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 730, extensions: { subjectAltName: { email: ['page-leaf@example.test'] }, keyUsage: ['digitalSignature'], extendedKeyUsage: ['emailProtection'] } },
    issuerCertificate: { path: 'page-ca.crt.pem' },
    subjectPublicKey: { path: 'page-leaf.csr.pem' },
    signer: { key: { path: 'keys/page-ca.key.pem' } },
};
const CMS_SPEC_ARGS = {
    content: { text: PAGE_TEXT },
    certificate: { path: 'page-leaf.crt.pem' },
    chain: [{ path: 'page-ca.crt.pem' }],
    signingTime: AT,
    signer: { key: { path: 'keys/page-leaf.key.pem' } },
};

export { TOOLS };

// ── The page PKI: two generated keys, then the creation cards ─

/**
 * Generate the two keys (the page's act, not pkinative's), then run the
 * creation cards' own engine calls to fill the page sandbox: the CA, the
 * CSR, the leaf issued from it, and a SignedData over a sentence. The
 * read and verdict cards then have something real to read.
 */
export async function bootPagePki() {
    if (!globalThis.crypto || !crypto.subtle) throw limitation('Web Crypto is not available here (an insecure origin?).', 'The server signs with Node\'s Web Crypto.');
    const algorithm = { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' };
    const makeKey = async () => {
        const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
        return { signingKey: { key: pair.privateKey, algorithm }, spki: new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)) };
    };
    page.vfs.set('keys/page-ca.key.pem', await makeKey());
    page.vfs.set('keys/page-leaf.key.pem', await makeKey());
    const ctx = context();
    const der = (r) => (r._resource.text !== undefined ? E.decodePem(r._resource.text)[0].bytes : fromBase64(r._resource.blob));
    const ca = await tool('create_certificate').run(CA_SPEC_ARGS, ctx);
    page.vfs.set('page-ca.crt.pem', { der: der(ca), label: 'CERTIFICATE' });
    const csr = await tool('create_csr').run(CSR_SPEC_ARGS, ctx);
    page.vfs.set('page-leaf.csr.pem', { der: der(csr), label: 'CERTIFICATE REQUEST' });
    const leaf = await tool('create_certificate').run(LEAF_SPEC_ARGS, ctx);
    page.vfs.set('page-leaf.crt.pem', { der: der(leaf), label: 'CERTIFICATE' });
    const cms = await tool('sign_cms').run(CMS_SPEC_ARGS, ctx);
    page.pki = { ca: der(ca), csr: der(csr), leaf: der(leaf), cms: der(cms) };
}

function tool(id) {
    return TOOLS.find((t) => t.id === id);
}

// ── Your files: sniffed by label, else by which parser accepts them ─

const PEM_KINDS = {
    'CERTIFICATE': 'certificate', 'X509 CERTIFICATE': 'certificate', 'TRUSTED CERTIFICATE': 'certificate',
    'CERTIFICATE REQUEST': 'csr', 'NEW CERTIFICATE REQUEST': 'csr', 'X509 CRL': 'crl', 'PKCS7': 'cms', 'CMS': 'cms',
    'PRIVATE KEY': 'key', 'ENCRYPTED PRIVATE KEY': 'key',
};

/** What a dropped file is: `{ kind, der, pem? }` per object it holds. */
export function classifyFile(name, bytes) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 1 << 20));
    if (text.includes('-----BEGIN')) {
        const blocks = E.decodePem(text, { mode: 'lax' });
        return { pemText: text, objects: blocks.map((b) => ({ kind: PEM_KINDS[b.label] ?? 'other', der: b.bytes, pem: E.encodePem(b.label, b.bytes), label: b.label })) };
    }
    const tries = [
        ['certificate', () => E.parseCertificate(bytes, quiet), 'CERTIFICATE'],
        ['csr', () => E.parseCertificationRequest(bytes, quiet), 'CERTIFICATE REQUEST'],
        ['crl', () => E.parseCertificateList(bytes, quiet), 'X509 CRL'],
        ['ocsp', () => E.parseOcspResponse(bytes, quiet), null],
        ['timestamp', () => E.parseTimeStampResponse(bytes, quiet), null],
        ['p12', () => E.parsePkcs12(bytes, quiet), null],
        ['key', () => E.parseEncryptedPrivateKeyInfo(bytes, quiet), null],
        ['key', () => E.parsePrivateKeyInfo(bytes, quiet), null],
        ['cms', () => E.parseSignedData(bytes, quiet), null],
    ];
    for (const [kind, parse, label] of tries) {
        try {
            const parsed = parse();
            const real = kind === 'cms' && parsed.contentType === '1.2.840.113549.1.9.16.1.4' ? 'timestamp' : kind;
            return { pemText: null, objects: [{ kind: real, der: bytes, label }] };
        } catch { /* not this one */ }
    }
    return { pemText: null, objects: [{ kind: 'other', der: bytes, label: null }] };
}

/** Add a dropped file to the page: certificates join the picker, the rest fill their slot. */
export function addFile(name, bytes) {
    const { pemText, objects } = classifyFile(name, bytes);
    // A PEM text holding key material never becomes convert_pem's input:
    // its arguments are shown and copied, and a key never enters arguments.
    if (pemText && !objects.some((o) => o.label && SECRET_LABEL.test(o.label))) page.pemText = pemText;
    objects.forEach((obj, i) => {
        const id = `file:${name}:${String(i)}`;
        const entry = { id, name, kind: obj.kind, der: obj.der, pem: obj.pem, label: obj.label };
        if (obj.kind === 'certificate') {
            const cert = E.parseCertificate(obj.der, quiet);
            entry.label = `your file: ${name} — ${dn(cert.subject)}`;
            entry.pem = obj.pem ?? E.encodePem('CERTIFICATE', obj.der);
            if (i === 0) page.certId = id;
        }
        if (obj.kind === 'key') page.vfs.set('keys/your.key', { der: obj.der, label: obj.label });
        if (obj.kind === 'p12') page.vfs.set('keys/your.p12', { der: obj.der, label: null });
        page.dropped.push(entry);
    });
    return objects.map((o) => o.kind);
}

// ── The context every card's args(ctx) and run(args, ctx) receive ─

function context() {
    const ctx = { vfs: page.vfs, password: page.password, loadRegistry: page.loadRegistry };
    if (!E) return ctx;
    const cut = certUnderTest();
    ctx.cert = { pem: cut.pem };
    ctx.pemText = page.pemText ?? cut.pem;
    const cutCert = E.parseCertificate(cut.der, quiet);
    const certIssuer = issuerOf(cutCert.issuer.der);
    if (certIssuer) ctx.certIssuer = { pem: certIssuer.pem };
    const csr = droppedOf('csr');
    ctx.csr = csr ? inputOf(csr) : page.pki ? { pem: E.encodePem('CERTIFICATE REQUEST', page.pki.csr) } : { path: 'requests/your.csr' };
    const crl = droppedOf('crl');
    if (crl) {
        const issuer = issuerOf(E.parseCertificateList(crl.der, quiet).issuer.der);
        ctx.crl = { input: inputOf(crl), ...(issuer ? { issuer: { pem: issuer.pem } } : {}) };
    }
    const ocsp = droppedOf('ocsp');
    if (ocsp) ctx.ocsp = { input: inputOf(ocsp) };
    const yourCerts = page.dropped.filter((f) => f.kind === 'certificate');
    const yourAnchors = (() => {
        const roots = yourCerts.filter((c) => { const p = E.parseCertificate(c.der, quiet); return hex(p.subject.der) === hex(p.issuer.der); });
        return (roots.length ? roots : yourCerts).map((c) => ({ pem: c.pem }));
    })();
    const cms = droppedOf('cms');
    if (cms) ctx.cms = { input: inputOf(cms), anchors: yourAnchors.length ? yourAnchors : [{ path: 'certs/root.crt' }] };
    else if (page.pki) ctx.cms = { input: { derBase64: toBase64(page.pki.cms) }, anchors: [{ pem: E.encodePem('CERTIFICATE', page.pki.ca) }], at: AT, purposes: ['emailProtection'] };
    const ts = droppedOf('timestamp');
    if (ts) {
        let imprint, isResponse = true;
        try { imprint = E.parseTimeStampResponse(ts.der, quiet).token?.tstInfo.messageImprint; } catch { isResponse = false; imprint = E.parseTimeStampToken(ts.der, quiet).tstInfo.messageImprint; }
        ctx.timestamp = {
            input: inputOf(ts),
            verifyArgs: { [isResponse ? 'response' : 'token']: inputOf(ts), ...(imprint ? { digestHex: hex(imprint.hashedMessage) } : {}), trustAnchors: yourAnchors.length ? yourAnchors : [{ path: 'certs/tsa-root.crt' }] },
        };
    }
    return ctx;
}

export { context, page };

// ── Display: payloads shortened on screen, copied whole ───────

function shorten(key, value) {
    if (typeof value !== 'string' || value.length <= 120) return value;
    const pem = /^-----BEGIN ([^-]+)-----\r?\n([\s\S]*?)-----END [^-]+-----\s*$/.exec(value);
    if (pem) return `-----BEGIN ${pem[1]}-----\n${pem[2].replace(/\s/g, '').slice(0, 40)}… (${String(value.length)} characters)\n-----END ${pem[1]}-----\n`;
    return `${value.slice(0, 64)}… (${String(value.length)} characters)`;
}

const displayArgs = (args) => JSON.stringify(args, shorten, 2);

function displayResult(result) {
    return JSON.stringify(result, (k, v) => (typeof v === 'string' && v.length > 6000 ? `${v.slice(0, 6000)}… (${String(v.length)} characters)` : v), 2);
}

/** What each file-fed card needs, and how the server gets it instead. */
const NEEDS = {
    crl: ['a CRL (.crl, DER or PEM) — and, for the verdict, the certificate of its issuer', 'The server reads the CRL you fetched yourself — inline as pem / derBase64, or by path from the sandbox. It never downloads one: there is no network code path.'],
    ocsp: ['an OCSP response (DER, as openssl ocsp -respout writes it) — and the issuer of the certificate under test', 'The server reads the response you fetched yourself — inline or by path. It never queries a responder.'],
    timestamp: ['a time-stamp response (.tsr) or token (.tst) — and, for the verdict, the TSA\'s root certificate', 'The server reads the token or response your TSA returned — inline or by path. It never contacts a TSA.'],
    key: ['a TEST private key (PKCS#8, plain or encrypted)', 'The server reads the key from the sandbox by path (or inline) and reports an allow-list view; it never returns a key byte.'],
    p12: ['a TEST PKCS#12 (.p12 / .pfx)', 'The server reads the file from the sandbox by path (or inline) and the password from the per-call input or PKINATIVE_MCP_PASSWORD.'],
};

function hasFile(kind) {
    if (kind === 'key') return page.vfs.has('keys/your.key');
    if (kind === 'p12') return page.vfs.has('keys/your.p12');
    return droppedOf(kind) !== undefined;
}

/** Run one card: the engine call, the projection, or the refusal as the assistant would see it. */
export async function runTool(t, args, ctx) {
    try {
        if (t.needs && !hasFile(t.needs)) throw limitation(`This card needs ${NEEDS[t.needs][0]}: drop it in the zone above. The page has none of its own — pkinative writes no CRL, OCSP response, time-stamp, key or PKCS#12, by doctrine.`, NEEDS[t.needs][1]);
        const full = await t.run(args, ctx);
        const result = t.id === 'describe_engine' || t.kind === 'artefact' ? project(full, undefined, { fields: args.fields }) : project(full, t.summary ? t.summary(full) : undefined, args);
        return { ok: true, result };
    } catch (error) {
        if (error && error.code === 'BROWSER_LIMITATION') return { ok: false, limitation: true, result: { code: 'BROWSER_LIMITATION', why: error.message, onTheServer: error.onTheServer } };
        const code = error && typeof error.code === 'string' ? error.code : 'ENGINE_ERROR';
        const data = {
            ...(error && error.data ? error.data : {}),
            ...(E && error instanceof E.PkiError ? { engineError: error.name, ...(error.path !== undefined ? { path: error.path } : {}), ...(error.offset !== undefined ? { offset: error.offset } : {}), ...(error.limit !== undefined ? { limit: error.limit, configured: String(error.configured), observed: String(error.observed) } : {}) } : {}),
        };
        const message = error && error.message ? error.message : String(error);
        return { ok: false, result: { content: [{ type: 'text', text: `${t.id} failed [${code}]: ${message}` }], isError: true, _meta: { error: { code, message, ...(Object.keys(data).length ? { data } : {}) } } } };
    }
}

// ── Cards ─────────────────────────────────────────────────────

const CLASS_LABEL = { readOnly: 'read-only', writes: 'writes a deterministic artefact', produces: 'produces a new artefact' };
const WHERE = {
    browser: 'runs here',
    needs: 'needs your file',
    server: 'server only',
};

function whereOf(t) {
    if (t.id === 'draft_governance_issue') return 'server';
    return t.needs ? 'needs' : 'browser';
}

function renderCards(container) {
    let group = null;
    let grid = null;
    for (const t of TOOLS) {
        if (t.group !== group) {
            group = t.group;
            container.appendChild(el('h3', `${group} (${String(TOOLS.filter((x) => x.group === group).length)})`));
            grid = el('div', null, 'pg-grid');
            container.appendChild(grid);
        }
        grid.appendChild(renderCard(t));
    }
}

function renderCard(t) {
    const card = el('article', null, 'pg-section');
    card.id = `tool-${t.id}`;
    const title = el('h4');
    title.appendChild(el('code', t.id));
    card.appendChild(title);
    const tags = el('p', null, 'pg-tags');
    tags.appendChild(el('span', CLASS_LABEL[t.cls], 'pg-tag'));
    tags.appendChild(el('span', t.kind, 'pg-tag'));
    tags.appendChild(el('span', WHERE[whereOf(t)], 'pg-tag'));
    card.appendChild(tags);
    card.appendChild(prose(el('p'), t.purpose));
    const ask = el('p', null, 'pg-note');
    ask.appendChild(el('strong', 'Ask: '));
    ask.appendChild(el('em', t.prompt));
    card.appendChild(ask);

    const details = el('details');
    details.appendChild(el('summary', 'tools/call arguments'));
    const payload = el('pre', null, 'pg-output');
    details.appendChild(payload);
    card.appendChild(details);

    const actions = el('div', null, 'pg-toolbar');
    const runs = [{ label: 'Run', args: t.args }, ...(t.variants ?? [])];
    let current = runs[0];
    const status = el('p', null, 'pg-status');
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    const out = el('pre', null, 'pg-output');
    out.hidden = true;
    const showPayload = () => { payload.textContent = `// tools/call ${t.id}\n${displayArgs(current.args(context()))}`; };
    for (const r of runs) {
        const button = el('button', r.label, 'btn btn-primary');
        button.type = 'button';
        button.disabled = true;
        button.dataset.run = '1';
        button.addEventListener('click', async () => {
            current = r;
            showPayload();
            button.disabled = true;
            status.className = 'pg-status info';
            status.textContent = 'Running…';
            const ctx = context();
            const args = r.args(ctx);
            const t0 = performance.now();
            const done = await runTool(t, args, ctx);
            const ms = (performance.now() - t0).toFixed(1);
            out.textContent = displayResult(done.result);
            out.hidden = false;
            if (done.ok) { status.className = 'pg-status ok'; status.textContent = `${t.id} — the engine call behind the tool, ${ms} ms. structuredContent shape, key fields as the server names them.`; }
            else if (done.limitation) { status.className = 'pg-status info'; status.textContent = 'BROWSER_LIMITATION — this page\'s own label, not a server code: what the server does instead is below.'; }
            else { status.className = 'pg-status error'; status.textContent = `${t.id} refused [${done.result._meta.error.code}] — the refusal an assistant would receive, with the engine's message.`; }
            button.disabled = false;
        });
        actions.appendChild(button);
    }
    const copy = el('button', 'Copy arguments', 'btn btn-secondary');
    copy.type = 'button';
    copy.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(JSON.stringify(current.args(context()), null, 2));
            status.className = 'pg-status ok';
            status.textContent = 'Arguments copied — complete, long values included.';
        } catch {
            status.className = 'pg-status error';
            status.textContent = 'The clipboard refused the write; select the arguments above instead.';
        }
    });
    actions.appendChild(copy);
    card.appendChild(actions);
    card.appendChild(status);
    card.appendChild(out);
    card.appendChild(prose(el('p', null, 'pg-note'), t.note));
    const ref = el('p', null, 'pg-note');
    const link = el('a', `${t.id} in the MCP guide`);
    link.href = `../guides/mcp.html#${t.id}`;
    ref.appendChild(link);
    card.appendChild(ref);
    card.addEventListener('pkinative:refresh', showPayload);
    showPayload();
    return card;
}

function refreshCards() {
    for (const card of document.querySelectorAll('#cards article')) card.dispatchEvent(new Event('pkinative:refresh'));
}

// ── Page wiring ───────────────────────────────────────────────

function wireTabs() {
    const tabs = [...document.querySelectorAll('#config-tabs [role="tab"]')];
    const select = (tab) => {
        for (const t of tabs) {
            const on = t === tab;
            t.setAttribute('aria-selected', String(on));
            t.tabIndex = on ? 0 : -1;
            t.classList.toggle('active', on);
            const panel = document.getElementById(t.getAttribute('aria-controls'));
            panel.hidden = !on;
            panel.classList.toggle('active', on);
        }
    };
    tabs.forEach((tab, i) => {
        tab.addEventListener('click', () => select(tab));
        tab.addEventListener('keydown', (e) => {
            const next = e.key === 'ArrowRight' ? tabs[(i + 1) % tabs.length] : e.key === 'ArrowLeft' ? tabs[(i - 1 + tabs.length) % tabs.length] : null;
            if (next) { e.preventDefault(); select(next); next.focus(); }
        });
    });
    const copy = document.getElementById('copy-config');
    const note = document.getElementById('copy-status');
    copy.addEventListener('click', async () => {
        const panel = document.querySelector('#config-panels .tab-panel:not([hidden]) code');
        try {
            await navigator.clipboard.writeText(panel.textContent);
            note.textContent = 'Copied.';
        } catch {
            note.textContent = 'The clipboard refused the write; select the snippet instead.';
        }
    });
}

function wireInputs() {
    const picker = document.getElementById('sample');
    const fill = () => {
        clear(picker);
        for (const c of knownCertificates()) picker.appendChild(Object.assign(el('option', c.label), { value: c.id }));
        picker.value = page.certId;
    };
    fill();
    picker.addEventListener('change', () => { page.certId = picker.value; refreshCards(); });

    const list = document.getElementById('your-files');
    const showFiles = () => {
        clear(list);
        if (page.dropped.length === 0) { list.appendChild(el('li', 'None yet. Nothing you drop leaves this tab.')); return; }
        for (const f of page.dropped) list.appendChild(el('li', `${f.name} — ${f.kind}${f.label && f.kind !== 'certificate' ? ` (${f.label})` : ''}, ${String(f.der.length)} bytes`));
    };
    showFiles();

    const status = document.getElementById('status');
    const take = async (files) => {
        for (const file of files) {
            try {
                const kinds = addFile(file.name, new Uint8Array(await file.arrayBuffer()));
                status.className = 'pg-status ok';
                status.textContent = `${file.name}: read as ${kinds.join(', ')} — the cards that take one now use it.`;
            } catch (error) {
                status.className = 'pg-status error';
                status.textContent = `${file.name}: ${error && error.message ? error.message : String(error)}`;
            }
        }
        fill();
        showFiles();
        refreshCards();
    };
    const drop = document.getElementById('drop');
    const input = document.getElementById('file');
    drop.addEventListener('click', () => input.click());
    drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    input.addEventListener('change', () => { take([...input.files]); input.value = ''; });
    drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('dragover'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('dragover'));
    drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('dragover'); take([...e.dataTransfer.files]); });

    document.getElementById('forget').addEventListener('click', () => {
        page.dropped = [];
        page.pemText = null;
        page.vfs.delete('keys/your.key');
        page.vfs.delete('keys/your.p12');
        page.certId = 'letsencrypt-org-leaf';
        fill();
        showFiles();
        refreshCards();
        status.className = 'pg-status info';
        status.textContent = 'Your files are forgotten.';
    });
    const password = document.getElementById('p12-password');
    password.addEventListener('input', () => { page.password = password.value; });
}

async function boot() {
    wireTabs();
    const status = document.getElementById('status');
    page.loadRegistry = async (name) => {
        const response = await fetch(`../data/${name}.json`);
        if (!response.ok) throw fail('ENGINE_ERROR', `../data/${name}.json answered ${String(response.status)}`);
        return response.json();
    };
    let loaded;
    try {
        loaded = await loadEngine();
    } catch {
        return; // loadEngine() has already said so on the page.
    }
    setEngine(loaded.mod);
    let pkiNote = 'the page PKI is ready (two ECDSA P-256 keys generated in this tab, non-extractable)';
    try {
        await bootPagePki();
    } catch (error) {
        pkiNote = `the page PKI could not be built (${error && error.message ? error.message : String(error)}) — the creation cards will say so`;
    }
    renderCards(document.getElementById('cards'));
    wireInputs();
    for (const button of document.querySelectorAll('#cards button[data-run]')) button.disabled = false;
    status.className = 'pg-status ok';
    status.textContent = `${loaded.source} loaded; ${pkiNote}. Every Run below calls it.`;
}

if (typeof document !== 'undefined') boot();
