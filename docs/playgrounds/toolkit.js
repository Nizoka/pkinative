/* ═══════════════════════════════════════════════════════════════
   pkinative.dev — PKI toolkit

   Five small tools on the published package, imported from a CDN
   pinned to the version this site documents (load-engine.js, held by
   the `cdn-pin` rule). Every value shown came out of the same exports a
   caller gets from npm; nothing is mocked or re-implemented here.

   ── One rule, without exception ──────────────────────────────
   Everything that reaches the page — pasted text, a dropped file,
   every string the engine returns — goes through textContent.
   innerHTML is never used. Structure is built with createElement.

   ── Keys ─────────────────────────────────────────────────────
   "Make a CSR" generates an ephemeral key pair, and it is THIS PAGE
   that does it, with crypto.subtle.generateKey, and this page that
   exports the public half (SubjectPublicKeyInfo) to describe it.
   pkinative generates no key and exports none: it receives the
   non-extractable private CryptoKey and hands it to Web Crypto to sign.

   Failure is a first-class output: a PkiError is rendered with its
   code and its class, as playground.js does.
   ═══════════════════════════════════════════════════════════════ */

import { loadEngine } from './load-engine.js';
import { SAMPLES } from './samples.js';

const { mod } = await loadEngine();
const {
    computeFingerprint,
    computeFingerprintAsync,
    computeKeyIdentifier,
    createCertificationRequest,
    decodeOid,
    decodePem,
    encodeObjectIdentifier,
    encodeOid,
    encodePem,
    encodeSubjectAltName,
    findRevocation,
    formatDistinguishedName,
    formatFingerprint,
    getOidName,
    isValidOid,
    OID_REGISTRY,
    parseCertificate,
    parseCertificateList,
    parseCertificationRequest,
    parseOcspResponse,
    PkiCertificateError,
    PkiCmsError,
    PkiCryptoError,
    PkiEncodingError,
    PkiError,
    PkiKeyError,
    PkiLimitError,
    verifyCertificateChain,
    verifyCertificationRequest,
    verifyCrlSignature,
    verifyOcspSignature,
} = mod;

// ── Small DOM helpers ─────────────────────────────────────────

const $ = (id) => document.getElementById(id);

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

function status(node, kind, text) {
    node.className = kind ? `pg-status ${kind}` : 'pg-status';
    node.textContent = text;
}

/** A titled box of the output panel. h3: each tool already has its h2. */
function section(panel, title) {
    const box = el('section', null, 'pg-section');
    box.appendChild(el('h3', title));
    panel.appendChild(box);
    return box;
}

/** A definition list of `[term, value]` pairs; empty values are skipped. */
function facts(parent, rows) {
    const list = el('dl', null, 'pg-facts');
    for (const [term, value] of rows) {
        if (value === undefined || value === null || value === '') continue;
        list.appendChild(el('dt', term));
        list.appendChild(el('dd', value));
    }
    parent.appendChild(list);
}

/** A table; a cell is text, or `{ text, wrap: true }` for prose. */
function table(parent, headers, rows) {
    const wrap = el('div', null, 'pg-table-wrap');
    // The wrapper scrolls sideways on a phone; a scrollable region must be
    // reachable from the keyboard (WCAG 2.1.1).
    wrap.tabIndex = 0;
    const t = el('table', null, 'pg-table');
    const head = el('tr');
    for (const h of headers) head.appendChild(el('th', h));
    t.appendChild(el('thead')).appendChild(head);
    const body = el('tbody');
    for (const row of rows) {
        const tr = el('tr');
        for (const cell of row) {
            const wrapCell = typeof cell === 'object' && cell !== null;
            tr.appendChild(el('td', wrapCell ? cell.text : cell, wrapCell && cell.wrap ? 'pg-wrap' : ''));
        }
        body.appendChild(tr);
    }
    t.appendChild(body);
    wrap.appendChild(t);
    parent.appendChild(wrap);
}

const note = (parent, text) => parent.appendChild(el('p', text, 'pg-note'));

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function base64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
}

const iso = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
const time = (t) => (t === undefined ? undefined : `${iso(t.epochMilliseconds)}  (${t.type})`);
const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

/** An OID with its registered name when there is one. */
function named(oid) {
    const name = getOidName(oid);
    return name === undefined ? oid : `${name}  (${oid})`;
}

/** Hexadecimal text (spaces, colons and a 0x prefix allowed) to bytes, or null. */
function fromHex(text) {
    const compact = text.trim().replace(/^0x/i, '').replace(/[\s:]/g, '');
    if (compact === '' || compact.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(compact)) return null;
    const out = new Uint8Array(compact.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(compact.slice(i * 2, i * 2 + 2), 16);
    return out;
}

function fromBase64(text) {
    const binary = atob(text.replace(/\s/g, ''));
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < out.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

/**
 * What a person has in the clipboard: PEM (every block), hexadecimal or
 * bare base64. Anything else is refused with a sentence rather than
 * handed to a decoder to fail on.
 */
function readInput(text, mode = 'strict') {
    const trimmed = text.trim();
    if (trimmed === '') return null;
    if (trimmed.includes('-----BEGIN')) {
        const blocks = decodePem(trimmed, { mode });
        if (blocks.length === 0) throw new Error('No PEM block found between the BEGIN and END lines.');
        return { blocks, form: 'PEM' };
    }
    const bytes = fromHex(trimmed);
    if (bytes) return { blocks: [{ label: undefined, bytes, offset: 0, headers: [] }], form: 'hexadecimal' };
    if (/^[A-Za-z0-9+/=\s]+$/.test(trimmed)) return { blocks: [{ label: undefined, bytes: fromBase64(trimmed), offset: 0, headers: [] }], form: 'base64' };
    throw new Error('Unrecognised input. Paste PEM, hexadecimal or base64.');
}

/** The shape of a refusal: its code, its class, and the fields that class adds. */
function describeFailure(error) {
    const where = (e) => `${e.path ? `\npath:   ${e.path}` : ''}${e.offset === undefined ? '' : `\noffset: ${String(e.offset)}`}`;
    if (error instanceof PkiLimitError) {
        return `${error.code}\n\nclass:      PkiLimitError\nlimit:      ${error.limit}\nconfigured: ${String(error.configured)}\nobserved:   ${String(error.observed)}\n\n${error.message}`;
    }
    if (error instanceof PkiCertificateError) return `${error.code}\n\nclass:  PkiCertificateError${where(error)}\n\n${error.message}`;
    if (error instanceof PkiEncodingError) return `${error.code}\n\nclass:  PkiEncodingError${where(error)}\n\n${error.message}`;
    if (error instanceof PkiCryptoError) return `${error.code}\n\nclass:  PkiCryptoError${error.algorithm ? `\nalgorithm: ${error.algorithm}` : ''}\n\n${error.message}`;
    if (error instanceof PkiCmsError) return `${error.code}\n\nclass:  PkiCmsError${where(error)}\n\n${error.message}`;
    if (error instanceof PkiKeyError) return `${error.code}\n\nclass:  PkiKeyError${where(error)}\n\n${error.message}`;
    if (error instanceof PkiError) return `${error.code}\n\nclass: PkiError\n\n${error.message}`;
    return String(error && error.message ? error.message : error);
}

/** A failure inside an output panel, in the error style. */
function failureBox(panel, title, error) {
    const box = section(panel, title);
    box.appendChild(el('p', describeFailure(error), 'pg-status error'));
}

/** Diagnostics a parse reported (never a refusal). */
function diagnostics(panel, list) {
    const box = section(panel, `Diagnostics (${String(list.length)})`);
    if (list.length === 0) { note(box, 'None. The structure matched its profile on every point pkinative checks.'); return; }
    const ul = el('ul', null, 'pg-diagnostics');
    for (const d of list) {
        const li = el('li');
        li.appendChild(el('code', d.code, `pg-sev-${d.severity}`));
        li.appendChild(el('span', ` ${d.message}`));
        li.appendChild(el('span', `${d.standard} · ${d.path}`, 'pg-diag-where'));
        ul.appendChild(li);
    }
    box.appendChild(ul);
}

/** The reasons of a verdict, as a table. */
function reasonsTable(parent, reasons) {
    if (reasons.length === 0) { note(parent, 'No reasons: the verdict is positive.'); return; }
    table(parent, ['Code', 'Where', 'Clause', 'Why'], reasons.map((r) => [r.code, r.path, r.standard, { text: r.message, wrap: true }]));
}

/** One GeneralName, as text. */
function generalName(name) {
    switch (name.kind) {
        case 'rfc822Name':
        case 'dNSName':
        case 'uniformResourceIdentifier': return `${name.kind}:${name.value}`;
        case 'iPAddress': return `iPAddress:${name.address}${name.mask === undefined ? '' : '/' + name.mask}`;
        case 'directoryName': return `directoryName:${formatDistinguishedName(name.name)}`;
        case 'registeredID': return `registeredID:${name.oid}`;
        case 'otherName': return `otherName:${name.typeId}`;
        default: return `${name.kind}:(${String(name.der ? name.der.length : 0)} bytes)`;
    }
}

/** A one-line rendering of a decoded extension. */
function extensionSummary(extension) {
    switch (extension.kind) {
        case 'basicConstraints': return extension.cA ? `CA, path length ${extension.pathLenConstraint === undefined ? 'unlimited' : String(extension.pathLenConstraint)}` : 'end entity';
        case 'keyUsage': return extension.usages.join(', ');
        case 'extendedKeyUsage': return extension.purposes.map(named).join(', ');
        case 'subjectAltName':
        case 'issuerAltName': return extension.names.map(generalName).join(', ');
        case 'subjectKeyIdentifier': return hex(extension.keyIdentifier);
        case 'authorityKeyIdentifier': return extension.keyIdentifier === undefined ? '(no key identifier)' : hex(extension.keyIdentifier);
        case 'crlDistributionPoints':
        case 'freshestCRL': return extension.points.flatMap((p) => (p.fullName ?? []).map(generalName)).join(', ');
        case 'authorityInfoAccess':
        case 'subjectInfoAccess': return extension.descriptions.map((d) => `${named(d.accessMethod)} → ${generalName(d.accessLocation)}`).join(', ');
        default: return extension.valueDer ? `${String(extension.valueDer.length)} bytes` : '';
    }
}

function extensionsTable(parent, extensions) {
    if (extensions.length === 0) { note(parent, 'No extensions.'); return; }
    table(parent, ['Extension', 'OID', 'Critical', 'Value'], extensions.map((e) => [e.kind, e.oid, e.critical ? 'yes' : 'no', { text: extensionSummary(e), wrap: true }]));
}

function keySummary(spki) {
    const size = spki.modulusBits !== undefined ? `${String(spki.modulusBits)} bits` : spki.curve ?? spki.namedCurve ?? '';
    return `${spki.kind}${size ? `, ${size}` : ''} — ${named(spki.algorithm.oid)}`;
}

/** Debounce a handler on `input`, so typing stays responsive. */
function onInput(node, handler) {
    let timer = 0;
    node.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(handler, 180); });
}

function fillSamples(select) {
    for (const sample of SAMPLES) select.appendChild(Object.assign(el('option', sample.label), { value: sample.id }));
}

/** Parse quietly: diagnostics are read from the result, not printed on the console. */
const QUIET = { onDiagnostic: () => {} };

/** Every sample, parsed once, by id. */
const CERTS = new Map(SAMPLES.map((s) => [s.id, parseCertificate(decodePem(s.pem)[0].bytes, QUIET)]));

// ── 1. PEM ↔ DER, hexadecimal, base64 ─────────────────────────

const downloads = [];

function runConvert() {
    const panel = $('conv-output');
    const line = $('conv-status');
    clear(panel);
    while (downloads.length > 0) URL.revokeObjectURL(downloads.pop());
    let parsed;
    try {
        parsed = readInput($('conv-input').value, $('conv-mode').value);
    } catch (error) {
        status(line, 'error', describeFailure(error));
        return;
    }
    if (parsed === null) { status(line, '', ''); return; }
    let written = 0;
    parsed.blocks.forEach((block, i) => {
        const box = section(panel, `${parsed.blocks.length > 1 ? `Block ${String(i)} — ` : ''}${block.label ?? 'bytes'} (${String(block.bytes.length)} bytes)`);
        let pem;
        try {
            pem = encodePem(block.label ?? $('conv-label').value.trim(), block.bytes);
            written++;
        } catch (error) {
            pem = describeFailure(error);
        }
        facts(box, [
            ['Read from', parsed.form === 'PEM' ? `PEM, offset ${String(block.offset)}${block.headers.length > 0 ? `, ${String(block.headers.length)} header line(s)` : ''}` : parsed.form],
            ['Hexadecimal', hex(block.bytes)],
            ['Base64', base64(block.bytes)],
        ]);
        const pre = el('pre', pem, 'pg-output');
        pre.tabIndex = 0;
        pre.setAttribute('aria-label', block.label ? 'PEM, re-encoded by encodePem' : 'PEM, written by encodePem');
        box.appendChild(pre);
        const link = el('a', `Download ${block.label ? block.label.toLowerCase().replace(/\s+/g, '-') : 'bytes'}.der`, 'btn btn-secondary');
        const url = URL.createObjectURL(new Blob([block.bytes], { type: 'application/octet-stream' }));
        downloads.push(url);
        link.href = url;
        link.download = `${block.label ? block.label.toLowerCase().replace(/\s+/g, '-') : 'bytes'}.der`;
        const bar = el('div', null, 'pg-toolbar');
        bar.appendChild(link);
        box.appendChild(bar);
    });
    status(line, 'ok', `${String(parsed.blocks.length)} object${parsed.blocks.length === 1 ? '' : 's'} read as ${parsed.form}${parsed.form === 'PEM' ? ` (${$('conv-mode').value} mode)` : `; PEM written with the label "${$('conv-label').value.trim()}"`} · ${String(written)} re-encoded`);
}

fillSamples($('conv-sample'));
$('conv-sample').addEventListener('change', () => {
    const sample = SAMPLES.find((s) => s.id === $('conv-sample').value);
    if (sample) { $('conv-input').value = sample.pem; runConvert(); }
});
onInput($('conv-input'), runConvert);
onInput($('conv-label'), runConvert);
$('conv-mode').addEventListener('change', runConvert);

// ── 2. OID resolver ───────────────────────────────────────────

function runOid() {
    const panel = $('oid-output');
    const line = $('oid-status');
    clear(panel);
    const text = $('oid-input').value.trim();
    if (text === '') { status(line, '', ''); return; }

    if (/^[0-9.]+$/.test(text)) {
        const valid = isValidOid(text);
        const box = section(panel, 'Dotted OID');
        const entry = OID_REGISTRY.find((e) => e.oid === text);
        facts(box, [
            ['isValidOid', valid ? 'true' : 'false'],
            ['getOidName', getOidName(text) ?? '(not in the registry)'],
            ['Defined by', entry ? entry.standard : ''],
        ]);
        try {
            const content = encodeOid(text);
            const tlv = encodeObjectIdentifier(text);
            facts(box, [['encodeOid (content octets)', hex(content)], ['encodeObjectIdentifier (whole TLV)', hex(tlv)], ['decodeOid, round trip', decodeOid(content)]]);
            status(line, 'ok', `${text} is ${entry ? `${entry.name}, from ${entry.standard}` : 'a valid OID the registry does not name'}`);
        } catch (error) {
            box.appendChild(el('p', describeFailure(error), 'pg-status error'));
            status(line, 'error', 'Not an OID: encodeOid refused it, with the code below.');
        }
        return;
    }

    const bytes = fromHex(text);
    if (bytes) {
        // A whole TLV (06 len …) is accepted too: its content is what decodeOid reads.
        const content = bytes[0] === 0x06 && bytes.length > 2 && bytes[1] === bytes.length - 2 ? bytes.subarray(2) : bytes;
        const box = section(panel, 'Hexadecimal');
        try {
            const dotted = decodeOid(content);
            facts(box, [
                ['Read as', content === bytes ? 'content octets' : 'a whole OBJECT IDENTIFIER TLV'],
                ['decodeOid', dotted],
                ['getOidName', getOidName(dotted) ?? '(not in the registry)'],
            ]);
            status(line, 'ok', `${hex(content)} decodes to ${dotted}`);
            return;
        } catch (error) {
            box.appendChild(el('p', describeFailure(error), 'pg-status error'));
            status(line, 'info', 'Not the content of an OID; the registry was searched for the text instead.');
        }
    }

    const needle = text.toLowerCase();
    const hits = OID_REGISTRY.filter((e) => e.name.toLowerCase().includes(needle));
    const box = section(panel, `Registry search (${String(hits.length)} of ${String(OID_REGISTRY.length)} entries)`);
    if (hits.length === 0) note(box, 'No registered name contains that text.');
    else table(box, ['OID', 'Name', 'Defined by'], hits.slice(0, 40).map((e) => [e.oid, e.name, { text: e.standard, wrap: true }]));
    if (hits.length > 40) note(box, `Showing the first 40 of ${String(hits.length)}; type more of the name to narrow it.`);
    if (!bytes) status(line, hits.length > 0 ? 'ok' : 'info', `${String(hits.length)} registered name${hits.length === 1 ? '' : 's'} contain "${text}"`);
}

onInput($('oid-input'), runOid);

// ── 3. Fingerprints and key identifiers ───────────────────────

let fpRun = 0;

async function runFingerprint() {
    const run = ++fpRun;
    const panel = $('fp-output');
    const line = $('fp-status');
    let parsed;
    try {
        parsed = readInput($('fp-input').value);
    } catch (error) {
        clear(panel);
        status(line, 'error', describeFailure(error));
        return;
    }
    if (parsed === null) { clear(panel); status(line, '', ''); return; }
    const der = parsed.blocks[0].bytes;
    const options = { separator: $('fp-separator').value, letterCase: $('fp-case').value };
    let cert;
    let parseError;
    try {
        cert = parseCertificate(der, QUIET);
    } catch (error) {
        parseError = error;
    }
    const rows = [];
    for (const algorithm of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
        const sync = computeFingerprint(der, algorithm);
        let agrees;
        try {
            agrees = sameBytes(sync, await computeFingerprintAsync(der, algorithm)) ? 'agrees' : 'DIFFERS';
        } catch (error) {
            agrees = `unavailable (${error && error.code ? error.code : 'error'})`;
        }
        rows.push([algorithm, { text: formatFingerprint(sync, options), wrap: true }, agrees]);
    }
    if (run !== fpRun) return;
    clear(panel);
    const box = section(panel, cert ? 'Certificate fingerprints' : 'Fingerprints of the bytes');
    table(box, ['Digest', 'computeFingerprint + formatFingerprint', 'computeFingerprintAsync (Web Crypto)'], rows);
    note(box, 'A fingerprint is a hash of the whole DER encoding. It identifies these exact bytes — a re-issued certificate for the same key has a different one.');

    if (cert) {
        const spki = cert.subjectPublicKeyInfo;
        const pin = computeFingerprint(spki.der, 'SHA-256');
        const keys = section(panel, 'Public key');
        facts(keys, [
            ['Subject', formatDistinguishedName(cert.subject) || '(empty)'],
            ['Key', keySummary(spki)],
            ['SPKI SHA-256', formatFingerprint(pin, options)],
            ['SPKI SHA-256, base64 (pin-sha256)', base64(pin)],
        ]);
        note(keys, 'Pin the SubjectPublicKeyInfo — algorithm and key together — not the certificate: a renewal normally keeps the key.');

        const sha1 = computeKeyIdentifier(spki.publicKey.bytes, 'SHA-1');
        const sha256 = computeKeyIdentifier(spki.publicKey.bytes, 'SHA-256');
        const ski = cert.extensions.find((e) => e.kind === 'subjectKeyIdentifier');
        let verdict = 'The certificate carries no subjectKeyIdentifier.';
        if (ski) {
            const id = ski.keyIdentifier;
            verdict = sameBytes(id, sha1) ? 'Equal to the SHA-1 key identifier: RFC 5280 §4.2.1.2, method (1).'
                : sameBytes(id, sha256.subarray(0, id.length)) ? `Equal to the SHA-256 key identifier truncated to ${String(id.length * 8)} bits (RFC 7093 §2, method 1).`
                    : 'Derived another way — RFC 5280 lets a CA choose its method, so a mismatch here is not a fault.';
        }
        const ids = section(panel, 'Key identifiers');
        facts(ids, [
            ['computeKeyIdentifier, SHA-1', hex(sha1)],
            ['computeKeyIdentifier, SHA-256', hex(sha256)],
            ['subjectKeyIdentifier in the certificate', ski ? hex(ski.keyIdentifier) : '(absent)'],
            ['Comparison', verdict],
        ]);
    } else if (parseError) {
        failureBox(panel, 'Not a certificate — no public key to identify', parseError);
    }
    status(line, 'ok', `${String(der.length)} bytes read as ${parsed.form}${cert ? ' · a certificate' : ''}`);
}

fillSamples($('fp-sample'));
$('fp-sample').addEventListener('change', () => {
    const sample = SAMPLES.find((s) => s.id === $('fp-sample').value);
    if (sample) { $('fp-input').value = sample.pem; runFingerprint(); }
});
onInput($('fp-input'), runFingerprint);
$('fp-separator').addEventListener('change', runFingerprint);
$('fp-case').addEventListener('change', runFingerprint);

// ── 4. CSR, CRL and OCSP inspection ───────────────────────────

/** A file that was dropped or chosen: its bytes win over the textarea until the text is edited. */
let loadedFile = null;
let inspRun = 0;

const KIND_OF_LABEL = { 'CERTIFICATE REQUEST': 'csr', 'NEW CERTIFICATE REQUEST': 'csr', 'X509 CRL': 'crl', 'OCSP RESPONSE': 'ocsp' };

async function renderCsr(der, panel) {
    const request = parseCertificationRequest(der, QUIET);
    const box = section(panel, 'Certification request (RFC 2986)');
    facts(box, [
        ['Subject', formatDistinguishedName(request.subject) || '(empty)'],
        ['Public key', keySummary(request.subjectPublicKeyInfo)],
        ['Signed with', named(request.signatureAlgorithm.oid)],
        ['Attributes', request.attributes.length === 0 ? 'none' : request.attributes.map((a) => named(a.oid)).join(', ')],
        ['challengePassword', request.challengePassword === undefined ? 'absent' : 'present (not shown)'],
    ]);
    const exts = section(panel, `Requested extensions (${String(request.extensions ? request.extensions.length : 0)})`);
    extensionsTable(exts, request.extensions ?? []);
    const report = await verifyCertificationRequest(der);
    const verdict = section(panel, 'verifyCertificationRequest');
    facts(verdict, [['valid', String(report.valid)], ['Signature verifications', String(report.signatureVerifications)]]);
    reasonsTable(verdict, report.reasons);
    note(verdict, 'A CSR is a proof of possession: its signature is checked with the public key it carries. A CA still decides what to certify.');
    return `a certification request, ${report.valid ? 'signature valid' : 'NOT valid'}`;
}

async function renderCrl(der, panel, issuer) {
    const crl = parseCertificateList(der, QUIET);
    const box = section(panel, 'Certificate revocation list (RFC 5280 §5)');
    facts(box, [
        ['Issuer', formatDistinguishedName(crl.issuer)],
        ['Version', `v${String(crl.version)}`],
        ['This update', time(crl.thisUpdate)],
        ['Next update', crl.nextUpdate === undefined ? '(absent — the list promises no successor)' : time(crl.nextUpdate)],
        ['CRL number', crl.crlNumber === undefined ? '(absent)' : crl.crlNumber.toString()],
        ['Delta CRL', crl.isDelta ? `yes, base ${crl.baseCrlNumber === undefined ? '?' : crl.baseCrlNumber.toString()}` : 'no'],
        ['Revoked entries', String(crl.entryCount)],
        ['Signed with', named(crl.signatureAlgorithm.oid)],
    ]);
    const exts = section(panel, `CRL extensions (${String(crl.extensions.length)})`);
    extensionsTable(exts, crl.extensions);

    const serialText = $('insp-serial').value.trim();
    if (serialText !== '') {
        const lookup = section(panel, 'findRevocation');
        const serial = fromHex(serialText);
        if (serial === null) note(lookup, 'The serial number is not hexadecimal.');
        else {
            const entry = findRevocation(der, serial, QUIET);
            facts(lookup, entry === undefined ? [['Serial', hex(serial)], ['Status', 'not on this list']] : [
                ['Serial', `${entry.serialNumber.hex}  (${entry.serialNumber.value.toString()})`],
                ['Status', 'REVOKED'],
                ['Revocation date', time(entry.revocationDate)],
                ['Reason', entry.reason ?? '(not given)'],
                ['Invalidity date', entry.invalidityDate === undefined ? '' : iso(entry.invalidityDate)],
            ]);
        }
    }
    if (issuer) {
        const sig = section(panel, 'verifyCrlSignature');
        const ok = await verifyCrlSignature(crl, issuer);
        facts(sig, [['Issuer checked against', formatDistinguishedName(issuer.subject)], ['Signature', ok ? 'valid' : 'does not verify with this issuer']]);
    }
    diagnostics(panel, crl.diagnostics);
    return `a CRL with ${String(crl.entryCount)} entr${crl.entryCount === 1 ? 'y' : 'ies'}`;
}

async function renderOcsp(der, panel, issuer) {
    const response = parseOcspResponse(der, QUIET);
    const box = section(panel, 'OCSP response (RFC 6960)');
    const basic = response.basicResponse;
    facts(box, [['Response status', response.status]]);
    if (basic) {
        const responder = basic.responderId.kind === 'byKey' ? `byKey ${hex(basic.responderId.keyHash)}` : `byName (${String(basic.responderId.nameDer.length)} bytes)`;
        facts(box, [
            ['Produced at', time(basic.producedAt)],
            ['Responder', responder],
            ['Signed with', named(basic.signatureAlgorithm.oid)],
            ['Certificates attached', String(basic.certificates.length)],
        ]);
        const single = section(panel, `Answers (${String(basic.responses.length)})`);
        table(single, ['Serial', 'Status', 'This update', 'Next update', 'CertID hash'], basic.responses.map((r) => [
            r.certId.serialNumber.hex,
            r.status.kind === 'revoked' ? `revoked ${iso(r.status.revocationTime.epochMilliseconds)}${r.status.reason ? ` (${r.status.reason})` : ''}` : r.status.kind,
            iso(r.thisUpdate.epochMilliseconds),
            r.nextUpdate === undefined ? '(absent)' : iso(r.nextUpdate.epochMilliseconds),
            named(r.certId.hashAlgorithm.oid),
        ]));
        if (issuer) {
            const sig = section(panel, 'verifyOcspSignature');
            const ok = await verifyOcspSignature(basic, issuer);
            facts(sig, [['Responder checked', formatDistinguishedName(issuer.subject)], ['Signature', ok ? 'valid' : 'does not verify with this certificate']]);
            note(sig, 'This checks the signature only. Whether that responder was authorised to answer for the certificate is checkOcspStatus\'s question, which verifyCertificateChain asks.');
        }
    } else {
        note(box, 'Only a successful response carries a signed answer; this one is the responder\'s refusal.');
    }
    diagnostics(panel, response.diagnostics);
    return `an OCSP response, status ${response.status}`;
}

async function runInspect() {
    const run = ++inspRun;
    const panel = $('insp-output');
    const line = $('insp-status');
    clear(panel);
    let der;
    let label;
    let form;
    try {
        if (loadedFile) {
            const text = new TextDecoder('utf-8', { fatal: false }).decode(loadedFile.bytes.subarray(0, 64));
            if (text.trimStart().startsWith('-----BEGIN')) {
                const parsed = readInput(new TextDecoder().decode(loadedFile.bytes));
                ({ bytes: der, label } = parsed.blocks[0]);
                form = `${loadedFile.name}, PEM`;
            } else {
                der = loadedFile.bytes;
                form = `${loadedFile.name}, DER`;
            }
        } else {
            const parsed = readInput($('insp-input').value);
            if (parsed === null) { status(line, 'info', 'Drop a file, paste one, or press Make a CSR.'); return; }
            ({ bytes: der, label } = parsed.blocks[0]);
            form = parsed.form;
        }
    } catch (error) {
        status(line, 'error', describeFailure(error));
        return;
    }
    const issuer = CERTS.get($('insp-issuer').value);
    const chosen = $('insp-kind').value;
    const kinds = chosen !== 'auto' ? [chosen] : label && KIND_OF_LABEL[label] ? [KIND_OF_LABEL[label]] : ['csr', 'crl', 'ocsp'];
    const render = { csr: renderCsr, crl: renderCrl, ocsp: renderOcsp };
    const failures = [];
    for (const kind of kinds) {
        const attempt = el('div');
        try {
            const summary = await render[kind](der, attempt, issuer);
            if (run !== inspRun) return;
            panel.appendChild(attempt);
            status(line, 'ok', `${String(der.length)} bytes read from ${form} · ${summary}`);
            return;
        } catch (error) {
            failures.push([kind, error]);
        }
    }
    if (run !== inspRun) return;
    if (label === 'CERTIFICATE' && chosen === 'auto') {
        status(line, 'info', 'That is a certificate, not a request, a CRL or an OCSP response: the certificate inspector and the fingerprint tool above read it.');
        return;
    }
    const names = { csr: 'parseCertificationRequest', crl: 'parseCertificateList', ocsp: 'parseOcspResponse' };
    for (const [kind, error] of failures) failureBox(panel, `${names[kind]} refused it`, error);
    status(line, 'error', failures.length > 1 ? 'Not a request, a CRL or an OCSP response: each reader refused it, as shown below.' : 'Refused — see below.');
}

/** The page, not pkinative, generates the key pair — see the header. */
async function makeCsr() {
    const line = $('insp-status');
    const name = $('csr-cn').value.trim() || 'toolkit.example';
    try {
        const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
        const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
        const der = await createCertificationRequest({
            subject: [[{ type: '2.5.4.3', value: name }]],
            subjectPublicKey: spki,
            extensions: [{ oid: '2.5.29.17', value: encodeSubjectAltName([{ kind: 'dNSName', value: name }]) }],
        }, { key: pair.privateKey, algorithm: { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' } });
        loadedFile = null;
        $('insp-input').value = encodePem('CERTIFICATE REQUEST', der);
        $('insp-kind').value = 'auto';
        await runInspect();
    } catch (error) {
        status(line, 'error', describeFailure(error));
    }
}

async function loadFile(file) {
    if (!file) return;
    if (file.size > 16 * 1024 * 1024) { status($('insp-status'), 'error', 'That file is over 16 MiB; this page reads files up to that size.'); return; }
    loadedFile = { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
    $('insp-input').value = '';
    await runInspect();
}

const drop = $('insp-drop');
drop.addEventListener('click', () => $('insp-file').click());
drop.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); $('insp-file').click(); } });
drop.addEventListener('dragover', (event) => { event.preventDefault(); drop.classList.add('dragover'); });
drop.addEventListener('dragleave', () => drop.classList.remove('dragover'));
drop.addEventListener('drop', (event) => { event.preventDefault(); drop.classList.remove('dragover'); loadFile(event.dataTransfer.files[0]); });
$('insp-file').addEventListener('change', () => loadFile($('insp-file').files[0]));
onInput($('insp-input'), () => { loadedFile = null; runInspect(); });
$('csr-make').addEventListener('click', makeCsr);
for (const id of ['insp-kind', 'insp-issuer']) $(id).addEventListener('change', runInspect);
onInput($('insp-serial'), runInspect);
fillSamples($('insp-issuer'));

// ── 5. Chain verdict ──────────────────────────────────────────

const SCENARIOS = [
    { id: 'r12-x1', label: 'R12 under ISRG Root X1 — a complete RSA chain', leaf: 'lets-encrypt-r12', candidates: [], anchors: ['isrg-root-x1'], at: '2026-10-01T00:00:00Z', host: '' },
    { id: 'e7-x2', label: 'E7 under ISRG Root X2 — a complete ECDSA chain', leaf: 'lets-encrypt-e7', candidates: [], anchors: ['isrg-root-x2'], at: '2026-10-01T00:00:00Z', host: '' },
    { id: 'r12-x2', label: 'R12 anchored at the wrong root', leaf: 'lets-encrypt-r12', candidates: [], anchors: ['isrg-root-x2'], at: '2026-10-01T00:00:00Z', host: '' },
    { id: 'r12-expired', label: 'R12 judged in 2028, after it expired', leaf: 'lets-encrypt-r12', candidates: [], anchors: ['isrg-root-x1'], at: '2028-01-01T00:00:00Z', host: '' },
    { id: 'leaf-ye2', label: 'letsencrypt.org — its issuer YE2 is not among the samples', leaf: 'letsencrypt-org-leaf', candidates: ['lets-encrypt-r12', 'lets-encrypt-e7'], anchors: ['isrg-root-x1', 'isrg-root-x2'], at: '2026-10-01T00:00:00Z', host: 'www.letsencrypt.org' },
    { id: 'leaf-host', label: 'letsencrypt.org checked against the wrong host name', leaf: 'letsencrypt-org-leaf', candidates: ['lets-encrypt-r12', 'lets-encrypt-e7'], anchors: ['isrg-root-x1', 'isrg-root-x2'], at: '2026-10-01T00:00:00Z', host: 'example.com' },
];

function checkboxes(fieldset, prefix) {
    for (const sample of SAMPLES) {
        const label = el('label', null, 'pg-switch');
        const box = document.createElement('input');
        box.type = 'checkbox';
        box.value = sample.id;
        box.id = `${prefix}-${sample.id}`;
        label.htmlFor = box.id;
        label.appendChild(box);
        label.appendChild(document.createTextNode(` ${sample.label}`));
        fieldset.appendChild(label);
    }
}

const checked = (fieldset) => Array.from(fieldset.querySelectorAll('input[type=checkbox]')).filter((b) => b.checked).map((b) => b.value);

/** An IPv4 literal as network-order bytes; anything else is a DNS name. */
function serverName(text) {
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
    if (v4 && v4.slice(1).every((n) => Number(n) <= 255)) return { kind: 'ip', value: new Uint8Array(v4.slice(1).map(Number)) };
    return { kind: 'dns', value: text };
}

let chainRun = 0;

async function runChain() {
    const run = ++chainRun;
    const panel = $('chain-output');
    const line = $('chain-status');
    clear(panel);
    const at = Date.parse($('chain-at').value.trim());
    if (Number.isNaN(at)) { status(line, 'error', 'The validation time is not a date: write it as ISO 8601, e.g. 2026-10-01T00:00:00Z.'); return; }
    const leaf = CERTS.get($('chain-leaf').value);
    const candidates = checked($('chain-candidates')).map((id) => CERTS.get(id));
    const anchors = checked($('chain-anchors')).map((id) => CERTS.get(id));
    let pasted = 0;
    try {
        const extra = readInput($('chain-extra').value);
        for (const block of extra ? extra.blocks : []) {
            const cert = parseCertificate(block.bytes, QUIET);
            (sameBytes(cert.subject.der, cert.issuer.der) ? anchors : candidates).push(cert);
            pasted++;
        }
    } catch (error) {
        status(line, 'error', `The pasted certificates were refused:\n\n${describeFailure(error)}`);
        return;
    }
    const host = $('chain-host').value.trim();
    status(line, 'info', 'Verifying…');
    let report;
    try {
        report = await verifyCertificateChain({
            leaf,
            candidates,
            trustAnchors: anchors,
            at,
            ...(host ? { serverName: serverName(host) } : {}),
            onDiagnostic: () => {},
        });
    } catch (error) {
        if (run === chainRun) status(line, 'error', describeFailure(error));
        return;
    }
    if (run !== chainRun) return;
    const verdict = section(panel, report.valid ? 'Verdict: valid' : 'Verdict: not valid');
    facts(verdict, [
        ['valid', String(report.valid)],
        ['Path', report.path.map((c) => formatDistinguishedName(c.subject) || '(empty subject)').join('  →  ')],
        ['Path length', String(report.path.length)],
        ['Signature verifications', String(report.signatureVerifications)],
        ['Paths explored', String(report.explored)],
        ['Judged at', iso(at)],
        ['Host name', host || '(none given — the name was not checked)'],
    ]);
    const reasons = section(panel, `Reasons (${String(report.reasons.length)})`);
    reasonsTable(reasons, report.reasons);
    if (report.reasons.some((r) => r.code === 'PKI_REASON_NO_TRUST_ANCHOR')) {
        const aia = leaf.extensions.find((e) => e.kind === 'authorityInfoAccess');
        const where = aia ? aia.descriptions.filter((d) => d.accessMethod === '1.3.6.1.5.5.7.48.2').map((d) => generalName(d.accessLocation)) : [];
        const issuerSample = SAMPLES.find((s) => sameBytes(CERTS.get(s.id).subject.der, leaf.issuer.der));
        note(reasons, issuerSample
            ? `No path reached a trust anchor. The leaf's issuer, "${formatDistinguishedName(leaf.issuer)}", is among the samples: tick it as a candidate or as a trust anchor.`
            : `No path reached a trust anchor. The leaf names its issuer "${formatDistinguishedName(leaf.issuer)}"${where.length > 0 ? `, published at ${where.join(', ')}` : ''}, which is not among the samples. pkinative fetches nothing: paste that certificate and its root in the box above to complete the path.`);
    }
    status(line, report.valid ? 'ok' : 'error', `${report.valid ? 'Valid' : 'Not valid'} — ${String(report.reasons.length)} reason${report.reasons.length === 1 ? '' : 's'}, ${String(report.signatureVerifications)} signature${report.signatureVerifications === 1 ? '' : 's'} verified${pasted > 0 ? `, ${String(pasted)} pasted certificate${pasted === 1 ? '' : 's'} used` : ''}`);
}

function applyScenario(id) {
    const scenario = SCENARIOS.find((s) => s.id === id);
    if (!scenario) return;
    $('chain-leaf').value = scenario.leaf;
    for (const box of $('chain-candidates').querySelectorAll('input')) box.checked = scenario.candidates.includes(box.value);
    for (const box of $('chain-anchors').querySelectorAll('input')) box.checked = scenario.anchors.includes(box.value);
    $('chain-at').value = scenario.at;
    $('chain-host').value = scenario.host;
    $('chain-scenario').value = id;
    runChain();
}

fillSamples($('chain-leaf'));
checkboxes($('chain-candidates'), 'cand');
checkboxes($('chain-anchors'), 'anchor');
for (const s of SCENARIOS) $('chain-scenario').appendChild(Object.assign(el('option', s.label), { value: s.id }));
$('chain-scenario').addEventListener('change', () => applyScenario($('chain-scenario').value));
$('chain-run').addEventListener('click', runChain);

// ── Start on something real ───────────────────────────────────

$('conv-sample').value = 'isrg-root-x2';
$('conv-input').value = SAMPLES.find((s) => s.id === 'isrg-root-x2').pem;
runConvert();
runOid();
$('fp-sample').value = 'letsencrypt-org-leaf';
$('fp-input').value = SAMPLES.find((s) => s.id === 'letsencrypt-org-leaf').pem;
runFingerprint();
runInspect();
applyScenario('r12-x1');
