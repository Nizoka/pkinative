/* ═══════════════════════════════════════════════════════════════
   pkinative.dev — playgrounds

   Runs the library in the browser, on a byte-for-byte copy of what
   `npm run build` produces (docs/playground/pkinative.js, held to the
   build by the `playground-freshness` rule). Nothing is mocked and
   nothing is re-implemented here: every value below came out of the
   same exports a caller gets from npm.

   ── One rule, without exception ──────────────────────────────
   Playground input is attacker-controlled by definition — the whole
   point is to paste hostile bytes at it. So every value that reaches
   the page goes through `textContent`, and `innerHTML` is never used
   with anything derived from input. Structure is built with
   createElement. zipnative shipped the other way first and had to fix
   it in two commits; this file starts where that ended.

   Failure is a first-class output. A PkiError is rendered with its
   code, its class and its offset, because the error registry is a
   product feature and this is the only place a reader can see it fire
   on bytes they chose.
   ═══════════════════════════════════════════════════════════════ */

import {
    computeFingerprint,
    decodeAsn1,
    decodeOid,
    decodePem,
    formatDistinguishedName,
    formatFingerprint,
    getOidName,
    parseCertificate,
    PkiCertificateError,
    PkiEncodingError,
    PkiError,
    PkiLimitError,
} from './pkinative.js';
import { SAMPLES } from './samples.js';

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

function status(node, kind, text) {
    node.className = 'pg-status ' + kind;
    node.textContent = text;
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const iso = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');

/**
 * Accept what a person actually has in the clipboard: PEM, raw
 * hexadecimal (with or without separators), or bare base64. Anything
 * else is refused here with a sentence, rather than handed to the
 * decoder to fail with a message about DER.
 */
function toDer(text) {
    const trimmed = text.trim();
    if (trimmed === '') throw new Error('Nothing to read — paste a certificate, or pick a sample.');
    if (trimmed.includes('-----BEGIN')) {
        const blocks = decodePem(trimmed);
        if (blocks.length === 0) throw new Error('No PEM block found between the BEGIN and END lines.');
        return { der: blocks[0].bytes, note: blocks.length > 1 ? `first of ${blocks.length} PEM blocks (${blocks[0].label})` : blocks[0].label };
    }
    const compact = trimmed.replace(/[\s:,-]/g, '');
    if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0) {
        const der = new Uint8Array(compact.length / 2);
        for (let i = 0; i < der.length; i++) der[i] = parseInt(compact.slice(i * 2, i * 2 + 2), 16);
        return { der, note: 'hexadecimal' };
    }
    if (/^[A-Za-z0-9+/=\s]+$/.test(trimmed)) {
        const binary = atob(trimmed.replace(/\s/g, ''));
        const der = new Uint8Array(binary.length);
        for (let i = 0; i < der.length; i++) der[i] = binary.charCodeAt(i);
        return { der, note: 'base64' };
    }
    throw new Error('Unrecognised input. Paste PEM, hexadecimal or base64.');
}

/**
 * The shape of a refusal. Every branch names the subclass, because the
 * subclass is what tells a caller which `catch` to write, and the extra
 * fields are the ones that subclass adds.
 */
function describeFailure(error) {
    if (error instanceof PkiLimitError) {
        return `${error.code}\n\nclass:      PkiLimitError\nlimit:      ${error.limit}\nconfigured: ${String(error.configured)}\nobserved:   ${String(error.observed)}\n\n${error.message}`;
    }
    if (error instanceof PkiCertificateError) {
        return `${error.code}\n\nclass:  PkiCertificateError\npath:   ${error.path || '(whole input)'}\noffset: ${error.offset === undefined ? '(unknown)' : String(error.offset)}\n\n${error.message}`;
    }
    if (error instanceof PkiEncodingError) {
        return `${error.code}\n\nclass:  PkiEncodingError\noffset: ${error.offset === undefined ? '(unknown)' : String(error.offset)}\n\n${error.message}`;
    }
    if (error instanceof PkiError) return `${error.code}\n\nclass: PkiError\n\n${error.message}`;
    return String(error && error.message ? error.message : error);
}

// ── Shared page wiring ────────────────────────────────────────

/**
 * Wires the sample picker, the textarea and the Inspect/Clear buttons,
 * and calls `render(der, note, panel)` on every run. `run` is debounced
 * on input so typing stays responsive on a 4 000-byte certificate.
 */
function wire(render) {
    const picker = document.getElementById('sample');
    const input = document.getElementById('input');
    const panel = document.getElementById('output');
    const note = document.getElementById('status');
    const clearBtn = document.getElementById('clear');

    for (const sample of SAMPLES) picker.appendChild(Object.assign(el('option', sample.label), { value: sample.id }));

    function run() {
        clear(panel);
        const text = input.value;
        if (text.trim() === '') { note.className = 'pg-status'; note.textContent = ''; return; }
        let parsed;
        try {
            parsed = toDer(text);
        } catch (error) {
            status(note, 'error', describeFailure(error));
            return;
        }
        try {
            const summary = render(parsed.der, panel);
            status(note, 'ok', `${String(parsed.der.length)} bytes read as ${parsed.note} · ${summary}`);
        } catch (error) {
            status(note, 'error', describeFailure(error));
        }
    }

    let timer = 0;
    input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(run, 180); });
    picker.addEventListener('change', () => {
        const sample = SAMPLES.find((s) => s.id === picker.value);
        if (sample) { input.value = sample.pem; run(); }
    });
    clearBtn.addEventListener('click', () => { input.value = ''; picker.value = ''; run(); input.focus(); });

    // Start on something real rather than an empty box: a blank
    // playground makes the reader do the work of finding a certificate
    // before it has shown them anything. The fragment picks which, so a
    // link can point at the certificate it is talking about.
    const wanted = SAMPLES.find((s) => s.id === decodeURIComponent(location.hash.slice(1)));
    const first = wanted ?? SAMPLES[0];
    picker.value = first.id;
    input.value = first.pem;
    run();
    addEventListener('hashchange', () => {
        const next = SAMPLES.find((s) => s.id === decodeURIComponent(location.hash.slice(1)));
        if (next) { picker.value = next.id; input.value = next.pem; run(); }
    });
}

/** A titled section of the output panel. */
function section(panel, title) {
    const box = el('section', null, 'pg-section');
    box.appendChild(el('h2', title));
    panel.appendChild(box);
    return box;
}

/** A definition list of `[term, value]` pairs. */
function facts(parent, rows) {
    const list = el('dl', null, 'pg-facts');
    for (const [term, value] of rows) {
        if (value === undefined || value === null || value === '') continue;
        list.appendChild(el('dt', term));
        list.appendChild(el('dd', value));
    }
    parent.appendChild(list);
}

// ── The certificate inspector ─────────────────────────────────

/**
 * An OID with its registered name when there is one. This is the
 * composition the library's layering asks for: `x509` never imports the
 * name registry, so a certificate carries dotted OIDs and a caller that
 * wants names pulls `getOidName` in itself — and only then pays for the
 * registry's bytes.
 */
function named(oid) {
    const name = getOidName(oid);
    return name === undefined ? oid : `${name}  (${oid})`;
}

/** One GeneralName, as text. The six forms do not share a value field. */
function generalName(name) {
    switch (name.kind) {
        case 'rfc822Name':
        case 'dNSName':
        case 'uniformResourceIdentifier': return `${name.kind}:${name.value}`;
        case 'iPAddress': return `iPAddress:${name.address}${name.mask === undefined ? '' : '/' + name.mask}`;
        case 'directoryName': return `directoryName:${formatDistinguishedName(name.name)}`;
        case 'registeredID': return `registeredID:${name.oid}`;
        case 'otherName': return `otherName:${name.typeId}`;
        default: return `${name.kind}:(${String(name.der.length)} bytes)`;
    }
}

/** A one-line rendering of a decoded extension, without its noise. */
function extensionSummary(extension) {
    switch (extension.kind) {
        case 'basicConstraints':
            return extension.cA
                ? `CA, path length ${extension.pathLenConstraint === undefined ? 'unlimited' : String(extension.pathLenConstraint)}`
                : 'end entity';
        case 'keyUsage': return extension.usages.join(', ');
        case 'extendedKeyUsage': return extension.purposes.map(named).join(', ');
        case 'subjectAltName':
        case 'issuerAltName': return extension.names.map(generalName).join(', ');
        case 'subjectKeyIdentifier': return hex(extension.keyIdentifier);
        case 'authorityKeyIdentifier': return extension.keyIdentifier === undefined ? '(no key identifier)' : hex(extension.keyIdentifier);
        case 'certificatePolicies': return extension.policies.map((p) => named(p.policyIdentifier)).join(', ');
        case 'policyMappings': return extension.mappings.map((m) => `${m.issuerDomainPolicy} → ${m.subjectDomainPolicy}`).join(', ');
        case 'policyConstraints': return [
            extension.requireExplicitPolicy === undefined ? null : `requireExplicitPolicy ${String(extension.requireExplicitPolicy)}`,
            extension.inhibitPolicyMapping === undefined ? null : `inhibitPolicyMapping ${String(extension.inhibitPolicyMapping)}`,
        ].filter(Boolean).join(', ');
        case 'nameConstraints': return [
            extension.permittedSubtrees === undefined ? null : `permitted: ${extension.permittedSubtrees.map((s) => generalName(s.base)).join(', ')}`,
            extension.excludedSubtrees === undefined ? null : `excluded: ${extension.excludedSubtrees.map((s) => generalName(s.base)).join(', ')}`,
        ].filter(Boolean).join(' · ');
        case 'crlDistributionPoints':
        case 'freshestCRL': return extension.points.flatMap((p) => (p.fullName ?? []).map(generalName)).join(', ');
        case 'authorityInfoAccess':
        case 'subjectInfoAccess': return extension.descriptions.map((d) => `${named(d.accessMethod)} → ${generalName(d.accessLocation)}`).join(', ');
        case 'inhibitAnyPolicy': return `skipCerts ${String(extension.skipCerts)}`;
        case 'signedCertificateTimestampList': return `${String(extension.list.length)} opaque bytes (RFC 6962 §3.3)`;
        case 'ocspNoCheck': return 'present';
        case 'unknown': return `${String(extension.valueDer.length)} bytes, not decoded`;
        default: return `${String(extension.valueDer.length)} bytes`;
    }
}

function renderCertificate(der, panel) {
    const cert = parseCertificate(der);

    const identity = section(panel, 'Identity');
    facts(identity, [
        ['Subject', formatDistinguishedName(cert.subject) || '(empty — the identity is in subjectAltName)'],
        ['Issuer', formatDistinguishedName(cert.issuer)],
        ['Serial', cert.serialNumber.hex],
        ['Version', `v${String(cert.version)}`],
        ['Self-issued', hex(cert.subject.der) === hex(cert.issuer.der) ? 'yes — subject and issuer are byte-identical' : 'no'],
    ]);

    const validity = section(panel, 'Validity');
    const now = Date.now();
    const state = now < cert.validity.notBefore.epochMilliseconds ? 'not yet valid'
        : now > cert.validity.notAfter.epochMilliseconds ? 'EXPIRED'
            : `${String(Math.floor((cert.validity.notAfter.epochMilliseconds - now) / 86400000))} days remaining`;
    facts(validity, [
        ['Not before', `${iso(cert.validity.notBefore.epochMilliseconds)}  (${cert.validity.notBefore.type})`],
        ['Not after', `${iso(cert.validity.notAfter.epochMilliseconds)}  (${cert.validity.notAfter.type})`],
        ['Against your clock', state],
    ]);

    const key = section(panel, 'Public key');
    const spki = cert.subjectPublicKeyInfo;
    facts(key, [
        ['Kind', spki.kind],
        ['Algorithm', named(spki.algorithm.oid)],
        ['Size', spki.modulusBits !== undefined ? `${String(spki.modulusBits)} bits` : spki.curve ?? spki.namedCurve ?? ''],
        ['Signed with', named(cert.signatureAlgorithm.oid)],
    ]);

    const prints = section(panel, 'Fingerprints');
    facts(prints, [
        ['Certificate SHA-256', formatFingerprint(computeFingerprint(cert.der, 'SHA-256'))],
        ['Certificate SHA-1', formatFingerprint(computeFingerprint(cert.der, 'SHA-1'))],
        ['Public key SHA-256', formatFingerprint(computeFingerprint(spki.der, 'SHA-256'))],
        ['Public key, for pinning', formatFingerprint(computeFingerprint(spki.der, 'SHA-256'), { separator: '', letterCase: 'lower' })],
    ]);
    prints.appendChild(el('p', 'Pin the public key, not the certificate: a renewal normally keeps the key. What is hashed here is the whole SubjectPublicKeyInfo — algorithm and key together — because hashing the key bits alone can collide across algorithms.', 'pg-note'));

    const exts = section(panel, `Extensions (${String(cert.extensions.length)})`);
    if (cert.extensions.length === 0) exts.appendChild(el('p', 'None. Only a v3 certificate may carry extensions.', 'pg-note'));
    else {
        const table = el('table', null, 'pg-table');
        const head = el('tr');
        for (const h of ['Extension', 'OID', 'Critical', 'Value']) head.appendChild(el('th', h));
        table.appendChild(el('thead')).appendChild(head);
        const body = el('tbody');
        for (const extension of cert.extensions) {
            const row = el('tr');
            row.appendChild(el('td', extension.kind));
            row.appendChild(el('td', extension.oid));
            row.appendChild(el('td', extension.critical ? 'yes' : 'no'));
            row.appendChild(el('td', extensionSummary(extension), 'pg-wrap'));
            body.appendChild(row);
        }
        table.appendChild(body);
        exts.appendChild(Object.assign(el('div', null, 'pg-table-wrap'), {})).appendChild(table);
    }

    const diags = section(panel, `Diagnostics (${String(cert.diagnostics.length)})`);
    if (cert.diagnostics.length === 0) diags.appendChild(el('p', 'None. The certificate matched the RFC 5280 profile on every point pkinative checks.', 'pg-note'));
    else {
        const list = el('ul', null, 'pg-diagnostics');
        for (const diagnostic of cert.diagnostics) {
            const item = el('li');
            item.appendChild(el('code', diagnostic.code, `pg-sev-${diagnostic.severity}`));
            item.appendChild(el('span', ` ${diagnostic.message}`));
            item.appendChild(el('span', `${diagnostic.standard} · ${diagnostic.path}`, 'pg-diag-where'));
            list.appendChild(item);
        }
        diags.appendChild(list);
        diags.appendChild(el('p', 'A diagnostic is a conformance note, never a refusal: pkinative reports and continues. Pass strict: true to turn every one of them into a thrown PKI_STRICT_DIAGNOSTIC instead.', 'pg-note'));
    }

    return `${String(cert.extensions.length)} extensions, ${String(cert.diagnostics.length)} diagnostics`;
}

// ── The ASN.1 tree ────────────────────────────────────────────

/**
 * Universal tag numbers, named. The library's own table is internal, so
 * the playground carries its own — which is the honest position: it is
 * a consumer of the public surface like any other caller.
 */
const UNIVERSAL = {
    1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL',
    6: 'OBJECT IDENTIFIER', 10: 'ENUMERATED', 12: 'UTF8String', 16: 'SEQUENCE', 17: 'SET',
    18: 'NumericString', 19: 'PrintableString', 20: 'TeletexString', 22: 'IA5String',
    23: 'UTCTime', 24: 'GeneralizedTime', 26: 'VisibleString', 28: 'UniversalString', 30: 'BMPString',
};

function tagName(node) {
    if (node.tagClass === 'universal') return UNIVERSAL[node.tagNumber] ?? `[UNIVERSAL ${String(node.tagNumber)}]`;
    return `[${node.tagClass === 'context' ? '' : node.tagClass.toUpperCase() + ' '}${String(node.tagNumber)}]`;
}

/** What a primitive is worth showing as, without pretending to know its schema. */
function primitivePreview(node) {
    if (node.tagClass === 'universal' && node.tagNumber === 6) {
        const dotted = decodeOid(node.content);
        const name = getOidName(dotted);
        return name === undefined ? dotted : `${dotted}  (${name})`;
    }
    const printable = node.content.length > 0 && node.content.every((b) => b >= 0x20 && b < 0x7f);
    if (printable && node.tagClass === 'universal' && node.tagNumber >= 12) return new TextDecoder().decode(node.content);
    const head = hex(node.content.subarray(0, 24));
    return node.content.length > 24 ? `${head}… (${String(node.content.length)} bytes)` : head || '(empty)';
}

function renderNode(node, parent, depth) {
    const line = `${tagName(node)}  ${String(node.contentLength)} bytes  @${String(node.offset)}`;
    if (!node.constructed) {
        const row = el('div', null, 'pg-leaf');
        row.appendChild(el('span', line, 'pg-tag'));
        row.appendChild(el('span', primitivePreview(node), 'pg-value'));
        parent.appendChild(row);
        return;
    }
    const details = el('details', null, 'pg-node');
    // Open the outer three levels: deeper than that and a certificate
    // fills the screen before it has said anything.
    if (depth < 3) details.open = true;
    details.appendChild(el('summary', `${line}  ·  ${String(node.children.length)} children`));
    for (const child of node.children) renderNode(child, details, depth + 1);
    parent.appendChild(details);
}

function renderAsn1(der, panel) {
    const ber = document.getElementById('ber').checked;
    const root = decodeAsn1(der, ber ? { encodingRules: 'ber' } : undefined);
    let count = 0;
    const walk = (node) => { count++; for (const child of node.children) walk(child); };
    walk(root);
    const tree = section(panel, `Tree (${String(count)} values)`);
    renderNode(root, tree, 0);
    return `${String(count)} values, depth-first`;
}

// ── Dispatch ──────────────────────────────────────────────────

const which = document.body.dataset.playground;
if (which === 'certificate') wire(renderCertificate);
else if (which === 'asn1') {
    const ber = document.getElementById('ber');
    wire(renderAsn1);
    // Re-run on the strictness switch: the whole point of the control is
    // to watch the same bytes be accepted and refused.
    ber.addEventListener('change', () => document.getElementById('input').dispatchEvent(new Event('input')));
}
