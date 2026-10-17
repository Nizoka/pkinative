/* ═══════════════════════════════════════════════════════════════
   pkinative.dev — CLI command builder

   Assembles a pkinative-cli command line. Nothing runs: the CLI is a
   Node.js process with a filesystem and exit codes, and this page
   only writes the line a reader will paste into one.

   ── Where the form comes from ────────────────────────────────
   The commands, subcommands, flags, aliases, value shapes,
   repeatability and operand rules are read at runtime from
   ../data/cli-surface.json, the projection of `pkinative schema
   manifest` (scripts/build-cli-surface.ts). There is no hand copy of
   the surface here, so the page cannot drift from the published CLI.

   ── Where the checks come from ───────────────────────────────
   Every check below that says "exit 2" mirrors a usageError() call in
   the pkinative-cli 1.0.0 sources, and names it (file:line) on the
   page. The handful of constant lists (key types, extension kinds,
   cert encode structures, schema subjects, shells) are the CLI's own
   arrays, cited where they are declared. Refusals that depend on the
   bytes of a file — an RSA key without --rsa-scheme, an encrypted key
   without a password — cannot be decided here, and are shown as notes.

   ── Passwords ────────────────────────────────────────────────
   The CLI refuses --password, --pass, --passin and --key-password
   (src/utils/secrets.ts:24). This page has no way to emit them and no
   field for a password: the three sources offered are the CLI's own,
   --password-file, --password-stdin and PKINATIVE_PASSWORD.

   ── One rule, without exception ──────────────────────────────
   Everything typed into the form reaches the page through
   textContent; innerHTML is never used.
   ═══════════════════════════════════════════════════════════════ */

const SURFACE_URL = '../data/cli-surface.json';

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

/** A sentence whose `backticked` spans become <code>, without any HTML parsing. */
function rich(tag, text, className) {
    const node = el(tag, null, className);
    String(text).split('`').forEach((piece, i) => {
        if (piece === '') return;
        node.appendChild(i % 2 === 1 ? el('code', piece) : document.createTextNode(piece));
    });
    return node;
}

// The footer slot every playground fills with the engine build it ran.
// This page runs none, and says so.
const engineSlot = $('engine-source');
if (engineSlot) engineSlot.textContent = 'none — this page runs nothing';

const statusLine = $('status');
function status(kind, text) {
    statusLine.className = kind ? `pg-status ${kind}` : 'pg-status';
    statusLine.textContent = text;
}

// ── The surface ───────────────────────────────────────────────

let surface;
try {
    const response = await fetch(SURFACE_URL);
    if (!response.ok) throw new Error(`HTTP ${String(response.status)}`);
    surface = await response.json();
} catch (error) {
    status('error', `Could not load ${SURFACE_URL} (${error && error.message ? error.message : String(error)}). The builder reads the CLI's command surface from it and has nothing to offer without it — reload the page.`);
    throw error;
}

/** One entry per command line the CLI accepts: `chain verify`, `doctor`, … */
const INVOCATIONS = [];
for (const command of surface.commands) {
    const subs = Array.isArray(command.subcommands) ? command.subcommands : [];
    if (subs.length > 0) {
        for (const sub of subs) {
            INVOCATIONS.push({ key: `${command.name} ${sub.name}`, command: command.name, sub: sub.name, group: command.group, summary: sub.summary, flags: sub.flags ?? [], operands: sub.operands ?? { max: 0 } });
        }
    } else {
        INVOCATIONS.push({ key: command.name, command: command.name, sub: null, group: command.group, summary: command.summary, flags: command.flags ?? [], operands: command.operands ?? { max: 0 } });
    }
}
const BY_KEY = new Map(INVOCATIONS.map((i) => [i.key, i]));
const GLOBAL_FLAGS = surface.globalFlags ?? [];

// ── The CLI's own constant lists (cited where they are declared) ──

/** src/utils/signer.ts:38 */
const KEY_TYPES = ['ec-p256', 'ec-p384', 'ec-p521', 'ed25519', 'ed448', 'rsa', 'rsa-pss'];
/** src/commands/cert.ts:63 */
const EXTENSION_KINDS = ['basicConstraints', 'keyUsage', 'extendedKeyUsage', 'subjectAltName', 'issuerAltName', 'subjectKeyIdentifier',
    'authorityKeyIdentifier', 'nameConstraints', 'certificatePolicies', 'policyMappings', 'policyConstraints',
    'inhibitAnyPolicy', 'authorityInfoAccess', 'subjectInfoAccess', 'crlDistributionPoints', 'freshestCRL',
    'signedCertificateTimestampList', 'ocspNoCheck', 'subjectDirectoryAttributes'];
/** src/commands/registry.ts:91 */
const CERT_ENCODE_STRUCTURES = ['name', 'name-attribute', 'validity', 'spki', 'algorithm-identifier', 'attribute', 'extension', 'extensions',
    'basic-constraints', 'key-usage', 'extended-key-usage', 'subject-alt-name', 'subject-key-identifier',
    'authority-key-identifier', 'signature-algorithm'];
/** src/commands/schema.ts:312 */
const SCHEMA_SUBJECTS = ['manifest', 'errors', 'limits', 'status', 'error', 'asn1-spec', 'cert-spec', 'csr-spec', 'config', 'cert-encode-spec', 'report', 'summary'];
/** src/commands/completion.ts:227 (pwsh is accepted for powershell) */
const SHELLS = ['bash', 'zsh', 'fish', 'powershell', 'pwsh'];
/** src/commands/asn1.ts:35 */
const READ_TYPES = ['boolean', 'integer', 'small-integer', 'enumerated', 'null', 'bit-string', 'octet-string', 'oid', 'relative-oid', 'string', 'time'];
/** src/utils/x509-spec.ts:103 — KEY_PURPOSES names, `any`, or a dotted OID */
const PURPOSES = ['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping', 'ocspSigning', 'any'];

/** Suggestions for value flags whose manifest shape is a placeholder. */
const SUGGESTIONS = { 'key-type': KEY_TYPES, extension: EXTENSION_KINDS, read: READ_TYPES, purpose: PURPOSES, at: ['now'] };

/** The two password flags the form replaces with its password-source control. */
const PASSWORD_FLAGS = ['password-file', 'password-stdin'];

/** Artefact writers with no default PEM label (src/utils/output.ts:64). */
const NO_DEFAULT_LABEL = new Set(['asn1 encode', 'cert encode', 'oid encode', 'ocsp request', 'ocsp cert-id', 'tsp request']);
/** Artefact writers whose default encoding is raw DER (emitArtifact … defaultEncoding: 'der'). */
const DER_BY_DEFAULT = new Set(['asn1 encode', 'cms sign', 'cms add-attribute', 'cms add-timestamp', 'ocsp request', 'tsp request']);
/** Invocations that load a signing key (src/utils/signer.ts loadSigner). */
const SIGNING = new Set(['cert create', 'csr create', 'cms sign']);

/** What each invocation's operands are, where "input file" would not say it. */
const OPERAND_LABELS = {
    'oid name': 'Dotted OIDs (one per line)',
    'oid encode': 'Dotted OID',
    'oid validate': 'Dotted OIDs (one per line)',
    'oid decode': 'OID bytes in hexadecimal',
    'asn1 encode': 'Spec file (JSON)',
    'cert encode': 'Structure',
    'cert match-name': 'Presented name, then reference name (one per line)',
    'chain validate': 'Path certificates, leaf first (one per line)',
    'ocsp request': 'Certificate file',
    'ocsp cert-id': 'Certificate file',
    'tsp verify': 'Time-stamp response file',
    explain: 'Code (PKI_…, PKI_REASON_…, PKI_DIAG_… or E_…)',
    schema: 'Subject, then command and subcommand for report or summary (one per line)',
    completion: 'Shell',
};
const OPERAND_SUGGESTIONS = { 'cert encode': CERT_ENCODE_STRUCTURES, completion: SHELLS, schema: SCHEMA_SUBJECTS };

/**
 * The literal choices of a `a|b|c` value shape, and whether the shape is
 * closed. The placeholder words are the CLI's own (completion.ts:43):
 * `hex|random` offers `random`, `instant|now|none` offers `now` and `none`.
 */
function choicesOf(value) {
    if (!value || !value.includes('|')) return null;
    const parts = value.split('|');
    const placeholder = (v) => ['n', 'name', 'oid', 'instant'].includes(v) || (v === 'hex' && value.includes('random'));
    const literal = parts.filter((v) => !placeholder(v));
    return { literal, closed: literal.length === parts.length };
}

// ── State ─────────────────────────────────────────────────────

const state = {
    key: 'cert inspect',
    perInvocation: new Map(),
    globals: {},
    password: { source: '', file: '' },
};

function current() {
    if (!state.perInvocation.has(state.key)) state.perInvocation.set(state.key, { flags: {}, operands: '' });
    return state.perInvocation.get(state.key);
}

// ── Form ──────────────────────────────────────────────────────

let fieldSeq = 0;

/** One flag as a labelled control, bound to `bag[flag.name]`. */
function field(flag, scope, bag) {
    const id = `${scope}-${flag.name}`;
    const wrap = el('div', null, 'cli-field');
    const label = el('label');
    label.htmlFor = id;
    label.appendChild(el('code', `--${flag.name}`));
    if (flag.alias) {
        label.appendChild(document.createTextNode(', '));
        label.appendChild(el('code', `-${flag.alias}`));
    }
    if (flag.value) label.appendChild(el('span', ` <${flag.value}>`, 'cli-value'));
    if (flag.repeatable) label.appendChild(el('span', ' · repeatable, one per line', 'cli-value'));

    if (!flag.value) {
        wrap.className = 'cli-field cli-check';
        const box = document.createElement('input');
        box.type = 'checkbox';
        box.id = id;
        box.checked = bag[flag.name] === true;
        box.addEventListener('change', () => {
            if (box.checked) bag[flag.name] = true; else delete bag[flag.name];
            update();
        });
        wrap.appendChild(box);
        wrap.appendChild(label);
        return wrap;
    }

    const choices = choicesOf(flag.value);
    let control;
    if (flag.repeatable) {
        control = document.createElement('textarea');
        control.rows = 2;
        control.className = 'pg-picker cli-lines';
        control.value = Array.isArray(bag[flag.name]) ? bag[flag.name].join('\n') : '';
        control.addEventListener('input', () => {
            const lines = control.value.split('\n').map((s) => s.trim()).filter(Boolean);
            if (lines.length > 0) bag[flag.name] = lines; else delete bag[flag.name];
            update();
        });
    } else if (choices && choices.closed) {
        control = document.createElement('select');
        control.className = 'pg-picker';
        control.appendChild(Object.assign(el('option', '(not given)'), { value: '' }));
        for (const choice of choices.literal) control.appendChild(Object.assign(el('option', choice), { value: choice }));
        control.value = typeof bag[flag.name] === 'string' ? bag[flag.name] : '';
        control.addEventListener('change', () => {
            if (control.value) bag[flag.name] = control.value; else delete bag[flag.name];
            update();
        });
    } else {
        control = document.createElement('input');
        control.type = 'text';
        control.className = 'pg-picker';
        control.placeholder = flag.value;
        control.value = typeof bag[flag.name] === 'string' ? bag[flag.name] : '';
        const suggestions = (choices ? choices.literal : []).concat(SUGGESTIONS[flag.name] ?? []);
        if (suggestions.length > 0) {
            const list = el('datalist');
            list.id = `${id}-choices-${String(++fieldSeq)}`;
            for (const s of new Set(suggestions)) list.appendChild(Object.assign(el('option'), { value: s }));
            wrap.appendChild(list);
            control.setAttribute('list', list.id);
        }
        control.addEventListener('input', () => {
            const v = control.value.trim();
            if (v) bag[flag.name] = v; else delete bag[flag.name];
            update();
        });
    }
    control.id = id;
    control.spellcheck = false;
    control.autocomplete = 'off';
    wrap.insertBefore(label, wrap.firstChild);
    wrap.appendChild(control);
    return wrap;
}

function renderCommandPickers() {
    const commandSel = $('command');
    clear(commandSel);
    const groups = new Map();
    for (const command of surface.commands) {
        if (!groups.has(command.group)) {
            const group = el('optgroup');
            group.label = command.group;
            groups.set(command.group, group);
            commandSel.appendChild(group);
        }
        groups.get(command.group).appendChild(Object.assign(el('option', `${command.name} — ${command.summary}`), { value: command.name }));
    }
}

function renderSubPicker() {
    const inv = BY_KEY.get(state.key);
    $('command').value = inv.command;
    const subSel = $('sub');
    clear(subSel);
    const command = surface.commands.find((c) => c.name === inv.command);
    const subs = Array.isArray(command.subcommands) ? command.subcommands : [];
    $('sub-wrap').hidden = subs.length === 0;
    for (const sub of subs) subSel.appendChild(Object.assign(el('option', `${sub.name} — ${sub.summary}`), { value: sub.name }));
    if (inv.sub) subSel.value = inv.sub;
}

function renderOperands() {
    const inv = BY_KEY.get(state.key);
    const wrap = $('operands-wrap');
    clear(wrap);
    const max = inv.operands.max;
    wrap.hidden = max === 0;
    if (max === 0) return;
    const bag = current();
    const label = el('label', OPERAND_LABELS[inv.key] ?? (max === 1 ? 'Input file (or - for stdin)' : 'Arguments (one per line)'));
    label.htmlFor = 'operands';
    wrap.appendChild(label);
    let control;
    if (max === 1) {
        control = document.createElement('input');
        control.type = 'text';
        const suggestions = OPERAND_SUGGESTIONS[inv.key];
        if (suggestions) {
            const list = el('datalist');
            list.id = 'operands-choices';
            for (const s of suggestions) list.appendChild(Object.assign(el('option'), { value: s }));
            wrap.appendChild(list);
            control.setAttribute('list', list.id);
        }
    } else {
        control = document.createElement('textarea');
        control.rows = max === null ? 3 : max;
        control.className = 'cli-lines';
    }
    control.id = 'operands';
    control.className = `pg-picker${control.tagName === 'TEXTAREA' ? ' cli-lines' : ''}`;
    control.spellcheck = false;
    control.autocomplete = 'off';
    control.value = bag.operands;
    control.addEventListener('input', () => { bag.operands = control.value; update(); });
    wrap.appendChild(control);
    const stands = inv.operands.for && inv.operands.for.length > 0 ? ` It stands for ${inv.operands.for.map((f) => `\`--${f}\``).join(' or ')}: give one or the other.` : '';
    const how = max === null ? 'Any number of arguments.' : `At most ${String(max)} argument${max === 1 ? '' : 's'}.`;
    const extra = OPERAND_SUGGESTIONS[inv.key] ? ` One of: ${OPERAND_SUGGESTIONS[inv.key].join(', ')}.` : '';
    wrap.appendChild(rich('p', `${how}${stands}${extra}`, 'pg-note'));
}

function renderFlags() {
    const inv = BY_KEY.get(state.key);
    const box = $('flags');
    clear(box);
    const bag = current().flags;
    const own = inv.flags.filter((f) => !PASSWORD_FLAGS.includes(f.name));
    for (const flag of own) box.appendChild(field(flag, 'f', bag));
    if (own.length === 0) box.appendChild(el('p', 'This invocation has no flags of its own; the global options below still apply.', 'pg-note'));
    const reads = inv.flags.some((f) => f.name === 'password-file');
    $('password-wrap').hidden = !reads;
    $('password-note').hidden = !reads;
    $('password-source').value = state.password.source;
    $('password-file').value = state.password.file;
    $('password-file-wrap').hidden = state.password.source !== 'file';
    $('summary').textContent = `pkinative ${inv.key} — ${inv.summary}. Group: ${inv.group}.`;
}

function renderGlobals() {
    const box = $('globals');
    clear(box);
    for (const flag of GLOBAL_FLAGS) box.appendChild(field(flag, 'g', state.globals));
}

function renderAll() {
    renderSubPicker();
    renderOperands();
    renderFlags();
    renderGlobals();
    update();
}

// ── The command line ──────────────────────────────────────────

/** The operands, one per non-empty line. */
function operandList() {
    return current().operands.split('\n').map((s) => s.trim()).filter(Boolean);
}

/** A token the CLI would read as a flag rather than a value (src/utils/args.ts:53). */
const looksLikeFlag = (v) => v.startsWith('-') && v !== '-' && !/^-\d/.test(v);

/**
 * The line as groups of raw words — `[flag, value]` pairs kept together so
 * a long line breaks between options, never inside one.
 */
function buildGroups() {
    const inv = BY_KEY.get(state.key);
    const flags = current().flags;
    const groups = [[...$('invoke').value.split(' '), inv.command, ...(inv.sub ? [inv.sub] : [])]];
    const operands = operandList();
    const protect = operands.some(looksLikeFlag);
    if (!protect) for (const o of operands) groups.push([o]);
    const emit = (flag, value) => {
        if (value === true) groups.push([`--${flag.name}`]);
        else if (Array.isArray(value)) for (const item of value) groups.push(looksLikeFlag(item) ? [`--${flag.name}=${item}`] : [`--${flag.name}`, item]);
        else if (typeof value === 'string') groups.push(looksLikeFlag(value) ? [`--${flag.name}=${value}`] : [`--${flag.name}`, value]);
    };
    for (const flag of inv.flags) if (!PASSWORD_FLAGS.includes(flag.name)) emit(flag, flags[flag.name]);
    if (passwordApplies()) {
        if (state.password.source === 'file') groups.push(['--password-file', state.password.file || 'password.txt']);
        if (state.password.source === 'stdin') groups.push(['--password-stdin']);
    }
    for (const flag of GLOBAL_FLAGS) emit(flag, state.globals[flag.name]);
    // `--` ends the flags (args.ts:57), so an operand that begins with a
    // dash goes after it, and is then never read as a flag.
    if (protect) groups.push(['--', ...operands]);
    return groups;
}

const passwordApplies = () => BY_KEY.get(state.key).flags.some((f) => f.name === 'password-file');

function quotePosix(word) {
    if (word === '') return "''";
    if (/^[A-Za-z0-9_\/.,:=+%@^-]+$/.test(word)) return word;
    if (/^~\/[A-Za-z0-9_\/.,:=+%@^-]*$/.test(word)) return word;
    return `'${word.replace(/'/g, `'\\''`)}'`;
}

function quotePowerShell(word) {
    if (word === '') return "''";
    // No comma (array), no @ (splat), no $ or backtick: those are syntax there.
    if (/^[A-Za-z0-9_\/.:=+\\-]+$/.test(word) && !word.startsWith('@')) return word;
    return `'${word.replace(/['‘’‚‛]/g, (q) => q + q)}'`;
}

function renderLine() {
    const shell = $('shell').value;
    const quote = shell === 'pwsh' ? quotePowerShell : quotePosix;
    const cont = shell === 'pwsh' ? ' `' : ' \\';
    const groups = buildGroups();
    const pieces = groups.map((g, i) => (i === 0 ? g.join(' ') : g.map(quote).join(' ')));
    const pipe = $('pipe').value.trim().replace(/\|\s*$/, '').trim();
    const head = pipe ? `${pipe} | ` : '';
    let line = head + pieces.join(' ');
    if (line.length > 88) {
        // Break before each option; an argument stays on the line before it.
        line = head + pieces[0];
        for (let i = 1; i < pieces.length; i++) line += groups[i][0].startsWith('-') ? `${cont}\n  ${pieces[i]}` : ` ${pieces[i]}`;
    }
    const lines = [];
    if (passwordApplies() && state.password.source === 'env') {
        lines.push(shell === 'pwsh'
            ? '# $env:PKINATIVE_PASSWORD must already be set in this session, from your secret store.'
            : '# PKINATIVE_PASSWORD must already be exported in this shell, from your secret store.');
    }
    lines.push(line);
    $('output').textContent = lines.join('\n');
}

// ── Checks ────────────────────────────────────────────────────

const ISO = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(\.\d{1,9})?)?(Z|([+-])(\d{2}):?(\d{2}))?)?$/i;

/** src/utils/time.ts:34 parseInstant — `now`, epoch milliseconds, or an ISO 8601 date that exists. */
function validInstant(raw) {
    if (raw === 'now') return true;
    if (/^\d+$/.test(raw)) return Number.isSafeInteger(Number(raw));
    const m = ISO.exec(raw);
    if (m === null) return false;
    const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const days = month === 2 ? (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28) : [4, 6, 9, 11].includes(month) ? 30 : 31;
    if (month < 1 || month > 12 || day < 1 || day > days) return false;
    if (m[4] !== undefined && (Number(m[4]) > 23 || Number(m[5]) > 59 || Number(m[6] ?? 0) > 59)) return false;
    return true;
}

/** src/utils/wire.ts:24 fromHex — optional 0x, spaces and colons ignored, an even number of digits. */
function hexBytes(raw) {
    const clean = raw.trim().replace(/^0x/i, '').replace(/[\s:]/g, '');
    if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(clean)) return -1;
    return clean.length / 2;
}

const SRC = (where) => `pkinative-cli src/${where}`;

function check() {
    const inv = BY_KEY.get(state.key);
    const key = inv.key;
    const f = current().flags;
    const g = state.globals;
    const ops = operandList();
    const out = [];
    const refuse = (text, where) => out.push({ level: 'refused', text, where: SRC(where) });
    const note = (text, where) => out.push({ level: 'note', text, where: where ? SRC(where) : '' });
    const has = (name) => f[name] !== undefined;
    const pw = passwordApplies() ? state.password.source : '';

    // ── Every command ──
    const takes = inv.operands.max;
    if (takes !== null && ops.length > takes) {
        refuse(`\`${key}\` takes ${takes === 0 ? 'no arguments' : `at most ${String(takes)} argument${takes === 1 ? '' : 's'}`}, got ${String(ops.length)}.`, 'utils/args.ts:241');
    }
    const standsFor = (inv.operands.for ?? []).find((name) => has(name));
    if (ops.length > 0 && standsFor) refuse(`\`${key}\` was given \`--${standsFor}\` and an argument; give one or the other.`, 'utils/args.ts:245');
    for (const o of ops) {
        if (/^--?(password|pass|passin|key-password)(=|$)/.test(o)) refuse('A password on the command line is refused before anything runs: it is visible to every process on the machine. Use the password source above.', 'utils/secrets.ts:24');
    }

    for (const flag of GLOBAL_FLAGS.filter((x) => x.name.startsWith('max-'))) {
        const raw = g[flag.name];
        if (typeof raw !== 'string') continue;
        const bytes = flag.name.endsWith('-bytes') || flag.name === 'max-content-size';
        const m = /^(\d+)\s*([a-z]*)$/i.exec(raw);
        const unit = m ? m[2].toLowerCase() : '';
        const ok = m !== null && (bytes ? ['', 'b', 'k', 'kb', 'kib', 'm', 'mb', 'mib', 'g', 'gb', 'gib'].includes(unit) : unit === '');
        if (!ok) refuse(`\`--${flag.name}\` expects ${bytes ? 'a byte count such as 65536, 64k, 16MiB or 1g' : 'a positive integer'}, got \`${raw}\`.`, 'utils/limits.ts:61');
        else if (/^0+$/.test(m[1]) || !Number.isSafeInteger(Number(m[1]))) refuse(`\`--${flag.name}\` must be a positive integer no greater than ${String(Number.MAX_SAFE_INTEGER)}: there is no "unbounded".`, 'utils/limits.ts:65');
    }
    for (const name of ['at', 'signing-time']) {
        const raw = f[name];
        if (typeof raw !== 'string') continue;
        if (name === 'signing-time' && raw === 'none') continue;
        if (!validInstant(raw)) refuse(`\`--${name}\` expects epoch milliseconds, \`now\` or an ISO 8601 date-time (UTC unless zoned) of a date that exists, got \`${raw}\`.`, 'utils/time.ts:44');
    }
    for (const [name, min, max] of [['index', 0, Number.MAX_SAFE_INTEGER], ['signer-index', 0, Number.MAX_SAFE_INTEGER], ['stale-tolerance', 0, Number.MAX_SAFE_INTEGER], ['future-tolerance', 0, Number.MAX_SAFE_INTEGER], ['salt-length', 0, 512], ['shake256', 1, 1048576]]) {
        const raw = f[name];
        if (typeof raw !== 'string') continue;
        if (!/^\d+$/.test(raw)) refuse(`\`--${name}\` expects a non-negative integer, got \`${raw}\`.`, 'utils/args.ts:192');
        else if (Number(raw) < min || Number(raw) > max) refuse(`\`--${name}\` must be between ${String(min)} and ${String(max)}, got ${raw}.`, 'utils/args.ts:194');
    }
    if (f.encoding === 'pem' && !has('label') && NO_DEFAULT_LABEL.has(key)) {
        refuse('`--encoding pem` needs a PEM label: pass `--label <LABEL>`, or use `--encoding der|hex`.', 'utils/output.ts:64');
    }
    const writesDer = (DER_BY_DEFAULT.has(key) && (f.encoding ?? 'der') === 'der')
        || (key === 'pem decode' && has('index') && (f.encoding ?? 'der') === 'der')
        || (key === 'asn1 decode' && has('reencode') && (f.encoding ?? 'der') === 'der')
        || (f.encoding === 'der');
    if (writesDer && (!has('output') || f.output === '-')) {
        note('This writes raw DER to stdout. The CLI refuses that when stdout is an interactive terminal (exit 2): redirect it, pass `--output <file>`, or choose `--encoding pem|hex`.', 'utils/output.ts:78');
    }
    if (g.config && g['no-config']) note('`--no-config` wins: the file `--config` names is never read. The CLI does not refuse the pair.', '');
    if (g.config) note('`--config` naming a file that does not exist is refused (exit 2) — only the real run can see your filesystem.', 'utils/config.ts:110');

    // ── Inputs read from stdin ──
    const forInput = (inv.operands.for ?? []).includes('input');
    const inputAbsent = forInput && ops.length === 0 && !has('input') && key !== 'oid decode';
    const pipe = $('pipe').value.trim();
    if (inputAbsent && !pipe) note('No input is named, so the CLI reads stdin. On an interactive terminal it refuses rather than hang (exit 2): name a file, or fill in "Pipe stdin from".', 'utils/io.ts:65');
    const stdinUsed = inputAbsent || ops.includes('-') || Object.entries(f).some(([name, v]) => !['output', 'certs-out'].includes(name) && (v === '-' || (Array.isArray(v) && v.includes('-'))));

    // ── Passwords ──
    if (pw === 'stdin' && stdinUsed) refuse('The password cannot come from stdin when an input is read from stdin too; use `--password-file <file>` or `PKINATIVE_PASSWORD`.', 'utils/secrets.ts:68');
    if (pw === 'file' && state.password.file === '-' && stdinUsed) refuse('`--password-file -` reads the password from stdin, which an input already reads; use a file or `PKINATIVE_PASSWORD`.', 'utils/secrets.ts:68');
    if (pw === 'stdin' && !pipe) note('`--password-stdin` reads the first line of stdin: fill in "Pipe stdin from" with the command that prints it (a secret manager, not `echo`).', '');
    if (pw === 'file' && !state.password.file) note('Name the password file; the line shows a placeholder until you do.', '');
    if (pw === 'env') note('Giving `PKINATIVE_PASSWORD` together with `--password-file` or `--password-stdin` is refused (exit 2): if the variable is set in your shell, it is the only source to use.', 'utils/secrets.ts:65');
    if (passwordApplies() && pw !== '' && pw !== 'env') note('If `PKINATIVE_PASSWORD` is also set in your environment, the CLI refuses the two sources together (exit 2).', 'utils/secrets.ts:65');

    // ── Per command ──
    const one = (a, b) => has(a) !== has(b);
    switch (key) {
        case 'pem decode':
            if (has('output') && !has('index')) refuse('`pem decode --output` needs `--index <n>`: without it, the command lists the blocks on stdout.', 'commands/pem.ts:26');
            break;
        case 'pem encode':
            if (!has('label')) refuse('`pem encode` needs `--label <LABEL>` (e.g. CERTIFICATE, PRIVATE KEY).', 'commands/pem.ts:47');
            break;
        case 'oid name': case 'oid validate': case 'oid encode':
            if (ops.length === 0) refuse(`\`${key}\` needs at least one dotted OID argument.`, 'commands/oid.ts:24');
            if (key === 'oid encode' && ops.length > 1) refuse('`oid encode` takes exactly one OID.', 'commands/oid.ts:38');
            if (key === 'oid encode' && has('relative') && !has('tlv')) refuse('`--relative` needs `--tlv`: pkinative encodes a RELATIVE-OID as a whole TLV only.', 'commands/oid.ts:41');
            break;
        case 'oid decode':
            if ((ops.length > 0) === has('input')) refuse('`oid decode` takes a hex argument or `--input <file>` — exactly one of the two.', 'commands/oid.ts:51');
            if (ops.length === 1 && hexBytes(ops[0]) < 0) refuse(`\`${ops[0]}\` is not hexadecimal.`, 'commands/oid.ts:55');
            if (has('relative') && !has('tlv')) refuse('`--relative` needs `--tlv`: pkinative decodes a RELATIVE-OID from its TLV only.', 'commands/oid.ts:62');
            break;
        case 'fingerprint':
            if (has('key-id') && has('shake256')) refuse('`--key-id` and `--shake256` are separate modes; pass one.', 'commands/fingerprint.ts:24');
            if (has('webcrypto') && (has('key-id') || has('shake256'))) refuse('`--webcrypto` applies to the fingerprint mode only.', 'commands/fingerprint.ts:25');
            break;
        case 'asn1 decode':
            if (has('sequence') && (has('path') || has('read') || has('reencode'))) refuse('`--sequence` lists every top-level object; `--path`, `--read` and `--reencode` work on one tree.', 'commands/asn1.ts:156');
            if (has('read') && has('reencode')) refuse('`--read` and `--reencode` are separate modes; pass one.', 'commands/asn1.ts:165');
            if (typeof f.path === 'string' && !f.path.split('.').every((s) => /^\d+$/.test(s))) refuse(`\`--path\` expects dot-separated child indices such as 0.2.1, got \`${f.path}\`.`, 'commands/asn1.ts:112');
            if (has('read') && !READ_TYPES.includes(f.read)) refuse(`\`--read\` expects one of ${READ_TYPES.join('|')}.`, 'utils/args.ts:185');
            if (f.encoding === 'pem' && !has('label')) note('`--encoding pem` takes its label from the input when the input was PEM; for a DER input, add `--label`.', 'utils/output.ts:64');
            break;
        case 'asn1 encode':
            if (!has('spec') && ops.length === 0) refuse('`asn1 encode` needs `--spec <file.json>` (or "-" for stdin).', 'commands/asn1.ts:185');
            break;
        case 'cert inspect':
            if (has('extension') && !EXTENSION_KINDS.includes(f.extension)) refuse(`\`--extension\` expects one of the ${String(EXTENSION_KINDS.length)} decoded kinds: ${EXTENSION_KINDS.join(', ')}.`, 'commands/cert.ts:91');
            if (has('extension') && has('raw-extensions')) refuse('`--extension` reads a decoded extension; drop `--raw-extensions`.', 'commands/cert.ts:92');
            break;
        case 'cert create':
            if (!has('spec')) refuse('`cert create` needs `--spec <file.json>`.', 'commands/cert.ts:185');
            if (!has('public-key') && has('issuer')) refuse('The subject public key is needed: pass `--public-key <cert|csr|public key>` (it is derived from `--key` only for a self-signed certificate from an unencrypted key).', 'commands/cert.ts:201');
            else if (!has('public-key')) note('Without `--public-key`, the subject key is derived from the signing key — which works only for a self-signed certificate from an unencrypted key.', 'commands/cert.ts:201');
            break;
        case 'cert encode': {
            const structure = ops[0];
            if (structure === undefined || !CERT_ENCODE_STRUCTURES.includes(structure)) refuse(`\`cert encode\` takes one structure: ${CERT_ENCODE_STRUCTURES.join(', ')}.`, 'commands/cert.ts:240');
            else if (structure === 'signature-algorithm' && has('spec')) refuse('`cert encode signature-algorithm` takes no `--spec`: the signer flags (`--key` or `--p12`, `--rsa-scheme`, `--hash`) decide it.', 'commands/cert.ts:244');
            else if (structure !== 'signature-algorithm' && !has('spec')) refuse(`\`cert encode ${structure}\` needs \`--spec <file.json>\` (or "-").`, 'commands/cert.ts:250');
            break;
        }
        case 'cert decode-extension':
            if (!has('oid')) refuse('`cert decode-extension` needs `--oid <oid>`.', 'commands/cert.ts:111');
            if (!one('value', 'input')) refuse('Give the extnValue content as `--value <hex>` or `--input <file>` — exactly one.', 'commands/cert.ts:114');
            if (has('value') && hexBytes(f.value) < 0) refuse(`\`--value\` \`${f.value}\` is not hexadecimal.`, 'commands/cert.ts:118');
            break;
        case 'cert check-name':
            if (!one('host', 'ip')) refuse('Give the reference identity as `--host <dns-name>` or `--ip <address>` — exactly one.', 'commands/cert.ts:145');
            break;
        case 'cert match-name':
            if (ops.length !== 2) refuse('`cert match-name` takes `<presented> <reference>`: two arguments.', 'commands/cert.ts:164');
            break;
        case 'cert check-purpose':
            if (!has('purpose')) refuse('`cert check-purpose` needs `--purpose <name|oid|any>`.', 'commands/cert.ts:173');
            break;
        case 'csr create':
            if (!has('spec')) refuse('`csr create` needs `--spec <file.json>`.', 'commands/csr.ts:50');
            if (!has('public-key')) note('Without `--public-key`, the public key is derived from `--key` — which works only for an unencrypted key.', 'commands/csr.ts:62');
            break;
        case 'chain verify': case 'chain build': case 'chain validate':
            if (!has('trust')) refuse(`\`${key}\` needs \`--trust <file>\` (repeatable): the trust anchors.`, 'commands/chain.ts:42');
            if (key === 'chain verify' && has('host') && has('ip')) refuse('Give `--host` or `--ip`, not both.', 'commands/chain.ts:64');
            if (key === 'chain validate' && !has('path') && ops.length === 0) refuse('`chain validate` needs the path, leaf first: `--path <file>...` or positional files.', 'commands/chain.ts:162');
            if (has('ocsp-nonce')) {
                const n = hexBytes(f['ocsp-nonce']);
                if (n < 0) refuse(`\`--ocsp-nonce\` expects hexadecimal, got \`${f['ocsp-nonce']}\`.`, 'commands/ocsp.ts:55');
                else if (n < 1 || n > 32) refuse(`\`--ocsp-nonce\` takes 1 to 32 octets (RFC 8954 §2.1), got ${String(n)}.`, 'commands/ocsp.ts:56');
            }
            if (key === 'chain verify' && !has('host') && !has('ip')) note('No `--host` or `--ip`: the chain is judged without a name. For a TLS peer, that accepts a certificate issued for somebody else.', '');
            if (!has('at') && key !== 'chain build') note('No `--at`: the verdict is taken at the moment the line runs. Pin it for a reproducible result.', '');
            break;
        case 'crl find':
            if (!one('serial', 'cert')) refuse('`crl find` takes `--serial <hex>` or `--cert <file>` — exactly one.', 'commands/crl.ts:78');
            if (has('serial') && hexBytes(f.serial) < 1) refuse(`\`--serial\` \`${f.serial}\` is not a hexadecimal serial number.`, 'commands/crl.ts:87');
            break;
        case 'crl verify-signature':
            if (!has('issuer')) refuse('`crl verify-signature` needs `--issuer <cert>`.', 'commands/crl.ts:104');
            break;
        case 'crl check':
            if (!has('cert')) refuse('`crl check` needs `--cert <file>`, the certificate to check.', 'commands/crl.ts:112');
            break;
        case 'ocsp request': case 'ocsp cert-id':
            if (!has('issuer')) refuse(`\`${key}\` needs \`--issuer <cert>\`: the CA that issued the certificate.`, 'commands/ocsp.ts:44');
            if (key === 'ocsp request' && has('nonce') && f.nonce !== 'random') {
                const n = hexBytes(f.nonce);
                if (n < 0) refuse(`\`--nonce\` expects hexadecimal or "random", got \`${f.nonce}\`.`, 'commands/ocsp.ts:55');
                else if (n < 1 || n > 32) refuse(`\`--nonce\` takes 1 to 32 octets (RFC 8954 §2.1), got ${String(n)}.`, 'commands/ocsp.ts:56');
            }
            break;
        case 'ocsp check':
            if (!has('cert') || !has('issuer')) refuse('`ocsp check` needs `--cert <file>` and `--issuer <file>`.', 'commands/ocsp.ts:157');
            if (has('nonce')) {
                const n = hexBytes(f.nonce);
                if (n < 0) refuse(`\`--nonce\` expects hexadecimal, got \`${f.nonce}\`.`, 'commands/ocsp.ts:55');
                else if (n < 1 || n > 32) refuse(`\`--nonce\` takes 1 to 32 octets (RFC 8954 §2.1), got ${String(n)}.`, 'commands/ocsp.ts:56');
            }
            break;
        case 'cms sign':
            if (has('content') && has('content-digest')) refuse('Give `--content` or `--content-digest`, not both.', 'commands/cms.ts:59');
            else if (!has('content') && !has('content-digest')) refuse('`cms sign` needs `--content <file>` (or `--content-digest <hex>` with `--detached`).', 'commands/cms.ts:73');
            if (has('content-digest') && !has('detached')) refuse('`--content-digest` signs a digest only, so it needs `--detached`.', 'commands/cms.ts:75');
            if (!has('cert') && !has('p12')) refuse('`cms sign` needs the signer certificate: `--cert <file>` (or a PKCS#12 that holds it).', 'commands/cms.ts:80');
            if (has('content-digest') && hexBytes(f['content-digest']) < 1) refuse(`\`--content-digest\` expects hexadecimal, got \`${f['content-digest']}\`.`, 'commands/cms.ts:51');
            if (typeof f['signing-time'] !== 'string') note('No `--signing-time`: the signature carries the time the line runs. Pin it (or pass `none`) for a reproducible artefact.', 'commands/cms.ts:64');
            break;
        case 'cms verify':
            if (has('content') && has('content-digest')) refuse('Give `--content` or `--content-digest`, not both.', 'commands/cms.ts:59');
            if (has('content-digest') && hexBytes(f['content-digest']) < 1) refuse(`\`--content-digest\` expects hexadecimal, got \`${f['content-digest']}\`.`, 'commands/cms.ts:51');
            if (!has('trust')) refuse('`cms verify` needs `--trust <file>` (repeatable): the trust anchors.', 'commands/cms.ts:167');
            break;
        case 'cms verify-signer':
            if (!has('cert')) refuse('`cms verify-signer` needs `--cert <file>`: the signer certificate.', 'commands/cms.ts:216');
            break;
        case 'cms add-attribute':
            if (!has('attribute')) refuse('`cms add-attribute` needs `--attribute <file>`: the DER of one Attribute.', 'commands/cms.ts:232');
            break;
        case 'cms add-timestamp':
            if (!has('token')) refuse('`cms add-timestamp` needs `--token <file>`: a TimeStampToken or a TimeStampResp.', 'commands/cms.ts:242');
            break;
        case 'tsp request':
            if (has('data') && has('digest')) refuse('Give `--data` or `--digest`, not both.', 'commands/tsp.ts:48');
            else if (!has('data') && !has('digest')) refuse('`tsp request` needs `--data <file>` or `--digest <hex>`.', 'commands/tsp.ts:65');
            if (has('digest') && hexBytes(f.digest) < 1) refuse(`\`--digest\` expects hexadecimal, got \`${f.digest}\`.`, 'commands/tsp.ts:51');
            if (has('nonce') && !/^(random|\d+|0x[0-9a-f]+)$/i.test(f.nonce)) refuse(`\`--nonce\` expects "random", a decimal or 0x-hex integer, got \`${f.nonce}\`.`, 'commands/tsp.ts:41');
            break;
        case 'tsp verify': {
            const response = has('response') || (!has('token') && ops.length > 0);
            if (has('token') === response) refuse('`tsp verify` takes `--token <file>` or `--response <file>` (or a response as an argument) — exactly one.', 'commands/tsp.ts:147');
            if (!has('trust')) refuse('`tsp verify` needs `--trust <file>` (repeatable): the trust anchors.', 'commands/tsp.ts:149');
            if (has('data') && has('digest')) refuse('Give `--data` or `--digest`, not both.', 'commands/tsp.ts:48');
            if (!has('request') && !has('data') && !has('digest')) refuse('`tsp verify` needs what was stamped: `--request <tsq>`, `--data <file>` or `--digest <hex>`.', 'commands/tsp.ts:156');
            if (has('digest') && hexBytes(f.digest) < 1) refuse(`\`--digest\` expects hexadecimal, got \`${f.digest}\`.`, 'commands/tsp.ts:51');
            break;
        }
        case 'p12 verify-mac': case 'p12 bags': case 'p12 open':
            if (pw === '') refuse(`\`${key}\` needs the password: \`--password-file <file>\`, \`--password-stdin\` or \`PKINATIVE_PASSWORD\`.`, 'commands/p12.ts:38');
            if (key === 'p12 open' && !has('rsa-scheme')) note('If the PKCS#12 holds an RSA key, name its scheme with `--rsa-scheme pkcs1|pss`: without it the report carries `PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED`, the key is not imported, and the CLI then exits 2 (`E_USAGE`). Only the file can tell.', 'utils/pkierr.ts:160');
            break;
        case 'key check':
            if (pw === '') note('An encrypted key needs its password (`--password-file`, `--password-stdin` or `PKINATIVE_PASSWORD`); an unencrypted one does not. Only the file can tell.', 'utils/signer.ts:138');
            break;
        case 'explain':
            if (ops.length === 0 && !has('list')) refuse('`explain` takes one code, e.g. `pkinative explain PKI_ASN1_TRUNCATED`, or `--list`.', 'commands/explain.ts:73');
            if (has('kind') && !has('list')) note('`--kind` filters `--list`; with a code it is ignored.', '');
            break;
        case 'schema': {
            const [subject, ...rest] = ops;
            if (subject !== undefined && !SCHEMA_SUBJECTS.includes(subject) && subject !== 'list') refuse(`Unknown schema subject \`${subject}\`. Subjects: ${SCHEMA_SUBJECTS.join(', ')}.`, 'commands/schema.ts:336');
            else if (subject !== undefined && subject !== 'report' && subject !== 'summary' && rest.length > 0) refuse(`\`schema ${subject}\` takes no further argument.`, 'commands/schema.ts:328');
            else if ((subject === 'report' || subject === 'summary') && !BY_KEY.has(rest.join(' '))) refuse(`\`schema ${subject}\` takes an invocation, e.g. \`schema ${subject} cert inspect\` or \`schema ${subject} fingerprint\`.`, 'commands/schema.ts:190');
            if (subject === undefined) note('With no subject, `schema` lists the twelve subjects.', '');
            break;
        }
        case 'completion':
            if (ops.length === 0) refuse('`completion` takes one shell: bash, zsh, fish or powershell.', 'commands/completion.ts:226');
            else if (!SHELLS.includes(ops[0])) refuse(`Unsupported shell \`${ops[0]}\`: bash, zsh, fish, powershell.`, 'commands/completion.ts:229');
            break;
        default:
            break;
    }

    // ── Signing keys (cert create, cert encode signature-algorithm, csr create, cms sign) ──
    const signs = SIGNING.has(key) || (key === 'cert encode' && ops[0] === 'signature-algorithm');
    if (signs) {
        if (has('key') === has('p12')) refuse(`\`${key}\` needs a signing key: \`--key <pkcs8>\` or \`--p12 <file>\` — exactly one.`, 'utils/signer.ts:112');
        if (has('p12') && pw === '') refuse('A PKCS#12 file needs its password: `--password-file`, `--password-stdin` or `PKINATIVE_PASSWORD`.', 'utils/signer.ts:177');
        if (has('key') && pw === '') note('An encrypted `--key` needs its password, and its type (`--key-type`, or the matching certificate or public key). Only the file can tell whether it is encrypted.', 'utils/signer.ts:138');
    }
    if (signs || key === 'key check' || key === 'p12 open') {
        const type = f['key-type'];
        if (typeof type === 'string' && !KEY_TYPES.includes(type)) refuse(`\`--key-type\` expects one of ${KEY_TYPES.join('|')}, got \`${type}\`.`, 'utils/args.ts:185');
        const rsa = type === 'rsa' || type === 'rsa-pss';
        if (typeof type === 'string' && KEY_TYPES.includes(type) && !rsa && (has('rsa-scheme') || has('salt-length'))) refuse('`--rsa-scheme` and `--salt-length` apply to RSA keys only.', 'utils/signer.ts:67');
        if ((type === 'ed25519' || type === 'ed448') && has('hash')) refuse(`\`--hash\` does not apply to ${type === 'ed25519' ? 'Ed25519' : 'Ed448'}, which hashes internally.`, 'utils/signer.ts:75');
        if (type === 'rsa' && !has('rsa-scheme')) refuse('An RSA key needs `--rsa-scheme pkcs1|pss`: pkinative has no default RSA signature scheme.', 'utils/signer.ts:80');
        if (type === 'rsa-pss' && f['rsa-scheme'] === 'pkcs1') refuse('An id-RSASSA-PSS key signs with RSA-PSS only.', 'utils/signer.ts:82');
        if (f['rsa-scheme'] === 'pkcs1' && has('salt-length')) refuse('`--salt-length` applies to `--rsa-scheme pss` only.', 'utils/signer.ts:83');
        if (signs && type === undefined && !has('rsa-scheme')) note('If the signing key is RSA, add `--rsa-scheme pkcs1|pss`: the CLI refuses an RSA key without one (exit 2). Only the key file can tell.', 'utils/signer.ts:80');
    }
    return out;
}

function renderChecks() {
    const box = $('validation');
    clear(box);
    const findings = check();
    const refused = findings.filter((x) => x.level === 'refused');
    const notes = findings.filter((x) => x.level === 'note');
    const head = el('p', refused.length > 0
        ? `The CLI would refuse this line with exit 2 (E_USAGE) — ${String(refused.length)} reason${refused.length === 1 ? '' : 's'}:`
        : 'Nothing the command line alone decides is refused here.', refused.length > 0 ? 'pg-status error' : 'pg-status ok');
    box.appendChild(head);
    if (findings.length === 0) return;
    const list = el('ul', null, 'pg-diagnostics cli-checks');
    for (const finding of [...refused, ...notes]) {
        const item = el('li');
        item.appendChild(el('code', finding.level === 'refused' ? 'exit 2' : 'note', finding.level === 'refused' ? 'pg-sev-warning' : ''));
        item.appendChild(document.createTextNode(' '));
        item.appendChild(rich('span', finding.text));
        if (finding.where) item.appendChild(el('span', finding.where, 'pg-diag-where'));
        list.appendChild(item);
    }
    box.appendChild(list);
}

function update() {
    renderLine();
    renderChecks();
    $('copy-note').textContent = '';
}

// ── Presets: each one is a sample script of pkinative-cli ──────

/**
 * `sample` names the script under samples/ in the pkinative-cli
 * repository the preset reproduces; the fixture directory prefixes
 * ("$F"/, "$O"/) are dropped. Two presets have no sample script:
 * the samples cover every invocation but `doctor`, and `schema
 * manifest` comes from the CLI guide.
 */
const PRESETS = [
    { id: 'cert-inspect', label: 'cert inspect · read a certificate', sample: 'cert/cert-inspect', key: 'cert inspect', operands: ['leaf.crt.pem'] },
    { id: 'cert-check-name', label: 'cert check-name · does it name this host?', sample: 'cert/cert-check-name', key: 'cert check-name', operands: ['leaf.crt.pem'], flags: { host: 'api.wild.example.test' } },
    { id: 'chain-verify', label: 'chain verify · trust, host, CRL, OCSP, pinned time', sample: 'chain/chain-verify', key: 'chain verify', operands: ['leaf.crt.pem'], flags: { untrusted: ['inter.crt.pem'], trust: ['root.crt.pem'], host: 'example.test', crl: ['inter.crl.pem'], ocsp: ['leaf.ocsp.der'], 'require-revocation': true, at: '2027-01-01T00:00:00Z' } },
    { id: 'chain-verify-revoked', label: 'chain verify · a revoked leaf, quietly', sample: 'chain/chain-verify-revoked', key: 'chain verify', operands: ['revoked.crt.pem'], flags: { untrusted: ['inter.crt.pem'], trust: ['root.crt.pem'], crl: ['inter.crl.pem'], at: '2027-01-01T00:00:00Z' }, globals: { quiet: true } },
    { id: 'crl-check', label: 'crl check · one certificate against a CRL', sample: 'crl/crl-check', key: 'crl check', operands: ['inter.crl.der'], flags: { cert: 'leaf.crt.pem', issuer: 'inter.crt.pem', at: '2027-01-01T00:00:00Z' } },
    { id: 'ocsp-request', label: 'ocsp request · write a request to send yourself', sample: 'ocsp/ocsp-request', key: 'ocsp request', flags: { cert: 'leaf.crt.pem', issuer: 'inter.crt.pem', output: 'ocsp-req.der' } },
    { id: 'ocsp-check', label: 'ocsp check · judge a response', sample: 'ocsp/ocsp-check', key: 'ocsp check', operands: ['revoked.ocsp.der'], flags: { cert: 'revoked.crt.pem', issuer: 'inter.crt.pem', at: '2027-01-01T00:00:00Z' }, globals: { quiet: true } },
    { id: 'cms-sign', label: 'cms sign · detached Ed25519 signature', sample: 'cms/cms-sign', key: 'cms sign', flags: { content: 'content.txt', cert: 'ca.pem', key: 'ed25519.key.pem', detached: true, 'signing-time': '2027-01-01T00:00:00Z', output: 'content.p7s' } },
    { id: 'cms-verify', label: 'cms verify · verdict as a JSON summary', sample: 'cms/cms-verify', key: 'cms verify', operands: ['attached.p7s'], flags: { trust: ['root.crt.pem'], at: '2027-01-01T00:00:00Z' }, globals: { json: true, summary: true } },
    { id: 'tsp-request', label: 'tsp request · a time-stamp request with a nonce', sample: 'tsp/tsp-request', key: 'tsp request', flags: { data: 'content.txt', nonce: '42', output: 'req.tsq' } },
    { id: 'tsp-verify', label: 'tsp verify · response, request and data', sample: 'tsp/tsp-verify', key: 'tsp verify', flags: { response: 'content.tsr', request: 'content.tsq', data: 'content.txt', trust: ['root.crt.pem'], at: '2027-01-01T00:00:00Z' }, globals: { quiet: true } },
    { id: 'csr-create', label: 'csr create · a request from a JSON spec', sample: 'csr/csr-create', key: 'csr create', flags: { spec: 'csr.json', key: 'leaf.key.pem', encoding: 'der', output: 'req.der' } },
    { id: 'p12-open', label: 'p12 open · with --password-file', sample: 'p12/p12-open', key: 'p12 open', operands: ['partner.p12'], flags: { 'certs-out': 'partner-chain.pem' }, globals: { json: true, summary: true }, password: { source: 'file', file: 'p12.pass' } },
    { id: 'key-check', label: 'key check · an encrypted key, password from the environment', sample: 'key/key-check', key: 'key check', operands: ['leaf.key.enc.pem'], flags: { 'key-type': 'ec-p256' }, globals: { json: true }, password: { source: 'env', file: '' } },
    { id: 'fingerprint-key-id', label: 'fingerprint · RFC 5280 key identifier', sample: 'fingerprint/fingerprint-key-id', key: 'fingerprint', operands: ['leaf.pub.pem'], flags: { 'key-id': true } },
    { id: 'explain', label: 'explain · one error code, as JSON', sample: 'explain/explain', key: 'explain', operands: ['PKI_CRYPTO_ALGORITHM_REFUSED'], globals: { json: true } },
    { id: 'limits', label: 'limits · with one bound raised', sample: 'limits/limits', key: 'limits', globals: { 'max-chain-length': '16', json: true, summary: true } },
    { id: 'schema-cert-spec', label: 'schema · the cert create spec', sample: 'schema/schema', key: 'schema', operands: ['cert-spec'] },
    { id: 'schema-manifest', label: 'schema · the capability manifest (CLI guide)', sample: '', key: 'schema', operands: ['manifest'], globals: { pretty: true } },
    { id: 'doctor', label: 'doctor · environment check for an agent (CLI guide)', sample: '', key: 'doctor', globals: { json: true } },
    { id: 'completion', label: 'completion · bash', sample: 'completion/completion', key: 'completion', operands: ['bash'] },
];

function resetState() {
    state.perInvocation.clear();
    state.globals = {};
    state.password = { source: '', file: '' };
    $('pipe').value = '';
}

function applyPreset(id) {
    const preset = PRESETS.find((p) => p.id === id);
    if (!preset || !BY_KEY.has(preset.key)) return false;
    resetState();
    state.key = preset.key;
    const bag = current();
    bag.operands = (preset.operands ?? []).join('\n');
    Object.assign(bag.flags, structuredClone(preset.flags ?? {}));
    Object.assign(state.globals, preset.globals ?? {});
    if (preset.password) state.password = { ...preset.password };
    $('preset').value = preset.id;
    renderAll();
    status('info', preset.sample
        ? `Preset from the pkinative-cli sample samples/${preset.sample}.sh (fixture paths shortened).`
        : 'Preset from the CLI reference guide; the CLI ships no sample script for it.');
    return true;
}

// ── Wiring ────────────────────────────────────────────────────

renderCommandPickers();
const presetSel = $('preset');
for (const preset of PRESETS) {
    const option = Object.assign(el('option', preset.sample ? `${preset.label} — sample ${preset.sample}` : preset.label), { value: preset.id });
    option.dataset.sample = preset.sample;
    presetSel.appendChild(option);
}

$('command').addEventListener('change', () => {
    const name = $('command').value;
    const first = INVOCATIONS.find((i) => i.command === name);
    state.key = first.key;
    presetSel.value = '';
    status('', '');
    renderAll();
});
$('sub').addEventListener('change', () => {
    state.key = `${$('command').value} ${$('sub').value}`;
    presetSel.value = '';
    renderAll();
});
presetSel.addEventListener('change', () => {
    if (presetSel.value && applyPreset(presetSel.value)) history.replaceState(null, '', `#${presetSel.value}`);
});
$('reset').addEventListener('click', () => {
    resetState();
    presetSel.value = '';
    status('', '');
    history.replaceState(null, '', location.pathname);
    renderAll();
});
for (const id of ['invoke', 'shell']) $(id).addEventListener('change', update);
$('pipe').addEventListener('input', update);
$('password-source').addEventListener('change', () => {
    state.password.source = $('password-source').value;
    $('password-file-wrap').hidden = state.password.source !== 'file';
    update();
});
$('password-file').addEventListener('input', () => { state.password.file = $('password-file').value.trim(); update(); });

$('copy').addEventListener('click', async () => {
    const text = $('output').textContent;
    const note = $('copy-note');
    try {
        await navigator.clipboard.writeText(text);
        note.textContent = 'Copied to the clipboard.';
    } catch {
        // No clipboard permission (an embedded frame, an old browser):
        // select the text so a keyboard copy works instead.
        const range = document.createRange();
        range.selectNodeContents($('output'));
        const selection = getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        note.textContent = 'The clipboard is not available here; the line is selected — press Ctrl+C (⌘C on a Mac).';
    }
});

// Start on something real: the preset the fragment names, or a full
// chain verification — a blank form shows nothing of what the CLI does.
if (!applyPreset(decodeURIComponent(location.hash.slice(1)))) applyPreset('chain-verify');
addEventListener('hashchange', () => { applyPreset(decodeURIComponent(location.hash.slice(1))); });
