/**
 * pkinative — Demo GIF of the README and the landing page (`npx tsx scripts/build-demo-gif.ts`)
 * ===========================================================================================
 *
 * Fifteen seconds that show what pkinative is for: `npm install pkinative`
 * adds one package, `scripts/demo/verify.mjs` issues a fictitious chain with
 * keys it makes itself (RFC 2606 names), and `verifyCertificateChain` refuses
 * the wrong host with a stable reason code and its RFC, then accepts the right
 * one.
 *
 * Nothing on screen is written by hand. The install output is what npm prints
 * in an empty directory, the excerpt is lines of the demo file, and the verdict
 * is what the demo prints when it runs against `src/` — so a change of wording
 * in the engine shows up the next time this runs, at each release.
 *
 * A terminal drawn in HTML is rendered by the headless Chromium that
 * `verify:diagrams` uses (`scripts/lib/chromium.ts`, `CHROME_BIN` overrides),
 * driven over the DevTools protocol, and each screenshot is encoded here — a
 * GIF89a writer with LZW and per-frame changed rectangles, no dependency.
 *
 * Writes `docs/assets/demo.gif` and `docs/assets/demo.png` (the last frame,
 * for `prefers-reduced-motion` and the pause button of the landing page).
 *
 * Usage:
 *   npx tsx scripts/build-demo-gif.ts [--work <dir>] [--install-output <file>] [--frames <dir>]
 *
 * `--work` is where `npm install pkinative` runs (a temporary directory by
 * default); `--install-output` reads a captured output instead of installing;
 * `--frames` also writes every screenshot there, to review the frames one by one.
 * Exit: 0 written; 1 the demo or the install failed, or the GIF is over budget;
 * 2 no Chromium-family browser.
 */
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inflateSync } from 'node:zlib';
import { findChromium } from './lib/chromium.js';

const REPO = join(import.meta.dirname, '..');
const DEMO = join(REPO, 'scripts', 'demo', 'verify.mjs');
const OUT_GIF = join(REPO, 'docs', 'assets', 'demo.gif');
const OUT_PNG = join(REPO, 'docs', 'assets', 'demo.png');
/** CSS size of the window; the screenshots are taken at twice this. */
const WIDTH = 800;
const HEIGHT = 330;
const SCALE = 2;
const BUDGET = 1024 * 1024;

// ── What the screen shows ──

/** Run the demo against the sources, exactly as a reader runs it against the package. */
function runDemo(): string[] {
    const source = readFileSync(DEMO, 'utf8');
    if (!source.includes("from 'pkinative'")) throw new Error('scripts/demo/verify.mjs no longer imports from pkinative');
    const runnable = join(REPO, 'scripts', 'demo', '.run.mts');
    writeFileSync(runnable, source.replace("from 'pkinative'", "from '../../src/index.ts'"));
    try {
        const run = spawnSync(process.execPath, ['--import', 'tsx', runnable], { cwd: REPO, encoding: 'utf8' });
        if (run.status !== 0) throw new Error(`the demo failed:\n${run.stderr}`);
        if (run.stderr.trim() !== '') throw new Error(`the demo wrote to stderr, which the GIF would hide:\n${run.stderr}`);
        const lines = run.stdout.trimEnd().split('\n');
        if (!lines.some((l) => l.startsWith('✗ ')) || !lines.some((l) => l.startsWith('✓ '))) {
            throw new Error(`the demo no longer refuses one host and accepts the other:\n${run.stdout}`);
        }
        return lines;
    } finally {
        rmSync(runnable, { force: true });
    }
}

/** What `npm install pkinative` prints in an empty directory. */
function installOutput(work: string | undefined, captured: string | undefined): string[] {
    if (captured !== undefined) return readFileSync(captured, 'utf8').trimEnd().split(/\r?\n/);
    const dir = mkdtempSync(join(work ?? tmpdir(), 'pkinative-demo-'));
    try {
        const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
        const run = spawnSync(npm, ['install', 'pkinative'], { cwd: dir, encoding: 'utf8', shell: process.platform === 'win32' });
        if (run.status !== 0) throw new Error(`npm install pkinative failed:\n${run.stderr}`);
        return run.stdout.trim().split(/\r?\n/);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

/** The lines of the demo that make the call, with their numbers. */
function excerpt(): { first: number; lines: string[] } {
    const all = readFileSync(DEMO, 'utf8').trimEnd().split(/\r?\n/);
    const first = all.findIndex((l) => l.startsWith('for (const host of'));
    if (first < 0) throw new Error('scripts/demo/verify.mjs has no verdict loop to show');
    return { first: first + 1, lines: all.slice(first) };
}

// ── The page ──

const escape = (text: string): string => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Just enough JavaScript highlighting for ten lines: comments, strings, keywords, calls. */
function highlight(line: string): string {
    const token = /(\/\/.*$)|(`(?:[^`\\]|\\.)*`|'(?:[^'\\]|\\.)*')|\b(const|for|of|if|else|await|async|import|from|return)\b|([A-Za-z_$][\w$]*)(?=\()/g;
    let out = '';
    let last = 0;
    for (const m of line.matchAll(token)) {
        out += escape(line.slice(last, m.index));
        const kind = m[1] !== undefined ? 'cm' : m[2] !== undefined ? 'st' : m[3] !== undefined ? 'kw' : 'fn';
        out += `<span class="${kind}">${escape(m[0])}</span>`;
        last = m.index + m[0].length;
    }
    return out + escape(line.slice(last));
}

/** One line of the demo's output, coloured as a terminal with colours would show it. */
function outputLine(line: string): string {
    if (line.startsWith('✓ ')) return `<span class="ok">${escape(line)}</span>`;
    if (line.startsWith('✗ ')) return `<span class="ko">${escape(line)}</span>`;
    const code = /^(\s*)(PKI_REASON_\w+)(.*)$/.exec(line);
    if (code !== null) return `${escape(code[1] ?? '')}<span class="code">${escape(code[2] ?? '')}</span><span class="dim">${escape(code[3] ?? '')}</span>`;
    return `<span class="dim">${escape(line)}</span>`;
}

interface Screen { readonly tab: 'terminal' | 'editor'; readonly html: string; readonly ms: number }

function screens(install: readonly string[], demo: readonly string[]): Screen[] {
    const out: Screen[] = [];
    const prompt = '<span class="pr">~/demo $</span> ';
    const cursor = '<span class="cu"></span>';
    const typed = (lines: readonly string[], command: string, ms: number): void => {
        for (let n = 2; n < command.length; n += 3) out.push({ tab: 'terminal', html: [...lines, prompt + escape(command.slice(0, n)) + cursor].join('\n'), ms });
        out.push({ tab: 'terminal', html: [...lines, prompt + escape(command) + cursor].join('\n'), ms: 450 });
    };
    typed([], 'npm install pkinative', 70);
    const installed = [prompt + 'npm install pkinative', ...install.map((l) => `<span class="dim">${escape(l)}</span>`)];
    out.push({ tab: 'terminal', html: [...installed, prompt + cursor].join('\n'), ms: 2600 });

    const { first, lines } = excerpt();
    const code = lines.map((l, i) => `<span class="ln">${String(first + i).padStart(3)}</span>  ${highlight(l)}`).join('\n');
    out.push({ tab: 'editor', html: code, ms: 4200 });

    typed([], 'node verify.mjs', 70);
    const shown: string[] = [prompt + 'node verify.mjs'];
    for (const [i, line] of demo.entries()) {
        shown.push(outputLine(line));
        out.push({ tab: 'terminal', html: shown.join('\n'), ms: i === 0 ? 300 : 220 });
    }
    out.push({ tab: 'terminal', html: [...shown, prompt + cursor].join('\n'), ms: 4500 });
    return out;
}

function page(): string {
    return `<!doctype html><html><head><meta charset="utf-8"><style>
html, body { margin: 0; background: #0b1020; }
.win { box-sizing: border-box; width: ${String(WIDTH)}px; height: ${String(HEIGHT)}px; background: #0f172a; color: #e2e8f0;
  font: 13px/1.55 "Cascadia Mono", Consolas, "SF Mono", Menlo, "DejaVu Sans Mono", monospace; overflow: hidden; }
.bar { display: flex; align-items: center; gap: 8px; height: 36px; padding: 0 14px; background: #1e293b; color: #94a3b8;
  font: 13px system-ui, "Segoe UI", sans-serif; }
.dot { width: 12px; height: 12px; border-radius: 50%; } .r { background: #f87171; } .y { background: #fbbf24; } .g { background: #4ade80; }
.tab { margin-left: 14px; padding: 4px 10px; border-radius: 6px; } .tab.on { background: #0f172a; color: #e2e8f0; }
.brand { margin-left: auto; color: #64748b; }
pre { margin: 0; padding: 18px 20px; white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; }
.pr { color: #38bdf8; } .dim { color: #94a3b8; } .ok { color: #4ade80; font-weight: 700; } .ko { color: #f87171; font-weight: 700; }
.code { color: #fbbf24; font-weight: 700; } .ln { color: #475569; }
.kw { color: #c084fc; } .st { color: #86efac; } .fn { color: #7dd3fc; } .cm { color: #64748b; }
.cu { display: inline-block; width: 8px; height: 17px; vertical-align: -3px; background: #e2e8f0; }
</style></head><body><div class="win"><div class="bar"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
<span class="tab" id="t-terminal">terminal</span><span class="tab" id="t-editor">verify.mjs</span><span class="brand">pkinative — 0 dependencies</span></div>
<pre id="screen"></pre></div>
<script>window.show = (tab, html) => { document.getElementById('screen').innerHTML = html;
for (const t of ['terminal', 'editor']) document.getElementById('t-' + t).className = 'tab' + (t === tab ? ' on' : ''); };</script>
</body></html>`;
}

// ── The browser ──

interface Cdp { send(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>>; close(): void }

async function openBrowser(browser: string, profile: string): Promise<{ cdp: Cdp; stop: () => Promise<void> }> {
    const child = spawn(browser, ['--headless=new', '--disable-gpu', '--no-sandbox', '--hide-scrollbars', '--no-first-run',
        '--force-color-profile=srgb', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
    const endpoint = await new Promise<string>((resolve, reject) => {
        let seen = '';
        const timer = setTimeout(() => { reject(new Error('the browser did not open its DevTools endpoint')); }, 20_000);
        child.stderr.on('data', (chunk: Buffer) => {
            seen += chunk.toString();
            const port = /DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//.exec(seen)?.[1];
            if (port !== undefined) { clearTimeout(timer); resolve(`http://127.0.0.1:${port}`); }
        });
        child.on('exit', () => { reject(new Error(`the browser exited before it listened:\n${seen}`)); });
    });
    const targets = await (await fetch(`${endpoint}/json/list`)).json() as Array<{ type: string; webSocketDebuggerUrl: string }>;
    const target = targets.find((t) => t.type === 'page');
    if (target === undefined) throw new Error('the browser opened no page');
    const socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise<void>((resolve, reject) => { socket.onopen = () => { resolve(); }; socket.onerror = () => { reject(new Error('DevTools socket error')); }; });
    let next = 0;
    const pending = new Map<number, { resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void }>();
    socket.onmessage = (event: { data: unknown }) => {
        const message = JSON.parse(String(event.data)) as { id?: number; result?: Record<string, unknown>; error?: { message: string } };
        const waiter = message.id === undefined ? undefined : pending.get(message.id);
        if (waiter === undefined || message.id === undefined) return;
        pending.delete(message.id);
        if (message.error !== undefined) waiter.reject(new Error(message.error.message));
        else waiter.resolve(message.result ?? {});
    };
    const cdp: Cdp = {
        send: (method, params = {}) => new Promise((resolve, reject) => {
            const id = ++next;
            pending.set(id, { resolve, reject });
            socket.send(JSON.stringify({ id, method, params }));
        }),
        close: () => { socket.close(); },
    };
    // The profile is removed after the browser has exited: before, Windows holds its files open.
    const exited = new Promise<void>((resolve) => { child.once('exit', () => { resolve(); }); });
    return { cdp, stop: async () => { cdp.close(); child.kill(); await exited; } };
}

// ── PNG in, GIF out ──

interface Image { readonly width: number; readonly height: number; readonly rgb: Uint8Array }

function decodePng(png: Buffer): Image {
    let at = 8;
    let width = 0, height = 0, channels = 0;
    const idat: Buffer[] = [];
    while (at < png.length) {
        const length = png.readUInt32BE(at);
        const type = png.toString('latin1', at + 4, at + 8);
        const data = png.subarray(at + 8, at + 8 + length);
        if (type === 'IHDR') {
            width = data.readUInt32BE(0); height = data.readUInt32BE(4);
            const [depth, colour, , , interlace] = [data[8], data[9], data[10], data[11], data[12]];
            if (depth !== 8 || interlace !== 0 || (colour !== 2 && colour !== 6)) throw new Error('unexpected screenshot format');
            channels = colour === 6 ? 4 : 3;
        } else if (type === 'IDAT') idat.push(data);
        at += 12 + length;
    }
    const raw = inflateSync(Buffer.concat(idat));
    const stride = width * channels;
    const pixels = new Uint8Array(height * stride);
    for (let y = 0; y < height; y++) {
        const filter = raw[y * (stride + 1)] ?? 0;
        const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
        for (let x = 0; x < stride; x++) {
            const a = x >= channels ? pixels[y * stride + x - channels] ?? 0 : 0;
            const b = y > 0 ? pixels[(y - 1) * stride + x] ?? 0 : 0;
            const c = x >= channels && y > 0 ? pixels[(y - 1) * stride + x - channels] ?? 0 : 0;
            const v = line[x] ?? 0;
            let predicted = 0;
            if (filter === 1) predicted = a;
            else if (filter === 2) predicted = b;
            else if (filter === 3) predicted = (a + b) >> 1;
            else if (filter === 4) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); predicted = pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
            pixels[y * stride + x] = (v + predicted) & 0xff;
        }
    }
    const rgb = new Uint8Array(width * height * 3);
    for (let i = 0, j = 0; i < pixels.length; i += channels, j += 3) { rgb[j] = pixels[i] ?? 0; rgb[j + 1] = pixels[i + 1] ?? 0; rgb[j + 2] = pixels[i + 2] ?? 0; }
    return { width, height, rgb };
}

/** The 256 most frequent colours, at 5 bits per channel, then every pixel to its nearest. */
function palette(images: readonly Image[]): { colours: number[]; index: (image: Image) => Uint8Array } {
    const counts = new Map<number, number>();
    for (const image of images) {
        for (let i = 0; i < image.rgb.length; i += 3) {
            const key = ((image.rgb[i] ?? 0) >> 3) << 10 | ((image.rgb[i + 1] ?? 0) >> 3) << 5 | (image.rgb[i + 2] ?? 0) >> 3;
            counts.set(key, (counts.get(key) ?? 0) + 1);
        }
    }
    const colours = [...counts.entries()].sort((x, y) => y[1] - x[1]).slice(0, 256).map(([key]) => key);
    const rgbOf = (key: number): [number, number, number] => [((key >> 10) & 31) * 255 / 31, ((key >> 5) & 31) * 255 / 31, (key & 31) * 255 / 31];
    const nearest = new Map<number, number>();
    const pick = (key: number): number => {
        const known = nearest.get(key);
        if (known !== undefined) return known;
        const [r, g, b] = rgbOf(key);
        let best = 0, bestDistance = Infinity;
        for (const [i, candidate] of colours.entries()) {
            const [cr, cg, cb] = rgbOf(candidate);
            const d = (r - cr) ** 2 * 3 + (g - cg) ** 2 * 4 + (b - cb) ** 2 * 2;
            if (d < bestDistance) { bestDistance = d; best = i; }
        }
        nearest.set(key, best);
        return best;
    };
    const index = (image: Image): Uint8Array => {
        const out = new Uint8Array(image.width * image.height);
        for (let p = 0, i = 0; p < out.length; p++, i += 3) {
            out[p] = pick(((image.rgb[i] ?? 0) >> 3) << 10 | ((image.rgb[i + 1] ?? 0) >> 3) << 5 | (image.rgb[i + 2] ?? 0) >> 3);
        }
        return out;
    };
    return { colours: colours.map((key) => { const [r, g, b] = rgbOf(key); return Math.round(r) << 16 | Math.round(g) << 8 | Math.round(b); }), index };
}

/** GIF LZW (minimum code size 8), packed into sub-blocks. */
function lzw(indices: Uint8Array): Buffer {
    const clear = 256, end = 257;
    const bytes: number[] = [];
    let buffer = 0, bits = 0, size = 9;
    const emit = (code: number): void => {
        buffer |= code << bits; bits += size;
        while (bits >= 8) { bytes.push(buffer & 0xff); buffer >>>= 8; bits -= 8; }
    };
    let table = new Map<number, number>();
    let next = 258;
    emit(clear);
    let prefix = indices[0] ?? 0;
    for (let i = 1; i < indices.length; i++) {
        const k = indices[i] ?? 0;
        const key = prefix << 8 | k;
        const found = table.get(key);
        if (found !== undefined) { prefix = found; continue; }
        emit(prefix);
        if (next < 4096) {
            table.set(key, next++);
            if (next > (1 << size) && size < 12) size++;
        } else {
            emit(clear);
            table = new Map(); next = 258; size = 9;
        }
        prefix = k;
    }
    emit(prefix);
    emit(end);
    if (bits > 0) bytes.push(buffer & 0xff);
    const out: number[] = [8];
    for (let i = 0; i < bytes.length; i += 255) { const block = bytes.slice(i, i + 255); out.push(block.length, ...block); }
    out.push(0);
    return Buffer.from(out);
}

function encodeGif(frames: ReadonlyArray<{ indices: Uint8Array; ms: number }>, width: number, height: number, colours: readonly number[]): Buffer {
    const parts: Buffer[] = [];
    const header = Buffer.alloc(13);
    header.write('GIF89a', 0, 'latin1');
    header.writeUInt16LE(width, 6); header.writeUInt16LE(height, 8);
    header[10] = 0xf7; // global table of 256 colours
    parts.push(header);
    const table = Buffer.alloc(768);
    for (const [i, c] of colours.entries()) { table[i * 3] = c >> 16; table[i * 3 + 1] = (c >> 8) & 0xff; table[i * 3 + 2] = c & 0xff; }
    parts.push(table);
    parts.push(Buffer.from([0x21, 0xff, 0x0b, ...Buffer.from('NETSCAPE2.0', 'latin1'), 0x03, 0x01, 0x00, 0x00, 0x00]));
    let previous: Uint8Array | undefined;
    for (const frame of frames) {
        let x0 = 0, y0 = 0, x1 = width - 1, y1 = height - 1;
        if (previous !== undefined) {
            x0 = width; y0 = height; x1 = -1; y1 = -1;
            for (let y = 0; y < height; y++) {
                for (let x = 0; x < width; x++) {
                    const p = y * width + x;
                    if (frame.indices[p] !== previous[p]) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
                }
            }
            if (x1 < 0) { x0 = 0; y0 = 0; x1 = 0; y1 = 0; }
        }
        const w = x1 - x0 + 1, h = y1 - y0 + 1;
        const delay = Math.round(frame.ms / 10);
        parts.push(Buffer.from([0x21, 0xf9, 0x04, 0x04, delay & 0xff, delay >> 8, 0x00, 0x00]));
        const descriptor = Buffer.alloc(10);
        descriptor[0] = 0x2c;
        descriptor.writeUInt16LE(x0, 1); descriptor.writeUInt16LE(y0, 3); descriptor.writeUInt16LE(w, 5); descriptor.writeUInt16LE(h, 7);
        parts.push(descriptor);
        const crop = new Uint8Array(w * h);
        for (let y = 0; y < h; y++) crop.set(frame.indices.subarray((y0 + y) * width + x0, (y0 + y) * width + x0 + w), y * w);
        parts.push(lzw(crop));
        previous = frame.indices;
    }
    parts.push(Buffer.from([0x3b]));
    return Buffer.concat(parts);
}

// ── Main ──

async function main(): Promise<number> {
    const args = process.argv.slice(2);
    const option = (name: string): string | undefined => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
    const browser = findChromium();
    if (browser === null) { console.error('build-demo-gif: no Chromium-family browser found — set CHROME_BIN'); return 2; }

    const demo = runDemo();
    const install = installOutput(option('--work'), option('--install-output'));
    const all = screens(install, demo);

    const work = mkdtempSync(join(tmpdir(), 'pkinative-demo-page-'));
    const html = join(work, 'demo.html');
    writeFileSync(html, page());
    const { cdp, stop } = await openBrowser(browser, join(work, 'profile'));
    const shots: Buffer[] = [];
    try {
        await cdp.send('Emulation.setDeviceMetricsOverride', { width: WIDTH, height: HEIGHT, deviceScaleFactor: SCALE, mobile: false });
        await cdp.send('Page.navigate', { url: pathToFileURL(html).href });
        await cdp.send('Runtime.evaluate', { expression: 'new Promise((r) => { const go = () => document.fonts.ready.then(r); document.readyState === "complete" ? go() : addEventListener("load", go); })', awaitPromise: true });
        for (const screen of all) {
            await cdp.send('Runtime.evaluate', { expression: `show(${JSON.stringify(screen.tab)}, ${JSON.stringify(screen.html)})` });
            const shot = await cdp.send('Page.captureScreenshot', { format: 'png' });
            shots.push(Buffer.from(String(shot['data']), 'base64'));
        }
    } finally {
        await stop();
        rmSync(work, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
    }

    const frames = option('--frames');
    if (frames !== undefined) for (const [i, shot] of shots.entries()) writeFileSync(join(frames, `frame-${String(i).padStart(2, '0')}.png`), shot);
    const images = shots.map(decodePng);
    const first = images[0];
    if (first === undefined) throw new Error('no frame was captured');
    const { colours, index } = palette(images);
    const gif = encodeGif(images.map((image, i) => ({ indices: index(image), ms: all[i]?.ms ?? 100 })), first.width, first.height, colours);
    writeFileSync(OUT_GIF, gif);
    writeFileSync(OUT_PNG, shots[shots.length - 1] ?? Buffer.alloc(0));
    const total = all.reduce((sum, s) => sum + s.ms, 0);
    console.log(`build-demo-gif: ${String(all.length)} frames, ${(total / 1000).toFixed(1)} s, ${String(first.width)}×${String(first.height)}, ` +
        `demo.gif ${(gif.length / 1024).toFixed(0)} KB, demo.png ${((shots[shots.length - 1]?.length ?? 0) / 1024).toFixed(0)} KB`);
    if (gif.length > BUDGET) { console.error(`build-demo-gif: demo.gif is over its ${String(BUDGET / 1024)} KB budget`); return 1; }
    return 0;
}

main().then((code) => { process.exitCode = code; }, (error: unknown) => {
    console.error(`build-demo-gif: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
});
