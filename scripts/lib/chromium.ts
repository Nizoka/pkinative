/**
 * pkinative — a Chromium-family browser for headless checks
 * ==========================================================
 * Ported from pdfnative's `scripts/lib/chromium.ts`. Used by
 * `scripts/verify-diagrams.ts` and the gate's skip condition. No download and
 * no npm dependency: an installed browser, or nothing.
 *
 * `CHROME_BIN` — the variable `scripts/a11y-check.ts` already reads — and then
 * pdfnative's `CHROME_PATH` are used as given and replace the search, so a
 * wrong path fails at launch rather than silently falling back to another
 * browser.
 *
 * @module scripts/lib/chromium
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';

function candidates(): string[] {
    const env = process.env;
    const out: string[] = [];
    if (process.platform === 'win32') {
        for (const base of [env['PROGRAMFILES'], env['PROGRAMFILES(X86)'], env['LOCALAPPDATA']]) {
            if (!base) continue;
            out.push(join(base, 'Google', 'Chrome', 'Application', 'chrome.exe'));
            out.push(join(base, 'Microsoft', 'Edge', 'Application', 'msedge.exe'));
            out.push(join(base, 'Chromium', 'Application', 'chrome.exe'));
        }
    } else if (process.platform === 'darwin') {
        out.push('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome');
        out.push('/Applications/Chromium.app/Contents/MacOS/Chromium');
        out.push('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge');
    } else {
        for (const name of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge']) out.push(`/usr/bin/${name}`);
        out.push('/snap/bin/chromium');
    }
    return out;
}

/** The browser to run headless: `CHROME_BIN`, `CHROME_PATH`, else an installed Chromium-family browser, else null. */
export function findChromium(): string | null {
    const override = process.env['CHROME_BIN'] ?? process.env['CHROME_PATH'];
    if (override) return override;
    for (const path of candidates()) if (existsSync(path)) return path;
    return null;
}
