/* ═══════════════════════════════════════════════════════════════
   pkinative.dev — playground engine loader

   The family's CDN pattern (pdfnative, zipnative): import the
   PUBLISHED package, pinned to the version this site documents, from
   esm.sh and then jsDelivr's +esm build. Each candidate is verified by
   a capability probe — a stale or wrong CDN build must fail loudly,
   never half-load. There is no local fallback: what runs here is the
   npm artefact a reader installs, nothing else (ADR 0023).

   VERSION is held to packages.pkinative.version of
   docs/assets/ecosystem.json by the `cdn-pin` verify-docs rule, and
   scripts/release-prepare.ts bumps it with every release.
   ═══════════════════════════════════════════════════════════════ */

const VERSION = '1.0.0';

const CDN_URLS = [
    `https://esm.sh/pkinative@${VERSION}`,
    `https://cdn.jsdelivr.net/npm/pkinative@${VERSION}/+esm`,
];

let cached = null;

/** The version the playgrounds pin, for pages that quote it. */
export const ENGINE_VERSION = VERSION;

/**
 * Load the engine once: `{ mod, source }`, where `source` names the CDN that
 * served it. Every page shows `source` in its #engine-source slot, so a
 * reader can always see which bytes ran.
 */
export async function loadEngine() {
    if (cached) return cached;
    let lastError = null;
    for (const url of CDN_URLS) {
        try {
            const m = await import(url);
            // esm.sh can nest the named exports under .default — normalise,
            // then PROBE two known exports so a wrong build fails here, loudly.
            const mod = typeof m.parseCertificate === 'function' ? m
                : (m.default && typeof m.default.parseCertificate === 'function') ? m.default
                    : Object.assign({}, m, m.default || {});
            if (typeof mod.parseCertificate === 'function' && typeof mod.decodeAsn1 === 'function') {
                cached = { mod, source: `pkinative@${VERSION} from ${new URL(url).host}` };
                const slot = document.getElementById('engine-source');
                if (slot) slot.textContent = cached.source;
                return cached;
            }
            lastError = new Error(`${url} loaded but does not export parseCertificate and decodeAsn1`);
        } catch (err) {
            lastError = err;
        }
    }
    const message = `pkinative@${VERSION} could not be loaded from esm.sh or jsDelivr — `
        + `check your network or content blocker and reload. (${lastError && lastError.message ? lastError.message : 'no details'})`;
    const slot = document.getElementById('engine-source');
    if (slot) slot.textContent = 'unavailable — CDN unreachable';
    const status = document.getElementById('status');
    if (status) { status.textContent = message; status.className = 'pg-status error'; }
    throw new Error(message);
}
