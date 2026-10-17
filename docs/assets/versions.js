/*!
 * pkinative.dev — live npm versions (the pdfnative and zipnative versions.js pattern)
 * ==================================================================================
 * Fills every `[data-pk-badge="<package>"]` with the version npm serves now for
 * `pkinative`, `pkinative-cli` and `pkinative-mcp`, and adds to the strip the
 * pkinative range each satellite pins in its `dependencies`, so a reader can
 * check the wiring at a glance.
 *
 * The page ships with the manifest's versions already written in: without
 * JavaScript, or with the registry unreachable, it still says something true.
 * FALLBACK mirrors docs/assets/ecosystem.json and the `versions-widget`
 * verify-docs rule holds both, and every badge, to it.
 *
 * Zero dependencies, zero build: one fetch per package to registry.npmjs.org.
 * Text only, through textContent — nothing from the network is parsed as HTML.
 */
(function () {
    'use strict';

    var NPM = 'https://registry.npmjs.org/';
    var PKGS = ['pkinative', 'pkinative-cli', 'pkinative-mcp'];
    var FALLBACK = {
        'pkinative': { version: '1.0.0', pin: null },
        'pkinative-cli': { version: '1.0.0', pin: '^1.0.0' },
        'pkinative-mcp': { version: '1.0.0', pin: '^1.0.0' }
    };

    function fetchPkg(name) {
        return fetch(NPM + name + '/latest', { mode: 'cors' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (!data || typeof data.version !== 'string') return FALLBACK[name];
                var pin = data.dependencies && typeof data.dependencies.pkinative === 'string' ? data.dependencies.pkinative : null;
                return { version: data.version, pin: pin };
            })
            .catch(function () { return FALLBACK[name]; });
    }

    function boot() {
        var badges = document.querySelectorAll('[data-pk-badge]');
        if (!badges.length) return;
        Promise.all(PKGS.map(fetchPkg)).then(function (results) {
            var byName = {};
            for (var i = 0; i < PKGS.length; i++) byName[PKGS[i]] = results[i] || FALLBACK[PKGS[i]];
            badges.forEach(function (badge) {
                var info = byName[badge.getAttribute('data-pk-badge')];
                if (!info) return;
                badge.textContent = 'v' + info.version;
                // In the strip, a satellite also shows the pkinative range it pins.
                var link = badge.closest('.pk-version-strip-pkg');
                if (link && info.pin && !link.querySelector('.pk-version-strip-pin')) {
                    var pin = document.createElement('span');
                    pin.className = 'pk-version-strip-pin';
                    pin.title = 'the pkinative range this package pins in its dependencies';
                    pin.textContent = ' (pkinative ' + info.pin + ')';
                    link.appendChild(pin);
                }
            });
        });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
    else boot();
})();
