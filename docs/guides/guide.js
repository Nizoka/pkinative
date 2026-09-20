/* ═══════════════════════════════════════════════════════════════
   pkinative.dev — Guide page enhancements
   Guides are PRE-RENDERED from the companion `.md` by build-guides.ts, and
   the guide-render-sync rule keeps them byte-identical to it. This script
   only adds chrome behaviour, the source bar, per-block copy buttons and
   Prism highlighting. No client-side Markdown rendering, ever — there is no
   fallback path that would render untrusted text into the page.
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ── Theme toggle (shared with the landing page) ───────────
  var toggle = document.querySelector('.theme-toggle');
  var root = document.documentElement;

  function getPreferred() {
    var stored = null;
    try { stored = localStorage.getItem('theme'); } catch (_) { /* private mode */ }
    if (stored === 'dark' || stored === 'light') return stored;
    return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    root.setAttribute('data-theme', theme);
    try { localStorage.setItem('theme', theme); } catch (_) { /* private mode */ }
    if (toggle) {
      toggle.textContent = theme === 'dark' ? '☀️' : '🌙';
      toggle.setAttribute('aria-pressed', String(theme === 'dark'));
    }
  }

  applyTheme(getPreferred());
  if (toggle) {
    toggle.addEventListener('click', function () {
      applyTheme(root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });
  }

  // ── Hamburger menu (shared) ───────────────────────────────
  var hamburger = document.querySelector('.nav-hamburger');
  var navLinks = document.querySelector('.nav-links');
  if (hamburger && navLinks) {
    hamburger.addEventListener('click', function () {
      var open = navLinks.classList.toggle('open');
      hamburger.setAttribute('aria-expanded', String(open));
      hamburger.textContent = open ? '✕' : '☰';
    });
  }

  // ── Guide enhancements ────────────────────────────────────
  var container = document.getElementById('guide-content');
  if (!container) return;

  // The Markdown source name is DERIVED from the page's own URL — every
  // guide pairs name.html with name.md — never from DOM text. data-md is
  // only an opt-in marker: it must agree with the derived name, and the
  // value that reaches fetch() and the source-bar href comes from location,
  // filtered to a plain same-directory Markdown filename.
  var page = (location.pathname.split('/').pop() || '').replace(/\.html$/, '');
  var src = page + '.md';
  var declared = container.getAttribute('data-md');
  if (!declared || declared !== src || !/^[A-Za-z0-9][A-Za-z0-9_-]*\.md$/.test(src)) return;

  // Pages are always pre-rendered; anything else is a build error the
  // verifier catches before it ships.
  if (container.getAttribute('data-prerendered') !== 'true') return;

  function copyTo(btn, text, label) {
    navigator.clipboard.writeText(text).then(function () {
      btn.textContent = 'Copied!';
      setTimeout(function () { btn.textContent = label; }, 1500);
    }, function () {
      btn.textContent = 'Failed';
      setTimeout(function () { btn.textContent = label; }, 1500);
    });
  }

  function addCopyButtons(scope) {
    scope.querySelectorAll('pre').forEach(function (pre) {
      // The button lives in a positioned wrapper OUTSIDE the scrollable
      // <pre>: as a child it would scroll away with wide code, and its
      // label would land in a manual text selection.
      if (pre.parentNode.classList && pre.parentNode.classList.contains('pre-wrap')) return;
      var wrap = document.createElement('div');
      wrap.className = 'pre-wrap';
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      var btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.type = 'button';
      btn.textContent = 'Copy';
      btn.addEventListener('click', function () {
        var code = pre.querySelector('code');
        copyTo(btn, code ? code.textContent : pre.textContent, 'Copy');
      });
      wrap.appendChild(btn);
    });
  }

  function addSourceBar(scope) {
    if (document.querySelector('.guide-source-bar')) return;
    var bar = document.createElement('div');
    bar.className = 'guide-source-bar';
    var copyMd = document.createElement('button');
    copyMd.type = 'button';
    copyMd.className = 'guide-source-btn';
    copyMd.textContent = 'Copy page as Markdown';
    copyMd.addEventListener('click', function () {
      fetch(src, { cache: 'no-cache' })
        .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
        .then(function (md) { copyTo(copyMd, md, 'Copy page as Markdown'); })
        .catch(function () {
          copyMd.textContent = 'Copy failed';
          setTimeout(function () { copyMd.textContent = 'Copy page as Markdown'; }, 1500);
        });
    });
    var view = document.createElement('a');
    view.className = 'guide-source-link';
    view.href = src;
    view.textContent = 'View Markdown source';
    bar.appendChild(copyMd);
    bar.appendChild(view);
    scope.parentNode.insertBefore(bar, scope);
  }

  // The layout-affecting enhancements run at once: deferring them behind the
  // Prism wait would shift the article down after it had already rendered.
  // Only the highlighting waits for the deferred Prism scripts.
  addSourceBar(container);
  addCopyButtons(container);
  var tries = 20;
  (function highlightWhenReady() {
    if (window.Prism && typeof window.Prism.highlightAllUnder === 'function') {
      window.Prism.highlightAllUnder(container);
      return;
    }
    if (tries-- > 0) setTimeout(highlightWhenReady, 100);
  })();
})();
