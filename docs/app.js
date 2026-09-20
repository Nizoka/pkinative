/* ═══════════════════════════════════════════════════════════════
   pkinative.dev — Interactions
   Theme toggle, hamburger menu, copy-to-clipboard, code tabs.
   Ported from the pdfnative charter by way of zipnative: same behaviours,
   same storage key, same keyboard contract.

   Two of the charter's blocks are absent because they have nothing to act
   on here. The install switcher needs more than one install target, and
   pkinative has one. The GitHub star counter is a network call whose answer
   on a pre-1.0 repository is weaker than the conformance numbers already in
   the metrics strip, so it would cost a request to say less.

   Everything below is progressive enhancement: the page is complete and
   readable with this file blocked. The one thing it cannot do without
   JavaScript is switch theme, which then follows prefers-color-scheme.
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ── Theme toggle ──────────────────────────────────────────
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

  // ── Hamburger menu ────────────────────────────────────────
  var hamburger = document.querySelector('.nav-hamburger');
  var navLinks = document.querySelector('.nav-links');

  if (hamburger && navLinks) {
    hamburger.addEventListener('click', function () {
      var open = navLinks.classList.toggle('open');
      hamburger.setAttribute('aria-expanded', String(open));
      hamburger.textContent = open ? '✕' : '☰';
    });
    navLinks.querySelectorAll('a').forEach(function (a) {
      a.addEventListener('click', function () {
        navLinks.classList.remove('open');
        hamburger.setAttribute('aria-expanded', 'false');
        hamburger.textContent = '☰';
      });
    });
  }

  // ── Copy to clipboard ─────────────────────────────────────
  // One helper for every copy affordance: the Clipboard API exists only in
  // secure contexts, so it is guarded and falls back to execCommand on a
  // temporary textarea rather than throwing inside the handler.
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (res, rej) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (_) { /* fall through */ }
      ta.remove();
      if (ok) res(); else rej(new Error('Clipboard unavailable'));
    });
  }

  function flash(btn, mark) {
    var prev = btn.innerHTML;
    btn.classList.add('copied');
    btn.innerHTML = mark;
    setTimeout(function () {
      btn.innerHTML = prev;
      btn.classList.remove('copied');
    }, 1500);
  }

  document.querySelectorAll('.copy-btn[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy');
      if (!text) return;
      copyText(text).then(function () { flash(btn, '✓'); }, function () { flash(btn, '✗'); });
    });
  });

  // "Copy as prompt": fetch a same-origin document and copy its text — the
  // agent-brief pattern shared with both siblings.
  document.querySelectorAll('[data-copy-url]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var url = btn.getAttribute('data-copy-url');
      if (!url) return;
      var prev = btn.textContent;
      fetch(url).then(function (r) {
        if (!r.ok) throw new Error(String(r.status));
        return r.text();
      }).then(copyText).then(function () {
        btn.textContent = '✓ Copied';
      }, function () {
        btn.textContent = '✗ Copy failed';
      }).then(function () {
        setTimeout(function () { btn.textContent = prev; }, 1500);
      });
    });
  });

  // ── Code tabs ─────────────────────────────────────────────
  // Scoped to the Examples section so a future tablist elsewhere on the page
  // is never captured by this one.
  var exampleTabBar = document.querySelector('#examples .tab-bar');
  var tabBtns = exampleTabBar ? exampleTabBar.querySelectorAll('.tab-btn') : [];
  var tabPanels = document.querySelectorAll('.tab-panel');

  function activateTab(btn) {
    var id = btn.getAttribute('data-tab');
    tabBtns.forEach(function (b) {
      b.classList.remove('active');
      b.setAttribute('aria-selected', 'false');
      b.setAttribute('tabindex', '-1');
    });
    tabPanels.forEach(function (p) { p.classList.remove('active'); });
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    btn.setAttribute('tabindex', '0');
    var panel = document.getElementById('tab-' + id);
    if (panel) panel.classList.add('active');
  }

  tabBtns.forEach(function (btn, i) {
    btn.addEventListener('click', function () { activateTab(btn); });
    // WAI-ARIA tabs pattern: arrow keys move and activate, Home/End jump.
    btn.addEventListener('keydown', function (e) {
      var next = null;
      if (e.key === 'ArrowRight') next = (i + 1) % tabBtns.length;
      else if (e.key === 'ArrowLeft') next = (i - 1 + tabBtns.length) % tabBtns.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabBtns.length - 1;
      if (next === null) return;
      e.preventDefault();
      tabBtns[next].focus();
      activateTab(tabBtns[next]);
    });
  });
})();
