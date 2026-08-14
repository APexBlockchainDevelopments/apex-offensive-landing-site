/*
 * APex Offensive — research beacon.
 *
 * Purpose: decide whether the client that submits the contact form actually
 * executed this page. Nearly every mass form-abuse tool POSTs directly to the
 * endpoint it scraped out of the HTML, because rendering costs money. A signed
 * nonce obtainable only by running this file splits the population on the very
 * first request.
 *
 * This is an INSTRUMENT, not a defence. It never blocks, never alters the form's
 * behaviour, and fails open in every error path — a broken beacon must degrade to
 * "the contact form still works", never to "the contact form is down".
 *
 * Signals collected here are deliberately COARSE: they discriminate headless
 * automation from real browsers while being close to useless for identifying an
 * individual person. See research/ETHICS.md section 3 before adding anything.
 */
(function () {
  'use strict';

  // Set to the CloudFront hostname in front of the collector API once INFRA.md
  // step 1 is done — the raw execute-api URL yields no JA3/JA4.
  var API = window.__APEX_TELEMETRY_API__ ||
            'https://2b88s68jnd.execute-api.us-east-1.amazonaws.com/prod';

  // Turning this on materially changes the IRB and GDPR posture: canvas and audio
  // hashes are durable cross-site identifiers for human visitors, not just bots.
  // Do not enable without specific approval. See ETHICS.md section 3.
  var INVASIVE = false;

  var state = {
    nonce: null,
    loadedAt: Date.now(),
    mouse: 0,
    keys: 0,
    scroll: 0,
    paste: 0,
    focusOrder: [],
    programmaticFill: false
  };

  /* ------------------------------------------------------------ nonce acquisition */

  function requestNonce() {
    try {
      fetch(API + '/prep', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ t: state.loadedAt })
      })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { if (d && d.nonce) state.nonce = d.nonce; })
        .catch(function () { /* fail open: submission proceeds without a nonce */ });
    } catch (e) { /* fail open */ }
  }

  /* ------------------------------------------------------ interaction observation */

  function countEvents() {
    // Passive listeners so nothing here can affect scrolling or input latency.
    var opts = { passive: true, capture: true };
    document.addEventListener('mousemove', function () { state.mouse++; }, opts);
    document.addEventListener('keydown', function () { state.keys++; }, opts);
    document.addEventListener('scroll', function () { state.scroll++; }, opts);
    document.addEventListener('paste', function () { state.paste++; }, opts);
    document.addEventListener('touchstart', function () { state.mouse++; }, opts);

    document.addEventListener('focusin', function (e) {
      var t = e.target;
      if (!t || !t.tagName) return;
      if (/^(INPUT|SELECT|TEXTAREA)$/.test(t.tagName) && state.focusOrder.length < 24) {
        // Field identity only — never the value.
        state.focusOrder.push((t.getAttribute('name') || t.type || 'x') + ':' +
                              (Date.now() - state.loadedAt));
      }
    }, opts);
  }

  /*
   * Programmatic-fill detection.
   *
   * A human types, pastes, or uses autofill — all of which produce input events.
   * An automation harness assigns `element.value = "..."` directly, which does not.
   * Wrapping the native value setter catches the assignment itself. Selenium and
   * Playwright driving real key events will NOT trip this, which is the point: it
   * separates "scripted DOM manipulation" from "driven browser", two different
   * populations that a naive timing check would merge.
   */
  function watchProgrammaticFill() {
    try {
      ['HTMLInputElement', 'HTMLTextAreaElement'].forEach(function (ctor) {
        var proto = window[ctor] && window[ctor].prototype;
        if (!proto) return;
        var desc = Object.getOwnPropertyDescriptor(proto, 'value');
        if (!desc || !desc.set || !desc.configurable) return;
        Object.defineProperty(proto, 'value', {
          configurable: true,
          enumerable: desc.enumerable,
          get: desc.get,
          set: function (v) {
            // Ignore our own reset-on-success, which also assigns programmatically.
            if (v !== '' && this.form && this.form.classList.contains('contact-form')) {
              state.programmaticFill = true;
            }
            return desc.set.call(this, v);
          }
        });
      });
    } catch (e) { /* fail open */ }
  }

  /* ---------------------------------------------------------------- client signals */

  function clientSignals() {
    var n = navigator, s = window.screen || {};
    var out = {
      // The single most direct automation tell; trivially spoofed, still worth having
      // because the population that does not bother to spoof it is large.
      webdriver: n.webdriver === true,
      plugins: (n.plugins && n.plugins.length) || 0,
      languages: (n.languages || []).slice(0, 6).join(','),
      hc: n.hardwareConcurrency || null,
      dm: n.deviceMemory || null,
      screen: (s.width || 0) + 'x' + (s.height || 0) + 'x' + (s.colorDepth || 0),
      dpr: window.devicePixelRatio || null,
      tz: new Date().getTimezoneOffset(),
      touch: ('ontouchstart' in window) || (n.maxTouchPoints || 0) > 0,
      uad_mobile: (n.userAgentData && n.userAgentData.mobile) || null,
      perf_ms: null
    };

    try {
      var nav = performance.getEntriesByType('navigation')[0];
      if (nav) out.perf_ms = Math.round(nav.domContentLoadedEventEnd);
    } catch (e) { /* ignore */ }

    // Consistency checks are stronger than any single value: a UA claiming mobile on a
    // 1920x1080 non-touch display is a spoof, and the mismatch survives UA rotation.
    out.inconsistent = [];
    if (out.uad_mobile === true && !out.touch) out.inconsistent.push('mobile_no_touch');
    if (/Mobile|Android|iPhone/i.test(n.userAgent) && s.width > 1400) {
      out.inconsistent.push('mobile_ua_desktop_screen');
    }
    if (out.plugins === 0 && !/Firefox/i.test(n.userAgent) && !out.touch) {
      out.inconsistent.push('no_plugins_desktop');
    }
    if (n.languages && n.languages.length === 0) out.inconsistent.push('empty_languages');
    out.inconsistent = out.inconsistent.join(',');

    if (INVASIVE) out.canvas = canvasHash();
    return out;
  }

  function canvasHash() {
    try {
      var c = document.createElement('canvas');
      c.width = 200; c.height = 40;
      var ctx = c.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(0, 0, 100, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('apex-research', 2, 15);
      var d = c.toDataURL();
      var h = 0;
      for (var i = 0; i < d.length; i++) { h = ((h << 5) - h + d.charCodeAt(i)) | 0; }
      return String(h);
    } catch (e) { return null; }
  }

  /* ------------------------------------------------------------------ public API */

  window.__apexBeacon = {
    /* Returns the fields the form merges into its POST body. Never throws. */
    collect: function () {
      try {
        var sig = clientSignals();
        return {
          _nonce: state.nonce,
          _telemetry: {
            dwell_ms: Date.now() - state.loadedAt,
            mouse: state.mouse,
            keys: state.keys,
            scroll: state.scroll,
            paste: state.paste,
            focus_order: state.focusOrder.join('|'),
            programmatic_fill: state.programmaticFill,
            webdriver: sig.webdriver,
            plugins: sig.plugins,
            languages: sig.languages,
            hc: sig.hc,
            dm: sig.dm,
            screen: sig.screen,
            dpr: sig.dpr,
            tz: sig.tz,
            touch: sig.touch,
            uad_mobile: sig.uad_mobile,
            perf_ms: sig.perf_ms,
            inconsistent: sig.inconsistent,
            canvas: sig.canvas || null
          }
        };
      } catch (e) {
        return {};
      }
    },

    /* Honeypot values, read straight from the DOM at submit time. */
    traps: function () {
      var out = {};
      try {
        ['website', 'phone2', 'company_url'].forEach(function (n) {
          var el = document.querySelector('[name="' + n + '"]');
          if (el && el.value) out[n] = el.value.slice(0, 500);
        });
      } catch (e) { /* ignore */ }
      return out;
    }
  };

  /* --------------------------------------------------------------------- startup */

  try {
    watchProgrammaticFill();
    countEvents();
    requestNonce();
  } catch (e) { /* fail open */ }
})();
