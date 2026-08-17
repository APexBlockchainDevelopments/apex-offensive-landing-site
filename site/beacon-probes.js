/*
 * APex Offensive — deep automation fingerprinting.
 *
 * Loads alongside beacon.js and extends its telemetry with signals that identify a
 * specific automation stack rather than merely "not a human". Written after observing
 * senders that render the page, execute script, and dispatch real key events, which
 * makes the coarse signals in beacon.js insufficient to tell them apart.
 *
 * Same rules as beacon.js: observes only, never blocks, fails open in every path, and
 * cannot break the contact form. Every probe is wrapped because several of these APIs
 * throw in hardened or unusual browsers, and a probe that throws must cost us the
 * probe, not the page.
 *
 * Nothing here touches the client beyond reading properties its own browser exposes
 * while rendering our page. See research/canary/ADVERSARY-PROBES.md section 0.
 */
(function () {
  'use strict';

  function safe(fn, fallback) {
    try {
      var v = fn();
      return (v === undefined) ? (fallback === undefined ? null : fallback) : v;
    } catch (e) {
      return (fallback === undefined) ? null : fallback;
    }
  }

  /* ------------------------------------------- driver and framework artifacts */

  // ChromeDriver injects globals of the form cdc_adoQpoasnfa76pfcZLmcfl_*. Their
  // presence is close to conclusive for Selenium-family automation. Playwright and
  // Puppeteer leave their own markers when not carefully cleaned up.
  function driverArtifacts() {
    var found = [];
    var patterns = [
      /^\$?cdc_/, /^\$?wdc_/,
      /^__playwright/, /^__pw_/, /^__puppeteer/, /^__nightmare/,
      /^_selenium/, /^callSelenium/, /^_Selenium_IDE_Recorder/,
      /^__webdriver/, /^__driver/, /^__fxdriver/, /^__selenium/,
      /^_phantom/, /^__phantomas/, /^callPhantom/,
      /^domAutomation/, /^__lastWatirAlert/
    ];
    safe(function () {
      for (var k in window) {
        for (var i = 0; i < patterns.length; i++) {
          if (patterns[i].test(k)) { found.push(k.slice(0, 60)); break; }
        }
      }
    });
    safe(function () {
      ['webdriver', 'selenium', '__webdriver_script_fn'].forEach(function (a) {
        if (document.documentElement.getAttribute(a) !== null) found.push('attr:' + a);
      });
    });
    return found.slice(0, 12).join(',');
  }

  /* ------------------------------------------------------- headless indicators */

  // Headless Chrome answers 'denied' for notifications while Notification.permission
  // still reads 'default'. Real Chrome keeps the two consistent. Async, so it lands
  // via callback rather than in the synchronous snapshot.
  var permissionMismatch = null;
  safe(function () {
    if (!navigator.permissions || !navigator.permissions.query) return;
    navigator.permissions.query({ name: 'notifications' }).then(function (r) {
      permissionMismatch =
        (r.state === 'denied' && window.Notification &&
         window.Notification.permission === 'default');
    }).catch(function () {});
  });

  // Software rasterisers mean no real GPU, which in practice means headless or a VM.
  function glRenderer() {
    return safe(function () {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return 'no-webgl';
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (!ext) return 'no-debug-ext';
      return String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '').slice(0, 120);
    }, 'error');
  }

  function glVendor() {
    return safe(function () {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return null;
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      return ext ? String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '').slice(0, 80)
                 : null;
    });
  }

  // Stealth plugins commonly override native functions. A patched function's toString
  // no longer reports as native code.
  function patchedNatives() {
    var patched = [];
    safe(function () {
      var checks = {
        'permissions.query': navigator.permissions && navigator.permissions.query,
        'toDataURL': HTMLCanvasElement.prototype.toDataURL,
        'getParameter': window.WebGLRenderingContext &&
                        WebGLRenderingContext.prototype.getParameter,
        'enumerateDevices': navigator.mediaDevices &&
                            navigator.mediaDevices.enumerateDevices,
        'appendChild': Node.prototype.appendChild
      };
      Object.keys(checks).forEach(function (k) {
        var fn = checks[k];
        if (typeof fn !== 'function') return;
        if (Function.prototype.toString.call(fn).indexOf('[native code]') === -1) {
          patched.push(k);
        }
      });
    });
    return patched.join(',');
  }

  // Headless builds typically enumerate no media devices at all.
  var mediaDeviceCount = null;
  safe(function () {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;
    navigator.mediaDevices.enumerateDevices().then(function (d) {
      mediaDeviceCount = d.length;
    }).catch(function () {});
  });

  // V8 in headless produces a distinguishable stack shape. Cheap and surprisingly stable.
  function stackShape() {
    return safe(function () {
      try { null.f(); } catch (err) {
        var s = String(err.stack || '');
        return s.split('\n').length + ':' + (s.indexOf('at ') > -1 ? 'at' : 'plain');
      }
      return null;
    });
  }

  // performance.now() granularity shifts measurably under instrumentation.
  function timerResolution() {
    return safe(function () {
      var deltas = [], last = performance.now();
      for (var i = 0; i < 5000; i++) {
        var t = performance.now();
        if (t !== last) { deltas.push(t - last); last = t; }
      }
      if (!deltas.length) return null;
      return Math.min.apply(null, deltas).toFixed(6);
    });
  }

  /* ------------------------------------------------------------------ collect */

  function snapshot() {
    var n = navigator;
    return {
      driver_artifacts: driverArtifacts(),
      patched_natives: patchedNatives(),
      permission_mismatch: permissionMismatch,
      media_devices: mediaDeviceCount,

      gl_renderer: glRenderer(),
      gl_vendor: glVendor(),

      outer_w: safe(function () { return window.outerWidth; }),
      outer_h: safe(function () { return window.outerHeight; }),
      inner_w: safe(function () { return window.innerWidth; }),
      inner_h: safe(function () { return window.innerHeight; }),
      // Headless has no browser chrome, so outer == inner exactly.
      no_chrome: safe(function () {
        return window.outerHeight === 0 ||
               window.outerHeight === window.innerHeight;
      }),

      has_chrome_obj: safe(function () { return !!window.chrome; }),
      has_chrome_runtime: safe(function () {
        return !!(window.chrome && window.chrome.runtime);
      }),
      has_connection: safe(function () { return !!n.connection; }),
      has_battery: safe(function () { return typeof n.getBattery === 'function'; }),
      pdf_viewer: safe(function () { return n.pdfViewerEnabled; }),
      webdriver: safe(function () { return n.webdriver; }),

      plugin_names: safe(function () {
        return Array.prototype.slice.call(n.plugins || [], 0, 6)
          .map(function (p) { return p.name; }).join('|');
      }, ''),
      mime_count: safe(function () { return (n.mimeTypes || []).length; }),
      lang_count: safe(function () { return (n.languages || []).length; }),
      platform: safe(function () { return n.platform; }),
      ua_data_platform: safe(function () {
        return n.userAgentData && n.userAgentData.platform;
      }),

      stack_shape: stackShape(),
      timer_res: timerResolution(),
      tz_name: safe(function () {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
      })
    };
  }

  /* --------------------------------------------------------------- public API */

  window.__apexProbes = {
    collect: function () {
      try {
        var s = snapshot();

        // A summary flag list is far easier to cluster on than 25 raw fields, and it
        // survives a browser adding or removing any individual API.
        var flags = [];
        if (s.driver_artifacts) flags.push('driver_globals');
        if (s.patched_natives) flags.push('patched_natives');
        if (s.permission_mismatch === true) flags.push('permission_mismatch');
        if (s.media_devices === 0) flags.push('no_media_devices');
        if (/swiftshader|llvmpipe|mesa offscreen|software/i.test(s.gl_renderer || ''))
          flags.push('software_gl');
        if (s.gl_renderer === 'no-webgl') flags.push('no_webgl');
        if (s.no_chrome === true) flags.push('no_browser_chrome');
        if (s.webdriver === true) flags.push('webdriver');
        if (s.lang_count === 0) flags.push('no_languages');
        if (s.mime_count === 0) flags.push('no_mimetypes');
        if (!s.has_chrome_runtime && /Chrome\//.test(navigator.userAgent))
          flags.push('chrome_ua_no_runtime');
        s.flags = flags.join(',');
        s.flag_count = flags.length;

        return s;
      } catch (e) {
        return { error: 'probe_failure' };
      }
    }
  };
})();
