/* APM approval panel: Touch ID glyph and sheet show/hide, from the approved
   prototype's touchid.js. Classic script. Defines window.TouchIdGlyph and
   window.ApmSheet. */
(function () {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var mq = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  function reduced() { return !!(mq && mq.matches); }

  /* ---------- easing ---------- */

  function cubic(x1, y1, x2, y2) {
    function A(a1, a2) { return 1 - 3 * a2 + 3 * a1; }
    function B(a1, a2) { return 3 * a2 - 6 * a1; }
    function C(a1) { return 3 * a1; }
    function calc(t, a1, a2) { return ((A(a1, a2) * t + B(a1, a2)) * t + C(a1)) * t; }
    function slope(t, a1, a2) { return 3 * A(a1, a2) * t * t + 2 * B(a1, a2) * t + C(a1); }
    return function (x) {
      if (x <= 0) return 0;
      if (x >= 1) return 1;
      var t = x;
      for (var i = 0; i < 8; i++) {
        var s = slope(t, x1, x2);
        if (Math.abs(s) < 1e-6) break;
        t -= (calc(t, x1, x2) - x) / s;
      }
      if (!(t >= 0 && t <= 1)) {
        var lo = 0, hi = 1;
        t = x;
        for (var j = 0; j < 24; j++) {
          if (calc(t, x1, x2) < x) lo = t; else hi = t;
          t = (lo + hi) / 2;
        }
      }
      return calc(t, y1, y2);
    };
  }
  var EASE = {
    linear: function (x) { return x; },
    out: cubic(0.16, 1, 0.3, 1),
    inOut: cubic(0.65, 0, 0.35, 1),
    spring: cubic(0.34, 1.4, 0.64, 1)
  };

  /* rAF tween. Resolves true when finished, false if cancelled (alive() turned false). */
  function tween(ms, ease, fn, alive) {
    return new Promise(function (resolve) {
      if (!alive()) return resolve(false);
      if (ms <= 0) { fn(1); return resolve(true); }
      var start = null;
      function frame(now) {
        if (!alive()) return resolve(false);
        if (start === null) start = now;
        var p = Math.min(1, (now - start) / ms);
        fn(ease(p));
        if (p < 1) requestAnimationFrame(frame); else resolve(true);
      }
      requestAnimationFrame(frame);
    });
  }
  function delay(ms, alive) {
    return new Promise(function (resolve) { setTimeout(function () { resolve(alive()); }, ms); });
  }

  /* ---------- fingerprint glyph (64 viewBox) ---------- */

  /* Apple's Touch ID symbol: SF Symbols "touchid", light weight, exact vector outline. */
  var GLYPH_D = 'M6.272 86.656C7.771 86.171 8.496 84.703 8.018 82.774C6.423 76.695 5.656 69.070 5.864 60.781C5.864 58.953 4.851 57.864 3.276 57.780C1.326 57.655 0.192 58.869 0.108 60.531C-0.267 67.698 0.288 76.598 2.463 84.436C3.028 86.254 4.610 87.146 6.272 86.656ZM3.889 50.119C5.391 50.722 7.296 50.073 7.987 48.123C17.852 19.640 42.082 5.756 66.485 5.756C78.241 5.756 87.086 8.511 94.171 12.814C95.840 13.789 97.787 13.606 98.519 11.978C99.334 10.153 98.363 8.981 97.031 8.134C88.502 2.710 78.890 0.000 66.485 0.000C39.142 0.000 13.428 14.810 2.428 45.323C1.529 47.770 2.428 49.515 3.889 50.119ZM131.956 71.806C133.580 71.806 134.790 70.429 134.627 68.608C132.095 44.537 123.352 27.839 109.321 15.865C107.937 14.605 106.115 14.862 105.185 15.875C104.138 16.968 104.058 18.748 105.561 20.091C118.212 31.613 126.961 46.630 129.038 68.729C129.201 70.467 130.294 71.806 131.956 71.806ZM14.121 104.725C15.016 106.099 17.001 106.425 18.499 105.173C22.817 101.532 25.053 95.460 25.015 89.640C24.901 80.875 21.229 76.751 21.229 65.619C21.229 41.578 41.603 21.204 65.682 21.204C95.860 21.204 114.547 45.402 114.699 80.536C114.775 93.603 112.726 103.676 110.077 110.337C109.387 112.071 110.108 113.737 111.410 114.348C112.870 115.000 114.702 114.431 115.389 112.693C118.121 105.185 120.421 94.301 120.421 80.532C120.421 42.068 99.344 15.482 65.682 15.482C38.442 15.482 15.507 38.455 15.507 65.619C15.507 76.010 19.339 82.986 19.419 89.598C19.419 93.829 17.751 98.007 14.728 100.631C13.472 101.724 13.229 103.431 14.121 104.725ZM40.896 83.547C39.118 79.022 36.718 73.195 36.718 66.460C36.718 49.277 49.340 36.614 66.485 36.614C72.644 36.614 75.900 37.663 81.032 40.485C82.691 41.286 84.144 40.842 84.790 39.704C85.525 38.358 85.299 36.578 83.374 35.378C78.892 32.608 72.702 30.892 66.485 30.892C46.138 30.892 30.955 46.075 30.955 66.460C30.955 73.238 32.807 79.618 35.334 85.736C36.104 87.519 37.641 88.251 39.432 87.561C40.896 86.950 41.503 85.250 40.896 83.547ZM27.796 116.068C32.383 113.679 38.687 105.655 40.369 99.123C40.737 97.555 39.977 95.924 38.433 95.431C36.972 94.983 35.508 95.795 34.939 97.457C33.226 103.517 29.757 107.771 25.242 110.884C23.379 112.178 23.174 113.837 23.778 115.051C24.461 116.311 26.047 117.005 27.796 116.068ZM90.437 48.600C96.381 57.372 99.335 69.906 99.335 84.217C99.335 99.333 95.215 114.025 88.246 123.073C87.354 124.288 87.157 126.071 88.253 127.243C89.433 128.454 91.657 128.451 92.670 126.993C100.360 116.595 104.973 100.578 104.973 84.016C104.973 66.812 101.279 54.755 95.503 45.629C94.372 43.815 92.550 43.406 91.208 44.172C89.743 44.984 89.219 46.854 90.437 48.600ZM40.806 124.175C50.720 116.182 56.195 103.431 56.116 89.210C56.036 78.502 52.201 71.796 52.201 65.663C52.201 57.546 57.932 52.138 66.104 52.138C78.397 52.138 83.245 65.189 83.495 83.351C83.867 102.962 76.773 119.024 67.518 127.342C66.342 128.393 66.092 130.017 66.984 131.238C67.917 132.543 69.867 132.824 71.241 131.606C81.123 122.605 89.005 103.699 88.925 83.021C88.845 61.414 82.384 46.416 66.104 46.416C55.052 46.416 46.562 53.972 46.562 65.249C46.562 72.015 50.273 80.518 50.352 89.210C50.432 101.644 45.696 112.657 37.163 119.633C35.785 120.809 35.581 122.506 36.431 123.765C37.489 125.188 39.356 125.424 40.806 124.175ZM54.923 129.199C59.902 125.572 65.597 118.254 68.508 109.349C68.906 108.027 68.553 106.195 67.005 105.626C65.294 105.095 63.761 105.834 63.237 107.284C59.940 116.177 55.766 121.270 51.470 124.536C50.135 125.591 49.774 127.294 50.624 128.630C51.516 130.049 53.466 130.288 54.923 129.199ZM71.982 95.685C73.844 87.635 73.023 76.385 69.840 67.569C69.080 65.516 67.582 64.894 65.958 65.380C64.421 65.866 63.605 67.361 64.171 69.144C67.225 77.637 67.928 87.351 66.306 94.835C65.983 96.375 66.632 97.877 68.416 98.158C70.116 98.481 71.580 97.510 71.982 95.685Z';
  var GLYPH_W = 134.642, GLYPH_H = 132.384;
  /* Fit into the 64 viewBox with 2 units of air on each side. */
  var GLYPH_S = 60 / Math.max(GLYPH_W, GLYPH_H);
  var GLYPH_T = 'translate(' + (32 - GLYPH_W * GLYPH_S / 2).toFixed(3) + ' ' + (32 - GLYPH_H * GLYPH_S / 2).toFixed(3) + ') scale(' + GLYPH_S.toFixed(5) + ')';

  var RING_R = 26, RING_C = 2 * Math.PI * RING_R;
  var CHECK_D = 'M21 33 l7 7 l15 -16';
  var CHECK_L = Math.hypot(7, 7) + Math.hypot(15, 16);
  var BAND = 22;

  function svgEl(tag, attrs) {
    var n = document.createElementNS(NS, tag);
    if (attrs) for (var k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }

  var uid = 0;

  /* TouchIdGlyph.mount(container, { size = 60, ridges = true }) -> controller */
  function mount(container, opts) {
    opts = opts || {};
    var size = opts.size || 60;
    var withRidges = opts.ridges !== false;
    var id = 'tid' + (++uid) + Math.random().toString(36).slice(2, 6);

    var svg = svgEl('svg', {
      viewBox: '0 0 64 64', width: size, height: size,
      class: 'tid-glyph', 'aria-hidden': 'true', focusable: 'false'
    });
    svg.style.display = 'block';
    svg.style.overflow = 'visible';

    var defs = svgEl('defs');
    var grad = svgEl('linearGradient', { id: id + 'g', gradientUnits: 'userSpaceOnUse', x1: 0, y1: 6, x2: 0, y2: 58 });
    grad.appendChild(svgEl('stop', { offset: 0, 'stop-color': '#ff6482' }));
    grad.appendChild(svgEl('stop', { offset: 1, 'stop-color': '#ff2d55' }));
    var bandGrad = svgEl('linearGradient', { id: id + 'b', x1: 0, y1: 0, x2: 0, y2: 1 });
    bandGrad.appendChild(svgEl('stop', { offset: 0, 'stop-color': '#fff', 'stop-opacity': 0 }));
    bandGrad.appendChild(svgEl('stop', { offset: 0.45, 'stop-color': '#fff', 'stop-opacity': 1 }));
    bandGrad.appendChild(svgEl('stop', { offset: 1, 'stop-color': '#fff', 'stop-opacity': 0 }));
    /* The "rising rect": a soft-edged band that clips the lit duplicate ridges. */
    var mask = svgEl('mask', { id: id + 'm', maskUnits: 'userSpaceOnUse', x: -8, y: -32, width: 80, height: 128 });
    var band = svgEl('rect', { x: -8, y: 64, width: 80, height: BAND, fill: 'url(#' + id + 'b)' });
    mask.appendChild(band);
    defs.appendChild(grad);
    defs.appendChild(bandGrad);
    defs.appendChild(mask);
    svg.appendChild(defs);

    var body = svgEl('g', { class: 'tid-body' });
    svg.appendChild(body);

    function ridgeGroup(cls, fill) {
      var g = svgEl('g', { class: cls });
      var p = svgEl('path', { d: GLYPH_D, transform: GLYPH_T });
      p.style.fill = fill;
      g.appendChild(p);
      body.appendChild(g);
      return { g: g };
    }

    var ridges = null, danger = null, lit = null;
    if (withRidges) {
      ridges = ridgeGroup('tid-ridges', 'url(#' + id + 'g)');
      danger = ridgeGroup('tid-danger', 'var(--danger)');
      lit = ridgeGroup('tid-lit', '#ffffff');
      lit.g.setAttribute('mask', 'url(#' + id + 'm)');
    }

    var ring = svgEl('circle', {
      class: 'tid-ring', cx: 32, cy: 32, r: RING_R, fill: 'none',
      'stroke-width': 3, 'stroke-linecap': 'round', transform: 'rotate(-90 32 32)'
    });
    ring.style.stroke = 'var(--success)';
    ring.style.strokeDasharray = RING_C + ' ' + (RING_C + 4);
    var check = svgEl('path', {
      class: 'tid-check', d: CHECK_D, fill: 'none',
      'stroke-width': 3, 'stroke-linecap': 'round', 'stroke-linejoin': 'round'
    });
    check.style.stroke = 'var(--success)';
    check.style.strokeDasharray = CHECK_L + ' ' + (CHECK_L + 4);
    body.appendChild(ring);
    body.appendChild(check);

    container.appendChild(svg);

    /* ---------- state ---------- */

    var token = 0, s = 1, tx = 0, done = false;
    function begin() { var my = ++token; return function () { return my === token; }; }
    function apply() {
      body.setAttribute('transform',
        'translate(' + tx.toFixed(3) + ' 0) translate(32 32) scale(' + s.toFixed(4) + ') translate(-32 -32)');
    }
    function idle() {
      s = 1; tx = 0; apply();
      if (ridges) {
        ridges.g.removeAttribute('transform');
        ridges.g.style.opacity = '1';
        danger.g.style.opacity = '0';
        lit.g.style.opacity = '0';
        band.setAttribute('y', 64);
      }
      ring.style.strokeDashoffset = String(RING_C + 2);
      ring.style.opacity = '0';
      check.style.strokeDashoffset = String(CHECK_L + 2);
      check.style.opacity = '0';
      done = false;
    }
    function showDone() {
      s = 1; tx = 0; apply();
      if (ridges) {
        ridges.g.style.opacity = '0';
        danger.g.style.opacity = '0';
        lit.g.style.opacity = '0';
      }
      ring.style.opacity = '1';
      ring.style.strokeDashoffset = '0';
      check.style.opacity = '1';
      check.style.strokeDashoffset = '0';
      done = true;
    }

    /* Ridges undraw outer -> inner, ring draws, check draws ~120ms after the ring starts. */
    function finale(alive) {
      if (reduced()) { showDone(); return Promise.resolve(true); }
      var jobs = [];
      if (ridges) {
        lit.g.style.opacity = '0';
        danger.g.style.opacity = '0';
        jobs.push(tween(200, EASE.inOut, function (v) {
          ridges.g.style.opacity = String(1 - v);
          ridges.g.setAttribute('transform', 'translate(32 32) scale(' + (1 - 0.18 * v).toFixed(4) + ') translate(-32 -32)');
        }, alive));
      }
      jobs.push(delay(40, alive).then(function (ok) {
        if (!ok) return false;
        ring.style.opacity = '1';
        return tween(320, EASE.out, function (v) {
          ring.style.strokeDashoffset = ((1 - v) * (RING_C + 2)).toFixed(2);
        }, alive);
      }));
      jobs.push(delay(160, alive).then(function (ok) {
        if (!ok) return false;
        check.style.opacity = '1';
        return tween(220, EASE.out, function (v) {
          check.style.strokeDashoffset = ((1 - v) * (CHECK_L + 2)).toFixed(2);
        }, alive);
      }));
      return Promise.all(jobs).then(function () {
        if (!alive()) return false;
        showDone();
        return true;
      });
    }

    function scan() {
      var alive = begin();
      idle();
      if (reduced() || !ridges) return finale(alive);
      lit.g.style.opacity = '1';
      band.setAttribute('y', 62);
      var press = tween(110, EASE.out, function (v) { s = 1 - 0.06 * v; apply(); }, alive)
        .then(function (ok) {
          return ok && tween(380, EASE.spring, function (v) { s = 0.94 + 0.06 * v; apply(); }, alive);
        });
      var sweep = delay(70, alive).then(function (ok) {
        return ok && tween(450, EASE.inOut, function (v) {
          band.setAttribute('y', (62 - v * (62 + BAND)).toFixed(2));
        }, alive);
      });
      return Promise.all([press, sweep]).then(function () {
        if (!alive()) return false;
        lit.g.style.opacity = '0';
        s = 1; apply();
        return finale(alive);
      });
    }

    function tick() {
      var alive = begin();
      idle();
      return finale(alive);
    }

    function fail() {
      var alive = begin();
      idle();
      if (!ridges) return Promise.resolve(true);
      if (reduced()) {
        danger.g.style.opacity = '1';
        return delay(700, alive).then(function (ok) {
          if (ok) danger.g.style.opacity = '0';
          return ok;
        });
      }
      var flash = tween(90, EASE.out, function (v) { danger.g.style.opacity = String(v); }, alive);
      var shake = tween(420, EASE.linear, function (p) {
        /* Damped sine; envelope follows ease-in-out so it settles smoothly. */
        tx = 6 * Math.sin(p * Math.PI * 6) * (1 - EASE.inOut(p));
        apply();
      }, alive);
      return Promise.all([flash, shake]).then(function () {
        if (!alive()) return false;
        tx = 0; apply();
        return tween(260, EASE.inOut, function (v) { danger.g.style.opacity = String(1 - v); }, alive);
      });
    }

    function dim(on) {
      svg.style.transition = reduced() ? 'none' : 'opacity 200ms cubic-bezier(.65,0,.35,1)';
      svg.style.opacity = on ? '0.35' : '1';
    }

    function reset() {
      begin();
      idle();
      dim(false);
    }

    function destroy() {
      begin();
      if (svg.parentNode) svg.parentNode.removeChild(svg);
    }

    idle();

    return {
      el: svg,
      scan: scan,
      tick: tick,
      fail: fail,
      dim: dim,
      reset: reset,
      destroy: destroy,
      get done() { return done; }
    };
  }

  /* ---------- sheet show / hide ---------- */

  function playClass(el, cls, fallbackMs, seq) {
    return new Promise(function (resolve) {
      var finished = false, timer = 0;
      function fin() {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        el.removeEventListener('animationend', onEnd);
        resolve(el._apmSheetSeq === seq);
      }
      function onEnd(e) { if (e.target === el) fin(); }
      el.addEventListener('animationend', onEnd);
      timer = setTimeout(fin, fallbackMs);
      el.classList.remove(cls);
      void el.offsetWidth;
      el.classList.add(cls);
    });
  }

  function show(el) {
    var seq = el._apmSheetSeq = (el._apmSheetSeq || 0) + 1;
    el.classList.remove('is-leaving', 'is-entering', 'is-gone', 'is-pre');
    if (reduced()) return Promise.resolve();
    return playClass(el, 'is-entering', 600, seq).then(function (current) {
      if (current) el.classList.remove('is-entering');
    });
  }

  function hide(el) {
    var seq = el._apmSheetSeq = (el._apmSheetSeq || 0) + 1;
    el.classList.remove('is-entering');
    if (el.classList.contains('is-gone')) { el.classList.remove('is-leaving'); return Promise.resolve(); }
    if (reduced()) { el.classList.add('is-gone'); return Promise.resolve(); }
    return playClass(el, 'is-leaving', 500, seq).then(function (current) {
      if (!current) return;
      el.classList.add('is-gone');
      el.classList.remove('is-leaving');
    });
  }

  window.TouchIdGlyph = { mount: mount };
  window.ApmSheet = { show: show, hide: hide };
})();
