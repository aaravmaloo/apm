/* APM approval panel: page logic. pm renders the sheet's text into the page
   and its helper (prompt.js) hosts it in a WKWebView. The page talks to the
   helper through three script message handlers:

     size   {height}             the panel height the sheet needs
     slot   {x, y, width, height} | null
                                 where to draw the system Touch ID glyph (CSS px
                                 from the top left), or null to stop Touch ID
     decide {approve, via} | {expired: true}
                                 the answer; the helper prints it and exits

   The helper calls back with window.apm.show() once the panel is on screen and
   window.apm.touch({ok, code, lock}) when a Touch ID check ends. It sets
   window.apmTouch before the page loads when the glyph can be armed. */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var root = document.documentElement;
  var sheet = $('sheet');
  var cap = $('cap');
  var D = sheet.dataset;

  var CAP = D.cap;
  var DONE = D.done;
  var WRONG = 'Not recognized. Try again.';
  var LOCKED = 'Too many tries. Use the buttons.';
  var LOCKED_TOUCH_ONLY = 'Too many tries. This request needs Touch ID.';
  /* MCP settings can say only a touch approves (data-approve-with="touchid"):
     while Touch ID is there, Approve is disabled and Space does nothing.
     Without Touch ID on this Mac the buttons and Space approve as usual. */
  var TOUCH_ONLY = D.approveWith === 'touchid';
  var MAX_FAILS = 3;

  var S = {
    phase: 'idle',     /* idle | pending | approving | done */
    touch: window.apmTouch === true,
    armed: false,      /* the helper should have the system glyph up */
    fails: 0,
    busy: false,
    locked: false,
    touchGone: false,  /* the system locked Touch ID: no longer required */
    glyph: null,
    capTimer: 0,
    ttlTimer: 0,
    deadline: Number(D.expires) || 0
  };

  function post(name, body) {
    try { window.webkit.messageHandlers[name].postMessage(body); } catch (e) { /* not in the helper */ }
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function setCaption(text, kind) {
    cap.textContent = text;
    cap.classList.toggle('is-err', kind === 'err');
    cap.classList.toggle('is-ok', kind === 'ok');
  }

  /* With the system glyph drawn over the slot, the page's own ridges stay
     hidden; the ring, the check and the failure shake are still the page's. */
  function mountGlyph(ridges) {
    if (S.glyph) S.glyph.destroy();
    S.glyph = window.TouchIdGlyph.mount($('slot'), { size: 60, ridges: ridges });
  }

  /* ---------- geometry ---------- */

  function postSize() {
    var cs = getComputedStyle(root);
    var top = parseFloat(cs.getPropertyValue('--gutter')) || 24;
    var bottom = parseFloat(cs.getPropertyValue('--gutter-bottom')) || 48;
    post('size', { height: Math.ceil(sheet.offsetHeight + top + bottom) });
  }

  /* Layout position, so the entrance transform doesn't skew it. */
  function slotRect() {
    var el = $('slot');
    var x = 0, y = 0;
    for (var n = el; n; n = n.offsetParent) { x += n.offsetLeft; y += n.offsetTop; }
    return { x: x, y: y, width: el.offsetWidth, height: el.offsetHeight };
  }

  function arm() {
    if (!S.touch || S.locked || S.phase !== 'pending') return;
    S.armed = true;
    post('slot', slotRect());
  }
  function disarm() {
    if (!S.armed) return;
    S.armed = false;
    post('slot', null);
  }

  /* ---------- countdown ---------- */

  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmt(sec) { return pad(Math.floor(sec / 60)) + ':' + pad(sec % 60); }
  function tickTtl() {
    var ms = Math.max(0, S.deadline - Date.now());
    $('ttl').textContent = fmt(Math.ceil(ms / 1000));
    if (ms <= 0) {
      clearInterval(S.ttlTimer);
      if (S.phase === 'pending') finish({ expired: true });
    }
  }

  /* ---------- flow ---------- */

  function show() {
    if (S.phase !== 'idle') return;
    S.phase = 'pending';
    tickTtl();
    S.ttlTimer = setInterval(tickTtl, 250);
    window.ApmSheet.show(sheet).then(arm);
  }

  function finish(answer) {
    if (S.phase === 'done') return;
    S.phase = 'done';
    clearInterval(S.ttlTimer);
    clearTimeout(S.capTimer);
    disarm();
    window.ApmSheet.hide(sheet).then(function () { post('decide', answer); });
  }

  /* A finger the system recognised: its glyph is gone, the page draws the tick. */
  function touchOK() {
    if (S.phase !== 'pending') return;
    S.phase = 'approving';
    S.armed = false;
    clearTimeout(S.capTimer);
    setCaption(CAP);
    S.glyph.tick().then(function () {
      setCaption(DONE, 'ok');
      return sleep(450);
    }).then(function () {
      finish({ approve: true, via: 'touchid' });
    });
  }

  /* A check that failed: show the page's ridges for the shake, then re-arm. */
  function touchFail(lock) {
    if (S.phase !== 'pending' || S.busy || S.locked) return;
    S.armed = false;
    S.busy = true;
    S.fails++;
    var lockNow = lock || S.fails >= MAX_FAILS;
    if (lock) {
      S.touchGone = true;
      syncApprove();
    }
    clearTimeout(S.capTimer);
    var lockedText = touchOnly() ? LOCKED_TOUCH_ONLY : LOCKED;
    setCaption(lockNow ? lockedText : WRONG, 'err');
    if (lockNow) {
      S.locked = true;
      post('slot', null);
    } else {
      S.capTimer = setTimeout(function () {
        if (S.phase === 'pending' && !S.locked) setCaption(CAP);
      }, 1800);
    }
    mountGlyph(true);
    S.glyph.fail().then(function () {
      S.busy = false;
      if (S.phase !== 'pending') return;
      if (lockNow) {
        S.glyph.dim(true);
        setCaption(lockedText);
        return;
      }
      mountGlyph(false);
      arm();
    });
  }

  /* Touch ID went away (no longer enrolled, not available): Space instead. */
  function touchOff() {
    if (!S.touch) return;
    S.touch = false;
    S.armed = false;
    keysMode();
  }

  /* After the system's own lockout Touch ID is gone for now: the buttons approve. */
  function touchOnly() { return TOUCH_ONLY && S.touch && !S.touchGone; }

  /* Approve is disabled, with its hint, while only a touch can approve. */
  function syncApprove() {
    var only = touchOnly();
    var btn = $('approveBtn');
    btn.disabled = only;
    var hint = $('approveHint');
    if (hint) hint.hidden = !only;
    if (only) btn.setAttribute('aria-describedby', 'approveHint');
    else btn.removeAttribute('aria-describedby');
  }

  function approve(via) {
    if (S.phase !== 'pending') return;
    if (via !== 'touchid' && touchOnly()) return;
    S.phase = 'approving';
    clearTimeout(S.capTimer);
    disarm();
    if (S.touch) {
      mountGlyph(false);
    } else {
      $('layerKeys').hidden = true;
      var ls = $('layerSensor');
      ls.hidden = false;
      ls.classList.add('is-in');
    }
    S.glyph.tick().then(function () {
      setCaption(DONE, 'ok');
      return sleep(450);
    }).then(function () {
      finish({ approve: true, via: via });
    });
  }

  function reject(via) {
    if (S.phase !== 'pending') return;
    setCaption(D.rejected);
    finish({ approve: false, via: via });
  }

  /* ---------- modes ---------- */

  function touchMode() {
    $('layerSensor').hidden = false;
    $('layerKeys').hidden = true;
    $('approveKbd').hidden = true;
    mountGlyph(false);
    setCaption(CAP);
    syncApprove();
  }
  function keysMode() {
    $('layerSensor').hidden = true;
    $('layerKeys').hidden = false;
    $('approveKbd').hidden = false;
    mountGlyph(false);
    setCaption('');
    syncApprove();
  }

  $('approveBtn').addEventListener('click', function () { approve('click'); });
  $('rejectBtn').addEventListener('click', function () { reject('click'); });
  $('closeBtn').addEventListener('click', function () { reject('click'); });

  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      reject('keyboard');
      return;
    }
    if (e.key === ' ' || e.code === 'Space') {
      /* Let Space press a focused button normally. */
      var ae = document.activeElement;
      if (ae && ae !== document.body && ae.closest('button')) return;
      e.preventDefault();
      if (!S.touch && !e.repeat) approve('keyboard');
    }
  });
  document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  document.addEventListener('dragover', function (e) { e.preventDefault(); });
  document.addEventListener('drop', function (e) { e.preventDefault(); });

  if (window.matchMedia) {
    var dm = window.matchMedia('(prefers-color-scheme: dark)');
    var onScheme = function () { root.setAttribute('data-theme', dm.matches ? 'dark' : 'light'); };
    if (dm.addEventListener) dm.addEventListener('change', onScheme);
    else if (dm.addListener) dm.addListener(onScheme);
  }

  if (window.ResizeObserver) {
    new ResizeObserver(function () {
      postSize();
      if (S.armed) post('slot', slotRect());
    }).observe(sheet);
  }

  window.apm = {
    show: show,
    touch: function (r) {
      r = r || {};
      if (r.ok) touchOK();
      else if (r.off) touchOff();
      else touchFail(!!r.lock);
    }
  };

  if (S.touch) touchMode(); else keysMode();
  var ready = function () { postSize(); };
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(ready, ready); else ready();
})();
