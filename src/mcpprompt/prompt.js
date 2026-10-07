// pm's own approval panel, run with `osascript -l JavaScript` when the APM
// app isn't running. It puts the approval page (page.html, rendered by pm)
// in a WKWebView on a borderless, non-activating panel that floats over every
// window and Space, arms Touch ID in place over the page's glyph when it can,
// and prints the answer as one line ("approve touchid", "reject keyboard",
// "expired" or "error: ...") before it exits. pm kills it when the request is
// answered somewhere else.
//
// pm passes its settings as JSON in APM_PROMPT: {page, reason, approveWith,
// debug}. page is the path of the rendered HTML; reason is the Touch ID
// reason; approveWith "touchid" means only a touch approves while Touch ID is
// there; debug (APM_PROMPT_DEBUG=1) logs what happens to stderr.
//
// LocalAuthentication cancels a check at once (systemCancel) when the app
// asking isn't the active one, so the helper activates itself whenever it
// arms Touch ID, like src/touchid does. A cancelled check is re-armed while
// the panel is key, a little later each time it keeps happening, and again
// as soon as the panel becomes key after the user clicked elsewhere.
ObjC.import('AppKit');
ObjC.import('WebKit');
ObjC.import('LocalAuthentication');

var BIOMETRICS = 1; // LAPolicyDeviceOwnerAuthenticationWithBiometrics
var LA = { failed: -1, userCancel: -2, systemCancel: -4, passcodeNotSet: -5, notAvailable: -6, notEnrolled: -7, lockout: -8, appCancel: -9 };
var WIDTH = 448;
var GLYPH = 64; // LAAuthenticationView draws its glyph at 64pt with the regular control size.
var BORDERLESS_NONACTIVATING = 1 << 7;
var BACKING_BUFFERED = 2;
var ALL_SPACES = 1 << 0, STATIONARY = 1 << 4, FULLSCREEN_AUX = 1 << 8;
var WIDTH_SIZABLE = 2, HEIGHT_SIZABLE = 16, MIN_Y_MARGIN = 8;
var ACCESSORY = 1;
var ANY_EVENT = Math.pow(2, 53) - 1; // NSEventMaskAny doesn't survive the trip through a JS number.
var REARM_MS = 600, REARM_MAX_MS = 5000;

var cfg = {};
var debug = false;
var result = '';
var shown = false;
var app, panel, content, web, touchView = null;
// gone: Touch ID went away (not enrolled, locked by the system), so a request
// that needs it can be approved with the buttons again.
var touch = { session: null, want: null, rearmAt: 0, cancels: 0, wasKey: false, gone: false };

var LA_NAMES = {};
Object.keys(LA).forEach(function (k) { LA_NAMES[LA[k]] = k; });

function log() {
  if (debug) console.log('apm-prompt: ' + Array.prototype.join.call(arguments, ' '));
}

function envString(name) {
  var v = $.NSProcessInfo.processInfo.environment.objectForKey($(name));
  return v && !v.isNil() ? ObjC.unwrap(v) : '';
}

function js(src) {
  web.evaluateJavaScriptCompletionHandler($(src), function () {});
}

// The LAAuthenticationView class (macOS 12+), or null when Touch ID can't be
// shown in place. Without it the page asks for Space instead of popping the
// system dialog.
function touchViewClass() {
  try {
    var ctx = $.LAContext.alloc.init;
    if (!ctx.canEvaluatePolicyError(BIOMETRICS, Ref())) return null;
    var bundle = $.NSBundle.bundleWithPath($('/System/Library/Frameworks/LocalAuthenticationEmbeddedUI.framework'));
    if (!bundle || bundle.isNil() || !bundle.load) return null;
    var cls = $.NSClassFromString($('LAAuthenticationView'));
    return cls && !cls.isNil() ? cls : null;
  } catch (e) {
    log('touch id unavailable:', e);
    return null;
  }
}

// The visible frame of the screen the mouse is on.
function visibleFrame() {
  var m = $.NSEvent.mouseLocation;
  var screens = $.NSScreen.screens;
  var pick = $.NSScreen.mainScreen;
  for (var i = 0; i < screens.count; i++) {
    var s = screens.objectAtIndex(i), f = s.frame;
    if (m.x >= f.origin.x && m.x < f.origin.x + f.size.width && m.y >= f.origin.y && m.y < f.origin.y + f.size.height) {
      pick = s;
      break;
    }
  }
  return pick.visibleFrame;
}

var place = { left: 0, top: 0 };

// Horizontally centred, its top 12% down the visible frame, height from the page.
function frameFor(height) {
  return $.NSMakeRect(place.left, place.top - height, WIDTH, height);
}

// Centres the system glyph on the page's slot (CSS px from the top left).
function placeView(view, r) {
  var h = content.bounds.size.height;
  var x = Math.round(r.x + (r.width - GLYPH) / 2);
  var top = r.y + (r.height - GLYPH) / 2;
  view.setFrame($.NSMakeRect(x, Math.round(h - top - GLYPH), GLYPH, GLYPH));
}

// Brings the helper forward with the panel key, so LocalAuthentication lets
// it run a check. A security prompt taking the focus is fine.
function activate() {
  if (!app.isActive) {
    log('activating the helper');
    app.activateIgnoringOtherApps(true);
  }
  if (!panel.isKeyWindow) panel.makeKeyAndOrderFront($());
}

function touchRequired() {
  return cfg.approveWith === 'touchid' && !!touchView && !touch.gone;
}

function arm(rect) {
  var ctx = $.LAContext.alloc.init;
  if (!ctx.canEvaluatePolicyError(BIOMETRICS, Ref())) {
    log('touch id no longer available');
    touch.want = null;
    touch.gone = true;
    js('window.apm.touch({off:true})');
    return;
  }
  activate();
  var view = touchView.alloc.initWithContextControlSize(ctx, 0);
  view.setAutoresizingMask(MIN_Y_MARGIN);
  placeView(view, rect);
  content.addSubviewPositionedRelativeTo(view, 1, $());
  var s = { ctx: ctx, view: view, done: false, ok: false, code: 0, started: Date.now() };
  touch.session = s;
  log('touch id armed, active', !!app.isActive, 'key', !!panel.isKeyWindow);
  // The reply comes on another thread: only note the outcome here, pump()
  // acts on it on the main thread.
  ctx.evaluatePolicyLocalizedReasonReply(BIOMETRICS, $(cfg.reason || 'approve a change'), function (ok, err) {
    var code = 0;
    if (!ok) {
      try { code = Number(err.code); } catch (e) { code = LA.failed; }
    }
    s.ok = !!ok;
    s.code = code;
    s.done = true;
  });
}

// Stops the check in flight. A cancelled check never reports success, even if
// a finger lands while the cancel is on its way.
function cancelTouch() {
  var s = touch.session;
  if (!s) return;
  touch.session = null;
  s.view.removeFromSuperview;
  s.ctx.invalidate;
}

function pump() {
  var s = touch.session;
  if (s && s.done) {
    touch.session = null;
    s.view.removeFromSuperview;
    var took = Date.now() - s.started;
    log('touch id result', s.ok ? 'ok' : (LA_NAMES[s.code] || 'error') + ' (' + s.code + ')', 'after', took + 'ms',
      'active', !!app.isActive, 'key', !!panel.isKeyWindow);
    if (s.ok) {
      touch.want = null;
      touch.cancels = 0;
      js('window.apm.touch({ok:true})');
    } else if (s.code === LA.userCancel || s.code === LA.systemCancel || s.code === LA.appCancel) {
      // Not a wrong finger: the system called it off, usually because
      // another app was active. Try again while the panel is key (arm()
      // activates the helper first), backing off while it keeps happening.
      touch.cancels++;
      var wait = Math.min(REARM_MS * Math.pow(2, touch.cancels - 1), REARM_MAX_MS);
      touch.rearmAt = Date.now() + wait;
      log('re-arming in', wait + 'ms', 'cancel', touch.cancels);
    } else if (s.code === LA.lockout) {
      touch.want = null;
      touch.gone = true;
      js('window.apm.touch({ok:false,lock:true})');
    } else if (s.code === LA.notAvailable || s.code === LA.notEnrolled || s.code === LA.passcodeNotSet) {
      touch.want = null;
      touch.gone = true;
      js('window.apm.touch({off:true})');
    } else {
      // A finger that didn't match. The page shakes its glyph and posts the
      // slot again to re-arm, or null after the last try.
      touch.want = null;
      js('window.apm.touch({ok:false})');
    }
  }
  var key = !!panel.isKeyWindow;
  if (key !== touch.wasKey) {
    touch.wasKey = key;
    log(key ? 'panel is key' : 'panel is not key');
    // Key again (the user clicked the panel): arm at once, with a fresh backoff.
    if (key) {
      touch.cancels = 0;
      touch.rearmAt = 0;
    }
  }
  if (touch.session && !key) {
    log('panel lost focus, touch id paused');
    cancelTouch();
  }
  if (!touch.session && touch.want && key && Date.now() >= touch.rearmAt) arm(touch.want);
}

function onMessage(name, body) {
  log('message', name, JSON.stringify(body));
  if (name === 'size') {
    var h = Math.max(120, Math.ceil(Number(body && body.height) || 0));
    panel.setFrameDisplay(frameFor(h), true);
    if (!shown) {
      shown = true;
      panel.orderFrontRegardless;
      // Touch ID runs only for the active app.
      if (touchView) app.activateIgnoringOtherApps(true);
      panel.makeKeyAndOrderFront($());
      panel.makeFirstResponder(web);
      log('panel shown, active', !!app.isActive, 'key', !!panel.isKeyWindow);
      js('window.apm.show()');
    }
  } else if (name === 'slot') {
    if (!touchView) return;
    if (!body) {
      touch.want = null;
      cancelTouch();
      return;
    }
    touch.want = body;
    if (touch.session) placeView(touch.session.view, body);
  } else if (name === 'decide') {
    if (body && body.expired) result = 'expired';
    else if (body && body.approve && body.via !== 'touchid' && touchRequired()) log('ignored an approve by', body.via, ': this request needs Touch ID');
    else if (body) result = (body.approve ? 'approve ' : 'reject ') + body.via;
  }
}

ObjC.registerSubclass({
  name: 'APMApprovalPanel',
  superclass: 'NSPanel',
  methods: {
    // Borderless windows can't become key by default; this one takes Space and Esc.
    canBecomeKeyWindow: { types: ['bool', []], implementation: function () { return true; } },
    canBecomeMainWindow: { types: ['bool', []], implementation: function () { return false; } }
  }
});

ObjC.registerSubclass({
  name: 'APMApprovalMessages',
  superclass: 'NSObject',
  methods: {
    'userContentController:didReceiveScriptMessage:': {
      types: ['void', ['id', 'id']],
      implementation: function (controller, message) {
        try {
          onMessage(ObjC.unwrap(message.name), ObjC.deepUnwrap(message.body));
        } catch (e) {
          log('message failed:', e);
        }
      }
    }
  }
});

function main() {
  cfg = JSON.parse(envString('APM_PROMPT') || '{}');
  debug = !!cfg.debug;
  var html = $.NSString.stringWithContentsOfFileEncodingError($(cfg.page || ''), $.NSUTF8StringEncoding, $());
  if (!html || html.isNil()) return 'error: no approval page';

  app = $.NSApplication.sharedApplication;
  app.setActivationPolicy(ACCESSORY);
  app.finishLaunching;

  touchView = touchViewClass();
  log('touch id', touchView ? 'in place' : 'off');

  var vf = visibleFrame();
  place.left = Math.round(vf.origin.x + (vf.size.width - WIDTH) / 2);
  place.top = vf.origin.y + vf.size.height - Math.round(vf.size.height * 0.12);

  panel = $.APMApprovalPanel.alloc.initWithContentRectStyleMaskBackingDefer(frameFor(480), BORDERLESS_NONACTIVATING, BACKING_BUFFERED, false);
  panel.setOpaque(false);
  panel.setBackgroundColor($.NSColor.clearColor);
  panel.setHasShadow(false);
  panel.setLevel($.NSScreenSaverWindowLevel);
  panel.setCollectionBehavior(ALL_SPACES | STATIONARY | FULLSCREEN_AUX);
  panel.setFloatingPanel(true);
  panel.setHidesOnDeactivate(false);
  panel.setBecomesKeyOnlyIfNeeded(false);
  panel.setReleasedWhenClosed(false);
  panel.setAnimationBehavior(2); // none: the page animates itself

  content = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, WIDTH, 480));
  panel.setContentView(content);

  var conf = $.WKWebViewConfiguration.alloc.init;
  var ucc = conf.userContentController;
  var messages = $.APMApprovalMessages.alloc.init;
  ['decide', 'size', 'slot'].forEach(function (n) { ucc.addScriptMessageHandlerName(messages, $(n)); });
  var boot = 'window.apmTouch = ' + (touchView ? 'true' : 'false') + ';';
  ucc.addUserScript($.WKUserScript.alloc.initWithSourceInjectionTimeForMainFrameOnly($(boot), 0, true));

  web = $.WKWebView.alloc.initWithFrameConfiguration(content.bounds, conf);
  web.setAutoresizingMask(WIDTH_SIZABLE | HEIGHT_SIZABLE);
  web.setValueForKey($.NSNumber.numberWithBool(false), $('drawsBackground'));
  try { web.setUnderPageBackgroundColor($.NSColor.clearColor); } catch (e) { /* macOS 11 */ }
  web.unregisterDraggedTypes;
  content.addSubview(web);
  web.loadHTMLStringBaseURL(html, $());

  var started = Date.now();
  while (!result) {
    var ev = app.nextEventMatchingMaskUntilDateInModeDequeue(ANY_EVENT, $.NSDate.dateWithTimeIntervalSinceNow(0.05), $.NSDefaultRunLoopMode, true);
    if (ev && !ev.isNil()) app.sendEvent(ev);
    pump();
    if (!shown && Date.now() - started > 15000) result = 'error: the approval page did not load';
  }
  cancelTouch();
  panel.orderOut($());
  return result;
}

function run() {
  try {
    return main();
  } catch (e) {
    return 'error: ' + e;
  }
}
