// Full JS instrumentation payload injected via CDP into every managed-browser page.
// Hooks sources and sinks, emits structured events over console.log bridge.
// Never injected into pages the operator opens manually — only scope-approved tabs.

export interface InstrumentationOptions {
  sessionId: string;
  canaryNonce?: string;
  hookEval?: boolean;
  hookFetch?: boolean;
  hookStorage?: boolean;
  hookPostMessage?: boolean;
}

export function buildInstrumentationPayload(opts: InstrumentationOptions): string {
  const { sessionId, canaryNonce = '', hookEval = true, hookFetch = true, hookStorage = true, hookPostMessage = true } = opts;

  return `(function() {
'use strict';
var __PF_SESSION = ${JSON.stringify(sessionId)};
var __PF_NONCE = ${JSON.stringify(canaryNonce)};
if (window.__pf_instrumented) return;
window.__pf_instrumented = true;
window.__pf_canary = __PF_NONCE || null;

// ---- Emit bridge ----
function emit(kind, type, value, extra) {
  try {
    var obj = {kind:kind, type:type, value:String(value).slice(0, 4096)};
    if (extra) obj.extra = extra;
    if (window.__pf_canary && String(value).indexOf(window.__pf_canary) >= 0) {
      obj.canaryNonce = window.__pf_canary;
    }
    console.log('__PF_TRACER__' + JSON.stringify(obj));
  } catch(e) {}
}

// ---- Sources ----
function captureInitialSources() {
  emit('source', 'location.search', location.search);
  emit('source', 'location.hash', location.hash);
  emit('source', 'location.href', location.href);
  emit('source', 'document.referrer', document.referrer);
  try { emit('source', 'window.name', window.name); } catch(e) {}
  try { emit('source', 'document.cookie', document.cookie); } catch(e) {}
}
captureInitialSources();

// ---- Sink: innerHTML / outerHTML / insertAdjacentHTML ----
(function() {
  var desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (desc && desc.set) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      configurable: true, enumerable: true,
      get: desc.get,
      set: function(v) { emit('sink', 'innerHTML', v); desc.set.call(this, v); }
    });
  }
  var desc2 = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
  if (desc2 && desc2.set) {
    Object.defineProperty(Element.prototype, 'outerHTML', {
      configurable: true, enumerable: true,
      get: desc2.get,
      set: function(v) { emit('sink', 'outerHTML', v); desc2.set.call(this, v); }
    });
  }
  var _iah = Element.prototype.insertAdjacentHTML;
  if (_iah) {
    Element.prototype.insertAdjacentHTML = function(pos, markup) {
      emit('sink', 'insertAdjacentHTML', markup);
      return _iah.call(this, pos, markup);
    };
  }
})();

// ---- Sink: document.write ----
(function() {
  var _dw = document.write.bind(document);
  document.write = function(s) { emit('sink', 'document.write', s); return _dw(s); };
  var _dwl = document.writeln.bind(document);
  document.writeln = function(s) { emit('sink', 'document.writeln', s); return _dwl(s); };
})();

// ---- Sink: eval + Function ----
${hookEval ? `(function() {
  var _eval = eval;
  try {
    window.eval = function(code) { emit('sink', 'eval', code); return _eval(code); };
  } catch(e) {}
  var _Fn = Function;
  try {
    window.Function = function() {
      var args = Array.prototype.slice.call(arguments);
      emit('sink', 'Function', args.join('\\n'));
      return _Fn.apply(null, args);
    };
    window.Function.prototype = _Fn.prototype;
  } catch(e) {}
})();` : '// eval hooks disabled'}

// ---- Sink: setTimeout / setInterval with string arg ----
(function() {
  var _st = setTimeout;
  window.setTimeout = function(fn) {
    if (typeof fn === 'string') emit('sink', 'setTimeout', fn);
    return _st.apply(window, arguments);
  };
  var _si = setInterval;
  window.setInterval = function(fn) {
    if (typeof fn === 'string') emit('sink', 'setInterval', fn);
    return _si.apply(window, arguments);
  };
})();

// ---- Sink: location assignments ----
(function() {
  var _loc = Object.getOwnPropertyDescriptor(window, 'location');
  var _href = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
  if (_href && _href.set) {
    Object.defineProperty(Location.prototype, 'href', {
      configurable: true, enumerable: true,
      get: _href.get,
      set: function(v) { emit('sink', 'location.href', v); _href.set.call(this, v); }
    });
  }
})();

// ---- Sink: element attribute sinks ----
(function() {
  var _setSrc = HTMLScriptElement.prototype.__lookupSetter__('src');
  var _setIframeSrc = HTMLIFrameElement.prototype.__lookupSetter__('src');
  if (_setSrc) {
    Object.defineProperty(HTMLScriptElement.prototype, 'src', {
      configurable: true, set: function(v) { emit('sink', 'script.src', v); _setSrc.call(this, v); },
      get: HTMLScriptElement.prototype.__lookupGetter__('src')
    });
  }
  if (_setIframeSrc) {
    Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
      configurable: true, set: function(v) { emit('sink', 'iframe.src', v); _setIframeSrc.call(this, v); },
      get: HTMLIFrameElement.prototype.__lookupGetter__('src')
    });
  }
})();

// ---- Sink: fetch + XMLHttpRequest (URL) ----
${hookFetch ? `(function() {
  var _fetch = window.fetch;
  window.fetch = function(url) {
    emit('sink', 'fetch.url', typeof url === 'string' ? url : (url && url.url) || String(url));
    return _fetch.apply(this, arguments);
  };
  var _XHRopen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    emit('sink', 'xhr.url', url);
    return _XHRopen.apply(this, arguments);
  };
})();` : '// fetch hooks disabled'}

// ---- Sink: Worker + importScripts ----
(function() {
  var _Worker = window.Worker;
  if (_Worker) {
    window.Worker = function(url, opts) {
      emit('sink', 'Worker', url);
      return new _Worker(url, opts);
    };
    window.Worker.prototype = _Worker.prototype;
  }
  if (typeof importScripts !== 'undefined') {
    var _is = importScripts;
    importScripts = function() {
      var args = Array.prototype.slice.call(arguments);
      args.forEach(function(u) { emit('sink', 'importScripts', u); });
      return _is.apply(this, arguments);
    };
  }
})();

// ---- Source: postMessage ----
${hookPostMessage ? `window.addEventListener('message', function(e) {
  emit('source', 'postMessage', JSON.stringify({data: e.data, origin: e.origin}));
}, true);` : '// postMessage hook disabled'}

// ---- Source: localStorage / sessionStorage reads ----
${hookStorage ? `(function() {
  function hookStorage(name, store) {
    var _getItem = store.getItem.bind(store);
    store.getItem = function(key) {
      var val = _getItem(key);
      if (val !== null) emit('source', name + '.getItem', JSON.stringify({key:key,value:val}));
      return val;
    };
  }
  try { hookStorage('localStorage', localStorage); } catch(e) {}
  try { hookStorage('sessionStorage', sessionStorage); } catch(e) {}
})();` : '// storage hooks disabled'}

})(); // end instrumentation IIFE`;
}

export function buildCanaryInjectionScript(nonce: string, targetSelector?: string): string {
  const stamp = `window.__pf_canary = ${JSON.stringify(nonce)}; console.log('__PF_TRACER__' + JSON.stringify({kind:'source',type:'canary-inject',value:${JSON.stringify(nonce)}}));`;
  if (!targetSelector) return stamp;
  return `try { var t = document.querySelector(${JSON.stringify(targetSelector)}); if (t) t.innerHTML = ${JSON.stringify(nonce)}; } catch(e) {} ${stamp}`;
}
