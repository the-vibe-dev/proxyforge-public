// CDP attach + isolated-world setup for the interactive DOM source→sink tracer.
// Bridges the managed browser (§6.5 CDP plumbing) to domTracerEngine.ts (off-thread via IPC).
// Instrumentation is injected per-navigation; never touches manually-opened tabs.
// Note: this file runs in the electron main process; it communicates with the renderer
// (which hosts domTracerEngine.ts) via ipcMain/ipcRenderer rather than direct import.

export interface TracerDriverConfig {
  projectId: string;
  sessionId?: string;
  inScopeOrigins: string[];
  canaryNonce?: string;
}

export interface TracerDriverHandle {
  sessionId: string;
  projectId: string;
  stop(): void;
  injectCanary(nonce: string, sinkTarget?: string): void;
}

// Placeholder CDP page reference — replaced by real CDP connection in electron/main.ts
export interface CdpPageRef {
  targetId: string;
  origin: string;
  addScriptToEvaluateOnNewDocument(script: string): Promise<void>;
  on(event: string, handler: (params: unknown) => void): void;
  off(event: string, handler: (params: unknown) => void): void;
  evaluate(expr: string): Promise<unknown>;
}

// IPC bridge — resolved when electron/main.ts injects the ipc sender
type IpcSender = (channel: string, ...args: unknown[]) => void;
let _ipcSend: IpcSender = () => {};

export function setIpcSender(fn: IpcSender): void {
  _ipcSend = fn;
}

const ACTIVE_DRIVERS = new Map<string, TracerDriverHandle>();

export function attachTracerToPage(
  page: CdpPageRef,
  config: TracerDriverConfig
): TracerDriverHandle {
  const sessionId = config.sessionId ?? `tracer-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  // Tell the renderer to create a tracer session (ipc → domTracerEngine.createTracerSession)
  _ipcSend('domtracer:session:create', { sessionId, projectId: config.projectId, url: page.origin });

  const domainOk = (origin: string) =>
    config.inScopeOrigins.length === 0 ||
    config.inScopeOrigins.some((o) => origin === o || origin.endsWith('.' + o));

  if (!domainOk(page.origin)) {
    return {
      sessionId,
      projectId: config.projectId,
      stop: () => _ipcSend('domtracer:session:stop', { sessionId }),
      injectCanary: () => {},
    };
  }

  const instrumentationScript = buildInstrumentationScript(sessionId);
  page.addScriptToEvaluateOnNewDocument(instrumentationScript).catch(() => {});

  const messageHandler = (params: unknown) => {
    const msg = params as { type?: string; args?: Array<{ value?: string }> };
    if (msg?.type !== 'log' || !msg.args?.length) return;
    const raw = msg.args[0]?.value ?? '';
    if (!raw.startsWith('__PF_TRACER__')) return;
    try {
      const evt = JSON.parse(raw.slice('__PF_TRACER__'.length)) as {
        kind: 'source' | 'sink';
        type: string;
        value: string;
        canaryNonce?: string;
      };
      // Forward to renderer via IPC → domTracerEngine
      _ipcSend(`domtracer:event:${evt.kind}`, {
        sessionId,
        type: evt.type,
        value: evt.value,
        canaryNonce: evt.canaryNonce,
        url: page.origin,
      });
    } catch {
      // malformed event — ignore
    }
  };

  page.on('Runtime.consoleAPICalled', messageHandler);

  const handle: TracerDriverHandle = {
    sessionId,
    projectId: config.projectId,
    stop() {
      page.off('Runtime.consoleAPICalled', messageHandler);
      _ipcSend('domtracer:session:stop', { sessionId });
      ACTIVE_DRIVERS.delete(sessionId);
    },
    injectCanary(nonce: string, sinkTarget?: string) {
      _ipcSend('domtracer:canary:set', { sessionId, nonce });
      const stamp = `window.__pf_canary = '${nonce}'; console.log('__PF_TRACER__' + JSON.stringify({kind:'source',type:'canary-inject',value:'${nonce}'}));`;
      const expr = sinkTarget
        ? `try { document.querySelector('[data-pf-canary-target="${sinkTarget}"]').innerHTML = '${nonce}'; } catch(e) {} ${stamp}`
        : stamp;
      page.evaluate(expr).catch(() => {});
    },
  };

  ACTIVE_DRIVERS.set(sessionId, handle);
  return handle;
}

export function getActiveDriver(sessionId: string): TracerDriverHandle | undefined {
  return ACTIVE_DRIVERS.get(sessionId);
}

export function detachAllTracers(): void {
  for (const handle of ACTIVE_DRIVERS.values()) {
    handle.stop();
  }
  ACTIVE_DRIVERS.clear();
}

function buildInstrumentationScript(sessionId: string): string {
  return `(function() {
  var SESSION = '${sessionId}';
  function emit(kind, type, value, canaryNonce) {
    try {
      console.log('__PF_TRACER__' + JSON.stringify({kind:kind, type:type, value:String(value).slice(0,2000), canaryNonce:canaryNonce||undefined}));
    } catch(e) {}
  }
  try { emit('source','location.search',location.search); } catch(e) {}
  try { emit('source','location.hash',location.hash); } catch(e) {}
  try { emit('source','document.referrer',document.referrer); } catch(e) {}
  var _origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');
  if (_origInnerHTML && _origInnerHTML.set) {
    Object.defineProperty(Element.prototype,'innerHTML',{
      set: function(v) {
        emit('sink','innerHTML',v, window.__pf_canary && String(v).indexOf(window.__pf_canary)>=0 ? window.__pf_canary : undefined);
        _origInnerHTML.set.call(this,v);
      },
      get: _origInnerHTML.get, configurable: true
    });
  }
  var _origEval = eval;
  try {
    window.eval = function(code) {
      emit('sink','eval',code, window.__pf_canary && String(code).indexOf(window.__pf_canary)>=0 ? window.__pf_canary : undefined);
      return _origEval(code);
    };
  } catch(e) {}
  var _origWrite = document.write.bind(document);
  document.write = function(s) {
    emit('sink','document.write',s, window.__pf_canary && String(s).indexOf(window.__pf_canary)>=0 ? window.__pf_canary : undefined);
    return _origWrite(s);
  };
  window.addEventListener('message', function(e) {
    emit('source','postMessage',JSON.stringify({data:e.data,origin:e.origin}));
  }, true);
})();`;
}
