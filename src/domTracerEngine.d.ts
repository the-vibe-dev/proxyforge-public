export type SourceKind = 'location.search' | 'location.hash' | 'location.href' | 'document.referrer' | 'window.name' | 'postMessage' | 'localStorage' | 'sessionStorage' | 'document.cookie' | 'fetch.response' | 'xhr.response' | 'window.opener';
export type SinkKind = 'innerHTML' | 'outerHTML' | 'insertAdjacentHTML' | 'document.write' | 'eval' | 'Function' | 'setTimeout(string)' | 'setInterval(string)' | 'srcdoc' | 'location.href' | 'location.assign' | 'location.replace' | 'element.src' | 'element.href' | 'element.action' | 'element.formaction' | 'postMessage.send' | 'Worker' | 'importScripts' | 'fetch.url' | 'xhr.open';
export interface SourceEvent {
    id: string;
    sessionId: string;
    source: SourceKind;
    value: string;
    url: string;
    timestamp: string;
}
export interface SinkEvent {
    id: string;
    sessionId: string;
    sink: SinkKind;
    value: string;
    canaryMatched?: boolean;
    canaryTransformation?: string;
    stack?: string;
    url: string;
    timestamp: string;
}
export interface CanaryConfig {
    nonce: string;
    source: SourceKind;
    probeCharSet?: string[];
}
export interface TracerSession {
    id: string;
    tabId: string;
    projectId: string;
    url: string;
    canary?: CanaryConfig;
    sources: SourceEvent[];
    sinks: SinkEvent[];
    status: 'active' | 'stopped' | 'promoted';
    startedAt: string;
    stoppedAt?: string;
}
export declare function createTracerSession(tabId: string, projectId: string, url: string): TracerSession;
export declare function getTracerSession(sessionId: string): TracerSession | null;
export declare function stopTracerSession(sessionId: string): void;
export declare function getAllSessions(): TracerSession[];
export declare function recordSourceEvent(sessionId: string, source: SourceKind, value: string, url: string): SourceEvent | null;
export declare function recordSinkEvent(sessionId: string, sink: SinkKind, value: string, url: string, stack?: string): SinkEvent | null;
export declare function setCanary(sessionId: string, source: SourceKind, probeCharSet?: string[]): CanaryConfig | null;
export declare function clearCanary(sessionId: string): void;
export declare function getCanaryTraces(sessionId: string): SinkEvent[];
export declare function getHighValueSinks(sessionId: string): SinkEvent[];
