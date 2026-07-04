declare module '@proxyforge/sdk' {
  // Hook names
  export type HookName =
    | 'request'
    | 'response'
    | 'tls_clienthello'
    | 'tcp_message'
    | 'scan_check'
    | 'editor_tab'
    | 'intruder_payload_processor'
    | 'repeater_action'
    | 'scanner_passive';

  // Hook payloads
  export interface RequestHookPayload {
    exchangeId: string;
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  }

  export interface ResponseHookPayload {
    exchangeId: string;
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body?: string;
  }

  export interface TlsClientHelloPayload {
    host: string;
    sni?: string;
    alpnProtocols?: string[];
    cipherSuites?: number[];
  }

  export interface TcpMessagePayload {
    direction: 'upstream' | 'downstream';
    bytes: Buffer;
  }

  export interface ScanCheckPayload {
    exchangeId: string;
    checkId: string;
    insertionPointId?: string;
    payload?: string;
  }

  export interface EditorTabPayload {
    tabId: string;
    content: string;
    contentType: string;
  }

  export interface IntruderPayloadProcessorPayload {
    original: string;
    position: number;
  }

  export interface RepeaterActionPayload {
    requestRaw: string;
    groupId?: string;
  }

  export interface ScannerPassivePayload {
    exchangeId: string;
    requestRaw: string;
    responseRaw: string;
  }

  // Hook results
  export interface RequestHookResult {
    headers?: Record<string, string>;
    body?: string;
    blocked?: boolean;
  }

  export interface ResponseHookResult {
    headers?: Record<string, string>;
    body?: string;
    blocked?: boolean;
  }

  export interface ScanCheckResult {
    finding?: {
      title: string;
      severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
      confidence: 'tentative' | 'firm' | 'certain';
      detail: string;
    };
  }

  export interface IntruderPayloadResult {
    transformed: string;
  }

  export interface ScannerPassiveResult {
    issues?: Array<{
      title: string;
      severity: string;
      detail: string;
    }>;
  }

  // Extension manifest
  export interface ExtensionManifest {
    id: string;
    name: string;
    version: string;
    description?: string;
    author?: string;
    license?: string;
    hooks: HookName[];
    permissions: string[];
    digest?: string;
    signature?: string;
  }

  // Extension API
  export interface ProxyForgeExtension {
    manifest: ExtensionManifest;
    onRequest?(payload: RequestHookPayload): Promise<RequestHookResult | void>;
    onResponse?(payload: ResponseHookPayload): Promise<ResponseHookResult | void>;
    onTlsClientHello?(payload: TlsClientHelloPayload): Promise<void>;
    onTcpMessage?(payload: TcpMessagePayload): Promise<void>;
    onScanCheck?(payload: ScanCheckPayload): Promise<ScanCheckResult | void>;
    onEditorTab?(payload: EditorTabPayload): Promise<void>;
    onIntruderPayload?(
      payload: IntruderPayloadProcessorPayload,
    ): Promise<IntruderPayloadResult | void>;
    onRepeaterAction?(payload: RepeaterActionPayload): Promise<void>;
    onScannerPassive?(payload: ScannerPassivePayload): Promise<ScannerPassiveResult | void>;
  }
}
