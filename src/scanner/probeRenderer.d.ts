import type { InsertionPointKind, PayloadVariant } from './types';
export interface RawHttpRequest {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: string;
}
export interface RenderedProbe {
    variantId: string;
    rawRequest: string;
    url: string;
    mutatedValue: string;
    insertionPointKind: InsertionPointKind;
    insertionPointName: string;
}
export declare function renderProbeForQuery(baseRequest: RawHttpRequest, paramName: string, variant: PayloadVariant): RenderedProbe;
export declare function renderProbeForHeader(baseRequest: RawHttpRequest, headerName: string, variant: PayloadVariant): RenderedProbe;
export declare function renderProbeForJsonField(baseRequest: RawHttpRequest, fieldPath: string, variant: PayloadVariant): RenderedProbe;
export declare function renderProbeForCookie(baseRequest: RawHttpRequest, cookieName: string, variant: PayloadVariant): RenderedProbe;
export declare function renderProbeForFormField(baseRequest: RawHttpRequest, fieldName: string, variant: PayloadVariant): RenderedProbe;
export declare function renderProbeForInsertionPoint(baseRequest: RawHttpRequest, kind: InsertionPointKind, name: string, variant: PayloadVariant): RenderedProbe;
