// Update Alt-Svc rule: overrides the Alt-Svc response header.
export function applyAltSvc(headers: Record<string, string>, altSvcValue: string): Record<string, string> {
  return { ...headers, 'Alt-Svc': altSvcValue };
}
