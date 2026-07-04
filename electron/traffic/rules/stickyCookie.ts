// Sticky cookie rule: pins a cookie value for all matching requests.
export function applyStickycookie(headers: Record<string, string>, cookieValue: string): Record<string, string> {
  return { ...headers, Cookie: cookieValue };
}
