// Anti-cache rule: removes caching headers from requests.
export function applyAnticacheToRequest(headers: Record<string, string>): Record<string, string> {
  const result = { ...headers };
  result['Cache-Control'] = 'no-cache, no-store, must-revalidate';
  result['Pragma'] = 'no-cache';
  delete result['If-None-Match'];
  delete result['If-Modified-Since'];
  return result;
}
