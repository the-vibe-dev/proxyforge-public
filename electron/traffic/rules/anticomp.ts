// Anti-compression rule: removes Accept-Encoding to prevent compressed responses.
export function applyAnticompToRequest(headers: Record<string, string>): Record<string, string> {
  const result = { ...headers };
  delete result['Accept-Encoding'];
  delete result['accept-encoding'];
  return result;
}
