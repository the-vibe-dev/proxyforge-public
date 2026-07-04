// Passive rule: WSDL file or SOAPAction header detected
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  const hits: string[] = [];

  if (url && /\.wsdl(?:\?|$)/i.test(url)) hits.push(`WSDL URL: ${url}`);
  if (url && /[?&]wsdl(?:=|$)/i.test(url)) hits.push(`WSDL query param in URL: ${url}`);

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  if (/definitions\s+xmlns/i.test(body)) hits.push('WSDL <definitions xmlns> in response body');
  if (/^SOAPAction:/im.test(requestRaw)) {
    const sa = /^SOAPAction:\s*([^\r\n]+)/im.exec(requestRaw)?.[1];
    hits.push(`SOAPAction header: ${sa}`);
  }
  if (/^Content-Type:\s*[^\r\n]*soap/im.test(responseRaw)) hits.push('SOAP Content-Type in response');

  if (hits.length === 0) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status >= 400) return null;

  return {
    checkId: 'wsdl-detected',
    title: 'WSDL / SOAP service detected',
    severity: 'info',
    confidence: hits.length >= 2 ? 'certain' : 'tentative',
    detail: 'A WSDL or SOAP service was detected. WSDL files enumerate all available operations and data types, aiding targeted attacks on legacy services.',
    evidence: hits.join('; '),
  };
}
