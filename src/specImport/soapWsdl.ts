// ---------------------------------------------------------------------------
// SOAP/WSDL Parser — regex-based, no external XML parser.
// Extracts operations, services, and metadata from WSDL 1.1 documents.
// No external dependencies.
// ---------------------------------------------------------------------------

export interface WsdlOperation {
  name: string;
  inputMessage?: string;
  outputMessage?: string;
  soapAction?: string;
}

export interface WsdlService {
  name: string;
  port?: string;
  address?: string;
}

export interface WsdlParsed {
  targetNamespace?: string;
  serviceName?: string;
  operations: WsdlOperation[];
  services: WsdlService[];
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Shape validator
// ---------------------------------------------------------------------------

export function validateWsdlShape(parsed: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    errors.push('Parsed WSDL result must be an object.');
    return { valid: false, errors };
  }

  const obj = parsed as Record<string, unknown>;

  if (!Array.isArray(obj['operations'])) {
    errors.push('Missing or non-array "operations" field.');
  }

  if (!Array.isArray(obj['services'])) {
    errors.push('Missing or non-array "services" field.');
  }

  if (!Array.isArray(obj['warnings'])) {
    errors.push('Missing or non-array "warnings" field.');
  }

  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Regex helpers
// ---------------------------------------------------------------------------

/** Extract the value of a named attribute from a tag string. */
function attr(tag: string, name: string): string | undefined {
  // Handles both single and double quotes, and optional whitespace around =
  const re = new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 'i');
  const m = re.exec(tag);
  if (!m) return undefined;
  return m[1] !== undefined ? m[1] : m[2];
}

/** Find all matches of a regex and return capture group 1 as strings. */
function findAll(re: RegExp, text: string): string[] {
  const results: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    results.push(m[1]);
  }
  return results;
}

/** Strip XML namespace prefix from a value like "tns:SomeMessage" → "SomeMessage". */
function stripNs(value: string): string {
  const idx = value.indexOf(':');
  return idx >= 0 ? value.slice(idx + 1) : value;
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

export function parseWsdl(raw: string): WsdlParsed {
  const warnings: string[] = [];

  if (!raw || !raw.trim()) {
    warnings.push('Empty WSDL input.');
    return { operations: [], services: [], warnings };
  }

  if (!/</.test(raw)) {
    warnings.push('Input does not appear to be XML.');
    return { operations: [], services: [], warnings };
  }

  // ---------------------------------------------------------------------------
  // targetNamespace from <definitions> or <wsdl:definitions>
  // ---------------------------------------------------------------------------
  let targetNamespace: string | undefined;
  {
    const defTag = /(<(?:wsdl:)?definitions[^>]*>)/i.exec(raw);
    if (defTag) {
      targetNamespace = attr(defTag[1], 'targetNamespace');
    }
  }

  // ---------------------------------------------------------------------------
  // Operations: scan <wsdl:operation> or <operation> blocks in portType/binding.
  // We look for all operation name= attributes at the portType level first,
  // then correlate soapAction / input / output from the binding section.
  // Strategy: split on <operation ... name="..."> tags and parse each block.
  // ---------------------------------------------------------------------------

  const operations: WsdlOperation[] = [];

  // We work with a normalised copy to simplify regex across namespaces.
  // Replace wsdl: prefix with nothing for uniform matching.
  const norm = raw.replace(/wsdl:/gi, '');

  // 1. Collect portType operation names and their messages.
  //    <portType name="..."> ... <operation name="X"> <input message="..."/> <output message="..."/> </operation> ...
  //    We collect all <operation name="X"> + their <input>/<output> within a portType block.
  const portTypeRe = /<portType[^>]*>([\s\S]*?)<\/portType>/gi;
  const opNameRe = /<operation\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/operation>/gi;
  const inputMsgRe = /<input[^>]*\smessage="([^"]+)"[^>]*/i;
  const outputMsgRe = /<output[^>]*\smessage="([^"]+)"[^>]*/i;

  // Map from opName → { inputMessage, outputMessage }
  const portTypeOps = new Map<string, { inputMessage?: string; outputMessage?: string }>();

  let ptMatch: RegExpExecArray | null;
  while ((ptMatch = portTypeRe.exec(norm)) !== null) {
    const ptBody = ptMatch[1];
    let opMatch: RegExpExecArray | null;
    const localOpRe = new RegExp(opNameRe.source, 'gi');
    while ((opMatch = localOpRe.exec(ptBody)) !== null) {
      const opName = opMatch[1];
      const opBody = opMatch[2];
      const inMsg = inputMsgRe.exec(opBody);
      const outMsg = outputMsgRe.exec(opBody);
      portTypeOps.set(opName, {
        inputMessage: inMsg ? stripNs(inMsg[1]) : undefined,
        outputMessage: outMsg ? stripNs(outMsg[1]) : undefined,
      });
    }
  }

  // 2. Collect soapAction from binding sections.
  //    <binding ...> ... <operation name="X"> <soap:operation soapAction="Y"/> ...
  const bindingRe = /<binding[^>]*>([\s\S]*?)<\/binding>/gi;
  const bindingOpRe = /<operation\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/operation>/gi;
  const soapActionRe = /<soap:operation[^>]+soapAction="([^"]*)"[^>]*/i;

  // Map from opName → soapAction
  const soapActions = new Map<string, string>();

  let bMatch: RegExpExecArray | null;
  while ((bMatch = bindingRe.exec(norm)) !== null) {
    const bBody = bMatch[1];
    let bOpMatch: RegExpExecArray | null;
    const localBindOpRe = new RegExp(bindingOpRe.source, 'gi');
    while ((bOpMatch = localBindOpRe.exec(bBody)) !== null) {
      const opName = bOpMatch[1];
      const opBody = bOpMatch[2];
      const saMatch = soapActionRe.exec(opBody);
      if (saMatch) soapActions.set(opName, saMatch[1]);
    }
  }

  // 3. Merge: start from portTypeOps; augment with soapActions.
  //    If there were no portType ops (e.g. malformed WSDL), fall back to
  //    all operation names found anywhere in the binding section.
  if (portTypeOps.size === 0) {
    warnings.push('No <portType> operations found; falling back to binding operation names.');
    const fallbackNames = findAll(/<operation\s+name="([^"]+)"/gi, norm);
    const seen = new Set<string>();
    for (const n of fallbackNames) {
      if (!seen.has(n)) {
        seen.add(n);
        portTypeOps.set(n, {});
      }
    }
  }

  for (const [name, msgs] of portTypeOps) {
    operations.push({
      name,
      inputMessage: msgs.inputMessage,
      outputMessage: msgs.outputMessage,
      soapAction: soapActions.get(name),
    });
  }

  // ---------------------------------------------------------------------------
  // Services: <service name="..."> ... <port name="..."> <soap:address location="..."/>
  // ---------------------------------------------------------------------------
  const services: WsdlService[] = [];
  const serviceBlockRe = /<service\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/service>/gi;
  const portBlockRe = /<port\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/port>/gi;
  const soapAddressRe = /<soap:address\s+location="([^"]+)"/i;

  let svcMatch: RegExpExecArray | null;
  while ((svcMatch = serviceBlockRe.exec(norm)) !== null) {
    const svcName = svcMatch[1];
    const svcBody = svcMatch[2];

    let portMatch: RegExpExecArray | null;
    const localPortRe = new RegExp(portBlockRe.source, 'gi');
    let foundPort = false;

    while ((portMatch = localPortRe.exec(svcBody)) !== null) {
      foundPort = true;
      const portName = portMatch[1];
      const portBody = portMatch[2];
      const addrMatch = soapAddressRe.exec(portBody);
      services.push({
        name: svcName,
        port: portName,
        address: addrMatch ? addrMatch[1] : undefined,
      });
    }

    // Service with no ports
    if (!foundPort) {
      services.push({ name: svcName });
    }
  }

  // serviceName = first service name for convenience
  const serviceName = services.length > 0 ? services[0].name : undefined;

  if (operations.length === 0) {
    warnings.push('No WSDL operations were extracted. Verify the input is a valid WSDL 1.1 document.');
  }

  return { targetNamespace, serviceName, operations, services, warnings };
}
