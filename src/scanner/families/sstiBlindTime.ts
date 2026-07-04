// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'ssti-blind-time',
  family: 'ssti-blind-time',
  title: 'SSTI blind timing oracle',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'cookie', 'header'],
  expectedSignals: ['timing-delta'],
  cwe: [94, 1336],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'ssti-blind-jinja2-sleep',
      family: 'ssti-blind-time',
      value: '{{range(10000000).__len__()}}',
      encoding: 'raw',
      intent: 'Jinja2 CPU-bound timing probe — large range iteration causes measurable delay',
      destructiveRisk: 'none',
      expectedSignals: ['timing-delta'],
    },
    {
      id: 'ssti-blind-twig-sleep',
      family: 'ssti-blind-time',
      value: '{% for i in 1..10000 %}x{% endfor %}',
      encoding: 'raw',
      intent: 'Twig loop-based timing probe',
      destructiveRisk: 'none',
      expectedSignals: ['timing-delta'],
    },
    {
      id: 'ssti-blind-velocity-sleep',
      family: 'ssti-blind-time',
      value: '#set($x=0)#foreach($i in [1..10000])#set($x=$x+1)#end$x',
      encoding: 'raw',
      intent: 'Velocity template loop timing probe',
      destructiveRisk: 'none',
      expectedSignals: ['timing-delta'],
    },
    {
      id: 'ssti-blind-freemarker-sleep',
      family: 'ssti-blind-time',
      value: '<#list 1..10000 as i>${i}</#list>',
      encoding: 'raw',
      intent: 'FreeMarker loop timing probe',
      destructiveRisk: 'none',
      expectedSignals: ['timing-delta'],
    },
    {
      id: 'ssti-blind-smarty-sleep',
      family: 'ssti-blind-time',
      value: '{foreach from=1|range:10000 item=i}{$i}{/foreach}',
      encoding: 'raw',
      intent: 'Smarty foreach timing probe',
      destructiveRisk: 'none',
      expectedSignals: ['timing-delta'],
    },
    {
      id: 'ssti-blind-mako-sleep',
      family: 'ssti-blind-time',
      value: '${",".join(str(i) for i in range(10000))}',
      encoding: 'raw',
      intent: 'Mako join-range timing probe',
      destructiveRisk: 'none',
      expectedSignals: ['timing-delta'],
    },
    {
      id: 'ssti-blind-nunjucks-sleep',
      family: 'ssti-blind-time',
      value: '{% for i in range(10000) %}{{ i }}{% endfor %}',
      encoding: 'raw',
      intent: 'Nunjucks/Swig loop timing probe',
      destructiveRisk: 'none',
      expectedSignals: ['timing-delta'],
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

  const timingDelta = resp.responseTimeMs - baseline.responseTimeMs;

  if (timingDelta > 3000) {
    responseClass = 'timing-delta';
    confidence = 0.7 + Math.min(0.2, timingDelta / 30000);
    nextAction = 'confirm';
    evidence.push(`Timing delta ${timingDelta}ms above baseline for SSTI probe "${variant.id}"`);
    evidence.push('Re-probe with smaller loop count to confirm linear scaling');
  } else if (timingDelta > 1000) {
    responseClass = 'timing-delta';
    confidence = 0.45;
    nextAction = 'mutate';
    evidence.push(`Marginal timing delta ${timingDelta}ms — retry with larger loop count`);
  } else {
    nextAction = 'stop-negative';
    evidence.push(`No timing signal (delta: ${timingDelta}ms) for ${variant.id}`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
