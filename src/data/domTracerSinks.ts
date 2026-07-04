// Registry of instrumented DOM sinks + severity hints for the DOM tracer.
// No external dependencies.

import type { SinkKind } from '../domTracerEngine';

export interface SinkDescriptor {
  id: SinkKind;
  category: 'execution' | 'navigation' | 'dom-mutation' | 'messaging' | 'network';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  exploitCondition: string;
  cweId: string;
}

export const DOM_TRACER_SINKS: SinkDescriptor[] = [
  {
    id: 'innerHTML',
    category: 'dom-mutation',
    severity: 'high',
    description: 'Direct HTML injection into the DOM. Can execute scripts if <script> tags or event handlers are included.',
    exploitCondition: 'Attacker-controlled value reaches innerHTML without sanitization',
    cweId: 'CWE-79',
  },
  {
    id: 'outerHTML',
    category: 'dom-mutation',
    severity: 'high',
    description: 'Replaces entire element with injected HTML.',
    exploitCondition: 'Attacker-controlled value reaches outerHTML',
    cweId: 'CWE-79',
  },
  {
    id: 'insertAdjacentHTML',
    category: 'dom-mutation',
    severity: 'high',
    description: 'Inserts HTML adjacent to an element.',
    exploitCondition: 'Attacker-controlled value reaches insertAdjacentHTML',
    cweId: 'CWE-79',
  },
  {
    id: 'document.write',
    category: 'dom-mutation',
    severity: 'critical',
    description: 'Writes HTML directly to the document. Bypasses most sanitizers.',
    exploitCondition: 'Any attacker-controlled value reaching document.write',
    cweId: 'CWE-79',
  },
  {
    id: 'eval',
    category: 'execution',
    severity: 'critical',
    description: 'Evaluates a JavaScript string as code.',
    exploitCondition: 'Any attacker-controlled value passed to eval()',
    cweId: 'CWE-95',
  },
  {
    id: 'Function',
    category: 'execution',
    severity: 'critical',
    description: 'Constructs and executes a function from a string.',
    exploitCondition: 'Attacker-controlled value in new Function() constructor',
    cweId: 'CWE-95',
  },
  {
    id: 'setTimeout(string)',
    category: 'execution',
    severity: 'high',
    description: 'setTimeout with string first argument — equivalent to eval.',
    exploitCondition: 'String form of setTimeout with attacker-controlled value',
    cweId: 'CWE-95',
  },
  {
    id: 'setInterval(string)',
    category: 'execution',
    severity: 'high',
    description: 'setInterval with string first argument — equivalent to eval.',
    exploitCondition: 'String form of setInterval with attacker-controlled value',
    cweId: 'CWE-95',
  },
  {
    id: 'srcdoc',
    category: 'dom-mutation',
    severity: 'high',
    description: 'Sets the srcdoc of an iframe — arbitrary HTML in sandboxed frame.',
    exploitCondition: 'Attacker-controlled value written to element.srcdoc',
    cweId: 'CWE-79',
  },
  {
    id: 'location.href',
    category: 'navigation',
    severity: 'medium',
    description: 'Navigates to a new URL. Can trigger javascript: or data: URIs.',
    exploitCondition: 'Attacker-controlled URL with javascript: or data: scheme',
    cweId: 'CWE-601',
  },
  {
    id: 'location.assign',
    category: 'navigation',
    severity: 'medium',
    description: 'Same as location.href assignment.',
    exploitCondition: 'Attacker-controlled URL with javascript: or data: scheme',
    cweId: 'CWE-601',
  },
  {
    id: 'location.replace',
    category: 'navigation',
    severity: 'medium',
    description: 'Navigates without adding history entry.',
    exploitCondition: 'Attacker-controlled URL with javascript: or data: scheme',
    cweId: 'CWE-601',
  },
  {
    id: 'element.src',
    category: 'dom-mutation',
    severity: 'medium',
    description: 'Sets element src — can trigger network requests or javascript: URLs.',
    exploitCondition: 'Attacker-controlled value includes javascript: or cross-origin URL',
    cweId: 'CWE-79',
  },
  {
    id: 'element.href',
    category: 'dom-mutation',
    severity: 'medium',
    description: 'Sets anchor or link href.',
    exploitCondition: 'Attacker-controlled value includes javascript: URI',
    cweId: 'CWE-79',
  },
  {
    id: 'element.action',
    category: 'dom-mutation',
    severity: 'medium',
    description: 'Sets form action — can redirect form submissions.',
    exploitCondition: 'Attacker-controlled cross-origin form action URL',
    cweId: 'CWE-601',
  },
  {
    id: 'element.formaction',
    category: 'dom-mutation',
    severity: 'medium',
    description: 'Sets button/input formaction — overrides form action on submit.',
    exploitCondition: 'Attacker-controlled cross-origin formaction URL',
    cweId: 'CWE-601',
  },
  {
    id: 'postMessage.send',
    category: 'messaging',
    severity: 'low',
    description: 'Sends a postMessage — can reach frames/windows with wide origin trust.',
    exploitCondition: 'Attacker-controlled data sent to a receiver that trusts any origin',
    cweId: 'CWE-346',
  },
  {
    id: 'Worker',
    category: 'execution',
    severity: 'high',
    description: 'Creates a Web Worker from a URL — can load attacker-controlled scripts.',
    exploitCondition: 'Attacker-controlled Worker URL (blob: or cross-origin)',
    cweId: 'CWE-95',
  },
  {
    id: 'importScripts',
    category: 'execution',
    severity: 'high',
    description: 'Imports scripts in a Worker context — can load attacker-controlled scripts.',
    exploitCondition: 'Attacker-controlled URL passed to importScripts()',
    cweId: 'CWE-95',
  },
  {
    id: 'fetch.url',
    category: 'network',
    severity: 'medium',
    description: 'Fetch call with a constructed URL — can trigger SSRF or credential leakage.',
    exploitCondition: 'Attacker-controlled fetch URL pointing to internal host',
    cweId: 'CWE-918',
  },
  {
    id: 'xhr.open',
    category: 'network',
    severity: 'medium',
    description: 'XMLHttpRequest URL construction — same risks as fetch.',
    exploitCondition: 'Attacker-controlled XMLHttpRequest URL',
    cweId: 'CWE-918',
  },
];

export function getSinkDescriptor(id: SinkKind): SinkDescriptor | null {
  return DOM_TRACER_SINKS.find((s) => s.id === id) ?? null;
}

export function getSinksBySeverity(severity: SinkDescriptor['severity']): SinkDescriptor[] {
  return DOM_TRACER_SINKS.filter((s) => s.severity === severity);
}

export function getCriticalSinks(): SinkDescriptor[] {
  return getSinksBySeverity('critical');
}
