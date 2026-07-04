import type { PayloadVariant } from '../types';

export const META = {
  id: 'dom-clobbering',
  family: 'dom-xss' as const,
  name: 'DOM Clobbering',
  description: 'Detects DOM clobbering via named anchor/form elements that overwrite global JS properties.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['body', 'query', 'json'],
};

const PROBES = [
  { value: '<a id="location">clobber</a>', intent: 'Clobber window.location via named anchor element', signals: ['dom-clobbering-detected'] },
  { value: '<form id="document"><input name="cookie"></form>', intent: 'Clobber document.cookie via nested form/input', signals: ['dom-clobbering-detected'] },
  { value: '<img name="innerHTML">', intent: 'Clobber innerHTML property via named img element', signals: ['dom-clobbering-detected'] },
  { value: '<a id="defaultView">clobber</a>', intent: 'Clobber document.defaultView via named anchor', signals: ['dom-clobbering-detected'] },
  { value: '<form id="body"><input name="baseURI"></form>', intent: 'Clobber document.body.baseURI via nested form/input', signals: ['dom-clobbering-detected'] },
  { value: '<a id="origin">clobber</a>', intent: 'Clobber window.origin via named anchor element', signals: ['dom-clobbering-detected'] },
  { value: '<form id="window"><input name="top"></form>', intent: 'Clobber window.top via nested form/input elements', signals: ['dom-clobbering-detected'] },
  { value: '<img id="x" name="x"><img id="x" name="x">', intent: 'Dual named elements — creates HTMLCollection instead of element', signals: ['dom-clobbering-detected'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `dom-clob-${i + 1}`,
    family: 'dom-xss' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: true,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
