// Web payload family validation recipe
// Validates all primary injection families against a target endpoint.
// §8.4 — Automation recipe engine

import type { AutomationRecipe } from '../playbookSchema';

export const webPayloadFamilyValidation: AutomationRecipe = {
  id: 'web-payload-family-validation',
  name: 'Web Payload Family Validation',
  summary: 'Validates all primary injection families against a target endpoint.',
  requiredInputs: ['targetExchangeId'],
  steps: [
    {
      id: 'baseline',
      type: 'scan',
      label: 'Capture baseline response',
      config: { checkIds: [] },
      onSuccess: 'sql-scan',
    },
    {
      id: 'sql-scan',
      type: 'scan',
      label: 'SQL injection probe',
      config: { checkIds: ['sql-injection'] },
      onSuccess: 'xss-scan',
      onFailure: 'xss-scan',
    },
    {
      id: 'xss-scan',
      type: 'scan',
      label: 'XSS probe',
      config: { checkIds: ['reflected-xss', 'xss-oracle'] },
      onSuccess: 'ssti-scan',
      onFailure: 'ssti-scan',
    },
    {
      id: 'ssti-scan',
      type: 'scan',
      label: 'SSTI probe',
      config: { checkIds: ['ssti'] },
      onSuccess: 'cmd-scan',
      onFailure: 'cmd-scan',
    },
    {
      id: 'cmd-scan',
      type: 'scan',
      label: 'Command injection probe',
      config: { checkIds: ['command-injection'] },
      onSuccess: 'export',
      onFailure: 'export',
    },
    {
      id: 'export',
      type: 'export',
      label: 'Export evidence bundle',
      config: { format: 'bundle' },
    },
  ],
  evidenceGates: [],
  stopConditions: ['budget.exceeded', 'scope.violated'],
  defaultBudgets: {
    maxRequests: 500,
    maxRuntimeMs: 300000,
    maxPayloadsPerInsertionPoint: 20,
  },
};
