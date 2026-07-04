// SSRF + OAST callback validation recipe
// Confirms SSRF via out-of-band DNS/HTTP callback to an OAST listener.
// §8.4 — Automation recipe engine

import type { AutomationRecipe } from '../playbookSchema';

export const ssrfCallbackValidation: AutomationRecipe = {
  id: 'ssrf-callback-validation',
  name: 'SSRF Callback Validation',
  summary: 'Confirms SSRF via out-of-band DNS/HTTP callback workflow.',
  requiredInputs: ['targetExchangeId', 'oastBaseUrl'],
  steps: [
    {
      id: 'baseline',
      type: 'scan',
      label: 'Capture baseline response',
      config: { checkIds: [] },
      onSuccess: 'ssrf-probe',
    },
    {
      id: 'ssrf-probe',
      type: 'scan',
      label: 'SSRF in-band probe',
      config: { checkIds: ['ssrf'] },
      onSuccess: 'oast-wait',
      onFailure: 'oast-wait',
    },
    {
      id: 'oast-wait',
      type: 'oast',
      label: 'Wait for OAST callback',
      config: {
        checkIds: ['ssrf-oast'],
        waitMs: 30000,
        pollIntervalMs: 2000,
      },
      onSuccess: 'oast-confirm',
      onFailure: 'export',
    },
    {
      id: 'oast-confirm',
      type: 'assert',
      label: 'Confirm OAST interaction recorded',
      config: {
        assertType: 'oast-callback-present',
        minCallbacks: 1,
      },
      onSuccess: 'export',
      onFailure: 'export',
    },
    {
      id: 'export',
      type: 'export',
      label: 'Export SSRF evidence bundle',
      config: {
        format: 'bundle',
        includeOastLogs: true,
      },
    },
  ],
  evidenceGates: [
    {
      id: 'ssrf-oast-gate',
      checkId: 'ssrf-oast',
      requiredClass: 'oast-callback-confirmed',
      minConfidence: 0.85,
      required: true,
    },
  ],
  stopConditions: ['budget.exceeded', 'scope.violated', 'oast.provider.unavailable'],
  defaultBudgets: {
    maxRequests: 100,
    maxRuntimeMs: 120000,
    maxPayloadsPerInsertionPoint: 10,
  },
};
