// API authorization matrix testing recipe
// Compares multiple user roles against the same endpoint to detect privilege escalation.
// §8.4 — Automation recipe engine

import type { AutomationRecipe } from '../playbookSchema';

export const apiAuthzMatrix: AutomationRecipe = {
  id: 'api-authz-matrix',
  name: 'API Authorization Matrix',
  summary: 'Compares multiple user role responses against the same endpoint to identify authorization gaps.',
  requiredInputs: ['targetExchangeId', 'roleSessionIds'],
  steps: [
    {
      id: 'capture-privileged',
      type: 'repeater',
      label: 'Capture privileged role baseline',
      config: {
        sessionRole: 'privileged',
        recordResponse: true,
      },
      onSuccess: 'capture-unprivileged',
    },
    {
      id: 'capture-unprivileged',
      type: 'repeater',
      label: 'Replay as unprivileged role',
      config: {
        sessionRole: 'unprivileged',
        recordResponse: true,
      },
      onSuccess: 'capture-anonymous',
      onFailure: 'compare-matrix',
    },
    {
      id: 'capture-anonymous',
      type: 'repeater',
      label: 'Replay as anonymous (no session)',
      config: {
        sessionRole: 'none',
        recordResponse: true,
      },
      onSuccess: 'compare-matrix',
      onFailure: 'compare-matrix',
    },
    {
      id: 'compare-matrix',
      type: 'assert',
      label: 'Compare role response matrix',
      config: {
        assertType: 'authz-matrix-diff',
        flagOnMatch: true,
        compareFields: ['statusCode', 'bodyLength', 'sensitiveFieldsPresent'],
      },
      onSuccess: 'idor-probe',
      onFailure: 'export',
    },
    {
      id: 'idor-probe',
      type: 'scan',
      label: 'IDOR probe on identified object IDs',
      config: {
        checkIds: ['idor', 'mass-assignment'],
        crossAccountMode: true,
      },
      onSuccess: 'export',
      onFailure: 'export',
    },
    {
      id: 'export',
      type: 'export',
      label: 'Export authorization matrix evidence',
      config: {
        format: 'bundle',
        includeRoleMatrix: true,
      },
    },
  ],
  evidenceGates: [
    {
      id: 'idor-gate',
      checkId: 'idor',
      requiredClass: 'expected-proof',
      minConfidence: 0.8,
      required: false,
    },
  ],
  stopConditions: ['budget.exceeded', 'scope.violated'],
  defaultBudgets: {
    maxRequests: 300,
    maxRuntimeMs: 180000,
    maxPayloadsPerInsertionPoint: 15,
  },
};
