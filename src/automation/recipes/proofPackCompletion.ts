// Proof pack completion recipe
// Assembles a complete proof pack for a confirmed finding including exploit template run and bundle export.
// §8.4 — Automation recipe engine

import type { AutomationRecipe } from '../playbookSchema';

export const proofPackCompletion: AutomationRecipe = {
  id: 'proof-pack-completion',
  name: 'Proof Pack Completion',
  summary: 'Confirms a finding, runs the appropriate exploit template, and exports a complete proof bundle.',
  requiredInputs: ['findingId', 'targetExchangeId', 'checkId'],
  steps: [
    {
      id: 'confirm-finding',
      type: 'scan',
      label: 'Re-confirm finding with fresh probe',
      config: {
        checkIds: [],
        reuseCheckId: true,
        confirmationMode: true,
        maxAttempts: 3,
      },
      onSuccess: 'run-exploit-template',
      onFailure: 'export-bundle',
    },
    {
      id: 'run-exploit-template',
      type: 'repeater',
      label: 'Run exploit template for finding type',
      config: {
        templateSelection: 'auto',
        captureEvidence: true,
        evidenceFields: [
          'requestBytes',
          'responseBytes',
          'timingMs',
          'oastCallbacks',
          'screenshotPath',
        ],
      },
      onSuccess: 'assert-proof',
      onFailure: 'export-bundle',
    },
    {
      id: 'assert-proof',
      type: 'assert',
      label: 'Assert proof requirements are satisfied',
      config: {
        assertType: 'expected-proof-present',
        useSkillletMetadata: true,
      },
      onSuccess: 'export-bundle',
      onFailure: 'export-bundle',
    },
    {
      id: 'export-bundle',
      type: 'export',
      label: 'Export complete proof bundle',
      config: {
        format: 'bundle',
        includeRequests: true,
        includeResponses: true,
        includeOastLogs: true,
        includeScreenshots: true,
        includeTimeline: true,
        signBundle: true,
      },
    },
  ],
  evidenceGates: [
    {
      id: 'confirmation-gate',
      requiredClass: 'expected-proof',
      minConfidence: 0.9,
      required: true,
    },
  ],
  stopConditions: ['budget.exceeded', 'scope.violated', 'finding.invalidated'],
  defaultBudgets: {
    maxRequests: 50,
    maxRuntimeMs: 60000,
    maxPayloadsPerInsertionPoint: 5,
  },
};
