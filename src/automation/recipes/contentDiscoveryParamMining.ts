// Content discovery + parameter mining recipe
// Discovers hidden paths and parameters, then probes discovered endpoints.
// §8.4 — Automation recipe engine

import type { AutomationRecipe } from '../playbookSchema';

export const contentDiscoveryParamMining: AutomationRecipe = {
  id: 'content-discovery-param-mining',
  name: 'Content Discovery + Parameter Mining',
  summary: 'Discovers hidden paths and undocumented parameters, then probes discovered endpoints for vulnerabilities.',
  requiredInputs: ['targetExchangeId', 'baseUrl'],
  steps: [
    {
      id: 'discover-paths',
      type: 'intruder',
      label: 'Content discovery — path bruteforce',
      config: {
        mode: 'path-discovery',
        wordlist: 'common-paths',
        concurrency: 10,
        followRedirects: true,
        recordDiscoveries: true,
      },
      onSuccess: 'mine-params',
      onFailure: 'mine-params',
    },
    {
      id: 'mine-params',
      type: 'intruder',
      label: 'Parameter mining on discovered paths',
      config: {
        mode: 'param-mining',
        wordlist: 'common-params',
        targetPaths: 'discovered',
        detectHiddenParams: true,
        recordDiscoveries: true,
      },
      onSuccess: 'probe-discovered',
      onFailure: 'export',
    },
    {
      id: 'probe-discovered',
      type: 'scan',
      label: 'Active probe on discovered endpoints',
      config: {
        checkIds: [
          'reflected-xss',
          'sql-injection',
          'open-redirect',
          'lfi-traversal',
          'mass-assignment',
          'idor',
        ],
        targetScope: 'discovered-endpoints',
        maxEndpoints: 50,
      },
      onSuccess: 'export',
      onFailure: 'export',
    },
    {
      id: 'export',
      type: 'export',
      label: 'Export discovery + findings bundle',
      config: {
        format: 'bundle',
        includeDiscoveryMap: true,
        includeParamInventory: true,
      },
    },
  ],
  evidenceGates: [],
  stopConditions: ['budget.exceeded', 'scope.violated', 'discovery.limit.reached'],
  defaultBudgets: {
    maxRequests: 2000,
    maxRuntimeMs: 600000,
    maxPayloadsPerInsertionPoint: 25,
  },
};
