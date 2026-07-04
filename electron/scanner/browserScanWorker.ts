// Browser scan worker — per-page sandbox contract for browser-driven checks.
// Phase 10 stub: worker always returns empty observations until a real Playwright
// implementation drives page interaction and collects signals.

export interface PageScanTask {
  taskId: string;
  url: string;
  checkId: string;
  payload?: string;
  insertionPoint?: string;
}

export type PageScanObservationType =
  | 'alert-triggered'
  | 'property-set'
  | 'network-request'
  | 'console-error'
  | 'dom-mutation'
  | 'navigation';

export interface PageScanObservation {
  taskId: string;
  checkId: string;
  observationType: PageScanObservationType;
  value?: string;
}

export interface PageScanWorkerConfig {
  maxObservations?: number;
  timeoutMs?: number;
}

export interface PageScanWorker {
  run(task: PageScanTask): Promise<PageScanObservation[]>;
  dispose(): void;
}

/**
 * Creates a page scan worker bound to the given configuration.
 *
 * Stub implementation: `run` always resolves to an empty observation list.
 * A real implementation would open a Playwright browser context, navigate to
 * task.url, inject task.payload at task.insertionPoint, and collect DOM/network
 * signals until timeoutMs or maxObservations is reached.
 */
export function createPageScanWorker(config?: PageScanWorkerConfig): PageScanWorker {
  const _maxObservations = config?.maxObservations ?? 100;
  const _timeoutMs = config?.timeoutMs ?? 15_000;
  void _maxObservations;
  void _timeoutMs;

  let disposed = false;

  return {
    async run(_task: PageScanTask): Promise<PageScanObservation[]> {
      if (disposed) {
        throw new Error('PageScanWorker has been disposed');
      }
      // Stub: no browser context is launched — return empty observations.
      return [];
    },

    dispose(): void {
      disposed = true;
    },
  };
}
