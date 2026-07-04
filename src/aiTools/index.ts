// AI tool registry — registers and gates agent-callable tools.
// Tools are only available when Mode ≠ 'safe' and the tool is explicitly
// authorized via the per-project tool allow-list.
// Adapted from source-reference/vantix/agent_skills/ (snapshot 2026-05-26).
// No external npm dependencies.

export type AiToolId =
  | 'captured-traffic-sql'
  | 'managed-browser-drive';

export interface AiTool {
  id: AiToolId;
  name: string;
  description: string;
  /** Required mode level before this tool activates. */
  minMode: 'standard' | 'attack';
  /** Whether this tool requires explicit per-project opt-in. */
  requiresExplicitEnable: boolean;
}

export interface AiToolInvocation {
  toolId: AiToolId;
  projectId: string;
  mode: string;
  operatorEnabled: boolean;
  input: Record<string, unknown>;
}

export interface AiToolResult {
  toolId: AiToolId;
  allowed: boolean;
  output?: unknown;
  refusalReason?: string;
}

const REGISTERED_TOOLS: AiTool[] = [
  {
    id: 'captured-traffic-sql',
    name: 'Captured Traffic SQL',
    description: 'Read-only parametrised SELECT against the active project exchange/issue/matrix tables.',
    minMode: 'standard',
    requiresExplicitEnable: true,
  },
  {
    id: 'managed-browser-drive',
    name: 'Managed Browser Drive',
    description: 'Drive the in-app managed browser session (click, type, evaluate-JS, screenshot) under Mode + Context gates.',
    minMode: 'standard',
    requiresExplicitEnable: true,
  },
];

export function getRegisteredTools(): AiTool[] {
  return REGISTERED_TOOLS.slice();
}

export function getTool(id: AiToolId): AiTool | undefined {
  return REGISTERED_TOOLS.find((t) => t.id === id);
}

export function isToolAllowed(
  toolId: AiToolId,
  mode: string,
  operatorEnabled: boolean,
): boolean {
  const tool = getTool(toolId);
  if (!tool) return false;
  if (mode === 'safe') return false;
  if (tool.minMode === 'attack' && mode !== 'attack') return false;
  if (tool.requiresExplicitEnable && !operatorEnabled) return false;
  return true;
}
