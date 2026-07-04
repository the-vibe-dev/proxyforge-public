// OAST payload broker: signs, tracks, and correlates out-of-band callback payloads.
// Adapted from source-reference/vantix/secops/skills/ OAST patterns.
// No runtime dependency on the vendored source.

import crypto from 'node:crypto';

export interface OastPayload {
  id: string;
  token: string;
  protocol: 'http' | 'dns' | 'smtp';
  endpoint: string;
  projectId: string;
  checkId: string;
  insertionPointId: string;
  exchangeId: string;
  createdAt: string;
  status: 'pending' | 'triggered' | 'expired';
  notes?: string;
}

export interface OastInteraction {
  id: string;
  payloadId: string;
  protocol: 'http' | 'dns' | 'smtp';
  observedAt: string;
  sourceIp?: string;
  sourceHost?: string;
  requestLine?: string;
  userAgent?: string;
  raw: string;
  projectId: string;
  correlatedAt: string;
}

const payloadStore = new Map<string, OastPayload>();
const interactionStore = new Map<string, OastInteraction>();

function hmacToken(projectId: string, payloadId: string, secret: string): string {
  return crypto
    .createHmac('sha256', secret)
    .update(`${projectId}:${payloadId}`)
    .digest('hex')
    .slice(0, 24);
}

export function createOastPayload(
  projectId: string,
  checkId: string,
  insertionPointId: string,
  exchangeId: string,
  oastBaseUrl: string,
  protocol: OastPayload['protocol'] = 'http',
  projectSecret: string = projectId,
): OastPayload {
  const id = `oast-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
  const token = hmacToken(projectId, id, projectSecret);
  const endpoint = `${oastBaseUrl.replace(/\/$/, '')}/${token}`;

  const payload: OastPayload = {
    id,
    token,
    protocol,
    endpoint,
    projectId,
    checkId,
    insertionPointId,
    exchangeId,
    createdAt: new Date().toISOString(),
    status: 'pending',
  };

  payloadStore.set(id, payload);
  return payload;
}

export function recordOastInteraction(
  payloadId: string,
  rawInteraction: string,
  sourceIp?: string,
  requestLine?: string,
): OastInteraction | null {
  const payload = payloadStore.get(payloadId);
  if (!payload) return null;

  const interaction: OastInteraction = {
    id: `oasti-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`,
    payloadId,
    protocol: payload.protocol,
    observedAt: new Date().toISOString(),
    sourceIp,
    requestLine,
    raw: rawInteraction,
    projectId: payload.projectId,
    correlatedAt: new Date().toISOString(),
  };

  interactionStore.set(interaction.id, interaction);

  // Mark payload as triggered
  payloadStore.set(payloadId, { ...payload, status: 'triggered' });

  return interaction;
}

export function correlateCallback(token: string, projectId: string): OastPayload | null {
  for (const payload of payloadStore.values()) {
    if (payload.token === token && payload.projectId === projectId) return payload;
  }
  return null;
}

export function getInteractionsForPayload(payloadId: string): OastInteraction[] {
  return Array.from(interactionStore.values()).filter((i) => i.payloadId === payloadId);
}

export function buildOastProofPayload(
  payload: OastPayload,
  interaction: OastInteraction,
): { verified: boolean; evidence: string[] } {
  const tokenInRaw = interaction.raw.includes(payload.token);
  const sameProject = payload.projectId === interaction.projectId;
  const verified = tokenInRaw && sameProject;

  return {
    verified,
    evidence: [
      verified ? `OAST callback verified: token ${payload.token} observed in interaction ${interaction.id}` : 'Token not found in interaction',
      `Source: ${interaction.sourceIp ?? 'unknown'} at ${interaction.observedAt}`,
      `Check: ${payload.checkId}, exchange: ${payload.exchangeId}`,
    ],
  };
}
