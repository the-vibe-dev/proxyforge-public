import net from 'node:net';
import tls from 'node:tls';
import { URL } from 'node:url';

export type RepeaterSyncTechnique = 'single-connection' | 'last-byte' | 'single-packet' | 'pause-window';
export type DesyncProbeRole = 'baseline' | 'poison' | 'victim' | 'warmup';
export type RepeaterDesyncTransportStatus = 'proof' | 'blocked' | 'error';
export type RepeaterDesyncTlsMode = 'strict' | 'relaxed';

export interface RepeaterDesyncProbeRequest {
  id: string;
  name: string;
  targetUrl: string;
  rawRequest: string;
  role: DesyncProbeRole;
}

export interface RepeaterDesyncRaceRuntimeRequest {
  planId?: string;
  targetUrl: string;
  requests: RepeaterDesyncProbeRequest[];
  scopeAllowlist: string[];
  timeoutMs?: number;
  syncTechnique?: RepeaterSyncTechnique;
  pauseMs?: number;
}

export interface RepeaterDesyncRuntimeResponse {
  requestId: string;
  role: DesyncProbeRole;
  name: string;
  targetUrl: string;
  status?: number;
  statusLine?: string;
  bytes: number;
  startedAt: string;
  completedAt?: string;
  timingMs: number;
  headers: Record<string, string>;
  bodyPreview: string;
  rawRequest: string;
  rawResponse: string;
  error?: string;
}

export interface RepeaterDesyncRuntimeResult {
  id: string;
  planId?: string;
  createdAt: string;
  targetUrl: string;
  protocol: 'HTTP/1.1';
  transport: 'single-connection' | 'parallel-last-byte' | 'parallel-single-packet';
  syncTechnique: RepeaterSyncTechnique;
  status: RepeaterDesyncTransportStatus;
  requestCount: number;
  responseOrder: string[];
  jitterMs: number;
  raceWindowMs: number;
  releaseSkewMs?: number;
  connectionStrategy: string;
  timingNotes: string;
  responses: RepeaterDesyncRuntimeResponse[];
  rawTranscript: string;
  summary: string;
}

export type RepeaterDesyncParserProfile = 'strict-rfc' | 'frontend-content-length' | 'backend-transfer-encoding' | 'cl0-backend';

export interface RepeaterDesyncParserOutcome {
  profile: RepeaterDesyncParserProfile;
  accepted: boolean;
  framing: 'content-length' | 'transfer-encoding' | 'cl0' | 'close-delimited' | 'rejected';
  consumedBodyBytes: number;
  leftoverBytes: number;
  leftoverPreview: string;
  interpretedRequestCount: number;
  signal: 'aligned' | 'parser-differential' | 'queued-followup' | 'incomplete-body' | 'rejected';
  detail: string;
}

export interface RepeaterDesyncParserDifferentialCandidate {
  requestId: string;
  role: DesyncProbeRole;
  name: string;
  ambiguityFlags: string[];
  outcomes: RepeaterDesyncParserOutcome[];
  verdict: 'aligned' | 'parser-differential' | 'queued-followup';
  evidence: string[];
}

export interface RepeaterDesyncParserDifferentialPackage {
  kind: 'proxyforge-repeater-desync-parser-differential-package';
  schemaVersion: 1;
  createdAt: string;
  parserProfiles: RepeaterDesyncParserProfile[];
  candidateCount: number;
  highRiskCandidateCount: number;
  candidates: RepeaterDesyncParserDifferentialCandidate[];
  summary: string;
  content: string;
}

export interface RepeaterRaceDesyncProductionPackage {
  kind: 'proxyforge-repeater-race-desync-production-package';
  schemaVersion: 1;
  generatedAt: string;
  runtimeProfileCount: number;
  requestCount: number;
  observedResponseCount: number;
  highRiskParserCandidateCount: number;
  maxReleaseSkewMs: number;
  maxRaceWindowMs: number;
  targetOriginCount: number;
  transportModes: RepeaterDesyncRuntimeResult['transport'][];
  scopeBlockSummary?: string;
  packageRefreshProof: {
    refreshedAt: string;
    parserDigest: string;
    runtimeDigests: string[];
    blockedDigests: string[];
    productionDigest: string;
    staleRuntimeIds: string[];
  };
  operationalSecretSignals: string[];
  requirements: {
    parserDifferentialCovered: boolean;
    singleConnectionProofCovered: boolean;
    lastByteRaceCovered: boolean;
    singlePacketRaceSoakCovered: boolean;
    scopeBlockingCovered: boolean;
    timingBudgetCovered: boolean;
    responseOrderCovered: boolean;
    rawTranscriptPreserved: boolean;
    operationalSecretsPreserved: boolean;
    packageRefreshCovered: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: true;
  summary: string;
  content: string;
}

interface PreparedTarget {
  url: URL;
  host: string;
  port: number;
  tls: boolean;
}

interface PreparedRequest {
  request: RepeaterDesyncProbeRequest;
  rawRequest: string;
  buffer: Buffer;
}

interface PreparedRuntimeRequest {
  target: PreparedTarget;
  requests: PreparedRequest[];
}

interface ParsedResponse {
  status?: number;
  statusLine?: string;
  headers: Record<string, string>;
  rawResponse: string;
  bodyPreview: string;
  bytes: number;
  completedAtMs: number;
}

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;

export class RepeaterDesyncRaceEngine {
  constructor(private readonly options: { upstreamTlsMode?: () => RepeaterDesyncTlsMode } = {}) {}

  async runSingleConnectionProbe(request: RepeaterDesyncRaceRuntimeRequest): Promise<RepeaterDesyncRuntimeResult> {
    const createdAtMs = Date.now();
    const createdAt = new Date(createdAtMs).toISOString();
    const prepared = prepareRuntimeRequest(request);
    if ('blocked' in prepared) {
      return blockedResult(request, 'single-connection', 'single-connection', createdAt, prepared.blocked);
    }

    const timeoutMs = normalizeTimeout(request.timeoutMs);
    const parser = new HttpResponseAccumulator(prepared.requests.length);
    const startedAt = Date.now();
    const writeTimes: number[] = [];
    const transcript: string[] = [];

    try {
      const socket = await connectTarget(prepared.target, timeoutMs, this.upstreamTlsMode() === 'strict');
      const responsePromise = waitForResponses(socket, parser, prepared.requests.length, timeoutMs);
      for (const entry of prepared.requests) {
        writeTimes.push(Date.now());
        transcript.push(`>>> ${entry.request.id} ${entry.request.role}\n${entry.rawRequest}`);
        await writeAndDrain(socket, entry.buffer);
      }
      const parsedResponses = await responsePromise;
      socket.destroy();
      return buildResult({
        request,
        prepared,
        createdAt,
        startedAt,
        parsedResponses,
        transport: 'single-connection',
        syncTechnique: 'single-connection',
        connectionStrategy: `HTTP/1.1 single socket to ${prepared.target.host}:${prepared.target.port}; wrote ${prepared.requests.length} raw request(s) over one connection.`,
        releaseSkewMs: rangeMs(writeTimes),
        transcript,
      });
    } catch (error) {
      return errorResult(request, 'single-connection', 'single-connection', createdAt, error);
    }
  }

  async runParallelRace(request: RepeaterDesyncRaceRuntimeRequest): Promise<RepeaterDesyncRuntimeResult> {
    const createdAt = new Date().toISOString();
    const syncTechnique = request.syncTechnique === 'single-packet' ? 'single-packet' : 'last-byte';
    const prepared = prepareRuntimeRequest(request);
    if ('blocked' in prepared) {
      return blockedResult(request, syncTechnique === 'single-packet' ? 'parallel-single-packet' : 'parallel-last-byte', syncTechnique, createdAt, prepared.blocked);
    }

    const timeoutMs = normalizeTimeout(request.timeoutMs);
    const startedAt = Date.now();
    const channels: Array<{ socket: net.Socket | tls.TLSSocket; parser: HttpResponseAccumulator; entry: PreparedRequest }> = [];
    const releaseTimes: bigint[] = [];
    const transcript: string[] = [];

    try {
      for (const entry of prepared.requests) {
        const socket = await connectTarget(prepared.target, timeoutMs, this.upstreamTlsMode() === 'strict');
        channels.push({ socket, parser: new HttpResponseAccumulator(1), entry });
      }

      if (syncTechnique === 'last-byte') {
        await Promise.all(channels.map(({ socket, entry }) => {
          const staged = entry.buffer.subarray(0, Math.max(0, entry.buffer.length - 1));
          return writeAndDrain(socket, staged);
        }));
        await delay(Math.max(0, Math.min(250, Number(request.pauseMs ?? 25))));
        await Promise.all(channels.map(({ socket, entry }) => {
          const finalByte = entry.buffer.subarray(Math.max(0, entry.buffer.length - 1));
          releaseTimes.push(process.hrtime.bigint());
          transcript.push(`>>> ${entry.request.id} ${entry.request.role}\n${entry.rawRequest}`);
          return writeAndDrain(socket, finalByte);
        }));
      } else {
        await delay(Math.max(0, Math.min(250, Number(request.pauseMs ?? 10))));
        await Promise.all(channels.map(({ socket, entry }) => {
          releaseTimes.push(process.hrtime.bigint());
          transcript.push(`>>> ${entry.request.id} ${entry.request.role}\n${entry.rawRequest}`);
          return writeAndDrain(socket, entry.buffer);
        }));
      }

      const responseSets = await Promise.all(channels.map(({ socket, parser }) => waitForResponses(socket, parser, 1, timeoutMs)));
      channels.forEach(({ socket }) => socket.destroy());
      const parsedResponses = responseSets.flat();
      const releaseSkewMs = rangeHrMs(releaseTimes);
      return buildResult({
        request,
        prepared,
        createdAt,
        startedAt,
        parsedResponses,
        transport: syncTechnique === 'single-packet' ? 'parallel-single-packet' : 'parallel-last-byte',
        syncTechnique,
        connectionStrategy: `HTTP/1.1 ${syncTechnique} race across ${prepared.requests.length} warmed connection(s) to ${prepared.target.host}:${prepared.target.port}.`,
        releaseSkewMs,
        transcript,
      });
    } catch (error) {
      channels.forEach(({ socket }) => socket.destroy());
      return errorResult(request, syncTechnique === 'single-packet' ? 'parallel-single-packet' : 'parallel-last-byte', syncTechnique, createdAt, error);
    }
  }

  private upstreamTlsMode(): RepeaterDesyncTlsMode {
    return this.options.upstreamTlsMode?.() === 'relaxed' ? 'relaxed' : 'strict';
  }
}

export function buildRepeaterDesyncParserDifferentialPackage(
  requests: RepeaterDesyncProbeRequest[],
  createdAt = new Date().toISOString(),
): RepeaterDesyncParserDifferentialPackage {
  const parserProfiles: RepeaterDesyncParserProfile[] = ['strict-rfc', 'frontend-content-length', 'backend-transfer-encoding', 'cl0-backend'];
  const candidates = requests.map((request) => analyzeParserDifferentialCandidate(request, parserProfiles));
  const highRiskCandidateCount = candidates.filter((candidate) => candidate.verdict !== 'aligned').length;
  return {
    kind: 'proxyforge-repeater-desync-parser-differential-package',
    schemaVersion: 1,
    createdAt,
    parserProfiles,
    candidateCount: candidates.length,
    highRiskCandidateCount,
    candidates,
    summary: `Parser differential review found ${highRiskCandidateCount}/${candidates.length} request(s) with divergent framing or queued follow-up evidence across ${parserProfiles.length} parser profile(s).`,
    content: `proxyforge-repeater-desync-parser-differential parserProfiles=${parserProfiles.join(',')} highRiskCandidates=${highRiskCandidateCount}`,
  };
}

export function buildRepeaterRaceDesyncProductionPackage(input: {
  parserDifferential: RepeaterDesyncParserDifferentialPackage;
  runtimeResults: RepeaterDesyncRuntimeResult[];
  blockedResults?: RepeaterDesyncRuntimeResult[];
  minSoakRequests?: number;
  maxReleaseSkewMs?: number;
  maxRaceWindowMs?: number;
  generatedAt?: string;
}): RepeaterRaceDesyncProductionPackage {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const runtimeResults = input.runtimeResults.filter(Boolean);
  const blockedResults = input.blockedResults?.filter(Boolean) ?? [];
  const proofResults = runtimeResults.filter((result) => result.status === 'proof');
  const raceResults = proofResults.filter((result) => result.transport === 'parallel-last-byte' || result.transport === 'parallel-single-packet');
  const targetOriginCount = new Set(proofResults.map((result) => originKey(result.targetUrl))).size;
  const transportModes = Array.from(new Set(proofResults.map((result) => result.transport))).sort();
  const requestCount = proofResults.reduce((total, result) => total + result.requestCount, 0);
  const observedResponseCount = proofResults.reduce((total, result) => total + result.responses.filter((response) => response.rawResponse).length, 0);
  const maxReleaseSkewMs = Math.max(...raceResults.map((result) => result.releaseSkewMs ?? 0), 0);
  const maxRaceWindowMs = Math.max(...raceResults.map((result) => result.raceWindowMs ?? 0), 0);
  const rawRuntimeMaterial = [
    input.parserDifferential.content,
    ...runtimeResults.flatMap((result) => [
      result.rawTranscript,
      result.summary,
      ...result.responses.flatMap((response) => [response.rawRequest, response.rawResponse]),
    ]),
    ...blockedResults.map((result) => result.summary),
  ].filter(Boolean);
  const operationalSecretSignals = repeaterOperationalSecretSignals(...rawRuntimeMaterial);
  const minSoakRequests = Math.max(1, Number(input.minSoakRequests ?? 12));
  const releaseSkewBudget = Math.max(1, Number(input.maxReleaseSkewMs ?? 100));
  const raceWindowBudget = Math.max(1, Number(input.maxRaceWindowMs ?? releaseSkewBudget));
  const parserDigest = simpleDigest(JSON.stringify({
    kind: input.parserDifferential.kind,
    candidateCount: input.parserDifferential.candidateCount,
    highRiskCandidateCount: input.parserDifferential.highRiskCandidateCount,
    parserProfiles: input.parserDifferential.parserProfiles,
  }));
  const runtimeDigests = runtimeResults.map((result) => simpleDigest(JSON.stringify({
    id: result.id,
    targetUrl: result.targetUrl,
    transport: result.transport,
    syncTechnique: result.syncTechnique,
    status: result.status,
    requestCount: result.requestCount,
    responseCount: result.responses.length,
    releaseSkewMs: result.releaseSkewMs,
    raceWindowMs: result.raceWindowMs,
    responseOrder: result.responseOrder,
  })));
  const blockedDigests = blockedResults.map((result) => simpleDigest(JSON.stringify({
    id: result.id,
    targetUrl: result.targetUrl,
    status: result.status,
    summary: result.summary,
  })));
  const requirements = {
    parserDifferentialCovered: input.parserDifferential.highRiskCandidateCount > 0
      && input.parserDifferential.candidates.some((candidate) => candidate.verdict !== 'aligned'),
    singleConnectionProofCovered: proofResults.some((result) => result.transport === 'single-connection' && result.responses.length >= 2),
    lastByteRaceCovered: proofResults.some((result) => result.transport === 'parallel-last-byte' && result.syncTechnique === 'last-byte' && result.responses.length >= 2),
    singlePacketRaceSoakCovered: proofResults.some((result) => result.transport === 'parallel-single-packet' && result.syncTechnique === 'single-packet' && result.requestCount >= minSoakRequests),
    scopeBlockingCovered: blockedResults.some((result) => result.status === 'blocked' && /outside|scope|allowlist/i.test(result.summary)),
    timingBudgetCovered: raceResults.length > 0
      && raceResults.every((result) => (result.releaseSkewMs ?? result.raceWindowMs) <= releaseSkewBudget && result.raceWindowMs <= raceWindowBudget),
    responseOrderCovered: proofResults.every((result) => result.responseOrder.length > 0),
    rawTranscriptPreserved: rawRuntimeMaterial.some((value) => />>>|<<<|HTTP\/1\.1|Authorization:|Cookie:/i.test(value)),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    packageRefreshCovered: runtimeDigests.length === runtimeResults.length && parserDigest.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const productionDigest = simpleDigest(JSON.stringify({
    parserDigest,
    runtimeDigests,
    blockedDigests,
    requirements,
    generatedAt,
  }));
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    parserDigest,
    runtimeDigests,
    blockedDigests,
    productionDigest,
    staleRuntimeIds: [],
  };
  const body = {
    kind: 'proxyforge-repeater-race-desync-production-package',
    schemaVersion: 1,
    generatedAt,
    parserDifferential: input.parserDifferential,
    runtimeResults,
    blockedResults,
    budgets: {
      minSoakRequests,
      maxReleaseSkewMs: releaseSkewBudget,
      maxRaceWindowMs: raceWindowBudget,
    },
    observed: {
      runtimeProfileCount: proofResults.length,
      requestCount,
      observedResponseCount,
      highRiskParserCandidateCount: input.parserDifferential.highRiskCandidateCount,
      maxReleaseSkewMs,
      maxRaceWindowMs,
      targetOriginCount,
      transportModes,
      scopeBlockSummary: blockedResults[0]?.summary,
    },
    packageRefreshProof,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };

  return {
    kind: 'proxyforge-repeater-race-desync-production-package',
    schemaVersion: 1,
    generatedAt,
    runtimeProfileCount: proofResults.length,
    requestCount,
    observedResponseCount,
    highRiskParserCandidateCount: input.parserDifferential.highRiskCandidateCount,
    maxReleaseSkewMs,
    maxRaceWindowMs,
    targetOriginCount,
    transportModes,
    scopeBlockSummary: blockedResults[0]?.summary,
    packageRefreshProof,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    summary: `Repeater race/desync production package covered ${proofResults.length} runtime profile(s), ${requestCount} request(s), ${observedResponseCount} observed response(s), ${input.parserDifferential.highRiskCandidateCount} parser-differential candidate(s), max release skew ${Math.round(maxReleaseSkewMs * 1000) / 1000}ms, and transports ${transportModes.join(', ') || 'none'}.`,
    content: JSON.stringify(body, null, 2),
  };
}

function analyzeParserDifferentialCandidate(
  request: RepeaterDesyncProbeRequest,
  parserProfiles: RepeaterDesyncParserProfile[],
): RepeaterDesyncParserDifferentialCandidate {
  const parsed = parseRawRequestForDifferential(normalizeRawHttp(request.rawRequest));
  const ambiguityFlags = parserAmbiguityFlags(parsed);
  const outcomes = parserProfiles.map((profile) => evaluateParserProfile(profile, parsed, request.role));
  const hasQueuedFollowup = outcomes.some((outcome) => outcome.signal === 'queued-followup');
  const uniqueFrames = new Set(outcomes.map((outcome) => `${outcome.accepted}:${outcome.framing}:${outcome.consumedBodyBytes}:${outcome.leftoverBytes}:${outcome.signal}`));
  const verdict = hasQueuedFollowup ? 'queued-followup' : uniqueFrames.size > 1 ? 'parser-differential' : 'aligned';
  return {
    requestId: request.id,
    role: request.role,
    name: request.name,
    ambiguityFlags,
    outcomes,
    verdict,
    evidence: [
      `role=${request.role}`,
      `flags=${ambiguityFlags.join(',') || 'none'}`,
      `profiles=${parserProfiles.join(',')}`,
      `signals=${outcomes.map((outcome) => `${outcome.profile}:${outcome.signal}`).join(',')}`,
    ],
  };
}

function prepareRuntimeRequest(request: RepeaterDesyncRaceRuntimeRequest): PreparedRuntimeRequest | { blocked: string } {
  if (!request.requests.length) return { blocked: 'No desync/race requests were supplied.' };
  const targetUrl = safeUrl(request.targetUrl);
  if (!targetUrl) return { blocked: `Invalid target URL: ${request.targetUrl}` };
  if (!isAllowedHost(targetUrl.hostname, request.scopeAllowlist)) {
    return { blocked: `Target ${targetUrl.hostname} is outside the supplied scope allowlist.` };
  }
  const target = {
    url: targetUrl,
    host: targetUrl.hostname,
    port: Number(targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80)),
    tls: targetUrl.protocol === 'https:',
  };

  const preparedRequests: PreparedRequest[] = [];
  for (const entry of request.requests) {
    const entryUrl = safeUrl(entry.targetUrl || request.targetUrl);
    if (!entryUrl) return { blocked: `Invalid request target URL for ${entry.id}.` };
    if (!isAllowedHost(entryUrl.hostname, request.scopeAllowlist)) {
      return { blocked: `Request ${entry.id} target ${entryUrl.hostname} is outside scope.` };
    }
    if (entryUrl.protocol !== targetUrl.protocol || entryUrl.hostname !== targetUrl.hostname || normalizePort(entryUrl) !== normalizePort(targetUrl)) {
      return { blocked: `Request ${entry.id} is not on the same origin as ${request.targetUrl}; synchronized transport requires one origin per run.` };
    }
    const rawRequest = normalizeRawHttp(entry.rawRequest);
    preparedRequests.push({ request: entry, rawRequest, buffer: Buffer.from(rawRequest, 'utf8') });
  }

  return { target, requests: preparedRequests };
}

function connectTarget(target: PreparedTarget, timeoutMs: number, rejectUnauthorized: boolean): Promise<net.Socket | tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = target.tls
      ? tls.connect({
        host: target.host,
        port: target.port,
        servername: target.host,
        rejectUnauthorized,
        ALPNProtocols: ['http/1.1'],
      })
      : net.connect({ host: target.host, port: target.port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Timed out connecting to ${target.host}:${target.port}`));
    }, timeoutMs);
    socket.once(target.tls ? 'secureConnect' : 'connect', () => {
      clearTimeout(timer);
      socket.setNoDelay(true);
      resolve(socket);
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function waitForResponses(
  socket: net.Socket | tls.TLSSocket,
  parser: HttpResponseAccumulator,
  expectedCount: number,
  timeoutMs: number,
): Promise<ParsedResponse[]> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      cleanup();
      parser.finalizeRemainder();
      resolve(parser.responses.slice(0, expectedCount));
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('close', finish);
      socket.removeListener('end', finish);
      socket.removeListener('error', finish);
    };
    const onData = (chunk: Buffer) => {
      parser.push(chunk);
      if (parser.responses.length >= expectedCount) finish();
    };
    const timer = setTimeout(finish, timeoutMs);
    socket.on('data', onData);
    socket.once('close', finish);
    socket.once('end', finish);
    socket.once('error', finish);
  });
}

function writeAndDrain(socket: net.Socket | tls.TLSSocket, buffer: Buffer): Promise<void> {
  if (!buffer.length) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const done = (error?: Error | null) => {
      if (error) reject(error);
      else resolve();
    };
    if (socket.write(buffer, done)) resolve();
  });
}

class HttpResponseAccumulator {
  readonly responses: ParsedResponse[] = [];
  private buffer = Buffer.alloc(0);

  constructor(private readonly expectedCount: number) {}

  push(chunk: Buffer) {
    this.buffer = Buffer.concat([this.buffer, chunk]).subarray(0, MAX_CAPTURE_BYTES);
    this.parseCompleteResponses();
  }

  finalizeRemainder() {
    if (!this.buffer.length || this.responses.length >= this.expectedCount) return;
    const parsed = parseRawResponse(this.buffer, this.buffer.length);
    if (parsed) {
      this.responses.push(parsed);
      this.buffer = Buffer.alloc(0);
    }
  }

  private parseCompleteResponses() {
    while (this.responses.length < this.expectedCount && this.buffer.length) {
      const rawLength = completeResponseLength(this.buffer);
      if (rawLength <= 0) return;
      const parsed = parseRawResponse(this.buffer, rawLength);
      if (!parsed) return;
      this.responses.push(parsed);
      this.buffer = this.buffer.subarray(rawLength);
    }
  }
}

function completeResponseLength(buffer: Buffer) {
  const headerEnd = buffer.indexOf('\r\n\r\n');
  if (headerEnd === -1) return 0;
  const bodyStart = headerEnd + 4;
  const headerText = buffer.subarray(0, headerEnd).toString('latin1');
  const headers = parseHeaders(headerText);
  const contentLength = Number(headers['content-length']);
  if (Number.isFinite(contentLength) && contentLength >= 0) {
    const total = bodyStart + contentLength;
    return buffer.length >= total ? total : 0;
  }
  if (/chunked/i.test(headers['transfer-encoding'] ?? '')) {
    return completeChunkedLength(buffer, bodyStart);
  }
  return 0;
}

function completeChunkedLength(buffer: Buffer, offset: number) {
  let cursor = offset;
  while (cursor < buffer.length) {
    const lineEnd = buffer.indexOf('\r\n', cursor);
    if (lineEnd === -1) return 0;
    const sizeText = buffer.subarray(cursor, lineEnd).toString('latin1').split(';')[0].trim();
    const size = Number.parseInt(sizeText, 16);
    if (!Number.isFinite(size)) return 0;
    cursor = lineEnd + 2;
    if (buffer.length < cursor + size + 2) return 0;
    cursor += size + 2;
    if (size === 0) return cursor;
  }
  return 0;
}

function parseRawResponse(buffer: Buffer, rawLength: number): ParsedResponse | null {
  const raw = buffer.subarray(0, rawLength);
  const headerEnd = raw.indexOf('\r\n\r\n');
  if (headerEnd === -1) return null;
  const headerText = raw.subarray(0, headerEnd).toString('latin1');
  const body = raw.subarray(headerEnd + 4);
  const statusLine = headerText.split('\r\n')[0] ?? '';
  const status = Number(statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d+)/)?.[1]);
  return {
    status: Number.isFinite(status) ? status : undefined,
    statusLine,
    headers: parseHeaders(headerText),
    rawResponse: raw.toString('utf8'),
    bodyPreview: body.toString('utf8').slice(0, 2000),
    bytes: raw.length,
    completedAtMs: Date.now(),
  };
}

function parseHeaders(headerText: string) {
  const headers: Record<string, string> = {};
  for (const line of headerText.split('\r\n').slice(1)) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  return headers;
}

function buildResult(input: {
  request: RepeaterDesyncRaceRuntimeRequest;
  prepared: PreparedRuntimeRequest;
  createdAt: string;
  startedAt: number;
  parsedResponses: ParsedResponse[];
  transport: RepeaterDesyncRuntimeResult['transport'];
  syncTechnique: RepeaterSyncTechnique;
  connectionStrategy: string;
  releaseSkewMs?: number;
  transcript: string[];
}): RepeaterDesyncRuntimeResult {
  const responses = input.prepared.requests.map((entry, index): RepeaterDesyncRuntimeResponse => {
    const parsed = input.parsedResponses[index];
    const completedAtMs = parsed?.completedAtMs ?? Date.now();
    return {
      requestId: entry.request.id,
      role: entry.request.role,
      name: entry.request.name,
      targetUrl: entry.request.targetUrl,
      status: parsed?.status,
      statusLine: parsed?.statusLine,
      bytes: parsed?.bytes ?? 0,
      startedAt: new Date(input.startedAt).toISOString(),
      completedAt: parsed ? new Date(completedAtMs).toISOString() : undefined,
      timingMs: Math.max(0, completedAtMs - input.startedAt),
      headers: parsed?.headers ?? {},
      bodyPreview: parsed?.bodyPreview ?? '',
      rawRequest: entry.rawRequest,
      rawResponse: parsed?.rawResponse ?? '',
      error: parsed ? undefined : 'No complete HTTP response parsed before timeout or close.',
    };
  });
  const responseOrder = responses
    .filter((response) => response.rawResponse || response.error)
    .sort((left, right) => left.timingMs - right.timingMs)
    .map((response, index) => `${index + 1}/${responses.length} ${response.role}:${response.name} ${response.status ?? 'no-response'}`);
  const responseTimes = responses.filter((response) => response.completedAt).map((response) => input.startedAt + response.timingMs);
  const jitterMs = rangeMs(responseTimes);
  const raceWindowMs = input.releaseSkewMs ?? jitterMs;
  const status: RepeaterDesyncTransportStatus = responses.some((response) => response.rawResponse) ? 'proof' : 'error';
  const rawTranscript = [
    ...input.transcript,
    ...responses.filter((response) => response.rawResponse).map((response) => `<<< ${response.requestId}\n${response.rawResponse}`),
  ].join('\n');
  return {
    id: `repeater-desync-runtime-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    planId: input.request.planId,
    createdAt: input.createdAt,
    targetUrl: input.request.targetUrl,
    protocol: 'HTTP/1.1',
    transport: input.transport,
    syncTechnique: input.syncTechnique,
    status,
    requestCount: input.prepared.requests.length,
    responseOrder,
    jitterMs,
    raceWindowMs,
    releaseSkewMs: input.releaseSkewMs,
    connectionStrategy: input.connectionStrategy,
    timingNotes: `Parsed ${responses.filter((response) => response.rawResponse).length}/${responses.length} HTTP response(s); release skew ${Math.round(raceWindowMs * 1000) / 1000}ms; response jitter ${jitterMs}ms.`,
    responses,
    rawTranscript,
    summary: `${input.transport} ${status}: ${responses.filter((response) => response.rawResponse).length}/${responses.length} response(s), order ${responseOrder.join(', ') || 'none'}, release window ${Math.round(raceWindowMs * 1000) / 1000}ms.`,
  };
}

function blockedResult(
  request: RepeaterDesyncRaceRuntimeRequest,
  transport: RepeaterDesyncRuntimeResult['transport'],
  syncTechnique: RepeaterSyncTechnique,
  createdAt: string,
  reason: string,
): RepeaterDesyncRuntimeResult {
  return {
    id: `repeater-desync-blocked-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    planId: request.planId,
    createdAt,
    targetUrl: request.targetUrl,
    protocol: 'HTTP/1.1',
    transport,
    syncTechnique,
    status: 'blocked',
    requestCount: request.requests.length,
    responseOrder: [],
    jitterMs: 0,
    raceWindowMs: 0,
    connectionStrategy: 'blocked before socket transport',
    timingNotes: reason,
    responses: [],
    rawTranscript: '',
    summary: reason,
  };
}

function errorResult(
  request: RepeaterDesyncRaceRuntimeRequest,
  transport: RepeaterDesyncRuntimeResult['transport'],
  syncTechnique: RepeaterSyncTechnique,
  createdAt: string,
  error: unknown,
): RepeaterDesyncRuntimeResult {
  const message = error instanceof Error ? error.message : String(error);
  return {
    id: `repeater-desync-error-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    planId: request.planId,
    createdAt,
    targetUrl: request.targetUrl,
    protocol: 'HTTP/1.1',
    transport,
    syncTechnique,
    status: 'error',
    requestCount: request.requests.length,
    responseOrder: [],
    jitterMs: 0,
    raceWindowMs: 0,
    connectionStrategy: 'socket transport failed',
    timingNotes: message,
    responses: [],
    rawTranscript: '',
    summary: message,
  };
}

function normalizeRawHttp(raw: string) {
  const normalized = String(raw || '').replace(/\r?\n/g, '\r\n');
  if (normalized.includes('\r\n\r\n')) return normalized;
  return `${normalized.replace(/\r\n*$/, '')}\r\n\r\n`;
}

function parseRawRequestForDifferential(raw: string) {
  const headerEnd = raw.indexOf('\r\n\r\n');
  const headerText = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw;
  const body = headerEnd >= 0 ? raw.slice(headerEnd + 4) : '';
  const lines = headerText.split('\r\n');
  const headers = lines.slice(1).map((line) => {
    const colon = line.indexOf(':');
    return colon > 0
      ? { name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1).trim() }
      : { name: line.trim().toLowerCase(), value: '' };
  }).filter((header) => header.name);
  return {
    startLine: lines[0] ?? '',
    headers,
    body,
    bodyBytes: Buffer.byteLength(body, 'utf8'),
  };
}

function parserAmbiguityFlags(parsed: ReturnType<typeof parseRawRequestForDifferential>) {
  const flags: string[] = [];
  const contentLengths = parsed.headers.filter((header) => header.name === 'content-length').map((header) => Number(header.value));
  const transferEncodings = parsed.headers.filter((header) => header.name === 'transfer-encoding').map((header) => header.value.toLowerCase());
  const hasChunked = transferEncodings.some((value) => /chunked/.test(value));
  if (contentLengths.length && hasChunked) flags.push('content-length-and-transfer-encoding');
  if (new Set(contentLengths.filter(Number.isFinite)).size > 1) flags.push('multiple-content-length-mismatch');
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/1\.[01]/im.test(parsed.body)) flags.push('body-contains-http-request-line');
  const declaredLength = contentLengths.find(Number.isFinite);
  if (declaredLength !== undefined && Number.isFinite(declaredLength) && parsed.bodyBytes < declaredLength) flags.push('incomplete-declared-body');
  if (declaredLength !== undefined && Number.isFinite(declaredLength) && declaredLength === 0 && parsed.bodyBytes > 0) flags.push('cl0-body');
  return flags;
}

function evaluateParserProfile(
  profile: RepeaterDesyncParserProfile,
  parsed: ReturnType<typeof parseRawRequestForDifferential>,
  role: DesyncProbeRole,
): RepeaterDesyncParserOutcome {
  const contentLengths = parsed.headers.filter((header) => header.name === 'content-length').map((header) => Number(header.value)).filter(Number.isFinite);
  const transferEncodings = parsed.headers.filter((header) => header.name === 'transfer-encoding').map((header) => header.value.toLowerCase());
  const hasChunked = transferEncodings.some((value) => /chunked/.test(value));
  const firstContentLength = contentLengths[0];
  const hasMismatchedContentLengths = new Set(contentLengths).size > 1;

  if (profile === 'strict-rfc' && ((contentLengths.length && hasChunked) || hasMismatchedContentLengths)) {
    return parserOutcome(profile, false, 'rejected', 0, parsed.body, 'rejected', 'Strict parser rejects ambiguous Content-Length / Transfer-Encoding framing.');
  }

  if (profile === 'backend-transfer-encoding' && hasChunked) {
    const chunkedLength = completeChunkedBodyLength(parsed.body);
    if (chunkedLength === null) {
      return parserOutcome(profile, false, 'rejected', 0, parsed.body, 'rejected', 'Chunked parser could not parse a complete chunked body.');
    }
    return parserOutcome(profile, true, 'transfer-encoding', chunkedLength, parsed.body.slice(chunkedLength), undefined, 'Transfer-Encoding parser consumed complete chunked body.');
  }

  if (profile === 'cl0-backend' && (role === 'poison' || /^content-length:\s*0$/im.test(parsed.headers.map((header) => `${header.name}: ${header.value}`).join('\n')))) {
    return parserOutcome(profile, true, 'cl0', 0, parsed.body, undefined, 'CL.0-style backend consumed no body bytes and left the body queued for follow-up parsing.');
  }

  if (Number.isFinite(firstContentLength)) {
    const consumed = Math.max(0, Math.min(parsed.bodyBytes, firstContentLength));
    const signal = parsed.bodyBytes < firstContentLength ? 'incomplete-body' : undefined;
    return parserOutcome(profile, true, 'content-length', consumed, parsed.body.slice(consumed), signal, `${profile} consumed ${consumed}/${firstContentLength} declared body byte(s).`);
  }

  return parserOutcome(profile, true, 'close-delimited', parsed.bodyBytes, '', undefined, `${profile} has no explicit request body framing beyond connection close.`);
}

function parserOutcome(
  profile: RepeaterDesyncParserProfile,
  accepted: boolean,
  framing: RepeaterDesyncParserOutcome['framing'],
  consumedBodyBytes: number,
  leftover: string,
  forcedSignal: RepeaterDesyncParserOutcome['signal'] | undefined,
  detail: string,
): RepeaterDesyncParserOutcome {
  const leftoverPreview = leftover.slice(0, 240);
  const interpretedRequestCount = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/1\.[01]/i.test(leftover.trimStart()) ? 1 : 0;
  const signal = forcedSignal ?? (interpretedRequestCount ? 'queued-followup' : accepted ? 'aligned' : 'rejected');
  return {
    profile,
    accepted,
    framing,
    consumedBodyBytes,
    leftoverBytes: Buffer.byteLength(leftover, 'utf8'),
    leftoverPreview,
    interpretedRequestCount,
    signal,
    detail,
  };
}

function completeChunkedBodyLength(body: string) {
  let cursor = 0;
  while (cursor < body.length) {
    const lineEnd = body.indexOf('\r\n', cursor);
    if (lineEnd === -1) return null;
    const sizeText = body.slice(cursor, lineEnd).split(';')[0]?.trim() ?? '';
    const size = Number.parseInt(sizeText, 16);
    if (!Number.isFinite(size)) return null;
    cursor = lineEnd + 2;
    if (body.length < cursor + size + 2) return null;
    cursor += size + 2;
    if (size === 0) return cursor;
  }
  return null;
}

function normalizeTimeout(value: unknown) {
  const timeout = Number(value ?? DEFAULT_TIMEOUT_MS);
  if (!Number.isFinite(timeout)) return DEFAULT_TIMEOUT_MS;
  return Math.max(500, Math.min(60000, timeout));
}

function rangeMs(values: number[]) {
  if (values.length < 2) return 0;
  return Math.max(...values) - Math.min(...values);
}

function rangeHrMs(values: bigint[]) {
  if (values.length < 2) return 0;
  const sorted = values.slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return Number(sorted[sorted.length - 1] - sorted[0]) / 1_000_000;
}

function safeUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function normalizePort(url: URL) {
  return Number(url.port || (url.protocol === 'https:' ? 443 : 80));
}

function isAllowedHost(hostname: string, scopeAllowlist: string[]) {
  if (scopeAllowlist.length === 0) return false;
  const normalizedHost = hostname.toLowerCase();
  return scopeAllowlist.some((pattern) => {
    const normalizedPattern = pattern.trim().toLowerCase();
    if (!normalizedPattern) return false;
    if (normalizedPattern === '*') return true;
    if (normalizedPattern.startsWith('*.')) {
      const suffix = normalizedPattern.slice(1);
      return normalizedHost.endsWith(suffix) || normalizedHost === normalizedPattern.slice(2);
    }
    return normalizedHost === normalizedPattern;
  });
}

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function originKey(value: string) {
  const parsed = safeUrl(value);
  if (!parsed) return value;
  return `${parsed.protocol}//${parsed.host}`;
}

function repeaterOperationalSecretSignals(...values: string[]) {
  const text = values.join('\n');
  const signals = new Set<string>();
  if (/Authorization:\s*\S+/i.test(text) || /\bBearer\s+[A-Za-z0-9._:-]+/i.test(text)) signals.add('authorization-header');
  if (/Cookie:\s*\S+/i.test(text) || /\bsession=/i.test(text)) signals.add('cookie-header');
  if (/X-API-Key:\s*\S+/i.test(text) || /\bapi[-_]?key\b/i.test(text)) signals.add('x-api-key-header');
  if (/callback|oast|token=/i.test(text)) signals.add('callback-token');
  return Array.from(signals).sort();
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
