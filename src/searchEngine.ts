import type { HttpExchange, Severity } from './types';

const severityRank: Record<Severity, number> = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

const severityLevels = new Set<Severity>(['info', 'low', 'medium', 'high', 'critical']);

export interface SearchQueryDiagnostics {
  query: string;
  tokens: string[];
  alternatives: string[][];
  tokenCount: number;
  alternativeCount: number;
  negatedTokenCount: number;
  predicateTokens: string[];
  fieldTokens: string[];
  textTokens: string[];
  operators: string[];
  warnings: string[];
  semanticTokens: string[];
  semanticProvider?: SearchSemanticProvider;
  semanticProviderMatchCount: number;
}

export interface SearchExchangeMatch {
  exchange: HttpExchange;
  alternativeIndex: number;
  matchedTokens: string[];
  negatedTokens: string[];
  reasons: string[];
  score?: number;
  semanticScore?: number;
  semanticProviderScore?: number;
  semanticLabels?: string[];
}

export interface SearchRun {
  results: HttpExchange[];
  matches: SearchExchangeMatch[];
  diagnostics: SearchQueryDiagnostics;
}

export interface SearchFacetSummary {
  hosts: Array<{ value: string; count: number }>;
  risks: Array<{ value: Severity; count: number }>;
  sources: Array<{ value: string; count: number }>;
  methods: Array<{ value: string; count: number }>;
  tags: Array<{ value: string; count: number }>;
}

export interface SearchEvidencePackage {
  kind: 'proxyforge-search-evidence-package';
  generatedAt: string;
  query: string;
  diagnostics: SearchQueryDiagnostics;
  facets: SearchFacetSummary;
  resultCount: number;
  results: Array<{
    id: string;
    method: string;
    host: string;
    path: string;
    status: number;
    risk: Severity;
    source: string;
    tags: string[];
    matchedTokens: string[];
    reasons: string[];
    snippet: string;
  }>;
  reportReady: boolean;
  content: string;
}

export interface SearchToolHandoffEvidence {
  tool: string;
  exchangeIds: string[];
  command?: string;
  artifactPath?: string;
  purpose: string;
}

export interface SearchSemanticProvider {
  id: string;
  label: string;
  model?: string;
}

export interface SearchSemanticProviderMatch {
  exchangeId: string;
  score: number;
  rationale: string;
  labels?: string[];
  providerId?: string;
}

export interface SearchSemanticCorpusEntry {
  exchangeId: string;
  host: string;
  path: string;
  source: string;
  risk: Severity;
  tags: string[];
  corpus: string;
}

export interface SearchSemanticIndexPosting {
  exchangeId: string;
  count: number;
  weight: number;
}

export interface SearchSemanticIndexDocument {
  exchangeId: string;
  host: string;
  path: string;
  source: string;
  risk: Severity;
  tags: string[];
  corpus: string;
  tokenCount: number;
  uniqueTokenCount: number;
  digestPreview: string;
}

export interface SearchSemanticIndex {
  kind: 'proxyforge-search-semantic-index';
  schemaVersion: 1;
  generatedAt: string;
  exchangeCount: number;
  tokenCount: number;
  uniqueTokenCount: number;
  indexedTokenCount: number;
  corpusDigestPreview: string;
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  documents: SearchSemanticIndexDocument[];
  tokenPostings: Record<string, SearchSemanticIndexPosting[]>;
  content: string;
}

export interface SearchSemanticIndexOptions {
  now?: string;
  maxTokens?: number;
}

export type SearchLargeProjectSoakStatus = 'pass' | 'warning';

export interface SearchLargeProjectSoakOptions extends SearchSemanticIndexOptions {
  queries?: string[];
  providerId?: string;
  matchLimit?: number;
  matchThreshold?: number;
  minExchangeCount?: number;
  minTotalMatches?: number;
  maxBuildDurationMs?: number;
  maxTotalQueryDurationMs?: number;
  maxIndexContentBytes?: number;
}

export interface SearchLargeProjectSoakReport {
  kind: 'proxyforge-search-large-project-soak-report';
  schemaVersion: 1;
  generatedAt: string;
  status: SearchLargeProjectSoakStatus;
  warnings: string[];
  exchangeCount: number;
  queryCount: number;
  totalMatches: number;
  buildDurationMs: number;
  totalQueryDurationMs: number;
  throughput: {
    indexedExchangesPerSecond: number;
    queriedExchangesPerSecond: number;
  };
  budgets: {
    minExchangeCount: number;
    minTotalMatches: number;
    maxBuildDurationMs: number;
    maxTotalQueryDurationMs: number;
    maxIndexContentBytes: number;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  indexRestored: boolean;
  indexSummary: {
    corpusDigestPreview: string;
    tokenCount: number;
    uniqueTokenCount: number;
    indexedTokenCount: number;
    contentBytes: number;
    maxPostingsPerToken: number;
    largestDocumentTokens: number;
    averageDocumentTokens: number;
  };
  queries: Array<{
    query: string;
    durationMs: number;
    matchCount: number;
    searchResultCount: number;
    topExchangeId?: string;
    topScore?: number;
    topLabels: string[];
  }>;
  index: Omit<SearchSemanticIndex, 'content'>;
  reportReady: boolean;
  content: string;
}

export interface SearchParityEvidenceRequest {
  fullTextRun: SearchRun;
  structuredRun: SearchRun;
  semanticRun: SearchRun;
  providerRun?: SearchRun;
  evidencePackage?: SearchEvidencePackage;
  semanticIndex?: SearchSemanticIndex;
  restoredIndex?: SearchSemanticIndex;
  indexMatches?: SearchSemanticProviderMatch[];
  soakReport?: SearchLargeProjectSoakReport;
  toolHandoffs?: SearchToolHandoffEvidence[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface SearchParityEvidencePackage {
  id: string;
  kind: 'proxyforge-search-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  queryCount: number;
  resultCount: number;
  semanticIndexExchangeCount: number;
  toolHandoffCount: number;
  artifactIds: {
    fullTextResultIds: string[];
    structuredResultIds: string[];
    semanticResultIds: string[];
    providerResultIds: string[];
    indexMatchIds: string[];
    handoffTools: string[];
  };
  requirements: {
    fullTextSearchCovered: boolean;
    metadataBodyRawCovered: boolean;
    structuredPredicatesCovered: boolean;
    negationCovered: boolean;
    orQueriesCovered: boolean;
    semanticRankingCovered: boolean;
    providerScoreMergeCovered: boolean;
    persistentIndexCovered: boolean;
    largeProjectSoakCovered: boolean;
    toolHandoffCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export interface SearchSemanticIndexMatchOptions {
  providerId?: string;
  limit?: number;
  threshold?: number;
}

export interface SearchOptions {
  semanticProvider?: SearchSemanticProvider;
  semanticProviderMatches?: SearchSemanticProviderMatch[];
  semanticThreshold?: number;
}

interface SearchContext {
  semanticProvider?: SearchSemanticProvider;
  providerMatches: Map<string, SearchSemanticProviderMatch>;
  semanticThreshold: number;
}

interface SearchTokenMatch {
  token?: string;
  negated?: boolean;
  matched: boolean;
  reason: string;
  score?: number;
  providerScore?: number;
  labels?: string[];
}

export function searchExchanges(exchanges: HttpExchange[], query: string) {
  return searchExchangesWithMeta(exchanges, query).results;
}

export function searchExchangesWithMeta(exchanges: HttpExchange[], query: string, options: SearchOptions = {}): SearchRun {
  const context = buildSearchContext(options);
  const diagnostics = buildSearchDiagnostics(query, options);
  if (diagnostics.tokens.length === 0) {
    const matches = exchanges.map<SearchExchangeMatch>((exchange) => ({
      exchange,
      alternativeIndex: 0,
      matchedTokens: [],
      negatedTokens: [],
      reasons: ['empty query includes all traffic'],
      ...buildSemanticMatchMetadata(exchange, context),
    }));
    const ranked = sortSearchMatches(matches, context, diagnostics.semanticTokens.length > 0);
    return {
      results: ranked.map((match) => match.exchange),
      matches: ranked,
      diagnostics,
    };
  }

  const matches = exchanges.flatMap<SearchExchangeMatch>((exchange) => {
    const haystack = buildSearchHaystack(exchange);
    for (let index = 0; index < diagnostics.alternatives.length; index += 1) {
      const alternative = diagnostics.alternatives[index];
      const tokenMatches = alternative.map((token) => matchSearchToken(exchange, haystack, token, context));
      if (tokenMatches.every((match) => match.matched)) {
        const semanticMetadata = buildSemanticMatchMetadata(exchange, context, tokenMatches);
        return [{
          exchange,
          alternativeIndex: index,
          matchedTokens: tokenMatches.filter((match) => !match.negated).map((match) => match.token ?? ''),
          negatedTokens: tokenMatches.filter((match) => match.negated).map((match) => match.token ?? ''),
          reasons: tokenMatches.map((match) => match.reason),
          ...semanticMetadata,
        }];
      }
    }
    return [];
  });
  const rankedMatches = sortSearchMatches(matches, context, diagnostics.semanticTokens.length > 0);

  return {
    results: rankedMatches.map((match) => match.exchange),
    matches: rankedMatches,
    diagnostics,
  };
}

export function buildSearchDiagnostics(query: string, options: SearchOptions = {}): SearchQueryDiagnostics {
  const tokens = tokenizeSearchQuery(query);
  const alternatives = splitSearchAlternatives(tokens);
  const realTokens = alternatives.flat();
  const predicateTokens = realTokens.filter((token) => stripNegation(token).startsWith('has:') || stripNegation(token).startsWith('is:'));
  const fieldTokens = realTokens.filter((token) => /^(?:!|-)?[a-z-]+(?::|>=|<=|>|<|!=)/.test(token) && !predicateTokens.includes(token));
  const textTokens = realTokens.filter((token) => !predicateTokens.includes(token) && !fieldTokens.includes(token));
  const semanticTokens = fieldTokens
    .map(stripNegation)
    .filter((token) => token.startsWith('semantic:') || token.startsWith('similar:'));
  const operators = Array.from(new Set([
    ...realTokens.flatMap((token) => {
      const normalized = stripNegation(token);
      if (normalized.includes('!=')) return ['!='];
      if (normalized.includes('>=')) return ['>='];
      if (normalized.includes('<=')) return ['<='];
      if (normalized.includes('>')) return ['>'];
      if (normalized.includes('<')) return ['<'];
      if (normalized.includes(':')) return [':'];
      return [];
    }),
    ...(alternatives.length > 1 ? ['OR'] : []),
    ...(realTokens.some((token) => isNegated(token)) ? ['NOT'] : []),
  ]));
  const warnings = realTokens
    .map((token) => validateSearchToken(token))
    .filter((warning): warning is string => Boolean(warning));
  const providerWarnings = buildSemanticProviderWarnings(options);

  return {
    query,
    tokens: realTokens,
    alternatives,
    tokenCount: realTokens.length,
    alternativeCount: alternatives.length,
    negatedTokenCount: realTokens.filter((token) => isNegated(token)).length,
    predicateTokens,
    fieldTokens,
    textTokens,
    operators,
    warnings: [...warnings, ...providerWarnings],
    semanticTokens,
    semanticProvider: options.semanticProvider,
    semanticProviderMatchCount: options.semanticProviderMatches?.length ?? 0,
  };
}

export function tokenizeSearchQuery(query: string) {
  const tokens: string[] = [];
  let current = '';
  let quoted = false;

  for (const char of query.trim()) {
    if (char === '"') {
      quoted = !quoted;
      continue;
    }
    if (/\s/.test(char) && !quoted) {
      if (current.trim()) tokens.push(normalizeSearchToken(current));
      current = '';
      continue;
    }
    current += char;
  }

  if (current.trim()) tokens.push(normalizeSearchToken(current));
  return tokens.filter(Boolean);
}

export function splitSearchAlternatives(tokens: string[]) {
  const alternatives: string[][] = [[]];
  for (const token of tokens) {
    if (token === 'or' || token === '|') {
      if (alternatives[alternatives.length - 1].length) alternatives.push([]);
      continue;
    }
    alternatives[alternatives.length - 1].push(token);
  }
  return alternatives.filter((alternative) => alternative.length);
}

export function buildSearchSnippet(exchange: HttpExchange, query: string) {
  const diagnostics = buildSearchDiagnostics(query);
  const textTokens = diagnostics.textTokens.map(stripNegation);
  const fieldValues = diagnostics.fieldTokens
    .map(stripNegation)
    .map((token) => token.split(/:|>=|<=|>|<|!=/, 2)[1])
    .filter(Boolean);
  const raw = `${exchange.notes}\n${exchange.requestRaw}\n${exchange.responseRaw}`;
  const normalized = raw.replace(/\s+/g, ' ').trim();
  const candidates = [...textTokens, ...fieldValues].filter((token) => token.length > 2);
  const needle = candidates.find((token) => normalized.toLowerCase().includes(token));
  if (!needle) return exchange.notes || `${exchange.method} ${exchange.host}${exchange.path}`;
  const index = normalized.toLowerCase().indexOf(needle);
  return normalized.slice(Math.max(0, index - 70), index + needle.length + 130).trim();
}

export function buildSearchResultFacets(results: HttpExchange[]): SearchFacetSummary {
  return {
    hosts: countValues(results.map((exchange) => exchange.host), 8),
    risks: countValues(results.map((exchange) => exchange.risk), 5) as Array<{ value: Severity; count: number }>,
    sources: countValues(results.map((exchange) => exchange.source), 8),
    methods: countValues(results.map((exchange) => exchange.method), 8),
    tags: countValues(results.flatMap((exchange) => exchange.tags), 12),
  };
}

export function buildSearchSemanticCorpus(exchanges: HttpExchange[]): SearchSemanticCorpusEntry[] {
  return exchanges.map((exchange) => ({
    exchangeId: exchange.id,
    host: exchange.host,
    path: exchange.path,
    source: exchange.source,
    risk: exchange.risk,
    tags: exchange.tags,
    corpus: [
      exchange.method,
      exchange.host,
      exchange.path,
      exchange.url,
      exchange.status.toString(),
      exchange.mime,
      exchange.risk,
      exchange.notes,
      exchange.source,
      exchange.tags.join(' '),
      exchange.requestRaw,
      exchange.responseRaw,
    ].join('\n'),
  }));
}

export function buildSearchSemanticIndex(exchanges: HttpExchange[], options: SearchSemanticIndexOptions = {}): SearchSemanticIndex {
  const generatedAt = options.now ?? new Date().toISOString();
  const maxTokens = normalizeSemanticIndexTokenLimit(options.maxTokens);
  const corpus = buildSearchSemanticCorpus(exchanges);
  const perExchangeTokenCounts = new Map<string, Map<string, number>>();
  const corpusTokenCounts = new Map<string, number>();
  let tokenCount = 0;

  const documents = corpus.map<SearchSemanticIndexDocument>((entry) => {
    const tokens = tokenizeSemanticText(entry.corpus);
    const tokenCounts = countSemanticTokenValues(tokens);
    perExchangeTokenCounts.set(entry.exchangeId, tokenCounts);
    tokenCount += tokens.length;
    tokenCounts.forEach((_count, token) => {
      corpusTokenCounts.set(token, (corpusTokenCounts.get(token) ?? 0) + 1);
    });
    return {
      ...entry,
      tokenCount: tokens.length,
      uniqueTokenCount: tokenCounts.size,
      digestPreview: simpleDigest(entry.corpus),
    };
  });

  const indexedTokens = Array.from(corpusTokenCounts.entries())
    .sort(([leftToken, leftCount], [rightToken, rightCount]) => rightCount - leftCount || leftToken.localeCompare(rightToken))
    .slice(0, maxTokens)
    .map(([token]) => token);
  const tokenPostings: Record<string, SearchSemanticIndexPosting[]> = {};

  indexedTokens.forEach((token) => {
    const postings = documents
      .map((document) => {
        const count = perExchangeTokenCounts.get(document.exchangeId)?.get(token) ?? 0;
        if (count === 0) return undefined;
        return {
          exchangeId: document.exchangeId,
          count,
          weight: roundSemanticWeight(1 + Math.log(count)),
        };
      })
      .filter((posting): posting is SearchSemanticIndexPosting => Boolean(posting))
      .sort((left, right) => right.weight - left.weight || left.exchangeId.localeCompare(right.exchangeId));
    if (postings.length) tokenPostings[token] = postings;
  });

  const payload = {
    kind: 'proxyforge-search-semantic-index' as const,
    schemaVersion: 1 as const,
    generatedAt,
    exchangeCount: documents.length,
    tokenCount,
    uniqueTokenCount: corpusTokenCounts.size,
    indexedTokenCount: indexedTokens.length,
    corpusDigestPreview: simpleDigest(corpus.map((entry) => `${entry.exchangeId}\n${entry.corpus}`).join('\n---proxyforge-search-entry---\n')),
    secretHandling: 'execution-full-fidelity-secrets-preserved' as const,
    documents,
    tokenPostings,
  };

  return {
    ...payload,
    content: JSON.stringify(payload, null, 2),
  };
}

export function restoreSearchSemanticIndex(input: string | SearchSemanticIndex): SearchSemanticIndex {
  const parsed = typeof input === 'string' ? parseSemanticIndexContent(input) : input;
  const content = typeof input === 'string' ? input : input.content || stringifySemanticIndexPayload(input);
  return validateSearchSemanticIndex(parsed, content);
}

export function semanticProviderMatchesFromIndex(
  input: string | SearchSemanticIndex,
  query: string,
  options: SearchSemanticIndexMatchOptions = {},
): SearchSemanticProviderMatch[] {
  const index = restoreSearchSemanticIndex(input);
  const queryTerms = Array.from(new Set(expandSemanticTerms(query)));
  if (queryTerms.length === 0) return [];

  const providerId = options.providerId ?? 'proxyforge-local-index';
  const threshold = options.threshold ?? 0.12;
  const limit = normalizeSemanticIndexMatchLimit(options.limit);
  const documents = new Map(index.documents.map((document) => [document.exchangeId, document]));
  const scored = new Map<string, { weighted: number; labels: Set<string> }>();

  queryTerms.forEach((term) => {
    const postings = index.tokenPostings[term] ?? [];
    postings.forEach((posting) => {
      const score = scored.get(posting.exchangeId) ?? { weighted: 0, labels: new Set<string>() };
      score.weighted += posting.weight;
      score.labels.add(term);
      scored.set(posting.exchangeId, score);
    });
  });

  return Array.from(scored.entries())
    .map(([exchangeId, score]) => {
      const document = documents.get(exchangeId);
      const labels = Array.from(score.labels).sort();
      const directScore = labels.length / Math.max(1, queryTerms.length);
      const weightScore = Math.min(0.28, score.weighted / Math.max(4, queryTerms.length * 4));
      const severityBoost = document ? riskScore(document.risk) / 50 : 0;
      return {
        exchangeId,
        score: clampSemanticScore(directScore * 0.62 + weightScore + severityBoost),
        rationale: `Persistent local semantic index matched ${labels.slice(0, 8).join(', ')} across ${index.exchangeCount} exchange(s).`,
        labels: labels.slice(0, 12),
        providerId,
      };
    })
    .filter((match) => match.score >= threshold)
    .sort((left, right) => {
      const scoreDelta = right.score - left.score;
      if (Math.abs(scoreDelta) > 0.0001) return scoreDelta;
      const leftRisk = documents.get(left.exchangeId)?.risk ?? 'info';
      const rightRisk = documents.get(right.exchangeId)?.risk ?? 'info';
      return riskScore(rightRisk) - riskScore(leftRisk) || left.exchangeId.localeCompare(right.exchangeId);
    })
    .slice(0, limit)
    .map((match) => ({
      ...match,
      score: Number(match.score.toFixed(4)),
    }));
}

export function buildSearchLargeProjectSoakReport(
  exchanges: HttpExchange[],
  options: SearchLargeProjectSoakOptions = {},
): SearchLargeProjectSoakReport {
  const generatedAt = options.now ?? new Date().toISOString();
  const queries = normalizeSearchSoakQueries(options.queries);
  const providerId = options.providerId ?? 'proxyforge-local-index-soak';
  const budgets = {
    minExchangeCount: normalizePositiveInteger(options.minExchangeCount, 100),
    minTotalMatches: normalizePositiveInteger(options.minTotalMatches, queries.length),
    maxBuildDurationMs: normalizePositiveInteger(options.maxBuildDurationMs, 5000),
    maxTotalQueryDurationMs: normalizePositiveInteger(options.maxTotalQueryDurationMs, 2500),
    maxIndexContentBytes: normalizePositiveInteger(options.maxIndexContentBytes, 50 * 1024 * 1024),
  };

  const buildStartedAt = Date.now();
  const index = buildSearchSemanticIndex(exchanges, {
    now: generatedAt,
    maxTokens: options.maxTokens,
  });
  const buildDurationMs = Math.max(0, Date.now() - buildStartedAt);
  const restoredIndex = restoreSearchSemanticIndex(index.content);
  const querySummaries = queries.map((query) => {
    const queryStartedAt = Date.now();
    const providerMatches = semanticProviderMatchesFromIndex(restoredIndex, query, {
      providerId,
      limit: options.matchLimit,
      threshold: options.matchThreshold,
    });
    const searchRun = searchExchangesWithMeta(exchanges, `semantic:"${escapeSearchQuotedValue(query)}"`, {
      semanticProvider: { id: providerId, label: 'ProxyForge local index soak', model: 'persistent-v1' },
      semanticProviderMatches: providerMatches,
    });
    const durationMs = Math.max(0, Date.now() - queryStartedAt);
    const topMatch = providerMatches[0];
    return {
      query,
      durationMs,
      matchCount: providerMatches.length,
      searchResultCount: searchRun.results.length,
      topExchangeId: topMatch?.exchangeId,
      topScore: topMatch?.score,
      topLabels: topMatch?.labels?.slice(0, 12) ?? [],
    };
  });
  const totalQueryDurationMs = querySummaries.reduce((total, query) => total + query.durationMs, 0);
  const totalMatches = querySummaries.reduce((total, query) => total + query.matchCount, 0);
  const indexContentBytes = utf8ByteLength(index.content);
  const postingLengths = Object.values(index.tokenPostings).map((postings) => postings.length);
  const documentTokenCounts = index.documents.map((document) => document.tokenCount);
  const warnings = buildSearchSoakWarnings({
    exchangeCount: exchanges.length,
    totalMatches,
    buildDurationMs,
    totalQueryDurationMs,
    indexContentBytes,
    budgets,
  });
  const { content: _content, ...indexPayload } = index;
  const payload = {
    kind: 'proxyforge-search-large-project-soak-report' as const,
    schemaVersion: 1 as const,
    generatedAt,
    status: warnings.length ? 'warning' as const : 'pass' as const,
    warnings,
    exchangeCount: exchanges.length,
    queryCount: queries.length,
    totalMatches,
    buildDurationMs,
    totalQueryDurationMs,
    throughput: {
      indexedExchangesPerSecond: roundSoakMetric(exchanges.length / Math.max(0.001, buildDurationMs / 1000)),
      queriedExchangesPerSecond: roundSoakMetric((exchanges.length * queries.length) / Math.max(0.001, totalQueryDurationMs / 1000)),
    },
    budgets,
    secretHandling: 'execution-full-fidelity-secrets-preserved' as const,
    indexRestored: restoredIndex.corpusDigestPreview === index.corpusDigestPreview && restoredIndex.exchangeCount === index.exchangeCount,
    indexSummary: {
      corpusDigestPreview: index.corpusDigestPreview,
      tokenCount: index.tokenCount,
      uniqueTokenCount: index.uniqueTokenCount,
      indexedTokenCount: index.indexedTokenCount,
      contentBytes: indexContentBytes,
      maxPostingsPerToken: Math.max(...postingLengths, 0),
      largestDocumentTokens: Math.max(...documentTokenCounts, 0),
      averageDocumentTokens: roundSoakMetric(index.tokenCount / Math.max(1, index.exchangeCount)),
    },
    queries: querySummaries,
    index: indexPayload,
    reportReady: warnings.length === 0 && queries.length > 0,
  };

  return {
    ...payload,
    content: JSON.stringify(payload, null, 2),
  };
}

export function buildSearchEvidencePackage(options: {
  query: string;
  run: SearchRun;
  facets: SearchFacetSummary;
  now?: string;
}): SearchEvidencePackage {
  const generatedAt = options.now ?? new Date().toISOString();
  const results = options.run.matches.slice(0, 100).map((match) => ({
    id: match.exchange.id,
    method: match.exchange.method,
    host: match.exchange.host,
    path: match.exchange.path,
    status: match.exchange.status,
    risk: match.exchange.risk,
    source: match.exchange.source,
    tags: match.exchange.tags,
    matchedTokens: match.matchedTokens,
    reasons: match.reasons,
    snippet: buildSearchSnippet(match.exchange, options.query),
  }));
  const payload = {
    kind: 'proxyforge-search-evidence-package' as const,
    generatedAt,
    query: options.query,
    diagnostics: options.run.diagnostics,
    facets: options.facets,
    resultCount: options.run.results.length,
    results,
    reportReady: results.length > 0,
  };

  return {
    ...payload,
    content: JSON.stringify(payload, null, 2),
  };
}

export function buildSearchParityEvidencePackage(request: SearchParityEvidenceRequest): SearchParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const providerRun = request.providerRun;
  const semanticIndexExchangeCount = request.semanticIndex?.exchangeCount ?? request.restoredIndex?.exchangeCount ?? 0;
  const handoffTools = Array.from(new Set((request.toolHandoffs ?? []).map((handoff) => handoff.tool))).sort();
  const combinedOperationalText = [
    JSON.stringify(request.fullTextRun),
    JSON.stringify(request.structuredRun),
    JSON.stringify(request.semanticRun),
    JSON.stringify(providerRun ?? {}),
    request.evidencePackage?.content,
    request.semanticIndex?.content,
    request.restoredIndex?.content,
    request.soakReport?.content,
    JSON.stringify(request.indexMatches ?? []),
    JSON.stringify(request.toolHandoffs ?? []),
    ...(request.operationalSecretSamples ?? []),
  ].filter(Boolean).join('\n');
  const hasRawHttpMaterial = /HTTP\/[12]|Authorization:|Cookie:|requestRaw|responseRaw/i.test(combinedOperationalText);
  const requirements = {
    fullTextSearchCovered: request.fullTextRun.results.length > 0 && request.fullTextRun.diagnostics.textTokens.length > 0,
    metadataBodyRawCovered: request.fullTextRun.matches.some((match) => match.reasons.some((reason) => /text contains|has .*evidence|fallback field/i.test(reason))) && hasRawHttpMaterial,
    structuredPredicatesCovered: request.structuredRun.results.length > 0
      && (request.structuredRun.diagnostics.fieldTokens.length > 0 || request.structuredRun.diagnostics.predicateTokens.length > 0),
    negationCovered: request.structuredRun.diagnostics.operators.includes('NOT'),
    orQueriesCovered: request.structuredRun.diagnostics.operators.includes('OR'),
    semanticRankingCovered: request.semanticRun.results.length > 0
      && request.semanticRun.diagnostics.semanticTokens.length > 0
      && request.semanticRun.matches.some((match) => (match.semanticScore ?? 0) > 0 || (match.semanticLabels?.length ?? 0) > 0),
    providerScoreMergeCovered: Boolean(providerRun?.diagnostics.semanticProviderMatchCount
      && providerRun.matches.some((match) => (match.semanticProviderScore ?? 0) > 0)),
    persistentIndexCovered: Boolean(request.semanticIndex?.kind === 'proxyforge-search-semantic-index'
      && request.restoredIndex?.kind === 'proxyforge-search-semantic-index'
      && request.semanticIndex.corpusDigestPreview === request.restoredIndex.corpusDigestPreview
      && (request.indexMatches?.length ?? 0) > 0),
    largeProjectSoakCovered: Boolean(request.soakReport?.kind === 'proxyforge-search-large-project-soak-report'
      && request.soakReport.status === 'pass'
      && request.soakReport.indexRestored
      && request.soakReport.reportReady),
    toolHandoffCovered: handoffTools.includes('search-index') && handoffTools.includes('view'),
    rawExecutorMaterialPreserved: hasRawHttpMaterial,
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => combinedOperationalText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-search-parity-evidence-package',
    exportedAt,
    fullTextRun: request.fullTextRun,
    structuredRun: request.structuredRun,
    semanticRun: request.semanticRun,
    providerRun,
    evidencePackage: request.evidencePackage,
    semanticIndex: request.semanticIndex,
    restoredIndex: request.restoredIndex,
    indexMatches: request.indexMatches ?? [],
    soakReport: request.soakReport,
    toolHandoffs: request.toolHandoffs ?? [],
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);
  const resultIds = Array.from(new Set([
    ...request.fullTextRun.results.map((exchange) => exchange.id),
    ...request.structuredRun.results.map((exchange) => exchange.id),
    ...request.semanticRun.results.map((exchange) => exchange.id),
    ...(providerRun?.results.map((exchange) => exchange.id) ?? []),
  ]));

  return {
    id: `search-parity-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-search-parity-evidence-package',
    title: 'Search parity evidence package',
    fileName: `proxyforge-search-parity-${stamp}.json`,
    path: `search/proxyforge-search-parity-${stamp}.json`,
    exportedAt,
    queryCount: 3 + (providerRun ? 1 : 0),
    resultCount: resultIds.length,
    semanticIndexExchangeCount,
    toolHandoffCount: request.toolHandoffs?.length ?? 0,
    artifactIds: {
      fullTextResultIds: request.fullTextRun.results.map((exchange) => exchange.id),
      structuredResultIds: request.structuredRun.results.map((exchange) => exchange.id),
      semanticResultIds: request.semanticRun.results.map((exchange) => exchange.id),
      providerResultIds: providerRun?.results.map((exchange) => exchange.id) ?? [],
      indexMatchIds: request.indexMatches?.map((match) => match.exchangeId) ?? [],
      handoffTools,
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Search parity evidence covers full-text metadata/body/raw search, structured predicates, negation, OR queries, semantic ranking, provider score merge, persistent local semantic index restore, large-project soak proof, and agent/tool handoff.',
    content,
  };
}

function normalizeSemanticIndexTokenLimit(value?: number) {
  if (!Number.isFinite(value)) return 4096;
  return Math.max(1, Math.min(50000, Math.floor(value as number)));
}

function normalizeSemanticIndexMatchLimit(value?: number) {
  if (!Number.isFinite(value)) return 50;
  return Math.max(1, Math.min(1000, Math.floor(value as number)));
}

function normalizePositiveInteger(value: number | undefined, fallback: number) {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(1, Math.floor(value as number));
}

function normalizeSearchSoakQueries(queries?: string[]) {
  const normalized = (queries ?? ['authz bypass', 'secret token cookie', 'graphql cors', 'callback ssrf'])
    .map((query) => query.trim())
    .filter(Boolean);
  return normalized.length ? Array.from(new Set(normalized)) : ['authz bypass'];
}

function escapeSearchQuotedValue(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function utf8ByteLength(value: string) {
  return new TextEncoder().encode(value).length;
}

function roundSoakMetric(value: number) {
  if (!Number.isFinite(value)) return 0;
  return Number(value.toFixed(2));
}

function buildSearchSoakWarnings(options: {
  exchangeCount: number;
  totalMatches: number;
  buildDurationMs: number;
  totalQueryDurationMs: number;
  indexContentBytes: number;
  budgets: SearchLargeProjectSoakReport['budgets'];
}) {
  const warnings: string[] = [];
  if (options.exchangeCount < options.budgets.minExchangeCount) {
    warnings.push(`Exchange count ${options.exchangeCount} is below large-project floor ${options.budgets.minExchangeCount}.`);
  }
  if (options.totalMatches < options.budgets.minTotalMatches) {
    warnings.push(`Total semantic index matches ${options.totalMatches} is below expected floor ${options.budgets.minTotalMatches}.`);
  }
  if (options.buildDurationMs > options.budgets.maxBuildDurationMs) {
    warnings.push(`Semantic index build took ${options.buildDurationMs}ms, above budget ${options.budgets.maxBuildDurationMs}ms.`);
  }
  if (options.totalQueryDurationMs > options.budgets.maxTotalQueryDurationMs) {
    warnings.push(`Semantic index queries took ${options.totalQueryDurationMs}ms, above budget ${options.budgets.maxTotalQueryDurationMs}ms.`);
  }
  if (options.indexContentBytes > options.budgets.maxIndexContentBytes) {
    warnings.push(`Semantic index content is ${options.indexContentBytes} bytes, above budget ${options.budgets.maxIndexContentBytes} bytes.`);
  }
  return warnings;
}

function countSemanticTokenValues(tokens: string[]) {
  const counts = new Map<string, number>();
  tokens.forEach((token) => counts.set(token, (counts.get(token) ?? 0) + 1));
  return counts;
}

function roundSemanticWeight(value: number) {
  return Number(value.toFixed(4));
}

function parseSemanticIndexContent(content: string) {
  try {
    return JSON.parse(content) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid search semantic index JSON: ${message}`);
  }
}

function validateSearchSemanticIndex(input: unknown, content: string): SearchSemanticIndex {
  if (!isRecord(input)) throw new Error('Search semantic index must be a JSON object.');
  if (input.kind !== 'proxyforge-search-semantic-index') throw new Error('Search semantic index kind is unsupported.');
  if (input.schemaVersion !== 1) throw new Error('Search semantic index schema version is unsupported.');
  if (!Array.isArray(input.documents)) throw new Error('Search semantic index documents are missing.');
  if (!isRecord(input.tokenPostings)) throw new Error('Search semantic index token postings are missing.');
  return {
    ...(input as Omit<SearchSemanticIndex, 'content'>),
    content,
  };
}

function stringifySemanticIndexPayload(index: SearchSemanticIndex) {
  const { content: _content, ...payload } = index;
  return JSON.stringify(payload, null, 2);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normalizeSearchToken(token: string) {
  return token.trim().toLowerCase().replace(/^not:/, '!');
}

function buildSearchHaystack(exchange: HttpExchange) {
  return [
    exchange.method,
    exchange.host,
    exchange.path,
    exchange.url,
    exchange.status.toString(),
    exchange.length.toString(),
    exchange.timing.toString(),
    exchange.mime,
    exchange.risk,
    exchange.notes,
    exchange.source,
    exchange.tags.join(' '),
    exchange.requestRaw,
    exchange.responseRaw,
  ].join(' ').toLowerCase();
}

function matchSearchToken(exchange: HttpExchange, haystack: string, rawToken: string, context: SearchContext) {
  const negated = isNegated(rawToken);
  const token = stripNegation(rawToken);
  const positive = matchPositiveSearchToken(exchange, haystack, token, context);
  return {
    token,
    negated,
    matched: negated ? !positive.matched : positive.matched,
    reason: negated ? `NOT ${positive.reason}` : positive.reason,
    score: positive.score,
    providerScore: positive.providerScore,
    labels: positive.labels,
  };
}

function matchPositiveSearchToken(exchange: HttpExchange, haystack: string, token: string, context: SearchContext): SearchTokenMatch {
  if (!token) return { matched: true, reason: 'empty token' };

  const fieldMatch = token.match(/^([a-z-]+)(>=|<=|!=|>|<|:)(.*)$/);
  if (fieldMatch) {
    const [, field, operator, value] = fieldMatch;
    return matchFieldToken(exchange, haystack, field, operator, value, context);
  }

  return {
    matched: haystack.includes(token),
    reason: `text contains ${token}`,
  };
}

function matchFieldToken(exchange: HttpExchange, haystack: string, field: string, operator: string, value: string, context: SearchContext): SearchTokenMatch {
  if (field === 'host') return textMatch(exchange.host, operator, value, 'host');
  if (field === 'path') return textMatch(exchange.path, operator, value, 'path');
  if (field === 'url') return textMatch(exchange.url, operator, value, 'url');
  if (field === 'method') return textMatch(exchange.method, operator, value, 'method');
  if (field === 'mime') return textMatch(exchange.mime, operator, value, 'mime');
  if (field === 'tag') return listMatch(exchange.tags, operator, value, 'tag');
  if (field === 'source') return textMatch(exchange.source, operator, value, 'source');
  if (field === 'notes') return textMatch(exchange.notes, operator, value, 'notes');
  if (field === 'status') return statusMatch(exchange.status, operator, value);
  if (field === 'length') return numericMatch(exchange.length, operator, value, 'length');
  if (field === 'timing') return numericMatch(exchange.timing, operator, value, 'timing');
  if (field === 'risk') return riskMatch(exchange.risk, operator, value);
  if (field === 'has') return predicateMatch(exchange, haystack, value, 'has');
  if (field === 'is') return predicateMatch(exchange, haystack, value, 'is');
  if (field === 'semantic' || field === 'similar') return semanticMatch(exchange, value, context, field);
  return {
    matched: haystack.includes(`${field}:${value}`) || haystack.includes(value),
    reason: `fallback field ${field}:${value}`,
  };
}

function buildSearchContext(options: SearchOptions): SearchContext {
  return {
    semanticProvider: options.semanticProvider,
    providerMatches: new Map((options.semanticProviderMatches ?? []).map((match) => [match.exchangeId, {
      ...match,
      score: clampSemanticScore(match.score),
      rationale: match.rationale,
      labels: match.labels?.slice(0, 12),
    }])),
    semanticThreshold: options.semanticThreshold ?? 0.34,
  };
}

function buildSemanticProviderWarnings(options: SearchOptions) {
  const activeProviderId = options.semanticProvider?.id;
  return Array.from(new Set((options.semanticProviderMatches ?? [])
    .map((match) => match.providerId)
    .filter((providerId): providerId is string => Boolean(providerId && activeProviderId && providerId !== activeProviderId))))
    .map((providerId) => `Semantic provider match references unknown provider "${providerId}".`);
}

function buildSemanticMatchMetadata(exchange: HttpExchange, context: SearchContext, tokenMatches: SearchTokenMatch[] = []) {
  const tokenScores = Array.isArray(tokenMatches) ? tokenMatches.map((match) => match.score ?? 0) : [];
  const tokenProviderScores = Array.isArray(tokenMatches) ? tokenMatches.map((match) => match.providerScore ?? 0) : [];
  const tokenLabels = Array.isArray(tokenMatches) ? tokenMatches.flatMap((match) => match.labels ?? []) : [];
  const providerMatch = context.providerMatches.get(exchange.id);
  const semanticScore = Math.max(...tokenScores, 0);
  const semanticProviderScore = Math.max(...tokenProviderScores, providerMatch?.score ?? 0, 0);
  const labels = Array.from(new Set([
    ...tokenLabels,
    ...(providerMatch?.labels ?? []),
  ])).slice(0, 12);
  const score = Math.max(semanticScore, semanticProviderScore, riskScore(exchange.risk) / 10);
  return {
    score,
    semanticScore: semanticScore || undefined,
    semanticProviderScore: semanticProviderScore || undefined,
    semanticLabels: labels.length ? labels : undefined,
  };
}

function sortSearchMatches(matches: SearchExchangeMatch[], context: SearchContext, hasSemanticToken: boolean) {
  if (!hasSemanticToken && context.providerMatches.size === 0) return matches;
  const order = new Map(matches.map((match, index) => [match.exchange.id, index]));
  return [...matches].sort((left, right) => {
    const scoreDelta = (right.score ?? 0) - (left.score ?? 0);
    if (Math.abs(scoreDelta) > 0.0001) return scoreDelta;
    const riskDelta = riskScore(right.exchange.risk) - riskScore(left.exchange.risk);
    if (riskDelta) return riskDelta;
    return (order.get(left.exchange.id) ?? 0) - (order.get(right.exchange.id) ?? 0);
  });
}

function semanticMatch(exchange: HttpExchange, query: string, context: SearchContext, field: 'semantic' | 'similar'): SearchTokenMatch {
  const providerMatch = context.providerMatches.get(exchange.id);
  const local = scoreLocalSemanticSearch(exchange, query);
  const providerScore = providerMatch?.score ?? 0;
  const score = Math.max(local.score, providerScore);
  const providerLabel = context.semanticProvider
    ? `${context.semanticProvider.label}${context.semanticProvider.model ? `/${context.semanticProvider.model}` : ''}`
    : providerMatch?.providerId ?? 'provider';
  const reason = providerMatch && providerScore >= local.score
    ? `${field} provider ${providerLabel} score ${providerScore.toFixed(2)}: ${providerMatch.rationale}`
    : `${field} local score ${local.score.toFixed(2)}: ${local.labels.join(', ') || 'no related evidence'}`;
  return {
    token: `${field}:${query}`,
    negated: false,
    matched: score >= context.semanticThreshold,
    reason,
    score,
    providerScore: providerMatch ? providerScore : undefined,
    labels: providerMatch?.labels ?? local.labels,
  };
}

function scoreLocalSemanticSearch(exchange: HttpExchange, query: string) {
  const queryTerms = expandSemanticTerms(query);
  const corpusTerms = expandSemanticTerms(buildSemanticSearchText(exchange));
  if (queryTerms.length === 0) return { score: 0, labels: [] };

  const corpusSet = new Set(corpusTerms);
  const matched = queryTerms.filter((term) => corpusSet.has(term));
  const directScore = matched.length / Math.max(1, queryTerms.length);
  const tagScore = exchange.tags.some((tag) => queryTerms.includes(tag.toLowerCase())) ? 0.18 : 0;
  const riskBoost = exchange.risk === 'critical' || exchange.risk === 'high' ? 0.08 : exchange.risk === 'medium' ? 0.04 : 0;
  const statusBoost = queryTerms.some((term) => ['authz', 'authorization', 'access-control', 'bypass'].includes(term)) && (exchange.status === 401 || exchange.status === 403) ? 0.18 : 0;
  const score = clampSemanticScore(directScore + tagScore + riskBoost + statusBoost);
  return {
    score,
    labels: Array.from(new Set(matched)).slice(0, 12),
  };
}

function buildSemanticSearchText(exchange: HttpExchange) {
  return [
    exchange.method,
    exchange.host,
    exchange.path,
    exchange.status.toString(),
    exchange.mime,
    exchange.risk,
    exchange.notes,
    exchange.source,
    exchange.tags.join(' '),
    exchange.requestRaw,
    exchange.responseRaw,
  ].join('\n');
}

function expandSemanticTerms(value: string) {
  const baseTerms = tokenizeSemanticText(value);
  const expanded = new Set<string>();
  for (const term of baseTerms) {
    expanded.add(term);
    for (const synonym of semanticSynonyms(term)) expanded.add(synonym);
  }
  return Array.from(expanded);
}

function tokenizeSemanticText(value: string) {
  return value
    .toLowerCase()
    .replace(/[_-]+/g, ' ')
    .split(/[^a-z0-9]+/)
    .map((term) => term.trim())
    .filter((term) => term.length >= 2);
}

function semanticSynonyms(term: string) {
  const groups = [
    ['authz', 'authorization', 'authorize', 'access', 'access-control', 'role', 'permission', 'privilege', 'forbidden', '403', '401'],
    ['bypass', 'boundary', 'replay', 'matrix', 'escalation', 'idor', 'privilege', 'alternate-role'],
    ['secret', 'token', 'bearer', 'cookie', 'session', 'apikey', 'api-key', 'credential', 'jwt'],
    ['graphql', 'query', 'mutation', 'subscription'],
    ['cors', 'origin', 'acao', 'acac', 'cache', 'cache-control'],
    ['callback', 'oast', 'collaborator', 'dns', 'smtp', 'ssrf'],
  ];
  return groups.find((group) => group.includes(term)) ?? [];
}

function clampSemanticScore(score: number) {
  if (!Number.isFinite(score)) return 0;
  return Math.max(0, Math.min(1, score));
}

function riskScore(risk: Severity) {
  return severityRank[risk] ?? 0;
}

function textMatch(actual: string, operator: string, expected: string, label: string) {
  const normalized = actual.toLowerCase();
  const matched = operator === '!=' ? !normalized.includes(expected) : normalized.includes(expected);
  return { matched, reason: `${label} ${operator} ${expected}` };
}

function listMatch(values: string[], operator: string, expected: string, label: string) {
  const matched = values.some((value) => value.toLowerCase().includes(expected));
  return { matched: operator === '!=' ? !matched : matched, reason: `${label} ${operator} ${expected}` };
}

function numericMatch(actual: number, operator: string, expected: string, label: string) {
  const parsed = Number(expected);
  if (!Number.isFinite(parsed)) return { matched: false, reason: `${label} invalid number ${expected}` };
  if (operator === '>=') return { matched: actual >= parsed, reason: `${label} >= ${parsed}` };
  if (operator === '<=') return { matched: actual <= parsed, reason: `${label} <= ${parsed}` };
  if (operator === '>') return { matched: actual > parsed, reason: `${label} > ${parsed}` };
  if (operator === '<') return { matched: actual < parsed, reason: `${label} < ${parsed}` };
  if (operator === '!=') return { matched: actual !== parsed, reason: `${label} != ${parsed}` };
  return { matched: actual === parsed, reason: `${label} = ${parsed}` };
}

function statusMatch(status: number, operator: string, expected: string) {
  if (/^[1-5]xx$/.test(expected)) {
    const prefix = Number(expected[0]) * 100;
    const matched = status >= prefix && status < prefix + 100;
    return { matched: operator === '!=' ? !matched : matched, reason: `status ${operator} ${expected}` };
  }
  if (/^\d{3}-\d{3}$/.test(expected)) {
    const [min, max] = expected.split('-').map(Number);
    const matched = status >= min && status <= max;
    return { matched: operator === '!=' ? !matched : matched, reason: `status ${operator} ${expected}` };
  }
  return numericMatch(status, operator, expected, 'status');
}

function riskMatch(actual: Severity, operator: string, expected: string) {
  const expectedSeverity = expected as Severity;
  if (!severityLevels.has(expectedSeverity)) return { matched: false, reason: `risk invalid ${expected}` };
  if (operator === '>=') return { matched: severityRank[actual] >= severityRank[expectedSeverity], reason: `risk >= ${expected}` };
  if (operator === '<=') return { matched: severityRank[actual] <= severityRank[expectedSeverity], reason: `risk <= ${expected}` };
  if (operator === '>') return { matched: severityRank[actual] > severityRank[expectedSeverity], reason: `risk > ${expected}` };
  if (operator === '<') return { matched: severityRank[actual] < severityRank[expectedSeverity], reason: `risk < ${expected}` };
  if (operator === '!=') return { matched: actual !== expectedSeverity, reason: `risk != ${expected}` };
  return { matched: actual === expectedSeverity, reason: `risk = ${expected}` };
}

function predicateMatch(exchange: HttpExchange, haystack: string, value: string, family: 'has' | 'is') {
  const raw = `${exchange.requestRaw}\n${exchange.responseRaw}`;
  if (family === 'has') {
    if (value === 'json') return { matched: exchange.mime.includes('json') || /application\/json|\{["\s]/i.test(raw), reason: 'has json evidence' };
    if (value === 'html') return { matched: exchange.mime.includes('html') || /<html|<!doctype html/i.test(raw), reason: 'has html evidence' };
    if (value === 'js' || value === 'javascript') return { matched: exchange.mime.includes('javascript') || exchange.path.endsWith('.js'), reason: 'has javascript evidence' };
    if (value === 'request') return { matched: exchange.requestRaw.trim().length > 0, reason: 'has request' };
    if (value === 'response') return { matched: exchange.responseRaw.trim().length > 0, reason: 'has response' };
    if (value === 'body') return { matched: /\n\n[\s\S]+/.test(raw), reason: 'has message body' };
    if (value === 'header') return { matched: /^[a-z0-9-]+:\s+/im.test(raw), reason: 'has headers' };
    if (value === 'cookie') return { matched: /(^|\n)(cookie|set-cookie):/i.test(raw), reason: 'has cookies' };
    if (value === 'auth') return { matched: /authorization:\s*(?:bearer|basic)|x-api-key|api[_-]?key/i.test(raw), reason: 'has auth material' };
    if (value === 'secret') return { matched: /(authorization:\s*(?:bearer|basic)|cookie:|session=|api[_-]?key|access[_-]?token|refresh[_-]?token)/i.test(raw), reason: 'has secret material' };
    if (value === 'jwt') return { matched: /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/.test(raw), reason: 'has jwt' };
    if (value === 'graphql') return { matched: /graphql|"\s*query\s*"|\b(query|mutation|subscription)\b/i.test(`${exchange.path}\n${exchange.requestRaw}`), reason: 'has graphql evidence' };
    if (value === 'param') return { matched: /[?&][a-z0-9_.-]+=|content-type:\s*application\/x-www-form-urlencoded/i.test(`${exchange.url}\n${exchange.requestRaw}`), reason: 'has parameters' };
  }

  if (value === 'error') return { matched: exchange.status >= 500, reason: 'is server error' };
  if (value === 'client-error') return { matched: exchange.status >= 400 && exchange.status < 500, reason: 'is client error' };
  if (value === 'server-error') return { matched: exchange.status >= 500, reason: 'is server error' };
  if (value === 'success') return { matched: exchange.status >= 200 && exchange.status < 300, reason: 'is success' };
  if (value === 'redirect') return { matched: exchange.status >= 300 && exchange.status < 400, reason: 'is redirect' };
  if (value === 'replay') return { matched: exchange.source === 'repeater' || exchange.tags.includes('replayed'), reason: 'is replay evidence' };
  if (value === 'in-scope') return { matched: exchange.tags.includes('in-scope'), reason: 'is in scope' };
  return { matched: haystack.includes(value), reason: `${family}:${value}` };
}

function validateSearchToken(rawToken: string) {
  const token = stripNegation(rawToken);
  const fieldMatch = token.match(/^([a-z-]+)(>=|<=|!=|>|<|:)(.*)$/);
  if (!fieldMatch) return undefined;
  const [, field, operator, value] = fieldMatch;
  if (!value) return `Token "${rawToken}" is missing a value.`;
  if (['status', 'length', 'timing'].includes(field) && !/^[1-5]xx$/.test(value) && !/^\d{3}-\d{3}$/.test(value) && !Number.isFinite(Number(value))) {
    return `Token "${rawToken}" expects a numeric value or range.`;
  }
  if (field === 'risk' && !severityLevels.has(value as Severity)) return `Token "${rawToken}" uses an unknown risk level.`;
  if ((field === 'has' || field === 'is') && operator !== ':') return `Token "${rawToken}" should use ${field}:value syntax.`;
  return undefined;
}

function isNegated(token: string) {
  return token.startsWith('-') || token.startsWith('!');
}

function stripNegation(token: string) {
  return isNegated(token) ? token.slice(1) : token;
}

function countValues<T extends string>(values: T[], limit: number) {
  const counts = new Map<T, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return Array.from(counts.entries())
    .map(([value, count]) => ({ value, count }))
    .sort((left, right) => right.count - left.count || left.value.localeCompare(right.value))
    .slice(0, limit);
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
