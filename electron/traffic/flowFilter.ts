// Flow filter evaluator — applies a parsed filter tree against an HTTP exchange.

import type { FilterNode } from './flowFilterParser';
import { parseFlowFilter } from './flowFilterParser';

export interface FilterableExchange {
  url: string;
  method: string;
  status?: number;
  requestRaw?: string;
  responseRaw?: string;
  host?: string;
  path?: string;
  source?: string;
}

export function matchesFilter(exchange: FilterableExchange, node: FilterNode): boolean {
  switch (node.kind) {
    case 'all': return true;

    case 'url':
      return node.pattern.test(exchange.url ?? '');

    case 'header': {
      const headers = extractHeaders(exchange.requestRaw ?? '') + extractHeaders(exchange.responseRaw ?? '');
      return node.pattern.test(headers);
    }

    case 'method':
      return node.pattern.test(exchange.method ?? '');

    case 'code': {
      const status = exchange.status ?? 0;
      if (Array.isArray(node.status)) {
        return status >= node.status[0] && status <= node.status[1];
      }
      return status === node.status;
    }

    case 'body': {
      const body = extractBody(exchange.requestRaw ?? '') + extractBody(exchange.responseRaw ?? '');
      return node.pattern.test(body);
    }

    case 'src':
      return node.pattern.test(exchange.source ?? '');

    case 'query': {
      try {
        const url = new URL(exchange.url ?? 'https://x');
        return node.pattern.test(url.search);
      } catch {
        return false;
      }
    }

    case 'and':
      return matchesFilter(exchange, node.left) && matchesFilter(exchange, node.right);

    case 'or':
      return matchesFilter(exchange, node.left) || matchesFilter(exchange, node.right);

    case 'not':
      return !matchesFilter(exchange, node.operand);

    default:
      return true;
  }
}

export function compileFilter(expression: string): (exchange: FilterableExchange) => boolean {
  if (!expression || !expression.trim()) return () => true;
  const node = parseFlowFilter(expression);
  return (exchange) => matchesFilter(exchange, node);
}

export function filterExchanges<T extends FilterableExchange>(exchanges: T[], expression: string): T[] {
  if (!expression || !expression.trim()) return exchanges;
  const filter = compileFilter(expression);
  return exchanges.filter(filter);
}

function extractHeaders(raw: string): string {
  const sep = raw.indexOf('\n\n');
  return sep >= 0 ? raw.slice(0, sep) : raw.slice(0, 4096);
}

function extractBody(raw: string): string {
  const sep = raw.indexOf('\n\n');
  return sep >= 0 ? raw.slice(sep + 2, sep + 4097) : '';
}

export { parseFlowFilter } from './flowFilterParser';
