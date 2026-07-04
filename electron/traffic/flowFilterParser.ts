// Flow filter DSL parser — parses mitmproxy-style filter expressions.
// Supports: ~u, ~h, ~m, ~c, ~b, ~s, ~q, & | !

export type FilterOperator = '&' | '|' | '!';

export type FilterToken =
  | { kind: 'url'; pattern: RegExp }
  | { kind: 'header'; pattern: RegExp }
  | { kind: 'method'; pattern: RegExp }
  | { kind: 'code'; status: number | [number, number] }
  | { kind: 'body'; pattern: RegExp }
  | { kind: 'src'; pattern: RegExp }
  | { kind: 'query'; pattern: RegExp }
  | { kind: 'and'; left: FilterNode; right: FilterNode }
  | { kind: 'or'; left: FilterNode; right: FilterNode }
  | { kind: 'not'; operand: FilterNode }
  | { kind: 'all' };

export type FilterNode = FilterToken;

class ParseError extends Error {}

export function parseFlowFilter(expression: string): FilterNode {
  const tokens = tokenize(expression.trim());
  if (tokens.length === 0) return { kind: 'all' };
  const { node } = parseOr(tokens, 0);
  return node;
}

function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < input.length) {
    if (/\s/.test(input[i])) { i++; continue; }
    if (input[i] === '&') { tokens.push('&'); i++; continue; }
    if (input[i] === '|') { tokens.push('|'); i++; continue; }
    if (input[i] === '!') { tokens.push('!'); i++; continue; }
    if (input[i] === '(') { tokens.push('('); i++; continue; }
    if (input[i] === ')') { tokens.push(')'); i++; continue; }
    if (input[i] === '~') {
      let j = i;
      while (j < input.length && !/\s/.test(input[j]) && input[j] !== '(' && input[j] !== ')' && input[j] !== '&' && input[j] !== '|') j++;
      tokens.push(input.slice(i, j));
      i = j;
      continue;
    }
    // Quoted string
    if (input[i] === '"' || input[i] === "'") {
      const quote = input[i];
      let j = i + 1;
      while (j < input.length && input[j] !== quote) {
        if (input[j] === '\\') j++;
        j++;
      }
      tokens.push(input.slice(i, j + 1));
      i = j + 1;
      continue;
    }
    // Unquoted term
    let j = i;
    while (j < input.length && !/[\s&|!()"']/.test(input[j])) j++;
    tokens.push(input.slice(i, j));
    i = j;
  }
  return tokens.filter(Boolean);
}

function parseOr(tokens: string[], pos: number): { node: FilterNode; pos: number } {
  let { node: left, pos: p } = parseAnd(tokens, pos);
  while (p < tokens.length && tokens[p] === '|') {
    p++;
    const { node: right, pos: nextP } = parseAnd(tokens, p);
    left = { kind: 'or', left, right };
    p = nextP;
  }
  return { node: left, pos: p };
}

function parseAnd(tokens: string[], pos: number): { node: FilterNode; pos: number } {
  let { node: left, pos: p } = parseUnary(tokens, pos);
  while (p < tokens.length && tokens[p] === '&') {
    p++;
    const { node: right, pos: nextP } = parseUnary(tokens, p);
    left = { kind: 'and', left, right };
    p = nextP;
  }
  return { node: left, pos: p };
}

function parseUnary(tokens: string[], pos: number): { node: FilterNode; pos: number } {
  if (tokens[pos] === '!') {
    const { node: operand, pos: p } = parseUnary(tokens, pos + 1);
    return { node: { kind: 'not', operand }, pos: p };
  }
  return parsePrimary(tokens, pos);
}

function parsePrimary(tokens: string[], pos: number): { node: FilterNode; pos: number } {
  if (tokens[pos] === '(') {
    const { node, pos: p } = parseOr(tokens, pos + 1);
    if (tokens[p] !== ')') throw new ParseError(`Expected ) at position ${p}`);
    return { node, pos: p + 1 };
  }
  return parseLeaf(tokens, pos);
}

function unquote(s: string): string {
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1).replace(/\\(.)/g, '$1');
  }
  return s;
}

function makeRegex(pattern: string): RegExp {
  return new RegExp(unquote(pattern), 'i');
}

function parseLeaf(tokens: string[], pos: number): { node: FilterNode; pos: number } {
  const tok = tokens[pos];
  if (!tok) return { node: { kind: 'all' }, pos };

  // ~u URL
  if (tok === '~u') {
    const pattern = tokens[pos + 1];
    return { node: { kind: 'url', pattern: makeRegex(pattern ?? '') }, pos: pos + 2 };
  }
  // ~h header
  if (tok === '~h') {
    const pattern = tokens[pos + 1];
    return { node: { kind: 'header', pattern: makeRegex(pattern ?? '') }, pos: pos + 2 };
  }
  // ~m method
  if (tok === '~m') {
    const pattern = tokens[pos + 1];
    return { node: { kind: 'method', pattern: makeRegex(pattern ?? '') }, pos: pos + 2 };
  }
  // ~c status code (exact or range)
  if (tok === '~c') {
    const raw = tokens[pos + 1];
    const rangeMatch = unquote(raw ?? '').match(/^(\d+)-(\d+)$/);
    if (rangeMatch) {
      return { node: { kind: 'code', status: [parseInt(rangeMatch[1]), parseInt(rangeMatch[2])] }, pos: pos + 2 };
    }
    return { node: { kind: 'code', status: parseInt(unquote(raw ?? '0')) }, pos: pos + 2 };
  }
  // ~b body
  if (tok === '~b') {
    const pattern = tokens[pos + 1];
    return { node: { kind: 'body', pattern: makeRegex(pattern ?? '') }, pos: pos + 2 };
  }
  // ~s source (alias for ~u)
  if (tok === '~s') {
    const pattern = tokens[pos + 1];
    return { node: { kind: 'src', pattern: makeRegex(pattern ?? '') }, pos: pos + 2 };
  }
  // ~q query string
  if (tok === '~q') {
    const pattern = tokens[pos + 1];
    return { node: { kind: 'query', pattern: makeRegex(pattern ?? '') }, pos: pos + 2 };
  }

  // Bare pattern — treat as URL filter
  return { node: { kind: 'url', pattern: makeRegex(tok) }, pos: pos + 1 };
}
