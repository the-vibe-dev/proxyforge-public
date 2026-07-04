// Rule pack engine: applies traffic transformation rules on request/response paths.

import type { FilterableExchange } from './flowFilter';
import { compileFilter } from './flowFilter';

export type RuleAction =
  | 'anticache'
  | 'anticomp'
  | 'block'
  | 'sticky-cookie'
  | 'sticky-auth'
  | 'proxy-auth'
  | 'upstream-auth'
  | 'map-local'
  | 'map-remote'
  | 'strip-dns-https'
  | 'update-alt-svc'
  | 'match-replace';

export interface TrafficRule {
  id: string;
  name: string;
  enabled: boolean;
  action: RuleAction;
  filter?: string;
  config?: Record<string, unknown>;
  matchPattern?: string;
  replaceWith?: string;
  scope?: 'request' | 'response' | 'both';
}

export interface RulePack {
  id: string;
  name: string;
  enabled: boolean;
  rules: TrafficRule[];
}

export interface AppliedRuleAnnotation {
  ruleId: string;
  action: RuleAction;
  field?: string;
  before?: string;
  after?: string;
}

export interface RuleApplicationResult {
  headers: Record<string, string>;
  body?: string;
  blocked: boolean;
  annotations: AppliedRuleAnnotation[];
}

function matchesRule(rule: TrafficRule, exchange: FilterableExchange): boolean {
  if (!rule.enabled) return false;
  if (!rule.filter) return true;
  return compileFilter(rule.filter)(exchange);
}

export function applyRequestRules(
  rules: TrafficRule[],
  headers: Record<string, string>,
  body: string,
  exchange: FilterableExchange,
): RuleApplicationResult {
  const result: RuleApplicationResult = {
    headers: { ...headers },
    body,
    blocked: false,
    annotations: [],
  };

  for (const rule of rules) {
    if (rule.scope === 'response') continue;
    if (!matchesRule(rule, exchange)) continue;

    switch (rule.action) {
      case 'anticache':
        result.headers['Cache-Control'] = 'no-cache, no-store';
        result.headers['Pragma'] = 'no-cache';
        delete result.headers['If-None-Match'];
        delete result.headers['If-Modified-Since'];
        result.annotations.push({ ruleId: rule.id, action: 'anticache' });
        break;

      case 'anticomp':
        delete result.headers['Accept-Encoding'];
        result.annotations.push({ ruleId: rule.id, action: 'anticomp' });
        break;

      case 'block':
        result.blocked = true;
        result.annotations.push({ ruleId: rule.id, action: 'block' });
        return result;

      case 'sticky-cookie':
        if (rule.config?.cookieValue && typeof rule.config.cookieValue === 'string') {
          result.headers['Cookie'] = rule.config.cookieValue;
          result.annotations.push({ ruleId: rule.id, action: 'sticky-cookie', after: rule.config.cookieValue });
        }
        break;

      case 'sticky-auth':
        if (rule.config?.authValue && typeof rule.config.authValue === 'string') {
          const before = result.headers['Authorization'] ?? '';
          result.headers['Authorization'] = rule.config.authValue;
          result.annotations.push({ ruleId: rule.id, action: 'sticky-auth', before, after: rule.config.authValue });
        }
        break;

      case 'upstream-auth':
        if (rule.config?.credentials && typeof rule.config.credentials === 'string') {
          const encoded = Buffer.from(rule.config.credentials).toString('base64');
          result.headers['Proxy-Authorization'] = `Basic ${encoded}`;
          result.annotations.push({ ruleId: rule.id, action: 'upstream-auth' });
        }
        break;

      case 'match-replace':
        if (rule.matchPattern && rule.replaceWith !== undefined) {
          const re = new RegExp(rule.matchPattern, 'g');
          const beforeBody = result.body ?? '';
          result.body = beforeBody.replace(re, rule.replaceWith);
          if (result.body !== beforeBody) {
            result.annotations.push({ ruleId: rule.id, action: 'match-replace', before: beforeBody.slice(0, 100), after: result.body.slice(0, 100) });
          }
        }
        break;

      default:
        break;
    }
  }

  return result;
}

export function applyResponseRules(
  rules: TrafficRule[],
  headers: Record<string, string>,
  body: string,
  exchange: FilterableExchange,
): RuleApplicationResult {
  const result: RuleApplicationResult = {
    headers: { ...headers },
    body,
    blocked: false,
    annotations: [],
  };

  for (const rule of rules) {
    if (rule.scope === 'request') continue;
    if (!matchesRule(rule, exchange)) continue;

    switch (rule.action) {
      case 'strip-dns-https':
        delete result.headers['alt-svc'];
        delete result.headers['Alt-Svc'];
        result.annotations.push({ ruleId: rule.id, action: 'strip-dns-https' });
        break;

      case 'update-alt-svc':
        if (rule.config?.altSvcValue) {
          result.headers['Alt-Svc'] = String(rule.config.altSvcValue);
          result.annotations.push({ ruleId: rule.id, action: 'update-alt-svc' });
        }
        break;

      case 'match-replace':
        if (rule.matchPattern && rule.replaceWith !== undefined) {
          const re = new RegExp(rule.matchPattern, 'g');
          const before = result.body ?? '';
          result.body = before.replace(re, rule.replaceWith);
          if (result.body !== before) {
            result.annotations.push({ ruleId: rule.id, action: 'match-replace' });
          }
        }
        break;

      default:
        break;
    }
  }

  return result;
}

export function applyRulePacks(
  packs: RulePack[],
  scope: 'request' | 'response',
  headers: Record<string, string>,
  body: string,
  exchange: FilterableExchange,
): RuleApplicationResult {
  const enabledRules = packs
    .filter((pack) => pack.enabled)
    .flatMap((pack) => pack.rules);

  return scope === 'request'
    ? applyRequestRules(enabledRules, headers, body, exchange)
    : applyResponseRules(enabledRules, headers, body, exchange);
}
