// Converts imported spec routes into scanner insertion points.
// Used by the Import Wizard and the Ajax spider to seed the insertion-point inventory.

import type { ImportedRoute, ImportedParam } from '../specImport/index';

export type InsertionPointKind =
  | 'query'
  | 'body'
  | 'header'
  | 'path'
  | 'json'
  | 'cookie'
  | 'multipart';

export interface SpecInsertionPoint {
  id: string;
  routeKey: string;
  method: string;
  path: string;
  kind: InsertionPointKind;
  name: string;
  baseValue?: string;
  required: boolean;
  schema?: unknown;
}

let _idSeq = 0;
function nextId(): string {
  return `sip-${++_idSeq}-${Math.random().toString(36).slice(2, 6)}`;
}

function paramLocationToKind(location: ImportedParam['location']): InsertionPointKind {
  switch (location) {
    case 'query': return 'query';
    case 'path': return 'path';
    case 'header': return 'header';
    case 'cookie': return 'cookie';
    case 'body': return 'body';
    default: return 'body';
  }
}

export function extractInsertionPoints(routes: ImportedRoute[]): SpecInsertionPoint[] {
  const points: SpecInsertionPoint[] = [];

  for (const route of routes) {
    const routeKey = `${route.method}:${route.path}`;

    for (const param of route.params) {
      points.push({
        id: nextId(),
        routeKey,
        method: route.method,
        path: route.path,
        kind: paramLocationToKind(param.location),
        name: param.name,
        baseValue: param.example,
        required: param.required,
        schema: param.schema,
      });
    }

    // If route has a JSON body, add a top-level JSON insertion point
    if (route.requestBody?.contentType?.includes('json')) {
      points.push({
        id: nextId(),
        routeKey,
        method: route.method,
        path: route.path,
        kind: 'json',
        name: '__body__',
        required: true,
      });
    }

    // If route has a multipart body
    if (route.requestBody?.contentType?.includes('multipart')) {
      points.push({
        id: nextId(),
        routeKey,
        method: route.method,
        path: route.path,
        kind: 'multipart',
        name: '__multipart__',
        required: true,
      });
    }

    // Extract path template params from the path string (e.g., /users/{id})
    const pathParamRe = /\{([^}]+)\}|:([a-zA-Z_][a-zA-Z0-9_]*)/g;
    let m: RegExpExecArray | null;
    const existingPathParams = new Set(points.filter((p) => p.routeKey === routeKey && p.kind === 'path').map((p) => p.name));
    while ((m = pathParamRe.exec(route.path)) !== null) {
      const name = m[1] ?? m[2];
      if (!existingPathParams.has(name)) {
        existingPathParams.add(name);
        points.push({
          id: nextId(),
          routeKey,
          method: route.method,
          path: route.path,
          kind: 'path',
          name,
          required: true,
        });
      }
    }
  }

  return points;
}

export function groupByRoute(points: SpecInsertionPoint[]): Map<string, SpecInsertionPoint[]> {
  const map = new Map<string, SpecInsertionPoint[]>();
  for (const p of points) {
    const arr = map.get(p.routeKey) ?? [];
    arr.push(p);
    map.set(p.routeKey, arr);
  }
  return map;
}

export function filterByKind(
  points: SpecInsertionPoint[],
  kinds: InsertionPointKind[]
): SpecInsertionPoint[] {
  const kindSet = new Set(kinds);
  return points.filter((p) => kindSet.has(p.kind));
}

export function filterRequiredOnly(points: SpecInsertionPoint[]): SpecInsertionPoint[] {
  return points.filter((p) => p.required);
}
