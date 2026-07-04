// SPDX 2.3 serializer (tag-value + JSON) for ProxyForge project SBOMs.
// No external dependencies.

import type { SbomMetadata } from '../sbomEngine';
import { buildSpdxTagValue, buildSpdxJson } from '../sbomEngine';

export function serializeSpdxTagValue(metadata: SbomMetadata): string {
  return buildSpdxTagValue(metadata);
}

export function serializeSpdxJson(metadata: SbomMetadata): string {
  return JSON.stringify(buildSpdxJson(metadata), null, 2);
}

export function validateSpdxJsonShape(obj: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (typeof obj !== 'object' || obj === null) {
    return { valid: false, errors: ['Not an object'] };
  }
  const spdx = obj as Record<string, unknown>;
  if (!String(spdx.spdxVersion ?? '').startsWith('SPDX-')) errors.push('Missing spdxVersion');
  if (spdx.dataLicense !== 'CC0-1.0') errors.push('Missing dataLicense: CC0-1.0');
  if (!spdx.documentName) errors.push('Missing documentName');
  if (!spdx.documentNamespace) errors.push('Missing documentNamespace');
  if (!spdx.creationInfo) errors.push('Missing creationInfo');
  if (!Array.isArray(spdx.packages)) errors.push('Missing packages array');
  return { valid: errors.length === 0, errors };
}
