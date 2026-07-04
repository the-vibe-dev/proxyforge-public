// CycloneDX 1.5 JSON serializer for ProxyForge project SBOMs.
// No external dependencies.

import type { SbomMetadata } from '../sbomEngine';
import { buildCycloneDx } from '../sbomEngine';

export function serializeCycloneDx(metadata: SbomMetadata): string {
  return JSON.stringify(buildCycloneDx(metadata), null, 2);
}

export function validateCycloneDxShape(obj: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (typeof obj !== 'object' || obj === null) {
    return { valid: false, errors: ['Not an object'] };
  }
  const cdx = obj as Record<string, unknown>;
  if (cdx.bomFormat !== 'CycloneDX') errors.push('Missing bomFormat: CycloneDX');
  if (cdx.specVersion !== '1.5') errors.push('Missing specVersion: 1.5');
  if (!cdx.serialNumber) errors.push('Missing serialNumber');
  if (!cdx.metadata) errors.push('Missing metadata');
  if (!Array.isArray(cdx.components)) errors.push('Missing components array');
  return { valid: errors.length === 0, errors };
}
