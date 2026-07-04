import type { PayloadVariant } from '../types';

export const META = {
  id: 'spring4shell-actuator',
  family: 'ssrf' as const,
  name: 'Spring Boot Actuator Exposure (CVE-2022-22965 companion)',
  description: 'Probes Spring Boot Actuator endpoints that may be inadvertently exposed alongside CVE-2022-22965 environments.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '/actuator', intent: 'Probe Spring Boot Actuator root — lists all exposed endpoints', signals: ['actuator-exposed'] },
  { value: '/actuator/env', intent: 'Probe /actuator/env — exposes environment variables and config properties', signals: ['actuator-exposed', 'config-exposed'] },
  { value: '/actuator/heapdump', intent: 'Probe /actuator/heapdump — downloads JVM heap dump containing secrets', signals: ['actuator-exposed', 'heapdump-exposed'] },
  { value: '/actuator/mappings', intent: 'Probe /actuator/mappings — enumerates all Spring MVC route mappings', signals: ['actuator-exposed'] },
  { value: '/actuator/beans', intent: 'Probe /actuator/beans — lists all Spring beans and their dependencies', signals: ['actuator-exposed'] },
  { value: '/actuator/loggers', intent: 'Probe /actuator/loggers — may allow changing log levels (write access)', signals: ['actuator-exposed', 'write-access'] },
  { value: '/actuator/httptrace', intent: 'Probe /actuator/httptrace — recent HTTP request/response history including auth headers', signals: ['actuator-exposed', 'traffic-exposed'] },
  { value: '/actuator/shutdown', intent: 'Probe /actuator/shutdown — POST triggers graceful shutdown (destructive if enabled)', signals: ['actuator-exposed', 'shutdown-exposed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `spring-actuator-${i + 1}`,
    family: 'ssrf' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
