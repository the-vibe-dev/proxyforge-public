import type { PayloadVariant } from '../types';

export const META = {
  id: 'source-code-disclosure-web-inf',
  family: 'lfi-traversal' as const,
  name: 'Source Code Disclosure via WEB-INF / META-INF',
  description: 'Detects exposed Java web application descriptor and class files under WEB-INF and META-INF.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '/WEB-INF/web.xml', intent: 'Probe WEB-INF/web.xml — Java EE deployment descriptor with servlet mappings and config', signals: ['config-file-exposed'] },
  { value: '/WEB-INF/classes/', intent: 'Probe WEB-INF/classes/ directory — compiled Java class files', signals: ['config-file-exposed'] },
  { value: '/META-INF/', intent: 'Probe META-INF/ directory — JAR manifest and service configuration', signals: ['config-file-exposed'] },
  { value: '/WEB-INF/lib/', intent: 'Probe WEB-INF/lib/ — JAR library listing reveals dependency versions for CVE targeting', signals: ['config-file-exposed'] },
  { value: '/WEB-INF/applicationContext.xml', intent: 'Probe Spring applicationContext.xml — bean definitions may contain credentials', signals: ['config-file-exposed'] },
  { value: '/WEB-INF/struts-config.xml', intent: 'Probe Struts struts-config.xml — action mappings and form beans', signals: ['config-file-exposed'] },
  { value: '/META-INF/MANIFEST.MF', intent: 'Probe MANIFEST.MF — reveals main class, classpath, and application metadata', signals: ['config-file-exposed'] },
  { value: '/WEB-INF/hibernate.cfg.xml', intent: 'Probe Hibernate config — may contain database credentials and connection URL', signals: ['config-file-exposed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `webinf-disclosure-${i + 1}`,
    family: 'lfi-traversal' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
