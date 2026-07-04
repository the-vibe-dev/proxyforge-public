import type { ContentView } from '../contentViews';
export const dnsPrettyView: ContentView = {
  id: 'dns', name: 'DNS',
  detect: (_, ct) => ct.includes('application/dns') || ct.includes('application/dns-message'),
  render: (body) => `[DNS message — ${body.length} bytes]\n${Buffer.from(body, 'binary').toString('hex').slice(0, 64)}...`,
};
