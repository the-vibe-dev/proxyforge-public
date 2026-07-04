import type { ContentView } from '../contentViews';
export const graphqlPrettyView: ContentView = {
  id: 'graphql', name: 'GraphQL',
  priority: 10,
  detect: (body, ct, url) => ct.includes('application/json') && /graphql|__schema|__typename/i.test(body + (url ?? '')),
  render: (body) => { try { return JSON.stringify(JSON.parse(body), null, 2); } catch { return body; } },
};
