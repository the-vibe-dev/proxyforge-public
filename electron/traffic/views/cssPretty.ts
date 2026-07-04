import type { ContentView } from '../contentViews';
export const cssPrettyView: ContentView = {
  id: 'css', name: 'CSS',
  detect: (body, ct) => ct.includes('text/css') || ct.includes('application/css'),
  render: (body) => body.replace(/\{/g, ' {\n  ').replace(/;/g, ';\n  ').replace(/\}/g, '\n}\n'),
};
