import type { ContentView } from '../contentViews';
export const zipTreeView: ContentView = {
  id: 'zip', name: 'ZIP/Archive',
  detect: (body, ct) => ct.includes('application/zip') || ct.includes('application/x-zip') || body.startsWith('PK'),
  render: () => '[ZIP archive — binary content not displayed]',
};
