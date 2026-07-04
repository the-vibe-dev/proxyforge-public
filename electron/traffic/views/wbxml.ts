import type { ContentView } from '../contentViews';
export const wbxmlView: ContentView = {
  id: 'wbxml', name: 'WBXML',
  detect: (_, ct) => ct.includes('application/vnd.wap.wbxml') || ct.includes('application/wbxml'),
  render: (body) => `[WBXML — ${body.length} bytes binary]\n${Buffer.from(body, 'binary').toString('hex').slice(0, 256)}...`,
};
