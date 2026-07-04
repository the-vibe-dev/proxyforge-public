import type { ContentView } from '../contentViews';
export const multipartView: ContentView = {
  id: 'multipart', name: 'Multipart',
  detect: (body, ct) => ct.includes('multipart/'),
  render: (body, ct) => {
    const boundary = ct.match(/boundary="?([^";]+)"?/i)?.[1];
    if (!boundary) return body;
    return body.split(`--${boundary}`).map((part, i) => `--- Part ${i} ---\n${part.trim()}`).join('\n\n');
  },
};
