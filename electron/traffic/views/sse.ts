import type { ContentView } from '../contentViews';
export const sseView: ContentView = {
  id: 'sse', name: 'Server-Sent Events',
  detect: (body, ct) => ct.includes('text/event-stream') || /^data:|^event:|^id:/m.test(body),
  render: (body) => body.split('\n').map((line) => line.startsWith('data:') ? `📨 ${line}` : line).join('\n'),
};
