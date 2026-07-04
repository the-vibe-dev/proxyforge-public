import type { ContentView } from '../contentViews';
export const socketioView: ContentView = {
  id: 'socketio', name: 'Socket.IO',
  detect: (body) => /^\d+(\[|{)/.test(body) || body.startsWith('0{'),
  render: (body) => {
    const match = body.match(/^(\d+)(.*)$/s);
    if (!match) return body;
    const [, type, data] = match;
    const types: Record<string, string> = { '0': 'CONNECT', '1': 'DISCONNECT', '2': 'EVENT', '3': 'ACK', '4': 'CONNECT_ERROR', '5': 'BINARY_EVENT', '6': 'BINARY_ACK' };
    return `Type: ${types[type] ?? type} (${type})\nData: ${data}`;
  },
};
