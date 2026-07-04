import type { ContentView } from '../contentViews';
export const mqttView: ContentView = {
  id: 'mqtt', name: 'MQTT',
  detect: (body, ct) => ct.includes('application/mqtt') || body.charCodeAt(0) === 0x10,
  render: (body) => `[MQTT frame — ${body.length} bytes]\nFirst byte: 0x${body.charCodeAt(0).toString(16).padStart(2,'0')}`,
};
