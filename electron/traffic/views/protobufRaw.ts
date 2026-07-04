import type { ContentView } from '../contentViews';
export const protobufRawView: ContentView = {
  id: 'protobuf-raw', name: 'Protobuf (raw)',
  detect: (_, ct) => ct.includes('application/grpc') || ct.includes('application/x-protobuf') || ct.includes('application/protobuf'),
  render: (body) => {
    const hex = Buffer.from(body, 'binary').toString('hex');
    return hex.match(/.{1,32}/g)?.join('\n') ?? hex;
  },
};
