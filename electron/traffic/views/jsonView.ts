import { registerView } from '../contentViews';

registerView({
  id: 'json',
  name: 'JSON',
  detect: (body, ct) => ct.includes('application/json') || (body.trimStart().startsWith('{') || body.trimStart().startsWith('[')),
  render: (body) => { try { return JSON.stringify(JSON.parse(body), null, 2); } catch { return body; } },
});
