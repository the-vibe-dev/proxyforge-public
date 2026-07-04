import { registerView } from '../contentViews';

registerView({
  id: 'form',
  name: 'Form Data',
  detect: (body, ct) => ct.includes('application/x-www-form-urlencoded'),
  render: (body) => {
    try {
      const params = new URLSearchParams(body);
      return Array.from(params.entries()).map(([k, v]) => `${k} = ${v}`).join('\n');
    } catch {
      return body;
    }
  },
});
