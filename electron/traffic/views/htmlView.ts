import { registerView } from '../contentViews';

registerView({
  id: 'html',
  name: 'HTML',
  detect: (body, ct) => ct.includes('text/html') || /^\s*<!DOCTYPE\s+html/i.test(body) || /^\s*<html/i.test(body),
  render: (body) => body,
});
