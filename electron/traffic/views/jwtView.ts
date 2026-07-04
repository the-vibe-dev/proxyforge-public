import { registerView } from '../contentViews';

function isJwt(s: string): boolean {
  const parts = s.trim().split('.');
  return parts.length === 3 && parts.every((p) => /^[A-Za-z0-9_\-]+$/.test(p));
}

function b64decode(s: string): string {
  try {
    return Buffer.from(s, 'base64url').toString('utf8');
  } catch {
    return s;
  }
}

registerView({
  id: 'jwt',
  name: 'JWT',
  detect: (body) => isJwt(body.trim()),
  render: (body) => {
    const [h, p, sig] = body.trim().split('.');
    try {
      const header = JSON.stringify(JSON.parse(b64decode(h)), null, 2);
      const payload = JSON.stringify(JSON.parse(b64decode(p)), null, 2);
      return `=== Header ===\n${header}\n\n=== Payload ===\n${payload}\n\n=== Signature ===\n${sig}`;
    } catch {
      return body;
    }
  },
});
