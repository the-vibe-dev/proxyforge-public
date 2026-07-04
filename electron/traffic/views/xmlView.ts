import { registerView } from '../contentViews';

registerView({
  id: 'xml',
  name: 'XML',
  detect: (body, ct) => {
    if (ct.includes('html')) return false;
    if (ct.includes('xml')) return true;
    const trimmed = body.trimStart();
    return trimmed.startsWith('<?xml') || (trimmed.startsWith('<') && !trimmed.startsWith('<!DOCTYPE html') && !trimmed.toLowerCase().startsWith('<html'));
  },
  render: (body) => {
    // Indent XML with basic indentation
    let depth = 0;
    return body
      .replace(/>\s*</g, '>\n<')
      .split('\n')
      .map((line) => {
        if (line.match(/^<\//)) depth = Math.max(0, depth - 1);
        const indented = '  '.repeat(depth) + line.trim();
        if (line.match(/^<[^/!?][^>]*[^/]>/) && !line.match(/<\/[^>]+>/)) depth++;
        return indented;
      })
      .join('\n');
  },
});
