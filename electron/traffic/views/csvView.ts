import { registerView } from '../contentViews';

registerView({
  id: 'csv',
  name: 'CSV',
  detect: (body, ct) => ct.includes('text/csv') || ct.includes('text/comma-separated'),
  render: (body) => {
    const lines = body.split('\n').filter(Boolean);
    if (!lines.length) return body;
    const [header, ...rows] = lines;
    const cols = header.split(',');
    const formatted = rows.map((row) =>
      row.split(',').map((v, i) => `  ${cols[i] ?? i}: ${v}`).join('\n')
    );
    return [`Columns: ${cols.join(', ')}`, ...formatted.map((r, i) => `--- Row ${i + 1} ---\n${r}`)].join('\n\n');
  },
});
