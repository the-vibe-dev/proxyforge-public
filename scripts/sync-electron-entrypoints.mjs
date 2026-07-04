import fs from 'node:fs/promises';
import path from 'node:path';

const root = process.cwd();
const sourceDir = path.join(root, 'dist-electron', 'electron');
const targetDir = path.join(root, 'dist-electron');

await fs.cp(sourceDir, targetDir, {
  recursive: true,
  force: true,
  errorOnExist: false,
});
