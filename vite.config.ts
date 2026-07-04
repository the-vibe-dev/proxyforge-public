import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    watch: {
      ignored: [
        '**/.git/**',
        '**/.gitignored/**',
        '**/dist/**',
        '**/dist-electron/**',
        '**/release/**',
        '**/test-results/**',
      ],
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  preview: {
    host: '127.0.0.1',
  },
});
