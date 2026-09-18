import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    include: ['pdfjs-dist'],
  },
  build: {
    minify: 'terser',
    // "hidden" emits .map files without adding a //# sourceMappingURL
    // comment to the shipped JS, so end users' devtools still show the
    // minified bundle, but real stack traces (function/component names,
    // file + line) are recoverable from the .map files for troubleshooting —
    // e.g. paste a prod error + the matching .map into an unminify tool, or
    // wire them into an error-tracking service later.
    sourcemap: 'hidden',
    rollupOptions: {
      output: {
        manualChunks: {
          pdfjs: ['pdfjs-dist'],
          xlsx: ['xlsx'],
          mammoth: ['mammoth'],
        }
      }
    }
  }
});
