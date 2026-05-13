import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    include: ['pdfjs-dist'],
  },
  build: {
    minify: 'terser',
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
