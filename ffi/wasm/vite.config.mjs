import { resolve } from 'path';
import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'pkg/main.js'),
      name: 'picky',
      fileName: (format) => `picky.${format}.js`
    }
  }
});
