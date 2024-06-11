import { defineConfig } from 'vite';
import topLevelAwait from 'vite-plugin-top-level-await';
import dtsPlugin from 'vite-plugin-dts';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  build: {
    lib: {
      entry: 'main.ts',
      name: '@Devolutions/picky',
      formats: ['es'],
    },
  },
  assetsInclude: ['pkg/picky_bg.wasm'],
  plugins: [wasm(), topLevelAwait(), dtsPlugin()],
});
