import { resolve } from "path";
import { defineConfig } from "vite";
import topLevelAwait from "vite-plugin-top-level-await";
import wasm from "vite-plugin-wasm";
import { viteStaticCopy } from "vite-plugin-static-copy";

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, "main.ts"),
      name: "Picky",
      fileName: "picky",
      formats: ["es", "umd"],
    },
  },
  plugins: [
    wasm(),
    topLevelAwait(),
    viteStaticCopy({
      targets: [
        {
          src: "./pkg/picky.d.ts",
          dest: "./",
        },
      ],
    }),
  ],
});
