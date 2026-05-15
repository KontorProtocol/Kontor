import { defineConfig } from "vite";
import dts from "vite-plugin-dts";
import { resolve } from "path";
import { copyFileSync, mkdirSync } from "fs";

// Library build for @kontor/sdk.
//
// We deliberately do NOT bundle the jco-generated component (its WASM
// loader uses `new URL('./kontor-ts.core.wasm', import.meta.url)`, which
// Vite/Rolldown lib mode rewrites to a base64 `data:` URL — fine for
// browsers but breaks Node's `fs.readFile(url)` which only accepts file://).
// Instead we mark the component as external and copy the whole component
// directory (JS + .d.ts + .wasm) into dist/, so the runtime URL resolution
// works in both Node and browser without rewriting.
export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      formats: ["es"],
      fileName: () => "index.js",
    },
    target: "es2022",
    emptyOutDir: true,
    rollupOptions: {
      external: (id) =>
        id.startsWith("node:") || id.includes("/component/kontor-ts"),
    },
  },
  plugins: [
    dts({
      include: ["src"],
      rollupTypes: false,
    }),
    {
      name: "copy-component",
      closeBundle() {
        mkdirSync("dist/component", { recursive: true });
        copyFileSync(
          "src/component/kontor-ts.js",
          "dist/component/kontor-ts.js",
        );
        copyFileSync(
          "src/component/kontor-ts.core.wasm",
          "dist/component/kontor-ts.core.wasm",
        );
      },
    },
  ],
});
