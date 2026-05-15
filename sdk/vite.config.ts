import { defineConfig } from "vite";
import dts from "vite-plugin-dts";
import { resolve } from "path";
import { copyFileSync, mkdirSync, readdirSync } from "fs";

// Library build for @kontor/sdk.
//
// We deliberately do NOT bundle the jco-generated component (its WASM
// loader uses `new URL('./kontor-sdk.core.wasm', import.meta.url)`, which
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
        id.startsWith("node:") || id.includes("/component/kontor-sdk"),
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
        // Copy the entire jco-emitted component bundle:
        // - .core.wasm: the Rust→WASM binary, loaded at runtime via
        //   `new URL('./kontor-sdk.core.wasm', import.meta.url)`
        // - .js: JS bindings that wrap the WASM
        // - .d.ts: top-level TS types for the world exports
        // - interfaces/*.d.ts: per-interface TS types (witApi, numericsApi)
        // All four are needed by consumers — the .d.ts files give IDE
        // type info, the others are the runtime.
        mkdirSync("dist/component/interfaces", { recursive: true });
        for (const f of [
          "kontor-sdk.js",
          "kontor-sdk.d.ts",
          "kontor-sdk.core.wasm",
        ]) {
          copyFileSync(`src/component/${f}`, `dist/component/${f}`);
        }
        for (const f of readdirSync("src/component/interfaces")) {
          copyFileSync(
            `src/component/interfaces/${f}`,
            `dist/component/interfaces/${f}`,
          );
        }
      },
    },
  ],
});
