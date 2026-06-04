import { defineConfig } from "vite";
import dts from "vite-plugin-dts";
import { resolve } from "path";
import { chmodSync, copyFileSync, mkdirSync, readdirSync } from "fs";

// Library build for @kontor/sdk.
//
// Multi-entry build:
//   - `index`:   the main runtime — canonical wrappers, codec, codegen()
//   - `vite`:    Vite 8 plugin (`@kontor/sdk/vite`)
//   - `regtest`: Node-only local devnet helper (`@kontor/sdk/regtest`)
//   - `cli`:     `kontor-codegen` bin (shebang re-added via rollup banner)
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
      entry: {
        index: resolve(__dirname, "src/index.ts"),
        vite: resolve(__dirname, "src/vite.ts"),
        regtest: resolve(__dirname, "src/regtest.ts"),
        cli: resolve(__dirname, "src/cli.ts"),
        "wallets/sats-connect": resolve(
          __dirname,
          "src/wallets/sats-connect.ts",
        ),
      },
      formats: ["es"],
    },
    target: "es2022",
    emptyOutDir: true,
    rollupOptions: {
      // Keep npm dependencies out of the bundle: `vite` is a peer dep,
      // and the `@scure/*` / `@noble/*` crypto libs are regular runtime
      // deps — consumers resolve them from `package.json`, so bundling
      // them in would just bloat the output and risk duplicate copies.
      external: (id) =>
        id.startsWith("node:") ||
        id === "vite" ||
        id.startsWith("@scure/") ||
        id.startsWith("@noble/") ||
        id.includes("/component/kontor-sdk"),
      output: {
        // Restore the shebang Rollup strips from CLI sources, so the
        // emitted dist/cli.js is directly executable by Node.
        banner: (chunk) => (chunk.name === "cli" ? "#!/usr/bin/env node" : ""),
      },
    },
  },
  plugins: [
    dts({
      include: ["src"],
      // The CLI is a bin, never imported — no .d.ts needed.
      exclude: ["src/cli.ts"],
      rollupTypes: false,
      // Emit declarations at the dist/ root (dist/index.d.ts) mirroring
      // the bundled JS entries. Without this they land under dist/src/
      // and package.json's `types` path can't resolve them.
      entryRoot: "src",
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
        // Make the CLI bin executable.
        chmodSync("dist/cli.js", 0o755);
      },
    },
  ],
});
