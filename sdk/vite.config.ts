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
// React Native target. `KONTOR_TARGET=native vite build` emits a single
// `dist/index.native.js` (referenced by package.json's `react-native`
// export condition) that swaps the WASM boundary for the native module:
//   - `./backend/index`      → `backend.native` (`@kontor/sdk-native`)
//   - `./component/kontor-sdk`→ a throwing dev-time stub (no WASM loader)
// The native module is external — resolved by the app's bundler (Metro),
// not here — so this pass builds even without the mobile toolchain, which
// lets the web CI verify the bundle emits. Actually running it is covered
// by the mobile CI. See the mobile plan.
const isNative = process.env.KONTOR_TARGET === "native";

// Redirect the two WASM-boundary modules to their native equivalents for
// the React Native bundle. A `resolveId` hook (not `resolve.alias`, which
// only matches bare import specifiers) so it catches the relative internal
// imports `./backend/index.js` and `./component/kontor-sdk.js` wherever
// they appear in the graph.
function nativeBackendPlugin() {
  return {
    name: "kontor-native-backend",
    enforce: "pre" as const,
    resolveId(source: string) {
      if (!isNative) return null;
      if (source.endsWith("/backend/index.js"))
        return resolve(__dirname, "src/backend/backend.native.ts");
      if (source.endsWith("/component/kontor-sdk.js"))
        return resolve(__dirname, "src/backend/component-stub.native.ts");
      return null;
    },
  };
}

export default defineConfig({
  build: {
    lib: {
      entry: isNative
        ? { "index.native": resolve(__dirname, "src/index.ts") }
        : {
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
    // The native pass must not wipe the web bundle it runs after.
    emptyOutDir: !isNative,
    rollupOptions: {
      // Keep npm dependencies out of the bundle: `vite` is a peer dep,
      // and the `@scure/*` / `@noble/*` crypto libs are regular runtime
      // deps — consumers resolve them from `package.json`, so bundling
      // them in would just bloat the output and risk duplicate copies.
      // On the native pass, `@kontor/sdk-native` is likewise external.
      external: (id) =>
        id.startsWith("node:") ||
        id === "vite" ||
        id.startsWith("@scure/") ||
        id.startsWith("@noble/") ||
        id === "@kontor/sdk-native" ||
        // On the native pass the component is redirected to a stub by
        // `nativeBackendPlugin`, so it must NOT be externalized here (an
        // external id short-circuits the resolveId redirect).
        (!isNative && id.includes("/component/kontor-sdk")),
      output: {
        // Restore the shebang Rollup strips from CLI sources, so the
        // emitted dist/cli.js is directly executable by Node.
        banner: (chunk) => (chunk.name === "cli" ? "#!/usr/bin/env node" : ""),
      },
    },
  },
  // The native pass reuses the web pass's .d.ts (identical public API) and
  // its copied component dir, so it skips dts + copy-component — it only
  // needs the module-redirect plugin.
  plugins: isNative
    ? [nativeBackendPlugin()]
    : [
        dts({
          include: ["src"],
          // The CLI is a bin, never imported — no .d.ts needed. The
          // native-only backend files import `@kontor/sdk-native` (a
          // mobile-only peer absent from the web build) — they are
          // type-checked in the mobile CI, not here.
          exclude: [
            "src/cli.ts",
            "src/backend/backend.native.ts",
            "src/backend/component-stub.native.ts",
          ],
          rollupTypes: false,
          // vite-plugin-dts emits per-file declarations under `dist/src/`
          // (mirroring the source tree); the runtime JS is bundled at the
          // `dist/` root. So package.json's `types` paths point into
          // `dist/src/**`, while `import` paths point at `dist/*.js`.
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
