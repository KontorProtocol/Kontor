/**
 * Vite 8 plugin: regenerates Kontor contract TypeScript bindings from
 * WIT files as part of the Vite pipeline.
 *
 * Usage:
 *
 *     // vite.config.ts
 *     import { defineConfig } from "vite";
 *     import { kontor } from "@kontor/sdk/vite";
 *
 *     export default defineConfig({
 *       plugins: [
 *         kontor({
 *           input: ["contracts/token.wit", "contracts/staking.wit"],
 *           outDir: "src/generated",
 *         }),
 *       ],
 *     });
 *
 * Each `*.wit` produces `<outDir>/<basename>.ts`. On `vite build` the
 * files are generated once during `buildStart`. On `vite` (dev), the
 * plugin watches the WIT files; rewrites trigger Vite's normal HMR
 * because the on-disk `.ts` artifact changes.
 *
 * `vite` is an optional peer dep — only required when this plugin is
 * actually imported.
 */
import type { Plugin } from "vite";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { generate } from "./codegen";

export interface KontorPluginOptions {
  /** Path(s) to WIT files. Resolved relative to Vite's root. */
  input: string | string[];
  /** Directory where generated `.ts` files are written. Resolved relative to Vite's root. */
  outDir: string;
}

export function kontor(opts: KontorPluginOptions): Plugin {
  let root = process.cwd();
  const inputs = Array.isArray(opts.input) ? opts.input : [opts.input];

  const resolved = (): string[] => inputs.map((p) => path.resolve(root, p));

  const targetFor = (witAbs: string): string =>
    path.resolve(root, opts.outDir, `${path.basename(witAbs, ".wit")}.ts`);

  function generateOne(witAbs: string): void {
    const text = readFileSync(witAbs, "utf8");
    const out = generate(text);
    const target = targetFor(witAbs);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, out);
  }

  return {
    name: "@kontor/sdk:codegen",

    configResolved(config) {
      root = config.root;
    },

    buildStart() {
      for (const wit of resolved()) generateOne(wit);
    },

    configureServer(server) {
      const watched = resolved();
      for (const w of watched) server.watcher.add(w);
      server.watcher.on("change", (file) => {
        const abs = path.resolve(file);
        if (!watched.includes(abs)) return;
        try {
          generateOne(abs);
        } catch (e) {
          server.config.logger.error(
            `[kontor] codegen failed for ${abs}: ${(e as Error).message}`,
          );
        }
      });
    },
  };
}
