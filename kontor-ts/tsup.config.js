import { defineConfig } from "tsup";
import { copyFile } from "fs/promises";
import { join } from "path";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  target: "es2022",
  async onSuccess() {
    await copyFile(
      "src/component/kontor-ts.core.wasm",
      "dist/kontor-ts.core.wasm",
    );
    console.log("✅ Wasm copied to dist");
  },
});
