import { configDefaults, defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";

export default defineConfig({
  test: {
    globalSetup: ["./vitest.globalSetup.ts"],
    // The live regtest suite has its own config (`vitest.regtest.config.ts`)
    // — it needs a `bitcoind` devnet, so it's kept out of the fast suite.
    exclude: [...configDefaults.exclude, "**/*.regtest.test.ts"],
    browser: {
      enabled: false,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
    },
  },
});
