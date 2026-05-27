import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";

// The live regtest suite — `*.regtest.test.ts`, driving a real
// `kontor regtest` devnet. Separate from the default `vitest` run
// (the unit suite, which excludes this glob) because bringup needs
// `bitcoind` and is minute-scale. Run via `npm run test:regtest`
// (node) or `npm run test:regtest:browser` (chromium).
export default defineConfig({
  // Pre-bundle the SDK's crypto deps so the browser run doesn't
  // discover + reload them mid-test (vitest flags that as flaky).
  optimizeDeps: {
    include: [
      "@scure/base",
      "@scure/btc-signer",
      "@scure/bip32",
      "@scure/bip39",
    ],
  },
  test: {
    globalSetup: ["./vitest.regtest.globalSetup.ts"],
    include: ["test/**/*.regtest.test.ts"],
    // A submit → block → result round-trip on the auto-mined devnet.
    testTimeout: 120_000,
    // One devnet is shared across every file. Run files one at a time so
    // a test can assert on the dev account's own state without another
    // file mutating it concurrently (e.g. `revoke` detaches to the
    // seller — the dev account — so its balance must hold still).
    fileParallelism: false,
    browser: {
      enabled: false,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
    },
  },
});
