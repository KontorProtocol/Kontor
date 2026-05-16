import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";

export default defineConfig({
  test: {
    globalSetup: ["./vitest.globalSetup.ts"],
    browser: {
      enabled: false,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
    },
  },
});
