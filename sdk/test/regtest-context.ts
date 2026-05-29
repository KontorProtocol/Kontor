/**
 * Shared shape of the `regtest` fixture `provide()`d by the live
 * regtest suite's globalSetup. Each `*.regtest.test.ts` imports this so
 * the `vitest` `ProvidedContext` augmentation is declared exactly once.
 *
 * Mirrors `ProvidedRegtestInfo` from `@kontor/sdk/regtest`: funding-UTXO
 * `value`s cross the worker boundary as strings (bigints don't survive
 * `provide()`'s structured clone reliably across browser workers), so
 * tests pass the injected fixture straight into `connectRegtest(...)`,
 * which converts them back to bigints.
 */

import type { ProvidedRegtestInfo } from "@kontor/sdk/regtest";

declare module "vitest" {
  interface ProvidedContext {
    regtest: ProvidedRegtestInfo & {
      /** Brotli-compressed token wasm, base64-encoded. The browser
       *  can't `fetch` the `.br` file directly — Vite/Chrome
       *  auto-decompresses brotli, which makes the indexer's publish
       *  step fail with "Invalid Data". So globalSetup reads it Node-
       *  side and ships the raw compressed bytes through `provide()`. */
      tokenWasmBrBase64: string;
    };
  }
}
