/**
 * Shared shape of the `regtest` fixture `provide()`d by the live
 * regtest suite's globalSetup. Each `*.regtest.test.ts` imports this so
 * the `vitest` `ProvidedContext` augmentation is declared exactly once.
 *
 * Funding-UTXO `value`s cross the worker boundary as strings (bigints
 * don't survive `provide()`'s structured clone reliably) — tests
 * `BigInt(...)` them back.
 */

export interface RegtestFundingUtxo {
  txid: string;
  vout: number;
  /** Satoshis, as a decimal string. */
  value: string;
  scriptPubKey: string;
}

export interface RegtestInfo {
  apiUrl: string;
  bitcoinRpc: string;
  devPrivateKey: string;
  /**
   * Independent dev-account funding UTXOs — one per regtest test file,
   * so files never collide on a shared output. `transfer` takes `[0]`,
   * `attach` takes `[1]`.
   */
  devFundingUtxos: RegtestFundingUtxo[];
}

declare module "vitest" {
  interface ProvidedContext {
    regtest: RegtestInfo;
  }
}
