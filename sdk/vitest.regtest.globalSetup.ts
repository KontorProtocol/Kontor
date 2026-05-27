/**
 * globalSetup for the live regtest suite. Runs in Node (always — even
 * when the tests themselves run in a browser): generates the token
 * bindings, stands up a `kontor regtest` devnet, and `provide()`s its
 * connection details to the tests. The returned teardown stops it.
 *
 * The tests stay pure HTTP clients — the chain is started here, once.
 */
import type { GlobalSetupContext } from "vitest/node";
import { startRegtest, type Regtest } from "./src/regtest.js";
import { generateTokenBindings } from "./vitest.globalSetup.js";

export default async function setup({ provide }: GlobalSetupContext) {
  generateTokenBindings();

  const devnet: Regtest = await startRegtest({
    kontorBin: process.env.KONTOR_BIN ?? "../core/target/release/kontor",
    inheritStdio: true,
  });

  // `provide` values cross into (possibly browser) test workers, so each
  // funding UTXO's bigint `value` goes over as a string. The matching
  // `connectRegtest()` accepts that wire shape and converts back.
  provide("regtest", {
    apiUrl: devnet.apiUrl,
    bitcoinRpc: devnet.bitcoinRpc,
    devPrivateKey: devnet.devPrivateKey,
    devPublicKey: devnet.devPublicKey,
    devAddress: devnet.devAddress,
    devFundingUtxos: devnet.devFundingUtxos.map((u) => ({
      txid: u.txid,
      vout: u.vout,
      value: u.value.toString(),
      scriptPubKey: u.scriptPubKey,
    })),
  });

  return async () => {
    await devnet.stop();
  };
}
