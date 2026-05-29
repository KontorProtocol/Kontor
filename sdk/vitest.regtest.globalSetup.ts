/**
 * globalSetup for the live regtest suite. Runs in Node (always — even
 * when the tests themselves run in a browser): generates the token
 * bindings, stands up a `kontor regtest` devnet, and `provide()`s its
 * connection details to the tests. The returned teardown stops it.
 *
 * The tests stay pure HTTP clients — the chain is started here, once.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { GlobalSetupContext } from "vitest/node";
import { startRegtest, type Regtest } from "./src/regtest.js";
import { startRpcProxy } from "./test/bitcoin-rpc-proxy.js";
import { generateTokenBindings } from "./vitest.globalSetup.js";

export default async function setup({ provide }: GlobalSetupContext) {
  generateTokenBindings();

  const devnet: Regtest = await startRegtest({
    kontorBin: process.env.KONTOR_BIN ?? "../core/target/release/kontor",
    inheritStdio: true,
  });

  // Browser tests can't `fetch` bitcoind's RPC directly (no CORS); they
  // also can't reliably `fetch` the indexer's `/api` in the
  // Vitest+Playwright+Chromium setup (see `bitcoin-rpc-proxy.ts` for the
  // gory details). One Node-side proxy fronts both — the browser only
  // ever talks to its port. Node tests use it too, keeping the injected
  // URL shapes uniform across runners.
  const rpcProxy = await startRpcProxy({
    bitcoinRpc: devnet.bitcoinRpc,
    apiUrl: devnet.apiUrl,
  });

  // Brotli-compressed token wasm — Node reads it from disk and ships it
  // over `provide()` as a base64 string. The browser CAN'T just `fetch`
  // `token.wasm.br` because Vite (or the browser's HTTP layer) honors
  // the `.br` extension and auto-decompresses the brotli stream — the
  // indexer then chokes on raw wasm bytes during `publish` execution
  // with "Invalid Data". Base64 is the simplest binary-safe channel
  // through `provide()`'s structured-clone-via-string boundary.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const tokenWasmBrBase64 = readFileSync(
    path.resolve(here, "../native-contracts/binaries/token.wasm.br"),
  ).toString("base64");

  // `provide` values cross into (possibly browser) test workers, so each
  // funding UTXO's bigint `value` goes over as a string. The matching
  // `connectRegtest()` accepts that wire shape and converts back.
  provide("regtest", {
    apiUrl: rpcProxy.apiUrl,
    bitcoinRpc: rpcProxy.bitcoinRpc,
    tokenWasmBrBase64,
    devPrivateKey: devnet.devPrivateKey,
    devPublicKey: devnet.devPublicKey,
    devAddress: devnet.devAddress,
    identities: devnet.identities.map((id) => ({
      privateKey: id.privateKey,
      publicKey: id.publicKey,
      address: id.address,
      fundingUtxo: {
        txid: id.fundingUtxo.txid,
        vout: id.fundingUtxo.vout,
        value: id.fundingUtxo.value.toString(),
        scriptPubKey: id.fundingUtxo.scriptPubKey,
      },
    })),
  });

  return async () => {
    await rpcProxy.stop();
    await devnet.stop();
  };
}
