import { expect, test } from "vitest";
import { hex } from "@scure/base";
import {
  p2tr,
  Script,
  TaprootControlBlock,
  Transaction,
} from "@scure/btc-signer";

import { signet } from "../src/chains.js";
import { LocalKey } from "../src/local-key.js";
import { buildSellerDetachPsbt } from "../src/offer.js";
import type { Signing } from "../src/signing.js";

const seller = LocalKey.fromMnemonic({
  mnemonic:
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  chain: signet,
});

function fixture() {
  const key = hex.decode(seller.identity.xOnlyPubKey);
  const amount = 600n;
  const amountBytes = new Uint8Array(8);
  new DataView(amountBytes.buffer).setBigUint64(0, amount, false);
  const script = Script.encode([
    key,
    "CHECKSIG",
    "OP_0",
    "IF",
    new Uint8Array([0x6b, 0x6f, 0x6e, 0x32]),
    amountBytes,
    hex.decode(signet.bitcoinNetworkMagic!),
    new Uint8Array([1]),
    "ENDIF",
  ]);
  const tap = p2tr(key, { script }, signet.network, true);
  const attach = new Transaction();
  attach.addInput({
    txid: "44".repeat(32),
    index: 0,
    witnessUtxo: {
      script: p2tr(key, undefined, signet.network).script,
      amount: 2000n,
    },
  });
  attach.addOutput({ script: tap.script, amount });
  return {
    attachRevealHex: hex.encode(attach.unsignedTx),
    detachLeaf: {
      leafVersion: 0xc0,
      script: hex.encode(script),
      controlBlock: hex.encode(
        TaprootControlBlock.encode(tap.tapLeafScript![0]![0]),
      ),
    },
    price: 1000n,
    network: signet.network,
  };
}

test("seller offer signature is verified against the escrow before it can be published", async () => {
  const params = fixture();
  const signed = Transaction.fromPSBT(
    hex.decode(await buildSellerDetachPsbt(seller, params)),
  );
  expect(signed.getInput(1).tapScriptSig?.[0]?.[1].at(-1)).toBe(0x83);
  expect(signed.getInput(1).witnessUtxo?.amount).toBe(600n);

  const wrongAmount: Signing = {
    identity: seller.identity,
    async psbt(bytes, opts) {
      const tx = Transaction.fromPSBT(bytes);
      const input = tx.getInput(1);
      tx.updateInput(1, {
        witnessUtxo: { script: input.witnessUtxo!.script, amount: 601n },
      });
      return seller.psbt(tx.toPSBT(), opts);
    },
  };
  await expect(buildSellerDetachPsbt(wrongAmount, params)).rejects.toThrow(
    /signature does not authorize/,
  );
});
