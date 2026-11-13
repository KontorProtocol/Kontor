import { expect, test } from "vitest";
import { hex } from "@scure/base";
import { p2tr, Script, Transaction } from "@scure/btc-signer";

import {
  signCommit,
  signReveal,
  verifyFinalizedTaprootTransaction,
} from "../src/transport/signing.js";
import { LocalKey } from "../src/local-key.js";
import { signet } from "../src/chains.js";
import type { Signing } from "../src/signing.js";

const buyer = LocalKey.fromMnemonic({
  mnemonic: "test test test test test test test test test test test junk",
  chain: signet,
});
const seller = LocalKey.fromMnemonic({
  mnemonic:
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  chain: signet,
});

function keypathPsbt(): Uint8Array {
  const key = hex.decode(buyer.identity.xOnlyPubKey);
  const payment = p2tr(key, undefined, signet.network);
  const tx = new Transaction();
  tx.addInput({
    txid: "11".repeat(32),
    index: 0,
    witnessUtxo: { script: payment.script, amount: 100_000n },
    tapInternalKey: payment.tapInternalKey,
  });
  tx.addOutput({ script: payment.script, amount: 90_000n });
  return tx.toPSBT();
}

function scriptpathPsbt(account: LocalKey, sighashType: number): Uint8Array {
  const key = hex.decode(account.identity.xOnlyPubKey);
  const leaf = Script.encode([
    key,
    "CHECKSIG",
    "OP_0",
    "IF",
    new Uint8Array([0x6b, 0x6f, 0x6e, 0x32]),
    new Uint8Array(8),
    hex.decode(signet.bitcoinNetworkMagic!),
    new Uint8Array([1]),
    "ENDIF",
  ]);
  const payment = p2tr(key, { script: leaf }, signet.network, true);
  const tx = new Transaction();
  tx.addInput({
    txid: "22".repeat(32),
    index: 0,
    witnessUtxo: { script: payment.script, amount: 100_000n },
    tapInternalKey: payment.tapInternalKey,
    tapLeafScript: payment.tapLeafScript,
    sighashType,
  });
  tx.addOutput({ script: payment.script, amount: 90_000n });
  return tx.toPSBT();
}

test("commit signs and verifies the exact requested key-path digest", async () => {
  const psbt = keypathPsbt();
  const raw = await signCommit(buyer, hex.encode(psbt));
  expect(Transaction.fromRaw(hex.decode(raw)).inputsLength).toBe(1);

  const altered: Signing = {
    identity: buyer.identity,
    async psbt(bytes) {
      const tx = Transaction.fromPSBT(bytes);
      tx.updateOutput(0, { amount: 80_000n });
      return buyer.psbt(tx.toPSBT(), { inputs: [{ index: 0 }] });
    },
  };
  await expect(signCommit(altered, hex.encode(psbt))).rejects.toThrow(
    /changed the unsigned transaction/,
  );

  const forged: Signing = {
    identity: buyer.identity,
    async psbt(bytes) {
      const tx = Transaction.fromPSBT(bytes);
      tx.updateInput(0, { tapKeySig: new Uint8Array(64) });
      return tx.toPSBT();
    },
  };
  await expect(signCommit(forged, hex.encode(psbt))).rejects.toThrow(
    /signature does not authorize/,
  );

  const wrongPrevout: Signing = {
    identity: buyer.identity,
    async psbt(bytes) {
      const tx = Transaction.fromPSBT(bytes);
      const original = tx.getInput(0).witnessUtxo!;
      tx.updateInput(0, {
        witnessUtxo: { script: original.script, amount: original.amount - 1n },
      });
      return buyer.psbt(tx.toPSBT(), { inputs: [{ index: 0 }] });
    },
  };
  await expect(signCommit(wrongPrevout, hex.encode(psbt))).rejects.toThrow(
    /signature does not authorize/,
  );

  const prefinalized: Signing = {
    identity: buyer.identity,
    async psbt(bytes, opts) {
      const tx = Transaction.fromPSBT(await buyer.psbt(bytes, opts));
      tx.finalize();
      return tx.toPSBT();
    },
  };
  const finalizedRaw = await signCommit(prefinalized, hex.encode(psbt));
  expect(Transaction.fromRaw(hex.decode(finalizedRaw)).id).toBe(
    Transaction.fromRaw(hex.decode(raw)).id,
  );
});

test("reveal verifies the chosen leaf key and the final transaction digest", async () => {
  const psbt = scriptpathPsbt(seller, 0x83);
  const tx = await signReveal(seller, hex.encode(psbt));
  expect(() => verifyFinalizedTaprootTransaction(tx)).not.toThrow();
  const changed = Transaction.fromPSBT(psbt);
  changed.updateOutput(0, { amount: 89_999n });
  changed.updateInput(0, {
    finalScriptWitness: tx.getInput(0).finalScriptWitness,
  });
  expect(() => verifyFinalizedTaprootTransaction(changed)).toThrow(
    /signature does not authorize/,
  );

  const forged: Signing = {
    identity: seller.identity,
    async psbt(bytes, opts) {
      const signed = Transaction.fromPSBT(await seller.psbt(bytes, opts));
      const entry = signed.getInput(0).tapScriptSig![0]!;
      signed.updateInput(0, {
        tapScriptSig: [
          [
            { ...entry[0], pubKey: hex.decode(buyer.identity.xOnlyPubKey) },
            entry[1],
          ],
        ],
      });
      return signed.toPSBT();
    },
  };
  await expect(signReveal(forged, hex.encode(psbt))).rejects.toThrow(
    /different signed sighash/,
  );
});
