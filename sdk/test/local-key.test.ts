/**
 * Unit tests for `LocalKey` — the in-process signer (a `Signing` that
 * carries its own `identity`). Key-derivation tests are known-answer (a
 * fixed mnemonic → a fixed P2TR address); `psbt` is exercised against a
 * real taproot key-path PSBT built with `@scure/btc-signer`.
 */
import { test, expect } from "vitest";
import { Transaction, p2tr } from "@scure/btc-signer";
import { LocalKey } from "../src/local-key.js";
import { SignerError } from "../src/errors.js";
import { regtestChain, signet } from "../src/chains.js";

// BIP-39 test vector mnemonic (the "test … junk" phrase). Deriving it at
// BIP-86 `m/86'/1'/0'/0/0` on a testnet chain is a fixed, known answer.
const MNEMONIC = "test test test test test test test test test test test junk";
const SIGNET_ADDRESS =
  "tb1pfewlxm8meyyvgjydfu7v8j4ej64symj6ut8sf66h9germp94qgzsgnnjhk";
const SIGNET_XONLY =
  "8c7fc6552af4384a13791e63bac79ff2bcfeedf143a88d6dc4b6080a8829cdc1";

function xOnlyBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/.{2}/g)!.map((h) => parseInt(h, 16)));
}

test("fromMnemonic: known mnemonic derives the expected P2TR identity", () => {
  const acct = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  expect(acct.identity.address).toBe(SIGNET_ADDRESS);
  expect(acct.identity.xOnlyPubKey).toBe(SIGNET_XONLY);
  expect(acct.identity.holderRef.kind).toBe("x-only-pubkey");
});

test("fromPrivateKey: round-trips the key fromMnemonic derived", () => {
  const fromSeed = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  const fromKey = LocalKey.fromPrivateKey({
    privateKey: fromSeed.privateKey,
    chain: signet,
  });
  expect(fromKey.identity.address).toBe(SIGNET_ADDRESS);
  expect(fromKey.identity.xOnlyPubKey).toBe(SIGNET_XONLY);
});

test("fromPrivateKey: hex string and Uint8Array forms are equivalent", () => {
  const bytes = LocalKey.fromMnemonic({
    mnemonic: MNEMONIC,
    chain: signet,
  }).privateKey;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  const a = LocalKey.fromPrivateKey({ privateKey: bytes, chain: signet });
  const b = LocalKey.fromPrivateKey({ privateKey: hex, chain: signet });
  const c = LocalKey.fromPrivateKey({ privateKey: `0x${hex}`, chain: signet });
  expect(a.identity.address).toBe(b.identity.address);
  expect(b.identity.address).toBe(c.identity.address);
});

test("fromPrivateKey: rejects a key that isn't 32 bytes", () => {
  expect(() =>
    LocalKey.fromPrivateKey({ privateKey: "aabbcc", chain: signet }),
  ).toThrow(SignerError);
});

test("fromMnemonic: rejects an invalid BIP-39 mnemonic", () => {
  expect(() =>
    LocalKey.fromMnemonic({ mnemonic: "not a real mnemonic", chain: signet }),
  ).toThrow(/invalid BIP-39 mnemonic/);
});

test("derivation: coin type follows the chain (regtest → bcrt address)", () => {
  const regtest = regtestChain({
    apiUrl: "http://localhost:1/api",
    bitcoinRpc: "http://localhost:2",
  });
  const acct = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: regtest });
  expect(acct.identity.address.startsWith("bcrt1p")).toBe(true);
  // regtest and signet share coin type 1, so the key matches; only the
  // address HRP differs.
  expect(acct.identity.xOnlyPubKey).toBe(SIGNET_XONLY);
});

test("schnorr: signs a 32-byte digest, rejects a wrong-length one", async () => {
  const acct = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  const sig = await acct.schnorr(new Uint8Array(32));
  expect(sig.length).toBe(64);
  await expect(acct.schnorr(new Uint8Array(31))).rejects.toBeInstanceOf(
    SignerError,
  );
});

test("psbt: signs a taproot key-path input", async () => {
  const acct = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  const payment = p2tr(
    xOnlyBytes(acct.identity.xOnlyPubKey),
    undefined,
    signet.network,
  );

  const tx = new Transaction();
  tx.addInput({
    txid: "00".repeat(32),
    index: 0,
    witnessUtxo: { script: payment.script, amount: 100_000n },
    tapInternalKey: payment.tapInternalKey,
  });
  tx.addOutputAddress(acct.identity.address, 90_000n, signet.network);
  const psbt = tx.toPSBT();

  const signed = await acct.psbt(psbt);
  expect(signed).not.toEqual(psbt);

  // The signed PSBT must finalize — proof input 0 carries a valid sig.
  const reparsed = Transaction.fromPSBT(signed);
  reparsed.finalize();
  expect(reparsed.isFinal).toBe(true);
});

test("psbt: signs a chosen input under an explicit sighash", async () => {
  const acct = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  const payment = p2tr(
    xOnlyBytes(acct.identity.xOnlyPubKey),
    undefined,
    signet.network,
  );

  const tx = new Transaction();
  tx.addInput({
    txid: "00".repeat(32),
    index: 0,
    witnessUtxo: { script: payment.script, amount: 100_000n },
    tapInternalKey: payment.tapInternalKey,
  });
  tx.addOutputAddress(acct.identity.address, 90_000n, signet.network);

  const signed = await acct.psbt(tx.toPSBT(), {
    inputs: [{ index: 0, sighash: "single-anyonecanpay" }],
  });

  // Input 0 is pinned to SIGHASH_SINGLE | ANYONECANPAY (0x83) and signed.
  const reparsed = Transaction.fromPSBT(signed);
  expect(reparsed.getInput(0).sighashType).toBe(0x83);
  expect(reparsed.getInput(0).tapKeySig).toBeDefined();
});

test("psbt: rejects bytes that aren't a PSBT", async () => {
  const acct = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  await expect(acct.psbt(new Uint8Array([1, 2, 3]))).rejects.toBeInstanceOf(
    SignerError,
  );
});
