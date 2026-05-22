/**
 * Unit tests for `LocalAccount` — the in-process signer. Key-derivation
 * tests are known-answer (a fixed mnemonic → a fixed P2TR address);
 * `signPsbt` is exercised against a real taproot key-path PSBT built
 * with `@scure/btc-signer`.
 */
import { test, expect } from "vitest";
import { Transaction, p2tr } from "@scure/btc-signer";
import { LocalAccount } from "../src/account/local.js";
import { SignerError } from "../src/errors.js";
import { signet } from "../src/chains.js";
import { regtestChain } from "../src/regtest.js";

// BIP-39 test vector mnemonic (the "test … junk" phrase). Deriving it at
// BIP-86 `m/86'/1'/0'/0/0` on a testnet chain is a fixed, known answer.
const MNEMONIC =
  "test test test test test test test test test test test junk";
const SIGNET_ADDRESS =
  "tb1pfewlxm8meyyvgjydfu7v8j4ej64symj6ut8sf66h9germp94qgzsgnnjhk";
const SIGNET_XONLY =
  "8c7fc6552af4384a13791e63bac79ff2bcfeedf143a88d6dc4b6080a8829cdc1";

function xOnlyBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/.{2}/g)!.map((h) => parseInt(h, 16)));
}

test("fromMnemonic: known mnemonic derives the expected P2TR account", () => {
  const acct = LocalAccount.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  expect(acct.address).toBe(SIGNET_ADDRESS);
  expect(acct.xOnlyPubKey).toBe(SIGNET_XONLY);
  expect(acct.holderRef.kind).toBe("x-only-pubkey");
});

test("fromPrivateKey: round-trips the key fromMnemonic derived", () => {
  const fromSeed = LocalAccount.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  const fromKey = LocalAccount.fromPrivateKey({
    privateKey: fromSeed.privateKey,
    chain: signet,
  });
  expect(fromKey.address).toBe(SIGNET_ADDRESS);
  expect(fromKey.xOnlyPubKey).toBe(SIGNET_XONLY);
});

test("fromPrivateKey: hex string and Uint8Array forms are equivalent", () => {
  const bytes = LocalAccount.fromMnemonic({
    mnemonic: MNEMONIC,
    chain: signet,
  }).privateKey;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  const a = LocalAccount.fromPrivateKey({ privateKey: bytes, chain: signet });
  const b = LocalAccount.fromPrivateKey({ privateKey: hex, chain: signet });
  const c = LocalAccount.fromPrivateKey({ privateKey: `0x${hex}`, chain: signet });
  expect(a.address).toBe(b.address);
  expect(b.address).toBe(c.address);
});

test("fromPrivateKey: rejects a key that isn't 32 bytes", () => {
  expect(() =>
    LocalAccount.fromPrivateKey({ privateKey: "aabbcc", chain: signet }),
  ).toThrow(SignerError);
});

test("fromMnemonic: rejects an invalid BIP-39 mnemonic", () => {
  expect(() =>
    LocalAccount.fromMnemonic({ mnemonic: "not a real mnemonic", chain: signet }),
  ).toThrow(/invalid BIP-39 mnemonic/);
});

test("derivation: coin type follows the chain (regtest → bcrt address)", () => {
  const regtest = regtestChain({
    apiUrl: "http://localhost:1/api",
    bitcoinRpc: "http://localhost:2",
  });
  const acct = LocalAccount.fromMnemonic({ mnemonic: MNEMONIC, chain: regtest });
  expect(acct.address.startsWith("bcrt1p")).toBe(true);
  // Different coin type (1 vs 1 but distinct purpose path is identical for
  // testnets) — regtest and signet share coin type 1, so the key matches;
  // only the address HRP differs.
  expect(acct.xOnlyPubKey).toBe(SIGNET_XONLY);
});

test("signMessage: rejects — BIP-322 not yet implemented", async () => {
  const acct = LocalAccount.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  await expect(acct.signMessage("hello")).rejects.toBeInstanceOf(SignerError);
});

test("signPsbt: signs a taproot key-path input", async () => {
  const acct = LocalAccount.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  const payment = p2tr(xOnlyBytes(acct.xOnlyPubKey), undefined, signet.network);

  const tx = new Transaction();
  tx.addInput({
    txid: "00".repeat(32),
    index: 0,
    witnessUtxo: { script: payment.script, amount: 100_000n },
    tapInternalKey: payment.tapInternalKey,
  });
  tx.addOutputAddress(acct.address, 90_000n, signet.network);
  const psbt = tx.toPSBT();

  const signed = await acct.signPsbt(psbt);
  expect(signed).not.toEqual(psbt);

  // The signed PSBT must finalize — proof input 0 carries a valid sig.
  const reparsed = Transaction.fromPSBT(signed);
  reparsed.finalize();
  expect(reparsed.isFinal).toBe(true);
});

test("signPsbt: rejects bytes that aren't a PSBT", async () => {
  const acct = LocalAccount.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  await expect(
    acct.signPsbt(new Uint8Array([1, 2, 3])),
  ).rejects.toBeInstanceOf(SignerError);
});
