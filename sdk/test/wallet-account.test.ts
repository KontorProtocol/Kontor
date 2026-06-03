/**
 * Tier-1 unit tests for `WalletAccount` (Node, no browser). Drives the
 * account through a `LocalAccount`-backed mock provider so signatures are
 * real: PSBTs go in, valid/finalizable PSBTs come out — exercising all the
 * marshaling (base64, signInputs, sighash→allowedSignHash, the RPC
 * envelope) without a wallet extension or prompts.
 */
import { test, expect } from "vitest";
import { base64 } from "@scure/base";
import { Transaction, p2tr } from "@scure/btc-signer";

import { LocalAccount } from "../src/account/local.js";
import { WalletAccount } from "../src/account/wallet.js";
import type { WalletRequest } from "../src/account/wallet.js";
import { SignerError } from "../src/errors.js";
import { regtestChain, signet } from "../src/chains.js";
import { mockWalletRequest } from "./mock-wallet.js";

const MNEMONIC =
  "test test test test test test test test test test test junk";

function xOnlyBytes(h: string): Uint8Array {
  return Uint8Array.from(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
}

/** A LocalAccount + a request fn that records every call made to it. */
function fixture(opts?: Parameters<typeof mockWalletRequest>[1]) {
  const local = LocalAccount.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
  const inner = mockWalletRequest(local, opts);
  const calls: { method: string; params: unknown }[] = [];
  const request: WalletRequest = (method, params) => {
    calls.push({ method, params });
    return inner(method, params);
  };
  return { local, request, calls };
}

/** A taproot key-path PSBT spending one input back to `address`. */
function taprootPsbt(xOnlyHex: string, address: string): Uint8Array {
  const payment = p2tr(xOnlyBytes(xOnlyHex), undefined, signet.network);
  const tx = new Transaction();
  tx.addInput({
    txid: "00".repeat(32),
    index: 0,
    witnessUtxo: { script: payment.script, amount: 100_000n },
    tapInternalKey: payment.tapInternalKey,
  });
  tx.addOutputAddress(address, 90_000n, signet.network);
  return tx.toPSBT();
}

test("connect: binds to the wallet's P2TR address + x-only key", async () => {
  const { local, request } = fixture();
  const acct = await WalletAccount.connect({ chain: signet, request });
  expect(acct.address).toBe(local.address);
  expect(acct.xOnlyPubKey).toBe(local.xOnlyPubKey);
  expect(acct.holderRef.kind).toBe("x-only-pubkey");
});

test("connect: normalizes a 33-byte compressed pubkey to x-only", async () => {
  const { local, request } = fixture({ pubkeyForm: "compressed" });
  const acct = await WalletAccount.connect({ chain: signet, request });
  expect(acct.xOnlyPubKey).toBe(local.xOnlyPubKey);
});

test("connect: rejects an address on the wrong network", async () => {
  // Wallet reports a regtest (bcrt1p) address while the session is signet (tb).
  const regtest = regtestChain({
    apiUrl: "http://localhost:1/api",
    bitcoinRpc: "http://localhost:2",
  });
  const local = LocalAccount.fromMnemonic({ mnemonic: MNEMONIC, chain: regtest });
  await expect(
    WalletAccount.connect({ chain: signet, request: mockWalletRequest(local) }),
  ).rejects.toBeInstanceOf(SignerError);
});

test("connect: rejects a wallet with no Taproot address", async () => {
  const request: WalletRequest = async (method) =>
    method === "getAccounts"
      ? {
          status: "success",
          result: [
            { address: "tb1qexamplepaymentaddrxxxxxxxxxxxxxxxxxxxx", publicKey: "ab".repeat(33), addressType: "p2wpkh", purpose: "payment" },
          ],
        }
      : { status: "error", error: { message: "unexpected" } };
  await expect(
    WalletAccount.connect({ chain: signet, request }),
  ).rejects.toThrow(/no Taproot/);
});

test("signPsbt: produces a valid, finalizable signed PSBT", async () => {
  const { local, request } = fixture();
  const acct = await WalletAccount.connect({ chain: signet, request });
  const psbt = taprootPsbt(local.xOnlyPubKey, local.address);

  const signed = await acct.signPsbt(psbt, { inputs: [{ index: 0 }] });

  const reparsed = Transaction.fromPSBT(signed);
  reparsed.finalize();
  expect(reparsed.isFinal).toBe(true);
});

test("signPsbt: maps single-anyonecanpay to allowedSignHash 131", async () => {
  const { local, request, calls } = fixture();
  const acct = await WalletAccount.connect({ chain: signet, request });
  const psbt = taprootPsbt(local.xOnlyPubKey, local.address);

  const signed = await acct.signPsbt(psbt, {
    inputs: [{ index: 0, sighash: "single-anyonecanpay" }],
  });

  // The request carried allowedSignHash 131 (= SIGHASH_SINGLE|ANYONECANPAY).
  const signPsbtCall = calls.find((c) => c.method === "signPsbt")!;
  const params = signPsbtCall.params as {
    psbt: string;
    allowedSignHash?: number;
    signInputs: Record<string, number[]>;
  };
  expect(params.allowedSignHash).toBe(0x83);
  // signInputs is keyed by the account address.
  expect(params.signInputs[local.address]).toEqual([0]);

  // The sighash is ALSO pinned on the PSBT we hand the wallet (not only via
  // allowedSignHash), so wallets that read PSBT_IN_SIGHASH_TYPE sign 0x83.
  expect(Transaction.fromPSBT(base64.decode(params.psbt)).getInput(0).sighashType).toBe(0x83);

  // And the returned signed input is pinned to 0x83.
  expect(Transaction.fromPSBT(signed).getInput(0).sighashType).toBe(0x83);
});

test("signPsbt: default sighash omits allowedSignHash", async () => {
  const { local, request, calls } = fixture();
  const acct = await WalletAccount.connect({ chain: signet, request });
  await acct.signPsbt(taprootPsbt(local.xOnlyPubKey, local.address), {
    inputs: [{ index: 0 }],
  });
  const call = calls.find((c) => c.method === "signPsbt")!;
  expect("allowedSignHash" in (call.params as object)).toBe(false);
});

test("signPsbt: rejects a mixed-sighash request", async () => {
  const { local, request } = fixture();
  const acct = await WalletAccount.connect({ chain: signet, request });
  await expect(
    acct.signPsbt(taprootPsbt(local.xOnlyPubKey, local.address), {
      inputs: [
        { index: 0 },
        { index: 1, sighash: "single-anyonecanpay" },
      ],
    }),
  ).rejects.toThrow(/can't mix sighash/);
});

test("signPsbt: requires an explicit inputs spec", async () => {
  const { local, request } = fixture();
  const acct = await WalletAccount.connect({ chain: signet, request });
  await expect(
    acct.signPsbt(taprootPsbt(local.xOnlyPubKey, local.address)),
  ).rejects.toThrow(/explicit `inputs`/);
});

test("signPsbt: surfaces a wallet rejection as SignerError", async () => {
  const { local } = fixture();
  // A request that connects fine but rejects the signPsbt.
  const base = mockWalletRequest(local);
  const request: WalletRequest = (method, params) =>
    method === "signPsbt"
      ? Promise.resolve({ status: "error", error: { message: "user declined" } })
      : base(method, params);
  const acct = await WalletAccount.connect({ chain: signet, request });
  await expect(
    acct.signPsbt(taprootPsbt(local.xOnlyPubKey, local.address), {
      inputs: [{ index: 0 }],
    }),
  ).rejects.toThrow(/user declined/);
});

test("signMessage: delegates to the wallet and returns its signature", async () => {
  const { request, calls } = fixture();
  const acct = await WalletAccount.connect({ chain: signet, request });
  const sig = await acct.signMessage("hello kontor");
  expect(typeof sig).toBe("string");
  const call = calls.find((c) => c.method === "signMessage")!;
  expect((call.params as { message: string }).message).toBe("hello kontor");
});
