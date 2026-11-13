/**
 * Tier-1 unit tests for the sats-connect wallet adapter (Node, no browser).
 * Drives the adapter through a `LocalKey`-backed mock provider so signatures are
 * real: PSBTs go in, valid/finalizable PSBTs come out — exercising all the
 * marshaling (base64, signInputs, per-input PSBT sighash, the RPC
 * envelope) without a wallet extension or prompts.
 */
import { test, expect } from "vitest";
import { base64 } from "@scure/base";
import { Transaction, p2tr } from "@scure/btc-signer";

import { LocalKey } from "../src/local-key.js";
import { connect } from "../src/wallets/sats-connect.js";
import type { WalletRequest } from "../src/wallets/sats-connect.js";
import { SignerError } from "../src/errors.js";
import { regtestChain, signet } from "../src/chains.js";
import { mockWalletRequest } from "./mock-wallet.js";

const MNEMONIC = "test test test test test test test test test test test junk";

function xOnlyBytes(h: string): Uint8Array {
  return Uint8Array.from(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
}

/** A LocalKey + a request fn that records every call made to it. */
function fixture(opts?: Parameters<typeof mockWalletRequest>[1]) {
  const local = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: signet });
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
  const acct = await connect({ chain: signet, request });
  expect(acct.identity.address).toBe(local.identity.address);
  expect(acct.identity.xOnlyPubKey).toBe(local.identity.xOnlyPubKey);
  expect(acct.identity.holderRef.kind).toBe("x-only-pubkey");
});

test("connect: normalizes a 33-byte compressed pubkey to x-only", async () => {
  const { local, request } = fixture({ pubkeyForm: "compressed" });
  const acct = await connect({ chain: signet, request });
  expect(acct.identity.xOnlyPubKey).toBe(local.identity.xOnlyPubKey);
});

test("connect: rejects an address on the wrong network", async () => {
  // Wallet reports a regtest (bcrt1p) address while the session is signet (tb).
  const regtest = regtestChain({
    apiUrl: "http://localhost:1/api",
    bitcoinRpc: "http://localhost:2",
  });
  const local = LocalKey.fromMnemonic({ mnemonic: MNEMONIC, chain: regtest });
  await expect(
    connect({ chain: signet, request: mockWalletRequest(local) }),
  ).rejects.toBeInstanceOf(SignerError);
});

test("connect: rejects a wallet with no Taproot address", async () => {
  const request: WalletRequest = async (method) =>
    method === "getAccounts"
      ? {
          status: "success",
          result: [
            {
              address: "tb1qexamplepaymentaddrxxxxxxxxxxxxxxxxxxxx",
              publicKey: "ab".repeat(33),
              addressType: "p2wpkh",
              purpose: "payment",
            },
          ],
        }
      : { status: "error", error: { message: "unexpected" } };
  await expect(connect({ chain: signet, request })).rejects.toThrow(
    /no Taproot/,
  );
});

test("signPsbt: produces a valid, finalizable signed PSBT", async () => {
  const { local, request } = fixture();
  const acct = await connect({ chain: signet, request });
  const psbt = taprootPsbt(local.identity.xOnlyPubKey, local.identity.address);

  const signed = await acct.psbt(psbt, { inputs: [{ index: 0 }] });

  const reparsed = Transaction.fromPSBT(signed);
  reparsed.finalize();
  expect(reparsed.isFinal).toBe(true);
});

test.each([
  ["all-anyonecanpay", 0x81],
  ["single-anyonecanpay", 0x83],
] as const)(
  "signPsbt: pins %s on the selected PSBT input",
  async (kind, flag) => {
    const { local, request, calls } = fixture();
    const acct = await connect({ chain: signet, request });
    const psbt = taprootPsbt(
      local.identity.xOnlyPubKey,
      local.identity.address,
    );

    const signed = await acct.psbt(psbt, {
      inputs: [{ index: 0, sighash: kind }],
    });

    const signPsbtCall = calls.find((c) => c.method === "signPsbt")!;
    const params = signPsbtCall.params as {
      psbt: string;
      allowedSignHash?: number;
      signInputs: Record<string, number[]>;
    };
    expect(params.allowedSignHash).toBeUndefined();
    // signInputs is keyed by the account address.
    expect(params.signInputs[local.identity.address]).toEqual([0]);

    expect(
      Transaction.fromPSBT(base64.decode(params.psbt)).getInput(0).sighashType,
    ).toBe(flag);

    expect(Transaction.fromPSBT(signed).getInput(0).sighashType).toBe(flag);
  },
);

test("signPsbt: default sighash omits allowedSignHash", async () => {
  const { local, request, calls } = fixture();
  const acct = await connect({ chain: signet, request });
  await acct.psbt(
    taprootPsbt(local.identity.xOnlyPubKey, local.identity.address),
    {
      inputs: [{ index: 0 }],
    },
  );
  const call = calls.find((c) => c.method === "signPsbt")!;
  expect("allowedSignHash" in (call.params as object)).toBe(false);
});

test("signPsbt: signs mixed per-input sighashes in one request", async () => {
  const { local, request, calls } = fixture();
  const acct = await connect({ chain: signet, request });
  const tx = Transaction.fromPSBT(
    taprootPsbt(local.identity.xOnlyPubKey, local.identity.address),
  );
  const payment = p2tr(
    xOnlyBytes(local.identity.xOnlyPubKey),
    undefined,
    signet.network,
  );
  tx.addInput({
    txid: "11".repeat(32),
    index: 1,
    witnessUtxo: { script: payment.script, amount: 100_000n },
    tapInternalKey: payment.tapInternalKey,
  });
  const signed = await acct.psbt(tx.toPSBT(), {
    inputs: [{ index: 0 }, { index: 1, sighash: "all-anyonecanpay" }],
  });
  const result = Transaction.fromPSBT(signed);
  expect(result.getInput(0).tapKeySig).toBeDefined();
  expect(result.getInput(1).tapKeySig).toBeDefined();
  expect(result.getInput(1).sighashType).toBe(0x81);
  const call = calls.find((c) => c.method === "signPsbt")!;
  expect(
    (call.params as { signInputs: Record<string, number[]> }).signInputs[
      local.identity.address
    ],
  ).toEqual([0, 1]);
});

test("signPsbt: empty inputs no-ops without calling the wallet", async () => {
  const { local, request, calls } = fixture();
  const acct = await connect({ chain: signet, request });
  const psbt = taprootPsbt(local.identity.xOnlyPubKey, local.identity.address);

  const out = await acct.psbt(psbt, { inputs: [] });

  expect(out).toEqual(psbt);
  expect(calls.some((c) => c.method === "signPsbt")).toBe(false);
});

test("signPsbt: requires an explicit inputs spec", async () => {
  const { local, request } = fixture();
  const acct = await connect({ chain: signet, request });
  await expect(
    acct.psbt(taprootPsbt(local.identity.xOnlyPubKey, local.identity.address)),
  ).rejects.toThrow(/explicit `inputs`/);
});

test("signPsbt: surfaces a wallet rejection as SignerError", async () => {
  const { local } = fixture();
  // A request that connects fine but rejects the signPsbt.
  const base = mockWalletRequest(local);
  const request: WalletRequest = (method, params) =>
    method === "signPsbt"
      ? Promise.resolve({
          status: "error",
          error: { message: "user declined" },
        })
      : base(method, params);
  const acct = await connect({ chain: signet, request });
  await expect(
    acct.psbt(taprootPsbt(local.identity.xOnlyPubKey, local.identity.address), {
      inputs: [{ index: 0 }],
    }),
  ).rejects.toThrow(/user declined/);
});

test("signMessage: delegates to the wallet and returns its signature", async () => {
  const { request, calls } = fixture();
  const acct = await connect({ chain: signet, request });
  const sig = await acct.message("hello kontor");
  expect(typeof sig).toBe("string");
  const call = calls.find((c) => c.method === "signMessage")!;
  expect((call.params as { message: string }).message).toBe("hello kontor");
});
