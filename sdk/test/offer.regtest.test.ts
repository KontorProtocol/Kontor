/**
 * Live regtest test of the marketplace swap — the whole Phase D path
 * against a real `kontor regtest` chain: `attachment.offer()` builds a
 * pre-signed offer blob; `session.openOffer(blob).accept()` assembles
 * the buyer's swap transaction (escrow + funding → price + OP_RETURN +
 * change) and broadcasts `[attachCommit, attachReveal, swapTx]`.
 *
 * Seller and buyer are both the dev account (it holds the issued
 * tokens) — a self-funded swap. The asset still detaches to a *distinct*
 * `recipient`, so the round-trip is verifiable: that pubkey's balance
 * goes from nothing to the offered amount.
 *
 * Funding: offer's attach-compose takes `devFundingUtxos[2]`, the
 * buyer's `accept()` takes `[3]` — distinct from the transfer (`[0]`)
 * and attach (`[1]`) suites.
 */
import { test, expect, inject } from "vitest";
import { Decimal, KontorSession, LocalAccount, http } from "@kontor/sdk";
import { regtestChain } from "@kontor/sdk/regtest";
import { Contract } from "./__generated__/token.js";
import "./regtest-context.js";

test("offer/accept: a marketplace swap detaches the asset to the recipient", async () => {
  const rt = inject("regtest");
  const chain = regtestChain({ apiUrl: rt.apiUrl, bitcoinRpc: rt.bitcoinRpc });

  const account = LocalAccount.fromPrivateKey({
    privateKey: rt.devPrivateKey,
    chain,
  });
  // A fresh party the asset is sold to — never funded, balance starts empty.
  const recipient = LocalAccount.fromPrivateKey({
    privateKey: "66".repeat(32),
    chain,
  });
  const sellerFunding = {
    ...rt.devFundingUtxos[2]!,
    value: BigInt(rt.devFundingUtxos[2]!.value),
  };
  const buyerFunding = {
    ...rt.devFundingUtxos[3]!,
    value: BigInt(rt.devFundingUtxos[3]!.value),
  };

  const session = new KontorSession({
    chain,
    account,
    // The `utxos` hook funds offer()'s attach compose.
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: () => Promise.resolve([sellerFunding]) }),
  });

  try {
    await session.ready();
    const token = session.bind(Contract, "token@0.0");

    const before = await token.balance(recipient.holderRef);
    expect(before == null || before.toString() === "0").toBe(true);

    // Seller — build the offer: compose the attach, pre-sign the detach.
    const offer = await token.attachment(Decimal.from("2")).offer({
      price: 600n,
    });
    const blob = offer.serialize();

    // Buyer — open the blob and inspect it.
    const incoming = session.openOffer(blob);
    const report = await incoming.inspect();
    expect(report.valid).toBe(true);
    expect(report.price).toBe(600n);

    // Buyer — accept: fund the swap, detach the asset to `recipient`.
    await incoming.accept({
      funding: buyerFunding,
      recipient: recipient.xOnlyPubKey,
    });

    // The devnet auto-mines; poll until the detach lands with the recipient.
    let after: Decimal | null = null;
    for (let i = 0; i < 90 && (after == null || after.toString() === "0"); i++) {
      await new Promise((r) => setTimeout(r, 1000));
      after = await token.balance(recipient.holderRef);
    }
    expect(after?.toString()).toBe("2");
  } finally {
    session.close();
  }
});
