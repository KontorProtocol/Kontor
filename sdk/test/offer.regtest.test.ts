/**
 * Live regtest test of the marketplace swap under the Sponsor +
 * ctx.payer() model — `attachment.offer()` builds a pre-signed offer
 * blob; `session.openOffer(blob).accept()` composes the buyer's
 * Sponsor commit + the swap reveal, signs both, and broadcasts
 * `[attachCommit, attachReveal, buyerCommit, swapReveal]`.
 *
 * Seller and buyer are distinct accounts — required by the new model,
 * which detaches the asset to whoever signed the buyer's Sponsor
 * input (= `ctx.payer()`). Both come from the pre-created identity
 * pool: each carries 1M sats + pre-issued native tokens, so the
 * buyer can pay gas for the Sponsor + sponsored detach ops without
 * any seed transfer.
 *
 * Funding: identities[3] (seller), identities[4] (buyer).
 */
import { test, expect, inject } from "vitest";
import { Decimal, KontorSession, http } from "@kontor/sdk";
import { connectRegtest } from "@kontor/sdk/regtest";
import { Contract } from "./__generated__/token.js";
import "./regtest-context.js";

test("offer/accept: a marketplace swap detaches the asset to the buyer", async () => {
  const regtest = connectRegtest(inject("regtest"));
  const { chain } = regtest;
  const { account: seller, fundingUtxo: sellerFunding } = regtest.accounts[3]!;
  const { account: buyer, fundingUtxo: buyerFunding } = regtest.accounts[4]!;

  const sellerSession = new KontorSession({
    chain,
    account: seller,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: [sellerFunding] }),
  });
  const buyerSession = new KontorSession({
    chain,
    account: buyer,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: [buyerFunding] }),
  });

  try {
    await sellerSession.ready();
    await buyerSession.ready();
    const sellerToken = sellerSession.bind(Contract, "token@0.0");
    const buyerToken = buyerSession.bind(Contract, "token@0.0");

    // Buyer starts with their pre-issued token balance (no seed needed).
    const initial = await buyerToken.balance(buyer.holderRef);
    expect(initial).not.toBeNull();

    // Seller — build the offer: compose the attach, pre-sign the detach.
    const offer = await sellerToken
      .attachment(Decimal.from("2"))
      .offer({ price: 600n });
    const blob = offer.serialize();

    // Buyer — open the blob and inspect it.
    const incoming = buyerSession.openOffer(blob);
    const report = await incoming.inspect();
    expect(report.valid).toBe(true);
    expect(report.price).toBe(600n);

    // Buyer — accept: fund the Sponsor commit + complete the swap.
    // Funding is sourced through the buyer session's transport.utxos()
    // (no explicit param) — same path as any other call.
    await incoming.accept();

    // The devnet auto-mines; poll until the buyer's balance grows
    // past the initial baseline by at least 2 tokens (the offer
    // detached 2). Exact equality would be brittle: the buyer also
    // burns a sliver of native token paying gas, so post-swap balance
    // ≈ initial + 2 − ε.
    const baseline = initial ?? Decimal.from("0");
    const threshold = baseline.add(Decimal.from("1"));
    let after: Decimal | null = null;
    for (
      let i = 0;
      i < 90 && (after == null || after.cmp(threshold) !== "greater");
      i++
    ) {
      await new Promise((r) => setTimeout(r, 1000));
      after = await buyerToken.balance(buyer.holderRef);
    }
    expect(after?.cmp(threshold)).toBe("greater");
  } finally {
    sellerSession.close();
    buyerSession.close();
  }
});
