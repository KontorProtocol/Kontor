/**
 * Live regtest test of the marketplace swap under the Sponsor +
 * ctx.payer() model — `attachment.offer()` builds a pre-signed offer
 * blob; `session.openOffer(blob).accept()` composes the buyer's
 * Sponsor commit + the swap reveal, signs both, and broadcasts
 * `[attachCommit, attachReveal, buyerCommit, swapReveal]`.
 *
 * Seller and buyer are distinct accounts — required by the new model,
 * which detaches the asset to whoever signed the buyer's Sponsor
 * input (= `ctx.payer()`). The seller starts with the issued tokens;
 * the test pre-funds the buyer with sats out of dev's wallet so they
 * have a UTXO for `accept()`'s Build commit.
 *
 * Funding: dev seeds the buyer from `devFundingUtxos[3]` (a separate
 * output from the seller's offer attach-compose at `[2]`, the transfer
 * suite at `[0]`, the attach suite at `[1]`).
 */
import { test, expect, inject } from "vitest";
import { Decimal, KontorSession, LocalAccount, http } from "@kontor/sdk";
import { connectRegtest } from "@kontor/sdk/regtest";
import { Contract } from "./__generated__/token.js";
import "./regtest-context.js";

test("offer/accept: a marketplace swap detaches the asset to the buyer", async () => {
  const regtest = connectRegtest(inject("regtest"));
  const { chain, devAccount: seller } = regtest;

  // Three distinct dev UTXOs: [2] funds the offer's attach compose;
  // [3] is spent to fund the buyer's bitcoin UTXO; [6] funds the
  // native-token seed transfer (revoke owns [4]/[5]). Three separate
  // UTXOs because all three Bitcoin txs sit in the mempool at once
  // and would otherwise RBF-conflict if they shared an input.
  const sellerFunding = regtest.devFundingUtxos[2]!;
  const seedFunding = regtest.devFundingUtxos[6]!;
  // Distinct buyer — the asset under the Sponsor + ctx.payer() model
  // detaches to whoever signs the swap reveal's Sponsor input, so
  // seller ≠ buyer is required for a verifiable round-trip. Fund out
  // of devFundingUtxos[3].
  const { account: buyer, fundingUtxo: buyerFunding } =
    await regtest.createAccount({
      sats: 50_000n,
      sourceUtxo: regtest.devFundingUtxos[3]!,
    });

  // Separate session for the native-token seed transfer, so it spends
  // `seedFunding` instead of the offer's `sellerFunding`.
  const seedSession = new KontorSession({
    chain,
    account: seller,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: () => Promise.resolve([seedFunding]) }),
  });
  const sellerSession = new KontorSession({
    chain,
    account: seller,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: () => Promise.resolve([sellerFunding]) }),
  });
  const buyerSession = new KontorSession({
    chain,
    account: buyer,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: () => Promise.resolve([buyerFunding]) }),
  });

  try {
    await sellerSession.ready();
    await seedSession.ready();
    await buyerSession.ready();
    const sellerToken = sellerSession.bind(Contract, "token@0.0");
    const seedToken = seedSession.bind(Contract, "token@0.0");
    const buyerToken = buyerSession.bind(Contract, "token@0.0");

    const initial = await buyerToken.balance(buyer.holderRef);
    expect(initial == null || initial.toString() === "0").toBe(true);

    // Seed the buyer with a tiny amount of the native token — they need a
    // balance to pay gas for the Sponsor + sponsored detach ops they
    // sign for in accept(). Without this, the runtime errors "Payer N
    // does not have enough token to cover gas limit".
    await seedToken.transfer(buyer.holderRef, Decimal.from("1"));
    const seeded = await buyerToken.balance(buyer.holderRef);
    expect(seeded?.toString()).toBe("1");

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
    await incoming.accept({ funding: buyerFunding });

    // The devnet auto-mines; poll until the buyer's balance grows
    // past the 1-token seed — the +2 from the detach lands once the
    // swap reveal is included. (Exact equality would be brittle: the
    // buyer also burns a sliver of native token paying gas for the
    // sponsored detach, so post-swap balance ≈ 1 + 2 − ε.)
    let after: Decimal | null = null;
    const threshold = Decimal.from("2");
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
    seedSession.close();
    buyerSession.close();
  }
});
