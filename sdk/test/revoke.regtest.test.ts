/**
 * Live regtest test of `Offer.revoke()` — the seller's escape hatch.
 *
 * The seller builds an offer (composes the attach, pre-signs the
 * detach), then changes their mind and revokes it. `revoke()` broadcasts
 * `[attachCommit, attachReveal, detachTx]`: the attach moves the asset
 * into the escrow, the detach — built without a `Sponsor` input, so
 * the reactor's payer defaults to the signer of the detach input (the
 * seller) — hands it straight back. The seller's token balance
 * therefore round-trips and ends exactly where it started; a broken
 * detach would strand the asset in the escrow, leaving the balance
 * short.
 *
 * Funding: identities[5]. The offer broadcast at creation consumes
 * the bootstrap UTXO and leaves the attach reveal's change as the
 * transport's tracked funding; the subsequent `revoke()` reads the
 * same change UTXO via `transport.utxos()` to pay the detach tx's
 * fee — no manual UTXO splitting needed.
 */
import { test, expect, inject } from "vitest";
import { Decimal, KontorSession, http } from "@kontor/sdk";
import { connectRegtest } from "@kontor/sdk/regtest";
import { Contract } from "./__generated__/token.js";
import "./regtest-context.js";

/** How many whole tokens `b` is below `a`. */
function deficit(a: Decimal, b: Decimal): number {
  return Number(a.toString()) - Number(b.toString());
}

test("offer/revoke: the seller cancels an offer and the asset returns", async () => {
  const regtest = connectRegtest(inject("regtest"));
  const { chain } = regtest;
  const { account, fundingUtxo } = regtest.accounts[5]!;

  const session = new KontorSession({
    chain,
    account,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: [fundingUtxo] }),
  });

  try {
    await session.ready();
    const token = session.bind(Contract, "token@0.0");

    const before = await token.balance(account.holderRef);
    expect(before).not.toBeNull();

    // Seller builds an offer (the attach broadcasts at creation, moving
    // 2 tokens into the escrow), then revokes it before any buyer
    // accepts. The detach (no Sponsor → payer defaults to the seller,
    // ctx.payer() inside detach resolves to seller's holder) returns
    // them. Both ops burn a sliver of gas, so the balance ends a hair
    // below `before` — never 2 whole tokens short, which is what a
    // broken detach (asset stranded in the escrow) would leave. Poll
    // past the early iterations (the txs may not have processed yet),
    // then stop once the balance has round-tripped to within gas of
    // `before`.
    const offer = await token.attachment(Decimal.from("2")).offer({
      price: 600n,
    });
    await offer.revoke();
    let after: Decimal | null = null;
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      after = await token.balance(account.holderRef);
      if (i >= 15 && after != null && deficit(before!, after) < 1) break;
    }
    expect(after).not.toBeNull();
    const lost = deficit(before!, after!);
    expect(lost).toBeGreaterThan(0); // gas was paid — the ops really ran
    expect(lost).toBeLessThan(1); // the 2 tokens returned, not stranded
  } finally {
    session.close();
  }
});
