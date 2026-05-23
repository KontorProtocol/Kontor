/**
 * Live regtest test of `Offer.revoke()` — the seller's escape hatch.
 *
 * The seller builds an offer (composes the attach, pre-signs the
 * detach), then changes their mind and revokes it. `revoke()` broadcasts
 * `[attachCommit, attachReveal, detachTx]`: the attach moves the asset
 * into the escrow, the detach — carrying no OP_RETURN recipient — hands
 * it straight back to the seller. The seller's token balance therefore
 * round-trips and ends exactly where it started; a broken detach would
 * strand the asset in the escrow, leaving the balance short.
 *
 * The seller is the dev account (it holds the issued tokens and the
 * Bitcoin funding). Funding: the offer's attach-compose takes
 * `devFundingUtxos[4]`, the revoke's fee input takes `[5]` — distinct
 * from the transfer (`[0]`), attach (`[1]`) and offer (`[2]`,`[3]`)
 * suites.
 */
import { test, expect, inject } from "vitest";
import { Decimal, KontorSession, LocalAccount, http } from "@kontor/sdk";
import { regtestChain } from "@kontor/sdk/regtest";
import { Contract } from "./__generated__/token.js";
import "./regtest-context.js";

/** How many whole tokens `b` is below `a`. */
function deficit(a: Decimal, b: Decimal): number {
  return Number(a.toString()) - Number(b.toString());
}

test("offer/revoke: the seller cancels an offer and the asset returns", async () => {
  const rt = inject("regtest");
  const chain = regtestChain({ apiUrl: rt.apiUrl, bitcoinRpc: rt.bitcoinRpc });

  const account = LocalAccount.fromPrivateKey({
    privateKey: rt.devPrivateKey,
    chain,
  });
  const offerFunding = {
    ...rt.devFundingUtxos[4]!,
    value: BigInt(rt.devFundingUtxos[4]!.value),
  };
  const revokeFunding = {
    ...rt.devFundingUtxos[5]!,
    value: BigInt(rt.devFundingUtxos[5]!.value),
  };

  const session = new KontorSession({
    chain,
    account,
    // The `utxos` hook funds offer()'s attach compose.
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: () => Promise.resolve([offerFunding]) }),
  });

  try {
    await session.ready();
    const token = session.bind(Contract, "token@0.0");

    const before = await token.balance(account.holderRef);
    expect(before).not.toBeNull();

    // Seller builds an offer, then revokes it before any buyer accepts.
    const offer = await token.attachment(Decimal.from("2")).offer({
      price: 600n,
    });
    await offer.revoke({ funding: revokeFunding });

    // revoke() broadcasts attach + detach: the attach moves 2 tokens into
    // the escrow and the detach (no OP_RETURN recipient) returns them to
    // the seller. Both ops burn a sliver of gas, so the balance ends a
    // hair below `before` — never 2 whole tokens short, which is what a
    // broken detach (asset stranded in the escrow) would leave. Poll past
    // the early iterations (the txs may not have processed yet), then
    // stop once the balance has round-tripped to within gas of `before`.
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
