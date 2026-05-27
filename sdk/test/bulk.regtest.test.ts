/**
 * Live regtest capstone for `session.bulk(...)`: bundle two transfers
 * into one Bitcoin tx, submit, wait for the tuple of per-Inst results,
 * and confirm both recipients' balances reflect the credits.
 *
 * Today bulk is only covered by mock-transport unit tests (bulk.test.ts).
 * This file proves the path end-to-end — the indexer materializes both
 * ops at positions (0,0) and (0,1) in the same input, each per-Inst
 * decoder runs on the right slot, and the bundled `await` resolves to
 * the typed tuple.
 *
 * Funding: devFundingUtxos[7] (the slot claimed for this suite; see
 * the bump from 7 → 8 splits in `kontor regtest`).
 */
import { test, expect, inject } from "vitest";
import { Decimal, KontorSession, LocalAccount, Result, http } from "@kontor/sdk";
import { connectRegtest } from "@kontor/sdk/regtest";
import { Contract as Token } from "./__generated__/token.js";
import "./regtest-context.js";

test("session.bulk: two transfers in one tx land both balances", async () => {
  const regtest = connectRegtest(inject("regtest"));
  const { chain, devAccount: sender } = regtest;

  const recipientA = LocalAccount.fromPrivateKey({
    privateKey: "aa".repeat(32),
    chain,
  });
  const recipientB = LocalAccount.fromPrivateKey({
    privateKey: "bb".repeat(32),
    chain,
  });

  // devFundingUtxos[7] — the slot for the bulk regtest. One submit,
  // one UTXO; bundle of two ops in the same input.
  const funding = regtest.devFundingUtxos[7]!;

  const session = new KontorSession({
    chain,
    account: sender,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: () => Promise.resolve([funding]) }),
  });

  try {
    await session.ready();
    const token = session.bind(Token, "token@0.0");

    const beforeA = await token.balance(recipientA.holderRef);
    const beforeB = await token.balance(recipientB.holderRef);
    expect(beforeA == null || beforeA.toString() === "0").toBe(true);
    expect(beforeB == null || beforeB.toString() === "0").toBe(true);

    // Bundle two transfers in a single Bitcoin tx. Each per-Inst
    // decoder runs on its own positional slot ((0,0) and (0,1)); the
    // returned tuple types reflect the inputs in order.
    const [resA, resB] = await session.bulk(
      token.transfer(recipientA.holderRef, Decimal.from("1")),
      token.transfer(recipientB.holderRef, Decimal.from("2")),
    );

    expect(Result.unwrap(resA).amt.toString()).toBe("1");
    expect(Result.unwrap(resB).amt.toString()).toBe("2");

    // Per-op outcomes apply atomically (one block) — both balances
    // should be visible immediately after the bundle resolves.
    const afterA = await token.balance(recipientA.holderRef);
    const afterB = await token.balance(recipientB.holderRef);
    expect(afterA?.toString()).toBe("1");
    expect(afterB?.toString()).toBe("2");
  } finally {
    session.close();
  }
});
