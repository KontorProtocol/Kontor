/**
 * Live regtest capstone — the depth-first slice end to end against a
 * real `kontor regtest` chain: bind the codegen'd token `Contract`,
 * `transfer(...)` (submit → poll → wait), and confirm the recipient's
 * `balance()` view reflects the credit. The test fires *two* transfers
 * back-to-back from the same sender to exercise the HTTP transport's
 * change-tracking: submit 2 must chain through submit 1's change
 * outputs (no fresh bootstrap UTXO available), proving `trackedFunding`
 * drives funding after the bootstrap is consumed.
 *
 * The devnet is started once by `vitest.regtest.globalSetup.ts`; this
 * file is a pure HTTP client, so it runs in Node and the browser
 * alike. Run via `npm run test:regtest` / `npm run test:regtest:browser`.
 */
import { test, expect, inject } from "vitest";
import { Decimal, KontorSession, LocalAccount, Result, http } from "@kontor/sdk";
import { connectRegtest } from "@kontor/sdk/regtest";
import { Contract } from "./__generated__/token.js";
import "./regtest-context.js";

test("transfer(): two chained submits land both credits via change-tracking", async () => {
  const regtest = connectRegtest(inject("regtest"));
  const { chain } = regtest;

  // Identity slot 0 — pre-issued tokens + 1M-sat funding UTXO. The second
  // submit *must* chain through the first's change to land, since this
  // identity has only its single bootstrap UTXO.
  const { account, fundingUtxo } = regtest.accounts[0]!;
  // A fresh, never-funded recipient — its balance starts empty.
  const recipient = LocalAccount.fromPrivateKey({
    privateKey: "22".repeat(32),
    chain,
  });

  const session = new KontorSession({
    chain,
    account,
    // Array form: bootstrap-once, then HTTP transport's trackedFunding
    // takes over for subsequent submits.
    transport: ({ chain, account }) => http({ chain, account, utxos: [fundingUtxo] }),
  });

  try {
    await session.ready();
    const token = session.bind(Contract, "token@0.0");

    const before = await token.balance(recipient.holderRef);
    expect(before == null || before.toString() === "0").toBe(true);

    // Dry-run: `simulate` predicts the outcome, broadcasts nothing.
    const sim = await token
      .transfer(recipient.holderRef, Decimal.from("1"))
      .simulate();
    expect(sim.status).toBe("Ok");
    expect(sim.value?.kind).toBe("ok");

    // Submit 1 — spends the bootstrap UTXO; change becomes trackedFunding.
    const first = await token.transfer(recipient.holderRef, Decimal.from("1"));
    expect(Result.unwrap(first).amt.toString()).toBe("1");
    expect((await token.balance(recipient.holderRef))?.toString()).toBe("1");

    // Submit 2 — bootstrap is consumed; funding must come from submit 1's
    // change UTXOs. If change-tracking is broken, this errors with no
    // funding available.
    const second = await token.transfer(recipient.holderRef, Decimal.from("1"));
    expect(Result.unwrap(second).amt.toString()).toBe("1");
    expect((await token.balance(recipient.holderRef))?.toString()).toBe("2");
  } finally {
    session.close();
  }
});
