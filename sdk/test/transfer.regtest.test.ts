/**
 * Live regtest capstone — the depth-first slice end to end against a
 * real `kontor regtest` chain: bind the codegen'd token `Contract`,
 * `transfer(...)` (submit → poll → wait), and confirm the recipient's
 * `balance()` view reflects the credit.
 *
 * The devnet is started once by `vitest.regtest.globalSetup.ts`; this
 * file is a pure HTTP client, so it runs in Node and the browser
 * alike. Run via `npm run test:regtest` / `npm run test:regtest:browser`.
 */
import { test, expect, inject } from "vitest";
import { Decimal, KontorSession, LocalAccount, http } from "@kontor/sdk";
import { regtestChain } from "@kontor/sdk/regtest";
import { Contract } from "./__generated__/token.js";

interface RegtestInfo {
  apiUrl: string;
  bitcoinRpc: string;
  devPrivateKey: string;
  devFundingUtxo: {
    txid: string;
    vout: number;
    value: string;
    scriptPubKey: string;
  };
}

declare module "vitest" {
  interface ProvidedContext {
    regtest: RegtestInfo;
  }
}

test("transfer(): submit/wait moves tokens; balance() view reflects it", async () => {
  const rt = inject("regtest");
  const chain = regtestChain({ apiUrl: rt.apiUrl, bitcoinRpc: rt.bitcoinRpc });

  const account = LocalAccount.fromPrivateKey({
    privateKey: rt.devPrivateKey,
    chain,
  });
  // A fresh, never-funded recipient — its balance starts empty.
  const recipient = LocalAccount.fromPrivateKey({
    privateKey: "22".repeat(32),
    chain,
  });
  const funding = {
    ...rt.devFundingUtxo,
    value: BigInt(rt.devFundingUtxo.value),
  };

  const session = new KontorSession({
    chain,
    account,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: () => Promise.resolve([funding]) }),
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

    // `await` on the proc Inst fires submit → wait; throws on a non-Ok
    // op status, so reaching here means the transfer landed.
    const result = await token.transfer(recipient.holderRef, Decimal.from("1"));
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") throw new Error("transfer returned err");
    expect(result.value.amt.toString()).toBe("1");

    const after = await token.balance(recipient.holderRef);
    expect(after?.toString()).toBe("1");
  } finally {
    session.close();
  }
});
