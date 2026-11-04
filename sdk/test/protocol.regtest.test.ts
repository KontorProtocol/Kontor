import { expect, inject, test } from "vitest";
import { Decimal, KontorSession, inMemoryFunding } from "@kontor/sdk";
import { connectRegtest } from "@kontor/sdk/regtest";
import { Contract as Token } from "./__generated__/token.js";
import "./regtest-context.js";

test("protocol discovery, view and contextual simulation use the running node", async () => {
  const regtest = connectRegtest(inject("regtest"));
  const { signing, fundingUtxo } = regtest.accounts[8]!;
  const recipient = regtest.accounts[1]!.signing.identity.holderRef;
  const session = new KontorSession({
    chain: regtest.chain,
    signing,
    funding: inMemoryFunding([fundingUtxo]),
  });
  try {
    await session.ready();
    const snapshot = await session.getProtocol();
    expect(snapshot.canonical?.protocol.installed).toBe(true);
    expect(snapshot.canonical?.protocol.protocol_number).toBe("1");
    const token = session.bind(Token, "token@0.0");
    const before = await token.balance(recipient);
    const preview = await token
      .transfer(recipient, Decimal.from("1"))
      .simulateWithContext();
    expect(preview.result.status).toBe("Ok");
    expect(preview.result.value?.amt.toString()).toBe("1");
    expect(preview.context.protocol_id).toBe(
      snapshot.canonical?.protocol.protocol_id,
    );
    expect((await token.balance(recipient))?.toString()).toBe(
      before?.toString(),
    );
  } finally {
    session.close();
  }
});
