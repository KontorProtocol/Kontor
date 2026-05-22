/**
 * Live regtest test of the attach/detach gift round-trip — the whole
 * Phase B+C path end to end against a real `kontor regtest` chain:
 * codegen's `attachment(...)` builder → `Attachment.to(recipient)` →
 * chained compose → sign commit + both reveals → broadcast the three-tx
 * package → poll both outcomes.
 *
 * Uses funding UTXO `[1]` (the `transfer` suite takes `[0]`) so the two
 * regtest files never collide on a shared dev-account output.
 */
import { test, expect, inject } from "vitest";
import { Attachment, Decimal, KontorSession, LocalAccount, http } from "@kontor/sdk";
import { regtestChain } from "@kontor/sdk/regtest";
import { Contract } from "./__generated__/token.js";
import "./regtest-context.js";

test("attachment().to(): attaches then detaches; recipient balance reflects it", async () => {
  const rt = inject("regtest");
  const chain = regtestChain({ apiUrl: rt.apiUrl, bitcoinRpc: rt.bitcoinRpc });

  const account = LocalAccount.fromPrivateKey({
    privateKey: rt.devPrivateKey,
    chain,
  });
  // A fresh, never-funded recipient — its balance starts empty.
  const recipient = LocalAccount.fromPrivateKey({
    privateKey: "55".repeat(32),
    chain,
  });
  const funding = {
    ...rt.devFundingUtxos[1]!,
    value: BigInt(rt.devFundingUtxos[1]!.value),
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

    // codegen emits `attachment(amt)` for the attach/detach pair; it
    // returns an `Attachment`, never a bare `Inst`.
    const attachment = token.attachment(Decimal.from("2"));
    expect(attachment).toBeInstanceOf(Attachment);

    // `.to(recipient)` broadcasts commit + attach reveal + detach
    // reveal; `wait()` resolves both ops once they land.
    const submitted = await attachment.to(recipient);
    const { attach, detach } = await submitted.wait();

    expect(attach.status).toBe("Ok");
    expect(attach.value?.kind).toBe("ok");
    expect(detach.status).toBe("Ok");
    expect(detach.value?.kind).toBe("ok");
    if (detach.value?.kind !== "ok") throw new Error("detach returned err");
    expect(detach.value.value.amt.toString()).toBe("2");

    // The detached asset landed with the recipient.
    const after = await token.balance(recipient.holderRef);
    expect(after?.toString()).toBe("2");
  } finally {
    session.close();
  }
});
