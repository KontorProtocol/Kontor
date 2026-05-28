/**
 * SDK capstone — one integration test walking the full SDK surface
 * against a live `kontor regtest` devnet in a single bringup. Acts
 * both as the end-to-end smoke test and as a showcase of every
 * top-level SDK feature.
 *
 * Phases (each on its own pre-created identity, so a phase's balance
 * assertions aren't muddied by another phase's transfers):
 *
 *   1. `publish` — deploy a contract, bind it, call its view.
 *   2. `transfer` — submit + simulate + chained second submit
 *      (proves change-tracking lets a second submit chain through
 *      the first's change UTXO without a fresh bootstrap).
 *   3. `bulk` — bundle two transfers in one Bitcoin tx, each
 *      per-Inst decoder running on its positional slot.
 *   4. `offer + accept` — marketplace swap under the Sponsor +
 *      ctx.payer() model: seller publishes an offer (attach
 *      broadcasts immediately), buyer accepts, asset detaches to
 *      buyer.
 *   5. `offer + revoke` — seller's escape hatch: detach the asset
 *      back to themselves, balance round-trips minus a sliver of gas.
 *
 * Runs via `npm run test:regtest` / `npm run test:regtest:browser`;
 * pure HTTP client, so it works in Node and the browser alike.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect, inject } from "vitest";
import {
  Decimal,
  KontorSession,
  LocalAccount,
  Result,
  http,
} from "@kontor/sdk";
import { connectRegtest } from "@kontor/sdk/regtest";
import { Contract as Token } from "./__generated__/token.js";
import "./regtest-context.js";

const here = path.dirname(fileURLToPath(import.meta.url));

/** Brotli-compressed token wasm — what the indexer's `Storage`
 *  expects on `insert_contract` (it decompresses via
 *  `component_bytes`). We use the native token binary (committed at
 *  `native-contracts/binaries/`) rather than a test-contract wasm
 *  built ad-hoc, so CI doesn't have to build `test-contracts/`
 *  before running the SDK regtest. Publishing this wasm creates a
 *  fresh, independent token instance at a runtime-assigned address —
 *  different storage from the genesis `token@0.0`. */
const TOKEN_WASM_BR = readFileSync(
  path.join(here, "..", "..", "native-contracts", "binaries", "token.wasm.br"),
);

/** How many whole tokens `b` is below `a` — used by the revoke phase
 *  to assert the balance round-tripped to within gas of the original. */
function deficit(a: Decimal, b: Decimal): number {
  return Number(a.toString()) - Number(b.toString());
}

test("SDK capstone: publish, transfer, bulk, marketplace", async () => {
  const regtest = connectRegtest(inject("regtest"));
  const { chain } = regtest;

  // ─── Phase 1 — publish ──────────────────────────────────────────
  {
    const { account, fundingUtxo } = regtest.accounts[0]!;
    const session = new KontorSession({
      chain,
      account,
      transport: ({ chain, account }) =>
        http({ chain, account, utxos: [fundingUtxo] }),
    });
    try {
      await session.ready();
      // Broadcast the publish, force the containing block — Publish's
      // result address depends on block height — then wait for the
      // result row. Publishing the native token wasm a second time
      // produces a fresh instance at a runtime-assigned address with
      // its own storage; it doesn't collide with the genesis
      // `token@0.0`.
      const submitted = await session
        .publish("republished-token", new Uint8Array(TOKEN_WASM_BR))
        .submit();
      await regtest.mine();
      const result = await submitted.wait();
      expect(result.status).toBe("Ok");
      const address = result.value;
      if (address == null) {
        throw new Error(
          `publish returned no address; result=${JSON.stringify(result)}`,
        );
      }
      expect(address.name).toBe("republished-token");
      expect(address.height).toBeGreaterThan(0n);

      // Confirm init ran by binding `Token` to the new instance and
      // reading a known-empty initial state: a fresh token contract
      // has no balances issued, so `balance(...)` for the publisher
      // returns null (or "0").
      const token = session.bind(Token, address);
      const bal = await token.balance(account.holderRef);
      expect(bal == null || bal.toString() === "0").toBe(true);
    } finally {
      session.close();
    }
  }

  // ─── Phase 2 — transfer + chained transfer (change-tracking) ────
  {
    const { account, fundingUtxo } = regtest.accounts[1]!;
    const recipient = LocalAccount.fromPrivateKey({
      privateKey: "22".repeat(32),
      chain,
    });
    const session = new KontorSession({
      chain,
      account,
      transport: ({ chain, account }) =>
        http({ chain, account, utxos: [fundingUtxo] }),
    });
    try {
      await session.ready();
      const token = session.bind(Token, "token@0.0");

      const before = await token.balance(recipient.holderRef);
      expect(before == null || before.toString() === "0").toBe(true);

      // Dry-run.
      const sim = await token
        .transfer(recipient.holderRef, Decimal.from("1"))
        .simulate();
      expect(sim.status).toBe("Ok");
      expect(sim.value?.kind).toBe("ok");

      // Submit 1 — spends the bootstrap UTXO.
      const first = await token.transfer(recipient.holderRef, Decimal.from("1"));
      expect(Result.unwrap(first).amt.toString()).toBe("1");
      expect((await token.balance(recipient.holderRef))?.toString()).toBe("1");

      // Submit 2 — must chain through submit 1's change. If
      // change-tracking is broken, this errors with no funding.
      const second = await token.transfer(recipient.holderRef, Decimal.from("1"));
      expect(Result.unwrap(second).amt.toString()).toBe("1");
      expect((await token.balance(recipient.holderRef))?.toString()).toBe("2");
    } finally {
      session.close();
    }
  }

  // ─── Phase 3 — bulk submit ──────────────────────────────────────
  {
    const { account, fundingUtxo } = regtest.accounts[2]!;
    const recipientA = LocalAccount.fromPrivateKey({
      privateKey: "aa".repeat(32),
      chain,
    });
    const recipientB = LocalAccount.fromPrivateKey({
      privateKey: "bb".repeat(32),
      chain,
    });
    const session = new KontorSession({
      chain,
      account,
      transport: ({ chain, account }) =>
        http({ chain, account, utxos: [fundingUtxo] }),
    });
    try {
      await session.ready();
      const token = session.bind(Token, "token@0.0");

      // Bundle two transfers in one Bitcoin tx. Each per-Inst decoder
      // runs on its own positional slot ((0,0) and (0,1)).
      const [resA, resB] = await session.bulk(
        token.transfer(recipientA.holderRef, Decimal.from("1")),
        token.transfer(recipientB.holderRef, Decimal.from("2")),
      );
      expect(Result.unwrap(resA).amt.toString()).toBe("1");
      expect(Result.unwrap(resB).amt.toString()).toBe("2");
      expect((await token.balance(recipientA.holderRef))?.toString()).toBe("1");
      expect((await token.balance(recipientB.holderRef))?.toString()).toBe("2");
    } finally {
      session.close();
    }
  }

  // ─── Phase 4 — marketplace: offer + accept ──────────────────────
  {
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
      const sellerToken = sellerSession.bind(Token, "token@0.0");
      const buyerToken = buyerSession.bind(Token, "token@0.0");

      const buyerBaseline =
        (await buyerToken.balance(buyer.holderRef)) ?? Decimal.from("0");

      // Seller creates an offer; attach broadcasts immediately.
      const offer = await sellerToken
        .attachment(Decimal.from("2"))
        .offer({ price: 600n });
      const blob = offer.serialize();

      // Buyer opens + inspects.
      const incoming = buyerSession.openOffer(blob);
      const report = await incoming.inspect();
      expect(report.valid).toBe(true);
      expect(report.price).toBe(600n);

      // Buyer accepts. Buyer's transport.utxos() provides the Sponsor
      // commit's funding; under Sponsor + ctx.payer() the asset detaches
      // to the buyer.
      await incoming.accept();

      // Poll until the buyer's balance grows past the baseline by at
      // least 1 token — they receive 2 minus a sliver of gas.
      const threshold = buyerBaseline.add(Decimal.from("1"));
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
  }

  // ─── Phase 5 — marketplace: offer + revoke ──────────────────────
  {
    const { account, fundingUtxo } = regtest.accounts[5]!;
    const session = new KontorSession({
      chain,
      account,
      transport: ({ chain, account }) =>
        http({ chain, account, utxos: [fundingUtxo] }),
    });
    try {
      await session.ready();
      const token = session.bind(Token, "token@0.0");

      const before = await token.balance(account.holderRef);
      expect(before).not.toBeNull();

      // Seller offers (attach moves 2 tokens into escrow), then
      // revokes before any buyer can accept. With no Sponsor, the
      // payer defaults to the signer of the escrow input (the
      // seller), so `detach` credits the asset back. Balance ends a
      // hair below `before` due to gas — never 2 tokens short, which
      // a broken detach (asset stranded) would leave.
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
  }
});
