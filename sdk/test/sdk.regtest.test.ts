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
 *   6. `registerBls` — mint a fresh signing, JS-generate a BlsKey,
 *      submit `session.registerBls(blsKey)`, then query the indexer's
 *      `/signers/{xonly}` endpoint and assert it carries the bls_pubkey
 *      we just registered. Exercises the bls-crypto wasm bridge end-
 *      to-end: schnorr/BLS proof bytes produced in JS verify on chain.
 *   7. `combineAggregate` — two contributors each sign a transfer
 *      fragment with their own BLS key; an aggregator combines the
 *      per-op signatures into one BLS aggregate, broadcasts, and both
 *      recipients land their credits. Proves the contributor → fragment
 *      → aggregator → combined Insts → on-chain verify pipeline.
 *
 * Runs via `npm run test:regtest` / `npm run test:regtest:browser`;
 * pure HTTP client, so it works in Node and the browser alike.
 */
import { test, expect, inject } from "vitest";
import {
  BlsKey,
  Decimal,
  KontorSession,
  LocalKey,
  Result,
  inMemoryFunding,
  type Utxo,
} from "@kontor/sdk";
import { hex, base64 } from "@scure/base";
import { Transaction, p2tr } from "@scure/btc-signer";
import { connectRegtest } from "@kontor/sdk/regtest";
import { Contract as Token } from "./__generated__/token.js";
import "./regtest-context.js";

/** How many whole tokens `b` is below `a` — used by the revoke phase
 *  to assert the balance round-tripped to within gas of the original. */
function deficit(a: Decimal, b: Decimal): number {
  return Number(a.toString()) - Number(b.toString());
}

test("SDK capstone: publish, transfer, bulk, marketplace", async () => {
  const injected = inject("regtest");
  const regtest = connectRegtest(injected);
  const { chain } = regtest;
  const tokenWasmBr = base64.decode(injected.tokenWasmBrBase64);

  // ─── Phase 1 — publish ──────────────────────────────────────────
  {
    const { signing, fundingUtxo } = regtest.accounts[0]!;
    const session = new KontorSession({
      chain,
      signing,
      funding: inMemoryFunding([fundingUtxo]),
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
        .publish("republished-token", tokenWasmBr)
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
      const bal = await token.balance(signing.identity.holderRef);
      expect(bal == null || bal.toString() === "0").toBe(true);
    } finally {
      session.close();
    }
  }

  // ─── Phase 2 — transfer + chained transfer (change-tracking) ────
  {
    const { signing, fundingUtxo } = regtest.accounts[1]!;
    const recipient = LocalKey.fromPrivateKey({
      privateKey: "22".repeat(32),
      chain,
    });
    const session = new KontorSession({
      chain,
      signing,
      funding: inMemoryFunding([fundingUtxo]),
    });
    try {
      await session.ready();
      const token = session.bind(Token, "token@0.0");

      const before = await token.balance(recipient.identity.holderRef);
      expect(before == null || before.toString() === "0").toBe(true);

      // Dry-run.
      const sim = await token
        .transfer(recipient.identity.holderRef, Decimal.from("1"))
        .simulate();
      expect(sim.status).toBe("Ok");
      expect(sim.value?.kind).toBe("ok");

      // Submit 1 — spends the bootstrap UTXO.
      const first = await token.transfer(
        recipient.identity.holderRef,
        Decimal.from("1"),
      );
      expect(Result.unwrap(first).amt.toString()).toBe("1");
      expect(
        (await token.balance(recipient.identity.holderRef))?.toString(),
      ).toBe("1");

      // Submit 2 — must chain through submit 1's change. If
      // change-tracking is broken, this errors with no funding.
      const second = await token.transfer(
        recipient.identity.holderRef,
        Decimal.from("1"),
      );
      expect(Result.unwrap(second).amt.toString()).toBe("1");
      expect(
        (await token.balance(recipient.identity.holderRef))?.toString(),
      ).toBe("2");
    } finally {
      session.close();
    }
  }

  // ─── Phase 3 — bulk submit ──────────────────────────────────────
  {
    const { signing, fundingUtxo } = regtest.accounts[2]!;
    const recipientA = LocalKey.fromPrivateKey({
      privateKey: "aa".repeat(32),
      chain,
    });
    const recipientB = LocalKey.fromPrivateKey({
      privateKey: "bb".repeat(32),
      chain,
    });
    const session = new KontorSession({
      chain,
      signing,
      funding: inMemoryFunding([fundingUtxo]),
    });
    try {
      await session.ready();
      const token = session.bind(Token, "token@0.0");

      // Bundle two transfers in one Bitcoin tx. Each per-Inst decoder
      // runs on its own positional slot ((0,0) and (0,1)).
      const [resA, resB] = await session.bulk(
        token.transfer(recipientA.identity.holderRef, Decimal.from("1")),
        token.transfer(recipientB.identity.holderRef, Decimal.from("2")),
      );
      expect(Result.unwrap(resA).amt.toString()).toBe("1");
      expect(Result.unwrap(resB).amt.toString()).toBe("2");
      expect(
        (await token.balance(recipientA.identity.holderRef))?.toString(),
      ).toBe("1");
      expect(
        (await token.balance(recipientB.identity.holderRef))?.toString(),
      ).toBe("2");
    } finally {
      session.close();
    }
  }

  // ─── Phase 4 — marketplace: offer + accept ──────────────────────
  {
    const { signing: seller, fundingUtxo: sellerFunding } =
      regtest.accounts[3]!;
    const { signing: buyer, fundingUtxo: buyerFunding } = regtest.accounts[4]!;

    const sellerSession = new KontorSession({
      chain,
      signing: seller,
      funding: inMemoryFunding([sellerFunding]),
    });
    const buyerSession = new KontorSession({
      chain,
      signing: buyer,
      funding: inMemoryFunding([buyerFunding]),
    });
    try {
      await sellerSession.ready();
      await buyerSession.ready();
      const sellerToken = sellerSession.bind(Token, "token@0.0");
      const buyerToken = buyerSession.bind(Token, "token@0.0");

      const buyerBaseline =
        (await buyerToken.balance(buyer.identity.holderRef)) ??
        Decimal.from("0");

      // Seller creates an offer; attach broadcasts immediately. A
      // marketplace listing fee rides along as an `extraOutputs`
      // payment, settled in the same attach reveal rather than a
      // separate tx — `accounts[0]` stands in as the marketplace.
      const market = regtest.accounts[0]!.signing.identity;
      const marketFee = 1_500n;
      const offer = await sellerToken.attachment(Decimal.from("2")).offer({
        price: 600n,
        extraOutputs: [{ pay: { address: market.address, value: marketFee } }],
      });
      const blob = offer.serialize();

      // The attach reveal carries a fixed output paying the fee to the
      // market's script — proves the rider output landed in the same tx.
      const marketScript = hex.encode(
        p2tr(hex.decode(market.xOnlyPubKey), undefined, chain.network).script,
      );
      const attachReveal = Transaction.fromRaw(
        hex.decode(JSON.parse(blob).attachReveal as string),
        { disableScriptCheck: true, allowUnknownOutputs: true },
      );
      let feePaid = false;
      for (let i = 0; i < attachReveal.outputsLength; i++) {
        const o = attachReveal.getOutput(i);
        if (
          o.script != null &&
          hex.encode(o.script) === marketScript &&
          o.amount === marketFee
        ) {
          feePaid = true;
          break;
        }
      }
      expect(feePaid).toBe(true);

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
        after = await buyerToken.balance(buyer.identity.holderRef);
      }
      expect(after?.cmp(threshold)).toBe("greater");
    } finally {
      sellerSession.close();
      buyerSession.close();
    }
  }

  // ─── Phase 5 — marketplace: offer + revoke ──────────────────────
  {
    const { signing, fundingUtxo } = regtest.accounts[5]!;
    const session = new KontorSession({
      chain,
      signing,
      funding: inMemoryFunding([fundingUtxo]),
    });
    try {
      await session.ready();
      const token = session.bind(Token, "token@0.0");

      const before = await token.balance(signing.identity.holderRef);
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
        after = await token.balance(signing.identity.holderRef);
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

  // ─── Phase 6 — BLS validator registration ───────────────────────
  {
    // Mint a fresh account funded from accounts[6]'s slot. The
    // pre-created pool entries already have a BLS pubkey registered
    // (the regtest binary registers them deterministically via the
    // Rust EIP-2333 path), so re-registering them with a freshly
    // JS-generated key would fail "already registered". A fresh
    // account has no BLS row yet, so this exercises the full path.
    const sourceAccount = regtest.accounts[6]!.signing;
    const { signing, fundingUtxo } = await regtest.createAccount({
      sats: 200_000n,
      sourceUtxo: regtest.accounts[6]!.fundingUtxo,
      sourceAccount,
    });
    const session = new KontorSession({
      chain,
      signing,
      funding: inMemoryFunding([fundingUtxo]),
    });
    try {
      await session.ready();

      // Issuance is system-paid, so the fresh account picks up tokens
      // without needing any prior balance. RegisterBlsKey is NOT
      // system-paid — it goes through `registry.registered()` and
      // charges gas — so the account needs a balance before the
      // registration call.
      const issued = await session.issuance().submit();
      expect((await issued.wait()).status).toBe("Ok");

      const blsKey = BlsKey.generate();
      await session.registerBls(blsKey);

      // Read back the signer entry and assert the chain stored exactly
      // the bls_pubkey we just produced in JS.
      const res = await fetch(
        `${regtest.apiUrl}/signers/${signing.identity.xOnlyPubKey}`,
      );
      expect(res.ok).toBe(true);
      const body = (await res.json()) as {
        result: { bls_pubkey: number[] | null };
      };
      expect(body.result.bls_pubkey).not.toBeNull();
      const storedHex = hex.encode(new Uint8Array(body.result.bls_pubkey!));
      expect(storedHex).toBe(hex.encode(blsKey.pubkey));
    } finally {
      session.close();
    }
  }

  // ─── Phase 7 — BLS aggregate calls ──────────────────────────────
  {
    // Chain-fund three fresh accounts (two contributors + an
    // aggregator) from accounts[7]'s unspent slot. After each
    // `createAccount`, the source's change output (same txid, vout 1)
    // becomes the source for the next call.
    let chainSource = regtest.accounts[7]!.fundingUtxo;
    const chainSourceAccount = regtest.accounts[7]!.signing;
    const fund = async (
      sats: bigint,
    ): Promise<{ signing: LocalKey; fundingUtxo: Utxo }> => {
      const r = await regtest.createAccount({
        sats,
        sourceUtxo: chainSource,
        sourceAccount: chainSourceAccount,
      });
      chainSource = {
        txid: r.fundingUtxo.txid,
        vout: 1,
        value: chainSource.value - sats - 500n,
        scriptPubKey: chainSource.scriptPubKey,
      };
      return r;
    };
    const contribA = await fund(200_000n);
    const contribB = await fund(200_000n);
    const aggregator = await fund(300_000n);

    /** Set a fresh account up as a contributor: open a session, mint
     *  tokens via Issuance (system-paid), and register a JS-generated
     *  BlsKey so the indexer can verify aggregate signatures. */
    const setupContributor = async (a: {
      signing: LocalKey;
      fundingUtxo: Utxo;
    }) => {
      const session = new KontorSession({
        chain,
        signing: a.signing,
        funding: inMemoryFunding([a.fundingUtxo]),
      });
      await session.ready();
      await (await session.issuance().submit()).wait();
      const blsKey = BlsKey.generate();
      await session.registerBls(blsKey);
      return { session, blsKey };
    };
    const cA = await setupContributor(contribA);
    const cB = await setupContributor(contribB);

    const aggregatorSession = new KontorSession({
      chain,
      signing: aggregator.signing,
      funding: inMemoryFunding([aggregator.fundingUtxo]),
    });
    try {
      await aggregatorSession.ready();

      const recipientA = LocalKey.fromPrivateKey({
        privateKey: "77".repeat(32),
        chain,
      });
      const recipientB = LocalKey.fromPrivateKey({
        privateKey: "88".repeat(32),
        chain,
      });

      // Each contributor signs a transfer fragment with their own
      // BlsKey. The Inst is built against their session (= their
      // identity); only the per-op BLS signature changes between A
      // and B.
      const tokenA = cA.session.bind(Token, "token@0.0");
      const tokenB = cB.session.bind(Token, "token@0.0");

      const fragmentA = await tokenA
        .transfer(recipientA.identity.holderRef, Decimal.from("1"))
        .signForAggregate(cA.blsKey);
      const fragmentB = await tokenB
        .transfer(recipientB.identity.holderRef, Decimal.from("2"))
        .signForAggregate(cB.blsKey);

      expect(fragmentA.verify()).toBe(true);
      expect(fragmentB.verify()).toBe(true);

      // Aggregator combines the per-op BLS signatures into one
      // aggregate signature and broadcasts the bundle. Aggregator pays
      // the Bitcoin fee; each contributor's op pays its own token gas.
      const bundle = aggregatorSession.combineAggregate([fragmentA, fragmentB]);
      const submitted = await bundle.submit();
      const results = await submitted.wait();
      expect(results.every((r) => r.status === "Ok")).toBe(true);

      // Both transfers landed: recipients see their credits, viewed
      // through the aggregator's session (any session works — view
      // queries are stateless).
      const aggToken = aggregatorSession.bind(Token, "token@0.0");
      expect(
        (await aggToken.balance(recipientA.identity.holderRef))?.toString(),
      ).toBe("1");
      expect(
        (await aggToken.balance(recipientB.identity.holderRef))?.toString(),
      ).toBe("2");
    } finally {
      cA.session.close();
      cB.session.close();
      aggregatorSession.close();
    }
  }
});
