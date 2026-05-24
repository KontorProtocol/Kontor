/**
 * Marketplace offers — the seller side of attach/detach (Phase D).
 *
 * An `Offer` is a pre-signed conditional detach: "whoever pays `price`
 * gets the asset." `Attachment.offer({ price })` builds one — it
 * composes the attach, signs it, then hand-builds a one-in/one-out
 * detach PSBT that spends the escrow and pays the seller `price`,
 * signing that input `single-anyonecanpay` so a buyer can complete the
 * rest of the transaction without being able to alter the seller's
 * payout.
 *
 * `offer()` broadcasts nothing. The seller then either:
 *   - hands out `serialize()` as-is — a deferred/"soft" offer, free and
 *     instant; the buyer's `accept()` broadcasts the attach too; or
 *   - calls `publishAttach()` — broadcasts the attach now, so the
 *     escrow is provably live on chain ("hard" offer).
 *
 * The buyer side — `session.openOffer(blob)` → `IncomingOffer` with
 * `inspect()` / `accept()` — completes the swap. `Offer.revoke()` is the
 * seller's escape hatch: detach the asset back to themselves.
 */

import { hex } from "@scure/base";
import { TaprootControlBlock, Transaction, p2tr, utils as btcUtils } from "@scure/btc-signer";

import type { Account } from "./account/index.js";
import type { Reveal, TapLeafScript } from "./bindings.js";
import type { BitcoinNetwork } from "./chains.js";
import { SignerError } from "./errors.js";
import type { BroadcastResult, Utxo, WireInsts } from "./json-codec.js";
import type { KontorSession } from "./session.js";
import { signCommit } from "./transport/signing.js";

/** P2TR dust floor — change below this is dropped into the fee. */
const DUST_SATS = 330n;
/** Default flat fee for the swap transaction, satoshis. */
const DEFAULT_SWAP_FEE = 1000n;

/** Build an `OP_RETURN <payload>` scriptPubKey (payloads are well under
 *  the 75-byte single-byte-push limit). */
function opReturnScript(payload: Uint8Array): Uint8Array {
  if (payload.length >= 0x4c) {
    throw new SignerError("offer: OP_RETURN payload too large");
  }
  return btcUtils.concatBytes(
    new Uint8Array([0x6a, payload.length]),
    payload,
  );
}

/**
 * The persistable offer blob — everything a buyer needs to complete the
 * swap with no contact with the seller. `Offer.serialize()` emits this
 * as JSON; `session.openOffer` rehydrates it.
 */
export interface OfferData {
  /** Blob format version. */
  v: 1;
  /** The signed attach commit transaction, raw hex. */
  attachCommit: string;
  /** The signed attach reveal transaction, raw hex — output 0 is the escrow. */
  attachReveal: string;
  /** The detach `Insts` — kept for tooling/inspection of the offer. */
  detachInsts: WireInsts;
  /**
   * The detach tap-leaf script + control block — the buyer needs it to
   * hand-build the escrow input's script-path witness.
   */
  detachLeaf: TapLeafScript;
  /**
   * The seller's detach PSBT, hex. Its single input spends the escrow
   * and is signed `SINGLE|ANYONECANPAY`; its single output (index 0)
   * pays the seller `price`. The buyer copies this input into the swap
   * transaction it assembles.
   */
  detachPsbt: string;
  /** Price the seller is paid, satoshis as a decimal string. */
  price: string;
  /** The seller's x-only public key, hex. */
  seller: string;
}

/**
 * A marketplace offer the seller holds — built by `Attachment.offer()`.
 * Hand `serialize()` out to buyers; `revoke()` takes the asset back.
 */
export class Offer {
  constructor(
    private readonly session: KontorSession,
    /** The raw offer blob — also what `serialize()` emits. */
    readonly data: OfferData,
  ) {}

  /** The persistable offer blob as a JSON string. */
  serialize(): string {
    return JSON.stringify(this.data);
  }

  /**
   * Broadcast the attach (commit + reveal) now, so the escrow is live
   * on chain before any buyer — the "hard offer" path. Optional: a
   * deferred offer skips this and lets the buyer's `accept()` broadcast
   * the attach.
   */
  publishAttach(): Promise<BroadcastResult> {
    return this.session.transport.broadcast([
      this.data.attachCommit,
      this.data.attachReveal,
    ]);
  }

  /**
   * Cancel the offer — detach the asset back to the seller. No
   * `Sponsor` input is involved, so the reactor's payer defaults to
   * the signer of the escrow input (the seller); the contract's
   * `detach` reads `ctx.payer()` and credits the asset back to that
   * signer. Single-party, no buyer needed.
   *
   * Spends the escrow plus a `funding` UTXO (the escrow output is dust;
   * `funding` covers the Bitcoin fee) into one output back to the
   * seller. Broadcasts `[attachCommit, attachReveal, detachTx]` — the
   * same package shape as `accept()`, so a deferred offer is revoked
   * even if its attach was never published.
   *
   * @param opts.funding  A seller UTXO covering `fee`.
   * @param opts.fee      Flat fee in sats. Default `DEFAULT_SWAP_FEE`.
   */
  async revoke(opts: { funding: Utxo; fee?: bigint }): Promise<BroadcastResult> {
    const { data } = this;
    const { account, chain, transport } = this.session;
    const fee = opts.fee ?? DEFAULT_SWAP_FEE;

    // The escrow — the attach reveal's output 0.
    const reveal = Transaction.fromRaw(hex.decode(data.attachReveal), LENIENT_TX);
    const escrow = reveal.getOutput(0);
    if (escrow.script == null || escrow.amount == null) {
      throw new SignerError("revoke: attach reveal has no escrow output 0", {
        docsPath: "/sdk/offer",
      });
    }

    const sellerXOnly = hex.decode(account.xOnlyPubKey);
    const recovered = escrow.amount + opts.funding.value - fee;
    if (recovered < DUST_SATS) {
      throw new SignerError(
        `revoke: escrow ${escrow.amount} + funding ${opts.funding.value} ` +
          `sats cannot cover fee ${fee}`,
        { docsPath: "/sdk/offer" },
      );
    }

    // Spend the escrow through the detach leaf; the seller is the
    // signer, no Sponsor is in play, so `ctx.payer()` inside detach
    // resolves to the seller and the asset is credited back. The
    // funding input covers the Bitcoin fee; one output returns
    // everything to the seller.
    const leafScript = btcUtils.concatBytes(
      hex.decode(data.detachLeaf.script),
      new Uint8Array([data.detachLeaf.leafVersion]),
    );
    const controlBlock = TaprootControlBlock.decode(
      hex.decode(data.detachLeaf.controlBlock),
    );

    const tx = new Transaction({ allowUnknownOutputs: true });
    tx.addInput({
      txid: reveal.id,
      index: 0,
      witnessUtxo: { script: escrow.script, amount: escrow.amount },
      tapLeafScript: [[controlBlock, leafScript]],
    });
    tx.addInput({
      txid: opts.funding.txid,
      index: opts.funding.vout,
      witnessUtxo: {
        script: hex.decode(opts.funding.scriptPubKey),
        amount: opts.funding.value,
      },
      tapInternalKey: sellerXOnly,
      // Opt-in RBF on the seller's funding input.
      sequence: 0xfffffffd,
    });
    tx.addOutput({
      script: p2tr(sellerXOnly, undefined, chain.network).script,
      amount: recovered,
    });

    // The seller owns both inputs; sign both `default`. Unlike the
    // offer's detach PSBT there is no buyer to leave outputs open for.
    const signed = await account.signPsbt(tx.toPSBT(), {
      inputs: [{ index: 0 }, { index: 1 }],
    });

    // Finalize by hand: input 0 the escrow's script-path spend, input 1
    // a plain key-path spend.
    const finalTx = Transaction.fromPSBT(signed);
    const escrowSig = finalTx.getInput(0).tapScriptSig?.[0]?.[1];
    if (escrowSig == null) {
      throw new SignerError("revoke: the escrow input was not signed");
    }
    finalTx.updateInput(0, {
      finalScriptWitness: [
        escrowSig,
        hex.decode(data.detachLeaf.script),
        hex.decode(data.detachLeaf.controlBlock),
      ],
    });
    const fundingSig = finalTx.getInput(1).tapKeySig;
    if (fundingSig == null) {
      throw new SignerError("revoke: the funding input was not signed");
    }
    finalTx.updateInput(1, { finalScriptWitness: [fundingSig] });

    const detachTxHex = hex.encode(finalTx.extract());
    return transport.broadcast([
      data.attachCommit,
      data.attachReveal,
      detachTxHex,
    ]);
  }
}

/** Lenient `Transaction.fromRaw` opts — Kontor reveals carry a
 *  non-standard taproot leaf; we only ever inspect, never re-validate. */
const LENIENT_TX = {
  disableScriptCheck: true,
  allowUnknownOutputs: true,
  allowUnknownInputs: true,
} as const;

/** Result of `IncomingOffer.inspect()` — a static validity report. */
export interface OfferInspection {
  /** Price the buyer pays the seller, satoshis. */
  price: bigint;
  /** The seller's x-only public key, hex. */
  seller: string;
  /**
   * Static validity — the blob is well-formed, parses, and the seller's
   * detach input is signed. This is NOT a chain check: whether the
   * escrow is still unspent is settled definitively by `accept()` (a
   * spent escrow makes the swap a rejected double-spend, so the buyer
   * pays nothing either way).
   */
  valid: boolean;
  /** Why `valid` is false, when it is. */
  problem?: string;
}

/**
 * The buyer's handle on an offer — rehydrated from a blob via
 * `session.openOffer(blob)`. `T` is lost across serialization, so the
 * detach result is decoded untyped.
 */
export class IncomingOffer {
  constructor(
    private readonly session: KontorSession,
    /** The decoded offer blob. */
    readonly data: OfferData,
  ) {}

  /**
   * Statically validate the offer — the blob parses, versions match,
   * the seller's detach input is signed, and the payout matches the
   * stated price. See `OfferInspection.valid` for what this does *not*
   * cover (chain liveness).
   */
  inspect(): Promise<OfferInspection> {
    const { data } = this;
    const seller = typeof data.seller === "string" ? data.seller : "";
    let price = 0n;
    try {
      price = BigInt(data.price);
      if (data.v !== 1) {
        throw new Error(`unsupported offer blob version: ${String(data.v)}`);
      }
      if (price <= 0n) throw new Error("price must be positive");
      Transaction.fromRaw(hex.decode(data.attachCommit), LENIENT_TX);
      Transaction.fromRaw(hex.decode(data.attachReveal), LENIENT_TX);
      const detach = Transaction.fromPSBT(hex.decode(data.detachPsbt));
      // Escrow at input 1, price at output 1 — slot 0 is a dummy
      // placeholder the buyer overwrites (see `buildSellerDetachPsbt`).
      if (detach.getInput(1).tapScriptSig == null) {
        throw new Error("the seller's detach input is not signed");
      }
      if (detach.getOutput(1).amount !== price) {
        throw new Error("the detach payout does not match the stated price");
      }
      return Promise.resolve({ price, seller, valid: true });
    } catch (e) {
      return Promise.resolve({
        price,
        seller,
        valid: false,
        problem: e instanceof Error ? e.message : String(e),
      });
    }
  }

  /**
   * Complete the swap under the Sponsor + ctx.payer() model.
   *
   * Build a Reveal with two participants — the buyer at input 0
   * (Sponsor commit, funded by `opts.funding`), the seller at input 1
   * (Existing escrow, pre-signed SACP). The indexer composes the
   * buyer's commit tx + the swap reveal PSBT; the buyer signs both
   * (key-path spend on the commit; script-path spend revealing the
   * Sponsor leaf on the swap reveal's input 0); the seller's pre-signed
   * SACP witness is injected at input 1; everything broadcasts as one
   * package: `[attachCommit, attachReveal, buyerCommit, swapReveal]`.
   *
   * The Sponsor at input 0 sponsors input 1's first op (the detach), so
   * `ctx.payer()` resolves to the buyer; the asset detaches to the
   * buyer (= signer of this `accept()` call). No OP_RETURN is involved.
   */
  async accept(opts: { funding: Utxo }): Promise<BroadcastResult> {
    const { data } = this;
    const { account, chain, transport } = this.session;

    // The seller's pre-signed detach PSBT: escrow at input 1, price at
    // output 1. The buyer extracts the SACP witness, the escrow's
    // prevout (for `CommitSource::Existing`), and the price-payout
    // shape (for the seller participant's paired Fixed output).
    const sellerTx = Transaction.fromPSBT(hex.decode(data.detachPsbt));
    const escrowIn = sellerTx.getInput(1);
    const priceOut = sellerTx.getOutput(1);
    const sellerSig = escrowIn.tapScriptSig?.[0]?.[1];
    if (escrowIn.witnessUtxo == null || sellerSig == null) {
      throw new SignerError("accept: offer's detach input is not signed", {
        docsPath: "/sdk/offer",
      });
    }
    if (
      escrowIn.txid == null ||
      escrowIn.index == null ||
      priceOut.script == null ||
      priceOut.amount == null
    ) {
      throw new SignerError("accept: offer's detach PSBT is malformed", {
        docsPath: "/sdk/offer",
      });
    }

    const buyerXOnly = account.xOnlyPubKey;
    const buyerScriptPubKey = hex.encode(
      p2tr(hex.decode(buyerXOnly), undefined, chain.network).script,
    );
    const escrowOutpoint = `${hex.encode(escrowIn.txid)}:${escrowIn.index}`;
    const escrowPrevoutScript = hex.encode(escrowIn.witnessUtxo.script);

    // Build the swap Reveal:
    //   participant 0 — buyer, Build with a Sponsor inst, paired
    //     Change so the buyer's leftover funding returns to them.
    //   participant 1 — seller, Existing (escrow), paired Fixed payout
    //     matching what the seller pre-signed (output 1 → price → seller).
    const reveal: Reveal = {
      sat_per_vbyte: await transport.feeRate(),
      participants: [
        {
          x_only_public_key: buyerXOnly,
          commit_insts: {
            ops: [{ gas_limit: 50_000, kind: "Sponsor" }],
            aggregate: null,
          },
          output: { Change: { script_pubkey: buyerScriptPubKey } },
          commit_source: {
            Build: {
              address: account.address,
              funding_utxo_ids: [`${opts.funding.txid}:${opts.funding.vout}`],
            },
          },
        },
        {
          x_only_public_key: data.seller,
          commit_insts: data.detachInsts,
          output: {
            Fixed: {
              script_pubkey: hex.encode(priceOut.script),
              value: priceOut.amount,
            },
          },
          commit_source: {
            Existing: {
              outpoint: escrowOutpoint,
              prevout: {
                value: Number(escrowIn.witnessUtxo.amount),
                script_pubkey: escrowPrevoutScript,
              },
            },
          },
        },
      ],
      extra_inputs: [],
      extra_outputs: [],
    };

    // Indexer builds the buyer's commit AND the swap reveal PSBT.
    const composed = await transport.compose(reveal);
    if (composed.commits.length !== 1) {
      throw new SignerError(
        `accept: expected 1 commit, got ${composed.commits.length}`,
        { docsPath: "/sdk/offer" },
      );
    }
    const buyerCommitHex = await signCommit(
      account,
      composed.commits[0]!.psbt_hex,
    );

    // Mixed-sighash signing on the swap reveal:
    //   input 0 — buyer's Sponsor leaf, sign `default` (commits all)
    //   input 1 — seller's pre-signed SACP, inject witness as-is
    const swapPrep = Transaction.fromPSBT(hex.decode(composed.reveal.psbt_hex));
    const buyerLeaf = composed.reveal.commit_tap_leaf_scripts[0]!;
    const buyerLeafScript = btcUtils.concatBytes(
      hex.decode(buyerLeaf.script),
      new Uint8Array([buyerLeaf.leafVersion]),
    );
    const buyerControlBlock = TaprootControlBlock.decode(
      hex.decode(buyerLeaf.controlBlock),
    );
    swapPrep.updateInput(
      0,
      { tapLeafScript: [[buyerControlBlock, buyerLeafScript]] },
      true,
    );

    const swapSigned = await account.signPsbt(swapPrep.toPSBT(), {
      inputs: [{ index: 0 }],
    });
    const swapFinal = Transaction.fromPSBT(swapSigned);
    const buyerSig = swapFinal.getInput(0).tapScriptSig?.[0]?.[1];
    if (buyerSig == null) {
      throw new SignerError("accept: buyer's Sponsor input was not signed", {
        docsPath: "/sdk/offer",
      });
    }
    swapFinal.updateInput(0, {
      finalScriptWitness: [
        buyerSig,
        hex.decode(buyerLeaf.script),
        hex.decode(buyerLeaf.controlBlock),
      ],
    });
    swapFinal.updateInput(1, {
      finalScriptWitness: [
        sellerSig,
        hex.decode(data.detachLeaf.script),
        hex.decode(data.detachLeaf.controlBlock),
      ],
    });

    const swapTxHex = hex.encode(swapFinal.extract());
    return transport.broadcast([
      data.attachCommit,
      data.attachReveal,
      buyerCommitHex,
      swapTxHex,
    ]);
  }
}

/** Inputs for building the seller's pre-signed detach PSBT. */
export interface SellerDetachParams {
  /** The signed attach reveal, raw hex — its output 0 is the escrow. */
  attachRevealHex: string;
  /** The detach tap-leaf script (compose's `chained_tap_leaf_script`). */
  detachLeaf: TapLeafScript;
  /** Price paid to the seller, satoshis. */
  price: bigint;
  /** Chain the seller's payout address is encoded for. */
  network: BitcoinNetwork;
}

/**
 * Hand-build the seller's detach PSBT — escrow at input 1, price-payout
 * at output 1, with a dummy input/output filling slot 0 — and sign the
 * escrow input `single-anyonecanpay`. Returns the partially-signed PSBT
 * as hex.
 *
 * Input 1 / output 1 (not 0) because the swap reveal the buyer
 * assembles places its own Sponsor input at index 0; `SINGLE|ANYONECANPAY`
 * commits the seller's signature to *this* input's index, so the
 * escrow must be signed at the index it'll actually land at in the
 * final tx. The dummy at slot 0 is purely structural — `SINGLE|ANYONECANPAY`
 * doesn't hash other inputs/outputs, so the buyer can replace it with
 * anything (the real Sponsor commit input + paired change/etc.) without
 * invalidating the seller's signature.
 */
export async function buildSellerDetachPsbt(
  account: Account,
  params: SellerDetachParams,
): Promise<string> {
  // Lenient parse — the reveal carries a non-standard taproot leaf.
  const reveal = Transaction.fromRaw(
    hex.decode(params.attachRevealHex),
    LENIENT_TX,
  );
  const escrow = reveal.getOutput(0);
  if (escrow.script == null || escrow.amount == null) {
    throw new SignerError("offer: attach reveal has no escrow output 0", {
      docsPath: "/sdk/offer",
    });
  }

  const leafScript = btcUtils.concatBytes(
    hex.decode(params.detachLeaf.script),
    new Uint8Array([params.detachLeaf.leafVersion]),
  );
  const controlBlock = TaprootControlBlock.decode(
    hex.decode(params.detachLeaf.controlBlock),
  );
  const sellerScript = p2tr(
    hex.decode(account.xOnlyPubKey),
    undefined,
    params.network,
  ).script;

  // 32-byte all-zeros txid + vout 0 — not a real outpoint, fine as a
  // placeholder since this input is never signed and the buyer replaces
  // it before broadcasting.
  const dummyTxid = "0".repeat(64);
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({
    txid: dummyTxid,
    index: 0,
    witnessUtxo: { script: new Uint8Array(), amount: 0n },
  });
  tx.addInput({
    txid: reveal.id,
    index: 0,
    witnessUtxo: { script: escrow.script, amount: escrow.amount },
    tapLeafScript: [[controlBlock, leafScript]],
  });
  // Output 0 mirrors the dummy input — pure structural filler so output 1
  // sits at index 1 (where the seller's SACP signature commits to it).
  tx.addOutput({ script: opReturnScript(new Uint8Array([0])), amount: 0n });
  tx.addOutput({ script: sellerScript, amount: params.price });

  const signed = await account.signPsbt(tx.toPSBT(), {
    inputs: [{ index: 1, sighash: "single-anyonecanpay" }],
  });
  return hex.encode(signed);
}
