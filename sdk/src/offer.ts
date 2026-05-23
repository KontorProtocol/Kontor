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
import type { TapLeafScript } from "./bindings.js";
import type { BitcoinNetwork } from "./chains.js";
import { SignerError } from "./errors.js";
import type { BroadcastResult, WireInsts } from "./json-codec.js";
import { encodeRecipientOpReturn } from "./op-return.js";
import type { KontorSession } from "./session.js";
import type { Utxo } from "./transport/http.js";

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
      if (detach.getInput(0).tapScriptSig == null) {
        throw new Error("the seller's detach input is not signed");
      }
      if (detach.getOutput(0).amount !== price) {
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
   * Complete the swap. Assembles one transaction —
   *   inputs:  [0] escrow (the seller's pre-signed `SINGLE|ANYONECANPAY`
   *                input), [1] the buyer's funding UTXO;
   *   outputs: [0] price → seller, [1] OP_RETURN naming the buyer as
   *                recipient, [2] buyer change
   * — signs the buyer's input `default` (committing every output, so
   * the OP_RETURN can't be redirected), and broadcasts
   * `[attachCommit, attachReveal, swapTx]` atomically.
   *
   * @param opts.funding    A buyer UTXO covering `price` + `fee`.
   * @param opts.fee        Flat fee in sats. Default `DEFAULT_SWAP_FEE`.
   * @param opts.recipient  Who the asset detaches to — an x-only pubkey.
   *                        Defaults to the accepting account (buyer is
   *                        recipient); override to detach elsewhere.
   */
  async accept(opts: {
    funding: Utxo;
    fee?: bigint;
    recipient?: string;
  }): Promise<BroadcastResult> {
    const { data } = this;
    const { account, chain, transport } = this.session;
    const fee = opts.fee ?? DEFAULT_SWAP_FEE;

    // The seller's pre-signed detach: input 0 = escrow, output 0 = price.
    const sellerTx = Transaction.fromPSBT(hex.decode(data.detachPsbt));
    const escrowIn = sellerTx.getInput(0);
    const priceOut = sellerTx.getOutput(0);
    const sellerSig = escrowIn.tapScriptSig?.[0]?.[1];
    if (escrowIn.witnessUtxo == null || sellerSig == null) {
      throw new SignerError("accept: offer's detach input is not signed", {
        docsPath: "/sdk/offer",
      });
    }
    if (priceOut.script == null || priceOut.amount == null) {
      throw new SignerError("accept: offer has no price output", {
        docsPath: "/sdk/offer",
      });
    }

    const escrowValue = escrowIn.witnessUtxo.amount;
    const change = escrowValue + opts.funding.value - priceOut.amount - fee;
    if (change < 0n) {
      throw new SignerError(
        `accept: funding ${opts.funding.value} sats cannot cover ` +
          `price ${priceOut.amount} + fee ${fee}`,
        { docsPath: "/sdk/offer" },
      );
    }

    // OP_RETURN names the recipient; signing `default` below binds it
    // (rewriting it breaks the buyer's signature).
    const opReturn = opReturnScript(
      encodeRecipientOpReturn([
        { inputIndex: 0, recipient: opts.recipient ?? account.xOnlyPubKey },
      ]),
    );
    const buyerXOnly = hex.decode(account.xOnlyPubKey);

    const tx = new Transaction({ allowUnknownOutputs: true });
    // Input 0 + output 0 must stay aligned — the seller's SIGHASH_SINGLE
    // commits input 0 to output 0.
    tx.addInput({
      txid: escrowIn.txid,
      index: escrowIn.index,
      witnessUtxo: escrowIn.witnessUtxo,
      tapLeafScript: escrowIn.tapLeafScript,
    });
    tx.addOutput({ script: priceOut.script, amount: priceOut.amount });
    tx.addOutput({ script: opReturn, amount: 0n });
    tx.addInput({
      txid: opts.funding.txid,
      index: opts.funding.vout,
      witnessUtxo: {
        script: hex.decode(opts.funding.scriptPubKey),
        amount: opts.funding.value,
      },
      tapInternalKey: buyerXOnly,
      // Opt-in RBF on the buyer's own input.
      sequence: 0xfffffffd,
    });
    if (change >= DUST_SATS) {
      tx.addOutput({
        script: p2tr(buyerXOnly, undefined, chain.network).script,
        amount: change,
      });
    }

    // Sign only the buyer's funding input, `default` sighash.
    const signed = await account.signPsbt(tx.toPSBT(), {
      inputs: [{ index: 1 }],
    });

    // Finalize by hand: the escrow input's witness is the seller's
    // script-path spend; the buyer's is a plain key-path spend.
    const finalTx = Transaction.fromPSBT(signed);
    finalTx.updateInput(0, {
      finalScriptWitness: [
        sellerSig,
        hex.decode(data.detachLeaf.script),
        hex.decode(data.detachLeaf.controlBlock),
      ],
    });
    const buyerSig = finalTx.getInput(1).tapKeySig;
    if (buyerSig == null) {
      throw new SignerError("accept: the buyer funding input was not signed");
    }
    finalTx.updateInput(1, { finalScriptWitness: [buyerSig] });

    const swapTxHex = hex.encode(finalTx.extract());
    // Broadcast the attach + the swap as one package. (A buyer who knows
    // the attach is already on chain could submit just the swap — left
    // for the upfront-offer path.)
    return transport.broadcast([
      data.attachCommit,
      data.attachReveal,
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
 * Hand-build the seller's detach PSBT — one input spending the escrow
 * (`attachReveal` output 0) via the detach leaf, one output paying the
 * seller `price` — and sign that input `single-anyonecanpay`. Returns
 * the partially-signed PSBT as hex.
 *
 * `SINGLE|ANYONECANPAY` commits to only this input and output 0 (the
 * payout): the seller's signature pins their payment but leaves the
 * recipient OP_RETURN, the buyer's funding input, and change open.
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

  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({
    txid: reveal.id,
    index: 0,
    witnessUtxo: { script: escrow.script, amount: escrow.amount },
    tapLeafScript: [[controlBlock, leafScript]],
  });
  tx.addOutput({ script: sellerScript, amount: params.price });

  const signed = await account.signPsbt(tx.toPSBT(), {
    inputs: [{ index: 0, sighash: "single-anyonecanpay" }],
  });
  return hex.encode(signed);
}
