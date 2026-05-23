/**
 * Attach/detach runtime — moving a native asset into a Bitcoin UTXO
 * escrow so a future, unknown buyer can claim it via an atomic swap.
 *
 * A contract supports the pattern when it exports a paired
 * `attach` / `detach` (token: `attach(vout, amt)` / `detach()`). An
 * `attach` alone would orphan the asset at a UTXO with no way back, so
 * the SDK never exposes either standalone: an `Attachment` is built
 * from *both* Insts and only resolves through `.offer({ price })`.
 *
 * The gift case — "send X to recipient" — has no escrow concern and
 * goes through the contract's own `transfer(recipient, amount)` proc.
 * Routing gifts through attach/detach was historical ceremony tied to
 * an OP_RETURN-driven recipient mechanism that no longer exists.
 */

import { instToWire, type Inst } from "./inst.js";
import type { WireInsts } from "./json-codec.js";
import { Offer, buildSellerDetachPsbt, type OfferData } from "./offer.js";
import type { KontorSession } from "./session.js";
import { signCommit, signReveal } from "./transport/signing.js";
import { TransportError } from "./errors.js";

/**
 * An attach paired with the detach that re-homes the asset — never one
 * without the other. Built from the two Insts (codegen emits this as
 * `contract.attachment(...)`); resolved through `.offer({ price })`.
 */
export class Attachment<T> {
  /**
   * @param session  Bound execution surface.
   * @param attach   The `attach(vout, ...)` Inst — `vout` is 0 by
   *                 compose convention (the escrow is reveal output 0).
   * @param detach   The matching `detach(...)` Inst.
   */
  constructor(
    private readonly session: KontorSession,
    private readonly attach: Inst<T>,
    private readonly detach: Inst<T>,
  ) {}

  /**
   * Open-offer terminal — compose the attach, pre-sign a detach PSBT
   * (`single-anyonecanpay`, paying the seller `price`), and bundle it
   * into a persistable `Offer` claimable by anyone who meets `price`.
   *
   * Broadcasts nothing: the seller hands out `offer.serialize()` as a
   * deferred offer, or calls `offer.publishAttach()` to put the escrow
   * on chain upfront. See `offer.ts`.
   */
  async offer(opts: { price: bigint }): Promise<Offer> {
    const { transport, account } = this.session;
    const attachWire: WireInsts = {
      ops: [instToWire(this.attach)],
      aggregate: null,
    };
    const detachWire: WireInsts = {
      ops: [instToWire(this.detach)],
      aggregate: null,
    };

    const composed = await transport.compose(attachWire, detachWire);
    const participant = composed.per_participant[0];
    if (participant?.chained_tap_leaf_script == null) {
      throw new TransportError(
        "offer: compose returned no detach (chained) leaf script",
        { docsPath: "/sdk/attach" },
      );
    }

    const commitHex = await signCommit(account, composed.commit_psbt_hex);
    const attachRevealHex = await signReveal(
      account,
      composed.reveal_psbt_hex,
      composed.per_participant,
    );
    const detachPsbt = await buildSellerDetachPsbt(account, {
      attachRevealHex,
      detachLeaf: participant.chained_tap_leaf_script,
      price: opts.price,
      network: this.session.chain.network,
    });

    const data: OfferData = {
      v: 1,
      attachCommit: commitHex,
      attachReveal: attachRevealHex,
      detachInsts: detachWire,
      detachLeaf: participant.chained_tap_leaf_script,
      detachPsbt,
      price: opts.price.toString(),
      seller: account.xOnlyPubKey,
    };
    return new Offer(this.session, data);
  }
}
