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

import { hex } from "@scure/base";
import { p2tr } from "@scure/btc-signer";

import type { Reveal } from "./bindings.js";
import { instToWire, type Inst } from "./inst.js";
import type { WireInsts } from "./json-codec.js";
import { Offer, buildSellerDetachPsbt, type OfferData } from "./offer.js";
import type { KontorSession } from "./session.js";
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
   * Open-offer terminal — compose the attach (commit + reveal),
   * broadcast it so the escrow is live on chain, pre-sign a detach
   * PSBT (`single-anyonecanpay`, paying the seller `price`), and
   * bundle it into a persistable `Offer` claimable by anyone who
   * meets `price`.
   *
   * The attach is broadcast immediately (the seller commits the asset
   * to the escrow on creation, the way OpenSea / Magic Eden lock the
   * asset at listing time): subsequent `revoke()` and `accept()` only
   * need to send the detach / swap tx, not re-broadcast attach.
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

    // Seller's reveal: one Build participant carrying the attach,
    // ChainedEnvelope output committing to the detach for the future
    // buyer to spend, and Change back to the seller (last position).
    const sellerScriptPubKey = hex.encode(
      p2tr(hex.decode(account.xOnlyPubKey), undefined, this.session.chain.network).script,
    );
    // Route through `submitReveal` so utxos/compose/sign/broadcast/track
    // run as one atomic block under the account's lock — no race with
    // a concurrent `submit` or marketplace flow on the same account.
    const { composed, revealHex: attachRevealHex } = await transport.submitReveal(
      async (utxos) => {
        const reveal: Reveal = {
          sat_per_vbyte: this.session.feeRate,
          participants: [
            {
              x_only_public_key: account.xOnlyPubKey,
              commit_insts: attachWire,
              output: null,
              commit_source: {
                Build: {
                  address: account.address,
                  funding_utxo_ids: utxos.map((u) => `${u.txid}:${u.vout}`),
                },
              },
            },
          ],
          extra_inputs: [],
          extra_outputs: [
            {
              ChainedEnvelope: {
                insts: detachWire,
                value: 600,
                internal_key: account.xOnlyPubKey,
              },
            },
            { Change: { script_pubkey: sellerScriptPubKey } },
          ],
        };
        return transport.composeAndSign(reveal);
      },
    );

    // The chained detach leaf script (for the future buyer to spend the
    // escrow output) lives on output 0 of the reveal — same position as
    // the ChainedEnvelope we declared in extra_outputs.
    const firstOutputInfo = composed.reveal.output_info[0];
    if (
      firstOutputInfo == null ||
      typeof firstOutputInfo === "string" ||
      !("ChainedEnvelope" in firstOutputInfo)
    ) {
      throw new TransportError(
        "offer: compose returned no ChainedEnvelope at reveal output 0",
        { docsPath: "/sdk/attach" },
      );
    }
    const detachLeaf = firstOutputInfo.ChainedEnvelope.tap_leaf_script;

    const detachPsbt = await buildSellerDetachPsbt(account, {
      attachRevealHex,
      detachLeaf,
      price: opts.price,
      network: this.session.chain.network,
    });

    const data: OfferData = {
      v: 1,
      attachReveal: attachRevealHex,
      detachInsts: detachWire,
      detachLeaf,
      detachPsbt,
      price: opts.price.toString(),
      seller: account.xOnlyPubKey,
    };
    return new Offer(this.session, data);
  }
}
