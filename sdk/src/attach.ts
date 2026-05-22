/**
 * Attach/detach runtime — moving a native asset between a signer and a
 * Bitcoin UTXO.
 *
 * A contract supports the pattern when it exports a paired
 * `attach` / `detach` (token: `attach(vout, amt)` / `detach()`). An
 * `attach` alone would orphan the asset at a UTXO with no way back, so
 * the SDK never exposes it standalone: an `Attachment` is built from
 * *both* Insts and only resolves through a terminal that also produces
 * the detach.
 *
 * `Attachment.to(recipient)` is the gift / round-trip terminal: one
 * party attaches the asset to a fresh UTXO and immediately detaches it
 * to `recipient`, in a single broadcast. It exercises the whole
 * chained-compose machinery — commit → reveal(attach) → reveal(detach):
 *
 *   1. `compose(attach, chained = detach)` — one composed pair, the
 *      commit sized to also fund the chained detach reveal.
 *   2. sign the commit (taproot key-path) and the attach reveal
 *      (script-path).
 *   3. `composeReveal(...)` — build the detach reveal, which spends the
 *      attach reveal's escrow output; its OP_RETURN names `recipient`.
 *   4. sign the detach reveal (script-path).
 *   5. broadcast `[commit, attachReveal, detachReveal]` as one package.
 *
 * `.offer({ price })` — the open-offer terminal — is Phase D.
 */

import { serializeInst } from "./component/kontor-sdk.js";
import { ContractError, TransportError } from "./errors.js";
import {
  instToWire,
  rawToOpResult,
  waitForTxsOutcomes,
  type Inst,
  type WaitOptions,
} from "./inst.js";
import type { OpResult, OpResultRaw, WireInsts } from "./json-codec.js";
import { encodeRecipientOpReturn } from "./op-return.js";
import type { KontorSession } from "./session.js";
import { signCommit, signReveal, txidOf } from "./transport/signing.js";

/**
 * Who an attached asset is detached to. Either a 32-byte x-only public
 * key (64-hex-char string) or anything carrying one — e.g. an
 * `Account`. The on-chain `OpReturnData` only encodes x-only pubkeys.
 */
export type Recipient = string | { readonly xOnlyPubKey: string };

/** The two per-Inst outcomes of an `Attachment.to(...)` round-trip. */
export interface AttachmentOutcome<T> {
  /** Outcome of the attach op (asset → escrow UTXO). */
  attach: OpResult<T>;
  /** Outcome of the detach op (escrow UTXO → recipient). */
  detach: OpResult<T>;
}

/**
 * Handle for a broadcast `Attachment.to(...)` package — the three
 * txids are known immediately; `wait()` resolves the attach + detach
 * outcomes once the indexer surfaces them.
 */
export interface SubmittedAttachment<T> {
  readonly commitTxid: string;
  readonly attachTxid: string;
  readonly detachTxid: string;
  wait(opts?: WaitOptions): Promise<AttachmentOutcome<T>>;
}

/**
 * An attach paired with the detach that re-homes the asset — never one
 * without the other. Built from the two Insts (codegen emits this as
 * `contract.attachment(...)`); resolved through `to()` / `offer()`.
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
   * Gift / round-trip: attach the asset to a fresh UTXO and detach it
   * to `recipient`, broadcast as one commit→reveal→reveal package.
   * One party, no payment — see `offer()` for the open-offer path.
   */
  async to(recipient: Recipient): Promise<SubmittedAttachment<T>> {
    const { transport, account } = this.session;

    // Encode the detach reveal's OP_RETURN up front — it doesn't depend
    // on the compose, and the WASM codec validates the recipient pubkey
    // here, so a bad recipient fails before any network round-trip.
    const opReturnData = [
      ...encodeRecipientOpReturn([
        { inputIndex: 0, recipient: recipientXOnly(recipient) },
      ]),
    ];

    const attachWire: WireInsts = {
      ops: [instToWire(this.attach)],
      aggregate: null,
    };
    const detachWire: WireInsts = {
      ops: [instToWire(this.detach)],
      aggregate: null,
    };

    // 1–2. Compose the commit + attach reveal (commit sized to fund the
    // chained detach), then sign both.
    const composed = await transport.compose(attachWire, detachWire);
    const participant = composed.per_participant[0];
    if (participant == null) {
      throw new TransportError(
        "attach: compose returned no participant scripts",
        { docsPath: "/sdk/attach" },
      );
    }
    const commitHex = await signCommit(account, composed.commit_psbt_hex);
    const attachRevealHex = await signReveal(
      account,
      composed.reveal_psbt_hex,
      composed.per_participant,
    );

    // 3. Build the detach reveal — it spends the attach reveal's escrow
    // output (vout 0); `commit_script_data` is the detach bundle, and
    // the OP_RETURN names the recipient. Same `detachWire` object the
    // compose committed to, so the leaf scripts match.
    const detachReveal = await transport.composeReveal({
      commit_tx_hex: attachRevealHex,
      sat_per_vbyte: null,
      participants: [
        {
          address: participant.address,
          x_only_public_key: participant.x_only_public_key,
          commit_vout: 0,
          commit_script_data: [...serializeInst(JSON.stringify(detachWire))],
          chained_instruction: null,
        },
      ],
      op_return_data: opReturnData,
      envelope: null,
    });

    // 4. Sign the detach reveal (script-path, against the escrow output).
    const detachRevealHex = await signReveal(
      account,
      detachReveal.psbt_hex,
      detachReveal.participants,
    );

    const commitTxid = txidOf(commitHex);
    const attachTxid = txidOf(attachRevealHex);
    const detachTxid = txidOf(detachRevealHex);

    // 5. Attach to the poller before broadcasting (closes the race
    // where a reveal's result event lands before `wait()` subscribes),
    // then broadcast the three-tx package in dependency order.
    const events = this.session.events();
    try {
      await transport.broadcast([commitHex, attachRevealHex, detachRevealHex]);
    } catch (e) {
      await events.return?.();
      throw e;
    }

    const attachDecode = (w: string): T => this.attach._decode(w);
    const detachDecode = (w: string): T => this.detach._decode(w);
    return {
      commitTxid,
      attachTxid,
      detachTxid,
      async wait(opts?: WaitOptions): Promise<AttachmentOutcome<T>> {
        try {
          const seen = await waitForTxsOutcomes(
            events,
            [attachTxid, detachTxid],
            opts,
          );
          return {
            attach: rawToOpResult(ownOp(seen.get(attachTxid), attachTxid), attachDecode),
            detach: rawToOpResult(ownOp(seen.get(detachTxid), detachTxid), detachDecode),
          };
        } finally {
          await events.return?.();
        }
      },
    };
  }

  /**
   * Open-offer terminal — broadcast the attach upfront and pre-sign a
   * detach PSBT into a persistable `Offer`, claimable by anyone who
   * meets `price`. Phase D.
   */
  offer(_opts: { price: bigint }): never {
    throw new ContractError(
      "Attachment.offer: the offer path is not implemented yet",
      { docsPath: "/sdk/attach" },
    );
  }
}

/** Pick a reveal's own op — input 0, op 0 — out of its outcomes. */
function ownOp(
  outcomes: OpResultRaw[] | undefined,
  txid: string,
): OpResultRaw {
  const raw = outcomes?.find((o) => o.inputIndex === 0 && o.opIndex === 0);
  if (raw === undefined) {
    throw new TransportError(
      `attach: tx ${txid} carried no result for op (0, 0)`,
      { docsPath: "/sdk/attach" },
    );
  }
  return raw;
}

/**
 * Pull the x-only pubkey string out of a `Recipient`. Validity — a
 * 32-byte key that's actually on the curve — is checked downstream by
 * the WASM codec in `encodeRecipientOpReturn`.
 */
function recipientXOnly(recipient: Recipient): string {
  return typeof recipient === "string" ? recipient : recipient.xOnlyPubKey;
}
