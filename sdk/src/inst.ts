/**
 * `Inst<T>` is the SDK-side reflection of Kontor's wire-level `Inst`
 * — exactly one instruction: a contract call, a publish, an issuance,
 * or a BLS-key registration. Each Contract method emitted by codegen
 * returns an `Inst<T>` (kind = Call).
 *
 * Three execution surfaces:
 *
 *   - `inst.inspect()`  — parse-only static analysis. Returns
 *                         `OpResult<T>` directly (no broadcast, no tx).
 *   - `inst.simulate()` — sandboxed live execution. Returns
 *                         `OpResult<T>` directly (no broadcast, no tx).
 *   - `inst.submit()`   — real broadcast. Returns a `SubmittedTx<T>`
 *                         handle immediately (txid known once the tx
 *                         hits the mempool); the per-Inst `OpResult<T>`
 *                         is resolved later via `.wait()`, which the
 *                         session's poller fulfils once the indexer
 *                         surfaces the result.
 *
 * The submit/wait split exists because a proc tx can take minutes to
 * land (Bitcoin block time). `submit()` returns as soon as the tx is
 * broadcast; `wait()` resolves when the result materializes.
 *
 * `Inst<T>` is also `PromiseLike` — `await inst` is sugar for
 * `submit()` → `wait()` → unwrap (throws `ContractError` on non-Ok
 * status). Use the explicit two-step form when you want the txid
 * early, or `.submit().wait()` with `OpResult` telemetry.
 *
 * Multiple `Inst`s ride one Bitcoin transaction by passing them
 * through `session.bulk(...)` (which produces an `Insts<...>` bundle).
 */

import type { AggregateFragment } from "./aggregate.js";
import type { Account } from "./account/index.js";
import type { ContractAddress } from "./canonical/ContractAddress.js";
import { ContractError, SignerError } from "./errors.js";
import type { OpResult } from "./json-codec.js";
import type { KontorSession } from "./session.js";

/**
 * Payment commitment carried by each `Inst`. Mirrors the chain's
 * `PaymentIntent` enum:
 *
 * - `SelfPay { limit }` — signer commits up to `limit` from their own
 *   balance for this Inst's gas.
 * - `Sponsored` — signer accepts publisher-paid gas; only valid inside
 *   a BLS aggregate that carries `publisher_sponsorship`.
 */
export type PaymentIntent =
  | { kind: "SelfPay"; limit: bigint }
  | { kind: "Sponsored" };

/**
 * The payload of an `Inst`. Codegen-emitted Contract methods always
 * produce `Call` insts; the other variants exist for SDK-internal
 * deployment / system flows.
 */
export type InstKind =
  | {
      kind: "Call";
      contract: ContractAddress;
      /** Function name on the wire (kebab-case). */
      fnName: string;
      /** Encoded WAVE expression — `name(arg1, arg2, ...)`. */
      expr: string;
    }
  | { kind: "Publish"; name: string; bytes: Uint8Array }
  | { kind: "Issuance" }
  | {
      kind: "RegisterBlsKey";
      blsPubkey: Uint8Array;
      schnorrSig: Uint8Array;
      blsSig: Uint8Array;
    };

/**
 * Per-Inst decoder. Takes the WAVE-encoded result string the chain
 * returned for this Inst and produces the user-typed value. For a
 * `Call` Inst, this is `JSON.parse(_wit.decodeResult(fnName, wave))`
 * piped through the per-type decode helper.
 */
export type InstDecoder<T> = (waveResult: string) => T;

/** Knobs for `SubmittedTx.wait()`. */
export interface WaitOptions {
  /** Block confirmations to wait for before resolving. Default 1. */
  confirmations?: number;
  /** Reject if the result hasn't landed within this many ms. */
  timeoutMs?: number;
  /** Abort the wait early. */
  signal?: AbortSignal;
}

/**
 * Handle returned by `submit()` once a tx has been broadcast. The
 * `txid` is available immediately; the result is resolved by
 * `wait()`, which the session's results poller fulfils when the
 * indexer surfaces the outcome.
 *
 * `R` is whatever `wait()` resolves to — `OpResult<T>` for a single
 * `Inst`, or the tuple `InstsOpResults<T>` for an `Insts` bundle.
 * Keeping `SubmittedTx` generic over the full wait-result (rather
 * than over the inner value) avoids double-wrapping for bundles.
 */
export interface SubmittedTx<R> {
  /** Bitcoin txid of the broadcast transaction. */
  readonly txid: string;
  /**
   * Wait for the indexer to confirm the tx and surface the outcome.
   * Resolves once the tx lands — regardless of Ok / non-Ok status
   * (callers inspect each `OpResult.status`).
   */
  wait(opts?: WaitOptions): Promise<R>;
}

export class Inst<T> implements PromiseLike<T> {
  /**
   * @param session  Bound execution surface.
   * @param payment  Payment commitment for this Inst.
   * @param kind     The Inst payload (Call / Publish / Issuance / RegisterBlsKey).
   * @param decode   Maps the raw WAVE-result string back into the user-typed value.
   */
  constructor(
    private readonly session: KontorSession,
    readonly payment: PaymentIntent,
    readonly kind: InstKind,
    private readonly decode: InstDecoder<T>,
  ) {}

  /**
   * `await inst` broadcasts the Inst, waits for it to land, and
   * returns the unwrapped typed value. Throws `ContractError` if the
   * chain reports a non-Ok status. For the txid up front, or for
   * `OpResult` telemetry without throwing, use `submit()` directly.
   */
  then<TResult1 = T, TResult2 = never>(
    onfulfilled?:
      | ((value: T) => TResult1 | PromiseLike<TResult1>)
      | undefined
      | null,
    onrejected?:
      | ((reason: unknown) => TResult2 | PromiseLike<TResult2>)
      | undefined
      | null,
  ): PromiseLike<TResult1 | TResult2> {
    return this.submit()
      .then((tx) => tx.wait())
      .then(unwrapOrThrow)
      .then(onfulfilled, onrejected);
  }

  /**
   * Broadcast for real. Resolves to a `SubmittedTx` handle as soon as
   * the tx is in the mempool — `handle.txid` is available
   * immediately, `handle.wait()` resolves the typed `OpResult<T>`
   * once the indexer surfaces the outcome.
   */
  async submit(): Promise<SubmittedTx<OpResult<T>>> {
    throw new Error("Inst.submit: not implemented");
  }

  /**
   * Sandboxed live execution. Runs the Inst against current chain
   * state in a throwaway transaction — no broadcast, no Bitcoin fees.
   * Returns the predicted `OpResult<T>` directly; useful for gas
   * estimation and result preview.
   */
  async simulate(): Promise<OpResult<T>> {
    throw new Error("Inst.simulate: not implemented");
  }

  /**
   * Static analysis only — parses the Inst as if it were going on
   * chain, but doesn't execute. Returns whatever the indexer can
   * determine from the payload alone (signature validity, op shape,
   * etc.) without touching contract state.
   */
  async inspect(): Promise<OpResult<T>> {
    throw new Error("Inst.inspect: not implemented");
  }

  /**
   * Sign this single Inst for inclusion in an aggregate broadcast by
   * another party. Returns one fragment carrying the Inst's payload +
   * the contributor's signature over the op-hash.
   *
   * The aggregator collects fragments from multiple contributors and
   * builds the combined `Insts` via `session.combineAggregate(...)`
   * before broadcasting.
   */
  async signForAggregate(_signer: Account): Promise<AggregateFragment> {
    throw new SignerError("Inst.signForAggregate: not implemented", {
      docsPath: "/sdk/aggregate",
    });
  }

  /** @internal — used by the session to decode raw chain output. */
  _decode(waveResult: string): T {
    return this.decode(waveResult);
  }
}

function unwrapOrThrow<T>(r: OpResult<T>): T {
  if (r.status === "Ok" && r.value !== undefined) {
    return r.value;
  }
  throw new ContractError(`contract call failed with status: ${r.status}`, {
    details: r.error,
  });
}
