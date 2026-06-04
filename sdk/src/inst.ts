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

import { hex } from "@scure/base";

import { AggregateFragment } from "./aggregate.js";
import type { BlsKey } from "./bls.js";
import { aggregateSigningMessage } from "./component/kontor-sdk.js";
import type {
  Inst as WireInst,
  InstKind as WireInstKind,
  Insts as WireInsts,
} from "./bindings.js";
import { ContractAddress } from "./canonical/ContractAddress.js";
import { ContractError, SignerError, TransportError } from "./errors.js";
import type { ChainEvent } from "./events.js";
import type {
  BroadcastResult,
  OpResult,
  OpResultRaw,
} from "./json-codec.js";
import type { KontorSession } from "./session.js";

/**
 * The payload of an `Inst`. Codegen-emitted Contract methods always
 * produce `Call` insts; the other variants exist for SDK-internal
 * deployment / system flows or — for `Sponsor` — the marketplace
 * payer-redirection mechanism.
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
    }
  /**
   * Payer-redirection directive: the signer of the input carrying this
   * Inst commits to paying gas (up to the outer `Inst.gasLimit`) for
   * every op in the *next* input. Used by the marketplace swap path so
   * the buyer's signature on their own input redirects payment for the
   * seller-signed detach. See the project's attach/detach redesign.
   */
  | { kind: "Sponsor" };

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
   * @param session   Bound execution surface.
   * @param gasLimit  Per-op gas cap. Default self-pay (input signer
   *                  pays up to this); overridden by a previous-input
   *                  `Sponsor` Inst in direct context, or by a
   *                  publisher-sponsored `AggregateSigner` in aggregate
   *                  context.
   * @param kind      The Inst payload (Call / Publish / Issuance /
   *                  RegisterBlsKey / Sponsor).
   * @param decode    Maps the raw WAVE-result string back into the user-typed value.
   */
  constructor(
    private readonly session: KontorSession,
    readonly gasLimit: bigint,
    readonly kind: InstKind,
    private readonly decode: InstDecoder<T>,
  ) {}

  /**
   * Return a copy of this Inst with a different gas cap. Immutable —
   * the original is left untouched, so an Inst can be shared (passed
   * into `session.bulk(...)`, an aggregate, ...) without a later
   * `.withGasLimit()` changing it underneath the holder.
   */
  withGasLimit(gasLimit: bigint): Inst<T> {
    return new Inst<T>(this.session, gasLimit, this.kind, this.decode);
  }

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
    const wire: WireInsts = { ops: [instToWire(this)], aggregate: null };
    // Attach to the poller's event stream *before* broadcasting, so the
    // tx's result event can't slip past between broadcast and wait().
    const events = this.session.events();
    let broadcast: BroadcastResult;
    try {
      broadcast = await this.session.transport.submit(wire);
    } catch (e) {
      await events.return?.();
      throw e;
    }
    const { txid } = broadcast;
    const decode = this.decode;
    return {
      txid,
      async wait(opts?: WaitOptions): Promise<OpResult<T>> {
        try {
          const outcomes = await waitForTxOutcomes(events, txid, opts);
          // A single Inst is always op (0, 0) of its own tx. Multi-Inst
          // (`bulk`) and aggregate bundles go through `Insts`, which
          // maps every op of the tx itself.
          const raw = outcomes.find(
            (o) => o.inputIndex === 0 && o.opIndex === 0,
          );
          if (raw === undefined) {
            throw new TransportError(
              `wait: tx ${txid} carried no result for op (0, 0)`,
            );
          }
          return rawToOpResult(raw, decode);
        } finally {
          await events.return?.();
        }
      },
    };
  }

  /**
   * Sandboxed live execution. Runs the Inst against current chain
   * state in a throwaway transaction — no broadcast, no Bitcoin fees.
   * Returns the predicted `OpResult<T>` directly; useful for gas
   * estimation and result preview.
   */
  async simulate(): Promise<OpResult<T>> {
    const wire: WireInsts = { ops: [instToWire(this)], aggregate: null };
    return this.decodeOwnOp(
      await this.session.transport.simulate(wire),
      "simulate",
    );
  }

  /**
   * Static analysis only — parses the Inst as if it were going on
   * chain, but doesn't execute. Returns whatever the indexer can
   * determine from the payload alone (signature validity, op shape,
   * etc.) without touching contract state.
   */
  async inspect(): Promise<OpResult<T>> {
    const wire: WireInsts = { ops: [instToWire(this)], aggregate: null };
    return this.decodeOwnOp(
      await this.session.transport.inspect(wire),
      "inspect",
    );
  }

  /**
   * Pick this single Inst's op — input 0, op 0 — out of a transport's
   * per-op outcomes and decode it into a typed `OpResult<T>`.
   */
  private decodeOwnOp(outcomes: OpResultRaw[], label: string): OpResult<T> {
    const raw = outcomes.find((o) => o.inputIndex === 0 && o.opIndex === 0);
    if (raw === undefined) {
      throw new TransportError(`${label}: no result for the submitted op`);
    }
    return rawToOpResult(raw, this.decode);
  }

  /**
   * Sign this single Inst for inclusion in a BLS-aggregate broadcast
   * by another party. Fetches the contributor's `next_nonce` from the
   * indexer, builds the per-op signing message via the kontor-sdk wasm
   * (`"KONTOR-OP-V1" ++ postcard((SignerRef::XOnlyPubkey, nonce, sponsored, Inst))`),
   * BLS-signs it with `blsKey`, and returns the fragment.
   *
   * `opts.sponsored` defaults to `false`; pass `true` for the
   * publisher-pays flow (the publisher's fragment will cover this op's
   * gas).
   *
   * The aggregator collects fragments, calls `fragment.verify()`,
   * then `session.combineAggregate(fragments).submit()`.
   */
  async signForAggregate(
    blsKey: BlsKey,
    opts?: { sponsored?: boolean },
  ): Promise<AggregateFragment> {
    const { identity } = this.session;
    const sponsored = opts?.sponsored ?? false;

    const entry = await this.session.transport.signer(identity.xOnlyPubKey);
    // Pre-registration signers (no DB row yet) carry an implicit nonce
    // of 0 — the indexer's `advance_nonce` accepts it and writes the
    // row on first use. Established signers reuse their stored
    // `next_nonce`.
    const nonce = BigInt(entry?.next_nonce ?? 0);

    const wireInst = instToWire(this);
    const claimJson = JSON.stringify({ XOnlyPubkey: identity.xOnlyPubKey });
    const instJson = JSON.stringify(wireInst);

    const msg = aggregateSigningMessage(claimJson, nonce, sponsored, instJson);
    const sig = blsKey.signBls(msg);

    return new AggregateFragment({
      inst: wireInst,
      signerXOnlyPubKey: identity.xOnlyPubKey,
      blsPubkey: hex.encode(blsKey.pubkey),
      nonce: nonce.toString(),
      sponsored,
      signature: hex.encode(sig),
    });
  }

  /** @internal — used by the session to decode raw chain output. */
  _decode(waveResult: string): T {
    return this.decode(waveResult);
  }
}

/**
 * Decode a transport `OpResultRaw` into a typed `OpResult<T>`.
 *
 * @internal
 */
export function rawToOpResult<T>(
  raw: OpResultRaw,
  decode: InstDecoder<T>,
): OpResult<T> {
  return {
    status: raw.status,
    gas: raw.gas,
    error: raw.error,
    value: raw.value !== undefined ? decode(raw.value) : undefined,
  };
}

function unwrapOrThrow<T>(r: OpResult<T>): T {
  // `value` is absent for void-returning Insts (Issuance, RegisterBlsKey)
  // even on success — gate solely on status so awaiting `inst<void>`
  // resolves to undefined rather than throwing.
  if (r.status === "Ok") {
    return r.value as T;
  }
  throw new ContractError(`contract call failed with status: ${r.status}`, {
    details: r.error,
  });
}

/**
 * Drain the poller's event stream until the `tx` event for `txid`
 * arrives, returning its per-op outcomes. Honors `timeoutMs` / `signal`
 * from `WaitOptions`. Shared by `Inst` and `Insts` `wait()`.
 *
 * @internal
 */
export function waitForTxOutcomes(
  events: AsyncIterableIterator<ChainEvent>,
  txid: string,
  opts?: WaitOptions,
): Promise<OpResultRaw[]> {
  return withWaitDeadline(
    async () => {
      for await (const ev of events) {
        if (ev.kind === "tx" && ev.txid === txid) return ev.outcomes;
      }
      throw new TransportError(
        `wait: event stream ended before tx ${txid} landed`,
      );
    },
    `tx ${txid}`,
    opts,
  );
}

/**
 * Like `waitForTxOutcomes`, but waits for several txids at once on one
 * event iterator — the attach/detach package broadcasts a commit and
 * two reveals, and the caller wants every reveal's outcomes. Returns a
 * map keyed by txid; resolves only once every requested txid is seen.
 *
 * @internal
 */
export function waitForTxsOutcomes(
  events: AsyncIterableIterator<ChainEvent>,
  txids: readonly string[],
  opts?: WaitOptions,
): Promise<Map<string, OpResultRaw[]>> {
  return withWaitDeadline(
    async () => {
      const pending = new Set(txids);
      const seen = new Map<string, OpResultRaw[]>();
      for await (const ev of events) {
        if (ev.kind === "tx" && pending.delete(ev.txid)) {
          seen.set(ev.txid, ev.outcomes);
          if (pending.size === 0) return seen;
        }
      }
      throw new TransportError(
        `wait: event stream ended before txs [${[...pending]}] landed`,
      );
    },
    `txs [${txids.join(", ")}]`,
    opts,
  );
}

/**
 * Race `scan` against the `WaitOptions` timeout / abort signal. With
 * neither set, `scan` runs unguarded. The losing `scan` unblocks when
 * the caller's `finally` closes the underlying event iterator.
 *
 * @internal
 */
export function withWaitDeadline<R>(
  scan: () => Promise<R>,
  label: string,
  opts?: WaitOptions,
): Promise<R> {
  if (opts?.timeoutMs == null && opts?.signal == null) return scan();

  return new Promise<R>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = (): void =>
      settle(() => reject(new TransportError(`wait: aborted (${label})`)));

    // First settler wins; on the way out, release the timer and abort
    // listener so neither keeps the event loop (or the signal) alive.
    const settle = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      fn();
    };

    scan().then(
      (r) => settle(() => resolve(r)),
      (e) => settle(() => reject(e)),
    );
    if (opts.timeoutMs != null) {
      timer = setTimeout(
        () =>
          settle(() =>
            reject(
              new TransportError(
                `wait: ${label} not seen within ${opts.timeoutMs}ms`,
              ),
            ),
          ),
        opts.timeoutMs,
      );
    }
    if (opts.signal != null) {
      if (opts.signal.aborted) onAbort();
      else opts.signal.addEventListener("abort", onAbort);
    }
  });
}

/**
 * Convert an SDK `Inst` to its wire shape — the JSON `Inst` the
 * indexer's compose endpoint consumes. Exported for `session.bulk`,
 * which assembles several into one `Insts` bundle.
 *
 * @internal
 */
export function instToWire(inst: Inst<unknown>): WireInst {
  return {
    gas_limit: Number(inst.gasLimit),
    kind: instKindToWire(inst.kind),
  };
}

/**
 * Inverse of `instToWire` — reconstructs an `Inst<unknown>` from the
 * wire payload. Used by `session.combineAggregate` to wrap
 * contributor-supplied Insts back into the Inst class so they fit
 * `Insts<...>`'s constructor. The decoder is identity (the aggregator
 * doesn't know contributor result types).
 *
 * For `Call`: the wire payload only carries `contract` + `expr` (no
 * `fnName`), so the reconstructed Inst has `fnName: ""`. That's fine
 * here — `fnName` is only used by codegen at signing time, not by
 * `instToWire` when broadcasting.
 */
export function wireInstToInst(
  session: KontorSession,
  wire: WireInst,
): Inst<unknown> {
  return new Inst<unknown>(
    session,
    BigInt(wire.gas_limit),
    wireKindToInstKind(wire.kind),
    (w) => w as unknown,
  );
}

function wireKindToInstKind(k: WireInstKind): InstKind {
  if (k === "Issuance") return { kind: "Issuance" };
  if (k === "Sponsor") return { kind: "Sponsor" };
  if ("Call" in k) {
    return {
      kind: "Call",
      contract: ContractAddress.fromWire(k.Call.contract),
      fnName: "",
      expr: k.Call.expr,
    };
  }
  if ("Publish" in k) {
    return {
      kind: "Publish",
      name: k.Publish.name,
      bytes: Uint8Array.from(k.Publish.bytes),
    };
  }
  if ("RegisterBlsKey" in k) {
    return {
      kind: "RegisterBlsKey",
      blsPubkey: Uint8Array.from(k.RegisterBlsKey.bls_pubkey),
      schnorrSig: Uint8Array.from(k.RegisterBlsKey.schnorr_sig),
      blsSig: Uint8Array.from(k.RegisterBlsKey.bls_sig),
    };
  }
  throw new Error(`unknown wire Inst kind: ${JSON.stringify(k)}`);
}

function instKindToWire(k: InstKind): WireInstKind {
  switch (k.kind) {
    case "Call":
      return { Call: { contract: k.contract.toWire(), expr: k.expr } };
    case "Issuance":
      return "Issuance";
    case "Publish":
      return { Publish: { name: k.name, bytes: [...k.bytes] } };
    case "RegisterBlsKey":
      return {
        RegisterBlsKey: {
          bls_pubkey: [...k.blsPubkey],
          schnorr_sig: [...k.schnorrSig],
          bls_sig: [...k.blsSig],
        },
      };
    case "Sponsor":
      return "Sponsor";
  }
}
