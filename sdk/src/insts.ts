/**
 * `Insts<T>` is the SDK-side reflection of Kontor's wire-level
 * `Insts` — the broadcastable bundle of one or more `Inst`s plus an
 * optional aggregate authorization. Built by:
 *
 *   - `session.bulk(inst1, inst2, ...)` — returns `Insts<[A, B, ...]>`
 *     where each input Inst's typed result populates one slot of the
 *     tuple.
 *   - `session.combineAggregate(fragments)` — returns
 *     `Insts<unknown[]>` because per-contributor result types don't
 *     survive the serialization boundary.
 *
 * Same execution surfaces as `Inst<T>`, mirroring the submit/wait
 * split:
 *
 *   - `insts.inspect()` / `.simulate()` — dry-runs, return the mapped
 *     tuple of `OpResult<T[K]>` directly (no broadcast).
 *   - `insts.submit()` — broadcasts the whole bundle as one Bitcoin
 *     tx, returns a `SubmittedTx` handle whose `wait()` resolves the
 *     tuple of per-Inst outcomes once the indexer surfaces them.
 *
 * `Insts<T>` is `PromiseLike` — `await insts` is sugar for
 * `submit()` → `wait()` → unwrap each `OpResult.value` into a tuple
 * (throws `ContractError` if any Inst's status is not Ok).
 */

import type { AggregateInfo } from "./aggregate.js";
import { ContractError } from "./errors.js";
import type { Inst, SubmittedTx } from "./inst.js";
import type { OpResult } from "./json-codec.js";
import type { KontorSession } from "./session.js";

/**
 * Mapped-tuple type: turn `[Inst<A>, Inst<B>, ...]` into
 * `[OpResult<A>, OpResult<B>, ...]`. Used by `Insts<T>` to keep
 * per-slot typing accurate.
 */
export type InstsOpResults<T extends readonly unknown[]> = {
  [K in keyof T]: OpResult<T[K]>;
};

export class Insts<T extends readonly unknown[]> implements PromiseLike<T> {
  /**
   * @param session    Bound execution surface.
   * @param insts      The ordered Insts to broadcast (≥1).
   * @param aggregate  Aggregate authorization data, present only when
   *                   this bundle was built via `combineAggregate`.
   */
  constructor(
    private readonly session: KontorSession,
    readonly insts: readonly Inst<unknown>[],
    readonly aggregate: AggregateInfo | null,
  ) {}

  /**
   * `await insts` broadcasts the whole bundle as one Bitcoin tx,
   * waits for it to land, and returns the tuple of unwrapped typed
   * values. Throws `ContractError` if any Inst's status is non-Ok —
   * use `submit()` directly when you want the txid early or per-Inst
   * telemetry regardless of outcome.
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
      .then(unwrapAllOrThrow<T>)
      .then(onfulfilled, onrejected);
  }

  /**
   * Broadcast for real. Resolves to a `SubmittedTx` handle as soon as
   * the bundle's tx is in the mempool — `handle.txid` is available
   * immediately, `handle.wait()` resolves the tuple of per-Inst
   * `OpResult`s (`InstsOpResults<T>`) once the indexer surfaces them.
   */
  async submit(): Promise<SubmittedTx<InstsOpResults<T>>> {
    throw new Error("Insts.submit: not implemented");
  }

  /** Sandboxed live execution; returns the same tuple shape as `submit`. */
  async simulate(): Promise<InstsOpResults<T>> {
    throw new Error("Insts.simulate: not implemented");
  }

  /** Static analysis; returns the same tuple shape as `submit`. */
  async inspect(): Promise<InstsOpResults<T>> {
    throw new Error("Insts.inspect: not implemented");
  }
}

function unwrapAllOrThrow<T extends readonly unknown[]>(
  results: InstsOpResults<T>,
): T {
  const out: unknown[] = [];
  for (const r of results as readonly OpResult<unknown>[]) {
    if (r.status === "Ok" && r.value !== undefined) {
      out.push(r.value);
    } else {
      throw new ContractError(
        `bulk Inst failed with status: ${r.status}`,
        { details: r.error },
      );
    }
  }
  return out as unknown as T;
}
