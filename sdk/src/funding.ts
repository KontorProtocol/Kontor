/**
 * `FundingSource` — where a transport gets spendable UTXOs for a submit,
 * and where it reports back what it spent and what change it created. The
 * SDK core holds NO funding state and NO lock; it just drives this small
 * protocol around each broadcast:
 *
 *   take() → compose/sign/broadcast → settle({ spent, change })   (success)
 *   take() → …                      → release(taken)              (failure)
 *
 * Two shipped implementations, both with identical `await token.x()`
 * ergonomics — pick by passing one as `KontorSession`'s `funding`:
 *
 *   - `inMemoryFunding(pool)` — optimistic chaining: a submit's change is
 *     available to the next submit immediately (no waiting for
 *     confirmation). For tests / high-throughput sequential use. Lock-free:
 *     `take()` reserves synchronously (single-threaded JS → no interleave),
 *     and FAILS FAST on genuine concurrency rather than queuing.
 *
 *   - `queryFunding(fetch)` — stateless: `take()` re-queries the wallet /
 *     indexer for the current spendable set; `settle`/`release` are no-ops.
 *     The real-app default (the wallet owns coin management).
 */

import { ChainError } from "./errors.js";
import type { Utxo } from "./json-codec.js";

export interface FundingSource {
  /** Candidate spendable UTXOs for the upcoming tx. May reserve them. */
  take(): Promise<Utxo[]>;
  /** After a successful broadcast: `spent` inputs are gone, `change`
   *  outputs are new spendable UTXOs. */
  settle(result: { spent: Utxo[]; change: Utxo[] }): void;
  /** On a failed submit (nothing broadcast): undo any reservation. */
  release(taken: Utxo[]): void;
}

const keyOf = (u: { txid: string; vout: number }): string =>
  `${u.txid}:${u.vout}`;

/** Order UTXOs smallest-value-first. `take()` hands the pool to the
 *  indexer's greedy head-walking selector, so dust at the head gets pulled
 *  in alongside the next larger UTXO and consolidated — rather than letting
 *  dust outputs (the 330-sat reveal change) accumulate over many submits.
 *  Value is sats (`bigint`); compare directly, no `Number()` precision risk. */
function dustFirst(utxos: Utxo[]): Utxo[] {
  return [...utxos].sort((a, b) =>
    a.value < b.value ? -1 : a.value > b.value ? 1 : 0,
  );
}

/**
 * An in-memory chaining pool. `take()` hands out (and reserves) the whole
 * pool, **smallest-value-first** so the indexer consolidates dust; `settle()`
 * drops the spent inputs and folds in the change, re-sorting. Single
 * in-flight reservation: a second `take()` before the first settles fails
 * fast rather than risking a double-spend (you can't chain off one
 * unconfirmed coin twice). In the await-each pattern that never trips,
 * because `take()` 2 runs after `settle()` 1.
 *
 * The dust-first ordering is *this source's* policy — other `FundingSource`
 * implementations (e.g. `queryFunding`) keep whatever order their backend
 * returns.
 */
export function inMemoryFunding(initial: Utxo[]): FundingSource {
  let pool: Utxo[] = dustFirst(initial);
  let outstanding: Utxo[] | null = null;

  return {
    take(): Promise<Utxo[]> {
      if (outstanding !== null) {
        return Promise.reject(
          new ChainError(
            "inMemoryFunding: a prior submit is still in flight — funding is " +
              "single-flight; await each submit before the next",
            { docsPath: "/sdk/funding" },
          ),
        );
      }
      if (pool.length === 0) {
        return Promise.reject(
          new ChainError(
            "inMemoryFunding: no spendable UTXOs left in the pool",
            {
              docsPath: "/sdk/funding",
            },
          ),
        );
      }
      // Reserve synchronously — no await between read and remove, so two
      // takes can't hand out the same coins.
      outstanding = pool;
      pool = [];
      return Promise.resolve(outstanding);
    },

    settle({ spent, change }): void {
      const spentKeys = new Set(spent.map(keyOf));
      const unspent = (outstanding ?? []).filter(
        (u) => !spentKeys.has(keyOf(u)),
      );
      pool = dustFirst([...change, ...unspent]);
      outstanding = null;
    },

    release(): void {
      if (outstanding !== null) {
        pool = dustFirst([...outstanding, ...pool]);
        outstanding = null;
      }
    },
  };
}

/**
 * A stateless funding source: every `take()` re-queries `fetch` for the
 * current spendable set; `settle`/`release` are no-ops. Use when the
 * wallet / indexer is the source of truth (the real-app default) — there's
 * no chaining state to protect, so no lock, ever. You can't spend a tx's
 * own change until it confirms and `fetch` reports it.
 */
export function queryFunding(fetch: () => Promise<Utxo[]>): FundingSource {
  return {
    take: () => fetch(),
    settle: () => {},
    release: () => {},
  };
}
