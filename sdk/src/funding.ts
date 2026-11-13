import { ChainError } from "./errors.js";
import type { Utxo } from "./json-codec.js";

export interface FundingDelta {
  spent: Utxo[];
  change: Utxo[];
}

/** One reservation. Its terminal methods cannot affect a later reservation. */
export interface FundingLease {
  readonly utxos: readonly Utxo[];
  /** Only when this submission has not attempted publication. */
  release(): void;
  /** Retire spent/at-risk candidates and admit verified usable change. */
  settle(delta: FundingDelta): void;
}

export interface FundingSource {
  reserve(): Promise<FundingLease>;
}

const keyOf = (utxo: Utxo): string => `${utxo.txid.toLowerCase()}:${utxo.vout}`;
const copy = (utxos: readonly Utxo[]): Utxo[] =>
  utxos.map((utxo) => ({ ...utxo }));

function dustFirst(utxos: Utxo[]): Utxo[] {
  return utxos.sort((a, b) =>
    a.value < b.value ? -1 : a.value > b.value ? 1 : 0,
  );
}

function lease(
  candidates: Utxo[],
  finish: (delta: FundingDelta) => void,
): FundingLease {
  const owned = copy(candidates);
  const keys = new Set(owned.map(keyOf));
  if (keys.size !== owned.length)
    throw new ChainError("funding returned duplicate outpoints");
  let open = true;
  const settle = (delta: FundingDelta): void => {
    if (!open) return;
    if (delta.spent.some((utxo) => !keys.has(keyOf(utxo))))
      throw new ChainError("funding settlement spends an unreserved outpoint");
    finish({ spent: copy(delta.spent), change: copy(delta.change) });
    open = false;
  };
  return {
    utxos: Object.freeze(owned.map((utxo) => Object.freeze({ ...utxo }))),
    release: () => settle({ spent: [], change: [] }),
    settle,
  };
}

/** Dust-first optimistic chaining with one outstanding reservation. */
export function inMemoryFunding(initial: Utxo[]): FundingSource {
  let pool = dustFirst(copy(initial));
  let reserved = false;
  return {
    async reserve(): Promise<FundingLease> {
      if (reserved)
        throw new ChainError(
          "inMemoryFunding: prior submission unresolved; single-flight funding requires recovery or completion",
          { docsPath: "/sdk/funding" },
        );
      if (!pool.length)
        throw new ChainError(
          "inMemoryFunding: no spendable UTXOs left in the pool",
          { docsPath: "/sdk/funding" },
        );
      const taken = pool;
      const reservation = lease(taken, ({ spent, change }) => {
        const spentKeys = new Set(spent.map(keyOf));
        pool = dustFirst([
          ...taken.filter((utxo) => !spentKeys.has(keyOf(utxo))),
          ...change,
        ]);
        reserved = false;
      });
      reserved = true;
      pool = [];
      return reservation;
    },
  };
}

/**
 * Query-backed funding, without an optimistic change cache. fetch must return a
 * complete authoritative wallet snapshot. Reservations and spent-outpoint filters
 * are shared by this source instance, not across processes or separate wallets.
 */
export function queryFunding(fetch: () => Promise<Utxo[]>): FundingSource {
  const reserved = new Set<string>();
  const retired = new Set<string>();
  return {
    async reserve(): Promise<FundingLease> {
      const snapshot = copy(await fetch());
      const present = new Set(snapshot.map(keyOf));
      for (const key of retired) if (!present.has(key)) retired.delete(key);
      const taken = snapshot.filter(
        (utxo) => !reserved.has(keyOf(utxo)) && !retired.has(keyOf(utxo)),
      );
      if (!taken.length)
        throw new ChainError(
          "queryFunding: no unreserved spendable UTXOs; recover unresolved submissions or refresh the wallet",
        );
      const reservation = lease(taken, ({ spent }) => {
        for (const utxo of spent) retired.add(keyOf(utxo));
        for (const utxo of taken) reserved.delete(keyOf(utxo));
      });
      // No await between filtering and reservation, even when queries overlap.
      for (const utxo of taken) reserved.add(keyOf(utxo));
      return reservation;
    },
  };
}
