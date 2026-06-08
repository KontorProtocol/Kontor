/**
 * Unit tests for the `FundingSource` implementations. `inMemoryFunding`
 * owns the dust-first ordering policy and a single-flight reservation;
 * `queryFunding` is a stateless pass-through that keeps its backend's order.
 */
import { test, expect } from "vitest";
import { inMemoryFunding, queryFunding } from "../src/funding.js";
import type { Utxo } from "../src/json-codec.js";

function utxo(tag: string, value: bigint): Utxo {
  return {
    txid: tag.repeat(64).slice(0, 64),
    vout: 0,
    value,
    scriptPubKey: "51",
  };
}

const values = (us: Utxo[]): bigint[] => us.map((u) => u.value);

test("inMemoryFunding: take() returns the pool smallest-value-first", async () => {
  const f = inMemoryFunding([
    utxo("a", 50_000n),
    utxo("b", 330n),
    utxo("c", 10_000n),
  ]);
  expect(values(await f.take())).toEqual([330n, 10_000n, 50_000n]);
});

test("inMemoryFunding: settle folds change + unspent, re-sorted dust-first", async () => {
  const big = utxo("a", 100_000n);
  const f = inMemoryFunding([big, utxo("b", 20_000n)]);
  const taken = await f.take();
  // Spend only the 20k input; the 100k stays unspent. Change is a dust
  // reveal output + a larger commit change, handed in non-sorted order.
  f.settle({
    spent: [taken.find((u) => u.value === 20_000n)!],
    change: [utxo("d", 40_000n), utxo("e", 330n)],
  });
  // Next take: dust (330) first, then 40k, then the leftover 100k.
  expect(values(await f.take())).toEqual([330n, 40_000n, 100_000n]);
});

test("inMemoryFunding: a second take() before settle fails fast (single-flight)", async () => {
  const f = inMemoryFunding([utxo("a", 1000n)]);
  await f.take();
  await expect(f.take()).rejects.toThrow(/single-flight/);
});

test("inMemoryFunding: release returns the reservation to the pool", async () => {
  const f = inMemoryFunding([utxo("a", 1000n), utxo("b", 2000n)]);
  const taken = await f.take();
  f.release(taken);
  // Pool is whole again and re-takeable.
  expect(values(await f.take())).toEqual([1000n, 2000n]);
});

test("inMemoryFunding: an empty pool rejects take()", async () => {
  const f = inMemoryFunding([]);
  await expect(f.take()).rejects.toThrow(/no spendable/i);
});

test("queryFunding: take() returns the backend order verbatim; settle/release no-op", async () => {
  // Deliberately NOT dust-first — a stateless source keeps its own order.
  const backend = [utxo("a", 50_000n), utxo("b", 330n)];
  const f = queryFunding(() => Promise.resolve(backend));
  expect(values(await f.take())).toEqual([50_000n, 330n]);
  // No-ops don't throw and don't change the next fetch.
  f.settle({ spent: backend, change: [] });
  f.release(backend);
  expect(values(await f.take())).toEqual([50_000n, 330n]);
});
