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
const values = (us: readonly Utxo[]): bigint[] => us.map((u) => u.value);

test("in-memory leases sort candidates and settle only their own reservation", async () => {
  const big = utxo("a", 100_000n);
  const small = utxo("b", 20_000n);
  const source = inMemoryFunding([big, small]);
  const first = await source.reserve();
  expect(values(first.utxos)).toEqual([20_000n, 100_000n]);
  await expect(source.reserve()).rejects.toThrow(/single-flight/);
  first.settle({
    spent: [small],
    change: [utxo("d", 40_000n), utxo("e", 330n)],
  });
  const next = await source.reserve();
  expect(values(next.utxos)).toEqual([330n, 40_000n, 100_000n]);
  first.release();
  first.settle({ spent: [], change: [small] });
  await expect(source.reserve()).rejects.toThrow(/single-flight/);
  next.release();
  expect(values((await source.reserve()).utxos)).toEqual([
    330n,
    40_000n,
    100_000n,
  ]);
});

test("release before publication restores candidates and empty pools reject", async () => {
  const source = inMemoryFunding([utxo("a", 1000n)]);
  const reservation = await source.reserve();
  reservation.release();
  expect(values((await source.reserve()).utxos)).toEqual([1000n]);
  await expect(inMemoryFunding([]).reserve()).rejects.toThrow(/no spendable/);
});

test("reservation copies inputs and rejects foreign settlement without losing ownership", async () => {
  const original = utxo("a", 1000n);
  const source = inMemoryFunding([original]);
  original.value = 99n;
  const reservation = await source.reserve();
  expect(reservation.utxos[0]!.value).toBe(1000n);
  expect(() =>
    reservation.settle({ spent: [utxo("b", 500n)], change: [] }),
  ).toThrow(/unreserved/);
  await expect(source.reserve()).rejects.toThrow(/single-flight/);
  reservation.release();
  expect((await source.reserve()).utxos).toHaveLength(1);
});

test("duplicate backend outpoints cannot create two spend candidates", async () => {
  const coin = utxo("a", 1000n);
  await expect(inMemoryFunding([coin, coin]).reserve()).rejects.toThrow(
    /duplicate/,
  );
  await expect(
    queryFunding(async () => [coin, coin]).reserve(),
  ).rejects.toThrow(/duplicate/);
});

test("query leases isolate overlapping asynchronous snapshots and preserve backend order", async () => {
  const a = utxo("a", 50_000n),
    b = utxo("b", 330n),
    c = utxo("c", 500n);
  const resolvers: Array<(coins: Utxo[]) => void> = [];
  const source = queryFunding(
    () => new Promise((resolve) => resolvers.push(resolve)),
  );
  const first = source.reserve(),
    second = source.reserve();
  resolvers[0]!([a, b]);
  const leaseA = await first;
  resolvers[1]!([a, b, c]);
  const leaseB = await second;
  expect(values(leaseA.utxos)).toEqual([50_000n, 330n]);
  expect(leaseB.utxos).toEqual([c]);
  leaseA.settle({ spent: [a], change: [] });
  leaseA.release();
  const third = source.reserve();
  resolvers[2]!([a, b, c]);
  const leaseC = await third;
  expect(leaseC.utxos).toEqual([b]);
  leaseB.release();
  leaseC.release();
});

test("query funding filters retired inputs until omitted by the backend", async () => {
  const a = utxo("a", 1000n),
    b = utxo("b", 2000n);
  let snapshot = [a, b];
  const source = queryFunding(async () => snapshot);
  const first = await source.reserve();
  first.settle({ spent: [a], change: [utxo("c", 500n)] });
  const second = await source.reserve();
  expect(second.utxos).toEqual([b]);
  second.release();
  snapshot = [b];
  (await source.reserve()).release();
  snapshot = [a, b];
  expect((await source.reserve()).utxos).toEqual([a, b]);
});

test("narrowed in-memory leases preserve unused coins exactly once on release and settlement", async () => {
  const a = utxo("a", 1000n),
    b = utxo("b", 2000n),
    change = utxo("c", 500n);
  const source = inMemoryFunding([a, b]);
  const first = await source.reserve();
  first.retain([a]);
  first.retain([a]);
  expect(first.utxos).toEqual([a]);
  expect(() => first.retain([a, b])).toThrow(/unreserved/);
  await expect(source.reserve()).rejects.toThrow(/single-flight/);
  first.release();
  const second = await source.reserve();
  expect(second.utxos).toEqual([a, b]);
  second.retain([a]);
  second.settle({ spent: [a], change: [change] });
  const third = await source.reserve();
  expect(third.utxos).toEqual([change, b]);
  second.release();
  await expect(source.reserve()).rejects.toThrow(/single-flight/);
});

test("query narrowing releases only unused keys, including release after preparation failure", async () => {
  const a = utxo("a", 1000n),
    b = utxo("b", 2000n);
  const source = queryFunding(async () => [a, b]);
  const first = await source.reserve();
  first.retain([a]);
  const second = await source.reserve();
  expect(second.utxos).toEqual([b]);
  expect(() => first.retain([b])).toThrow(/unreserved/);
  first.release();
  const third = await source.reserve();
  expect(third.utxos).toEqual([a]);
  first.release();
  await expect(source.reserve()).rejects.toThrow(/no unreserved/);
  second.release();
  third.release();
  expect((await source.reserve()).utxos).toEqual([a, b]);
});
