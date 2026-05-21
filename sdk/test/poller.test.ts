/**
 * Unit tests for the indexer-following loop: the `BlockHashCache` and
 * the `ResultsPoller`'s drain + reorg-detection behaviour, driven by a
 * mock `fetch`.
 */
import { test, expect } from "vitest";
import { BlockHashCache, ResultsPoller } from "../src/poller.js";

// ─── BlockHashCache ───────────────────────────────────────────────

test("BlockHashCache: insert + get", () => {
  const c = new BlockHashCache(10);
  c.insert(1, "a");
  c.insert(2, "b");
  expect(c.get(1)).toBe("a");
  expect(c.get(2)).toBe("b");
  expect(c.get(3)).toBeUndefined();
});

test("BlockHashCache: re-insert of a known height is a no-op", () => {
  const c = new BlockHashCache(10);
  c.insert(1, "a");
  c.insert(1, "different");
  expect(c.get(1)).toBe("a");
});

test("BlockHashCache: capacity evicts the oldest-inserted entry", () => {
  const c = new BlockHashCache(2);
  c.insert(1, "a");
  c.insert(2, "b");
  c.insert(3, "c"); // evicts height 1
  expect(c.get(1)).toBeUndefined();
  expect(c.get(2)).toBe("b");
  expect(c.get(3)).toBe("c");
});

test("BlockHashCache: truncateAbove drops entries above the fork", () => {
  const c = new BlockHashCache(10);
  for (let h = 1; h <= 5; h++) c.insert(h, `h${h}`);
  c.truncateAbove(3);
  expect(c.get(3)).toBe("h3");
  expect(c.get(4)).toBeUndefined();
  expect(c.get(5)).toBeUndefined();
  expect(c.minHeight()).toBe(1);
});

// ─── ResultsPoller ────────────────────────────────────────────────

interface MockInfo {
  height: number;
  last_result_id: number;
  recent_blocks: Array<{ height: number; hash: string }>;
  signature: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Build a `fetch` that serves `GET /api/` from a scripted sequence of
 * `Info` snapshots (bootstrap = first, then one per long-poll), and
 * `GET /api/results` from a fixed row set. Long-polls past the script
 * just repeat the last snapshot, so the loop idles.
 */
function mockFetch(opts: {
  infos: MockInfo[];
  results?: unknown[];
}): typeof fetch {
  let pollCount = 0;
  return (async (url: string) => {
    const path = url.replace(/^.*\/api/, "");
    let result: unknown;
    if (path === "/") {
      result = opts.infos[0]; // bootstrap
    } else if (path.startsWith("/?wait=")) {
      await sleep(5); // mimic a long-poll, avoid a busy loop
      pollCount += 1;
      result = opts.infos[Math.min(pollCount, opts.infos.length - 1)];
    } else if (path.startsWith("/results")) {
      result = { results: opts.results ?? [], pagination: { has_more: false, next_offset: null, total_count: 0 } };
    } else {
      throw new Error(`unexpected mock path: ${path}`);
    }
    return new Response(JSON.stringify({ result }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

function row(id: number, txid: string, height: number, status = "Ok") {
  return {
    id,
    height,
    tx_index: 0,
    input_index: 0,
    op_index: 0,
    result_index: 0,
    func: "transfer",
    gas: 10,
    status,
    value: null,
    contract: "token_0_0",
    txid,
    signer_id: 1,
  };
}

test("ResultsPoller: drains results into a per-tx event", async () => {
  const fetch = mockFetch({
    infos: [
      { height: 1, last_result_id: 0, recent_blocks: [{ height: 1, hash: "a" }], signature: "s0" },
      { height: 1, last_result_id: 2, recent_blocks: [{ height: 1, hash: "a" }], signature: "s1" },
    ],
    // two op-results sharing one txid → one `tx` event, two outcomes
    results: [row(1, "txAA", 1), row(2, "txAA", 1)],
  });
  const poller = new ResultsPoller({ baseUrl: "http://test/api", fetch });
  const iter = poller.events();
  poller.start();

  const first = await iter.next();
  poller.stop();

  expect(first.done).toBe(false);
  const ev = first.value!;
  expect(ev.kind).toBe("tx");
  if (ev.kind !== "tx") throw new Error("expected tx");
  expect(ev.txid).toBe("txAA");
  expect(ev.id).toBe(2); // cursor = last row id in the group
  expect(ev.height).toBe(1n);
  expect(ev.outcomes).toHaveLength(2);
  expect(ev.outcomes[0]!.gas).toBe(10n);
});

test("ResultsPoller: a changed recent-block hash yields a reorg event", async () => {
  const fetch = mockFetch({
    infos: [
      {
        height: 3,
        last_result_id: 0,
        recent_blocks: [
          { height: 3, hash: "c" },
          { height: 2, hash: "b" },
          { height: 1, hash: "a" },
        ],
        signature: "s0",
      },
      {
        // height 3 re-mined: c → c2; the fork point is height 2
        height: 3,
        last_result_id: 0,
        recent_blocks: [
          { height: 3, hash: "c2" },
          { height: 2, hash: "b" },
          { height: 1, hash: "a" },
        ],
        signature: "s1",
      },
    ],
  });
  const poller = new ResultsPoller({ baseUrl: "http://test/api", fetch });
  const iter = poller.events();
  poller.start();

  const first = await iter.next();
  poller.stop();

  const ev = first.value!;
  expect(ev.kind).toBe("reorg");
  if (ev.kind !== "reorg") throw new Error("expected reorg");
  expect(ev.forkHeight).toBe(2n);
});

test("ResultsPoller: ready() resolves once the node is reachable", async () => {
  const fetch = mockFetch({
    infos: [
      { height: 1, last_result_id: 0, recent_blocks: [{ height: 1, hash: "a" }], signature: "s0" },
    ],
  });
  const poller = new ResultsPoller({ baseUrl: "http://test/api", fetch });
  poller.start();
  await expect(poller.ready()).resolves.toBeUndefined();
  poller.stop();
});

test("ResultsPoller: ready() rejects when the node is unreachable", async () => {
  const deadFetch = (() =>
    Promise.reject(new Error("ECONNREFUSED"))) as typeof fetch;
  const poller = new ResultsPoller({
    baseUrl: "http://test/api",
    fetch: deadFetch,
    retryBackoffMs: 1, // keep the bootstrap retries near-instant
  });
  poller.start();
  await expect(poller.ready()).rejects.toThrow(/poll request failed/);
  poller.stop();
});
