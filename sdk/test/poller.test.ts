import { test, expect, afterEach } from "vitest";
import { ResultsPoller } from "../src/poller.js";
import { ReceiptStreamError } from "../src/errors.js";

const openPollers: ResultsPoller[] = [];
afterEach(() => {
  for (const poller of openPollers.splice(0)) poller.stop();
});
const token = (cursor: number, generation = 0) => `g${generation}c${cursor}`;
const tokenCursor = (value: string | null) => Number(value?.split("c")[1] ?? 0);
const page = (
  rows: ReturnType<typeof row>[],
  hasMore = false,
  generation = 0,
  highWater?: number,
) => ({
  kind: "page",
  receipts: rows.map((receipt) => ({
    receipt,
    resume_token: token(receipt.id, generation),
  })),
  next_token: token(highWater ?? rows.at(-1)?.id ?? 0, generation),
  has_more: hasMore,
});
const response = (result: unknown) => new Response(JSON.stringify({ result }));

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
  results?: ReturnType<typeof row>[];
}): typeof fetch {
  let pollCount = 0;
  return (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (url.searchParams.has("wait")) {
      await sleep(5);
      pollCount += 1;
    }
    const info = opts.infos[Math.min(pollCount, opts.infos.length - 1)]!;
    if (url.pathname.endsWith("/receipt-stream")) {
      if (url.searchParams.has("start"))
        return response({
          kind: "start",
          resume_token: token(
            url.searchParams.get("start") === "origin"
              ? 0
              : info.last_result_id,
          ),
        });
      const cursor = tokenCursor(
        url.searchParams.get("page") ?? url.searchParams.get("from"),
      );
      return response(
        page(
          (opts.results ?? []).filter(
            (row) => row.id > cursor && row.id <= info.last_result_id,
          ),
          false,
          0,
          info.last_result_id,
        ),
      );
    }
    return response(info);
  }) as typeof fetch;
}

function row(
  id: number,
  txid: string,
  height: number,
  opIndex = 0,
  resultIndex = 0,
) {
  return {
    id,
    height,
    tx_index: 0,
    input_index: 0,
    op_index: opIndex,
    result_index: resultIndex,
    func: "transfer",
    gas: 10,
    status: "Ok",
    value: null,
    contract: "token_0_0",
    txid,
    signer_id: 1,
  };
}

test("ResultsPoller: drains results into a per-tx event", async () => {
  const fetch = mockFetch({
    infos: [
      {
        height: 1,
        last_result_id: 0,
        recent_blocks: [{ height: 1, hash: "a" }],
        signature: "s0",
      },
      {
        height: 1,
        last_result_id: 2,
        recent_blocks: [{ height: 1, hash: "a" }],
        signature: "s1",
      },
    ],
    // two distinct ops (op_index 0 and 1) of one txid → one `tx` event,
    // two outcomes.
    results: [row(1, "txAA", 1, 0), row(2, "txAA", 1, 1)],
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
  expect(ev.executionHeight).toBe(1n);
  expect(ev.confirmedHeight).toBeNull();
  expect(ev.confirmedBitcoinTxIndex).toBeNull();
  expect(ev.outcomes).toHaveLength(2);
  expect(ev.outcomes[0]!.gas).toBe(10n);
});

test("execution events remain snapshots while transaction lookups follow confirmation and reorg", async () => {
  const txid = "aa".repeat(32);
  const receipt = {
    ...row(1, txid, 1),
    execution_height: 1,
    tx_index: null,
    confirmed_height: null,
    confirmed_bitcoin_tx_index: null,
    batch_height: 9,
  };
  let current = {
    id: 1,
    txid,
    height: 1,
    execution_height: 1,
    tx_index: null as number | null,
    confirmed_height: null as number | null,
    confirmed_bitcoin_tx_index: null as number | null,
    batch_height: 9,
  };
  const eventsFetch = mockFetch({
    infos: [
      {
        height: 1,
        last_result_id: 0,
        recent_blocks: [{ height: 1, hash: "a" }],
        signature: "s0",
      },
      {
        height: 1,
        last_result_id: 1,
        recent_blocks: [{ height: 1, hash: "a" }],
        signature: "s1",
      },
    ],
    results: [receipt],
  });
  const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).includes("/transactions/"))
      return new Response(JSON.stringify({ result: current }));
    return eventsFetch(input, init);
  }) as typeof globalThis.fetch;
  const poller = new ResultsPoller({ baseUrl: "http://test/api", fetch });
  const iter = poller.events();
  poller.start();
  const event = (await iter.next()).value!;
  poller.stop();
  expect(event.kind).toBe("tx");
  if (event.kind !== "tx") throw new Error("expected transaction");
  expect(event.txIndex).toBeNull();
  expect(event.batchHeight).toBe(9n);
  expect(event.confirmedHeight).toBeNull();
  expect(event.confirmedBitcoinTxIndex).toBeNull();
  for (const position of [null, 2, null, 4]) {
    current = {
      ...current,
      tx_index: position === null ? null : 0,
      confirmed_height: position === null ? null : 2,
      confirmed_bitcoin_tx_index: position,
    };
    const info = await poller.transaction(txid);
    expect(info?.execution_height).toBe(1);
    expect(info?.batch_height).toBe(9);
    expect(info?.confirmed_height).toBe(position === null ? null : 2);
    expect(info?.confirmed_bitcoin_tx_index).toBe(position);
    expect(event.confirmedBitcoinTxIndex).toBeNull();
    expect(event.outcomes[0]?.coordinates?.confirmedBitcoinTxIndex).toBeNull();
  }
});

test("transaction lookup preserves unknown historical positions and distinguishes errors from absence", async () => {
  let status = 200;
  const fetch = (async () =>
    new Response(
      JSON.stringify({
        result: {
          id: 1,
          txid: "old",
          height: 1,
          tx_index: 0,
          confirmed_height: 2,
          batch_height: null,
        },
      }),
      { status },
    )) as typeof globalThis.fetch;
  const poller = new ResultsPoller({ baseUrl: "http://test/api", fetch });
  expect(await poller.transaction("old")).toMatchObject({
    execution_height: 1,
    confirmed_bitcoin_tx_index: null,
  });
  status = 404;
  await expect(poller.transaction("missing")).resolves.toBeNull();
  status = 500;
  await expect(poller.transaction("failed")).rejects.toThrow(/500/);
});

test.each([
  [null, 2],
  [2, null],
  [2, 4],
])(
  "one event uses one confirmation snapshot across pages (%s to %s)",
  async (before, after) => {
    const txid = "bb".repeat(32);
    const infos = mockFetch({
      infos: [
        {
          height: 2,
          last_result_id: 0,
          recent_blocks: [{ height: 2, hash: "a" }],
          signature: "s0",
        },
        {
          height: 2,
          last_result_id: 2,
          recent_blocks: [{ height: 2, hash: "a" }],
          signature: "s1",
        },
      ],
    });
    const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (
        url.pathname.endsWith("/receipt-stream") &&
        !url.searchParams.has("start")
      ) {
        const second =
          tokenCursor(
            url.searchParams.get("page") ?? url.searchParams.get("from"),
          ) === 1;
        const position = second ? after : before;
        const receipt = {
          ...row(second ? 2 : 1, txid, 1, second ? 1 : 0),
          execution_height: 1,
          confirmed_height: position === null ? null : 2,
          confirmed_bitcoin_tx_index: position,
          batch_height: 9,
        };
        return new Response(
          JSON.stringify({
            result: page([receipt], !second),
          }),
        );
      }
      return infos(input, init);
    }) as typeof globalThis.fetch;
    const poller = new ResultsPoller({ baseUrl: "http://test/api", fetch });
    const iter = poller.events();
    poller.start();
    const event = (await iter.next()).value!;
    poller.stop();
    if (event.kind !== "tx") throw new Error("expected transaction");
    expect(event.id).toBe(2);
    expect(event.outcomes).toHaveLength(2);
    expect(event.confirmedBitcoinTxIndex).toBe(after);
    for (const outcome of event.outcomes) {
      expect(outcome.coordinates).toEqual({
        executionHeight: 1n,
        confirmedHeight: after === null ? null : 2n,
        confirmedBitcoinTxIndex: after,
        batchHeight: 9n,
      });
    }
  },
);

test("mixed execution pages retry without emitting mixed outcomes or duplicating completed transactions", async () => {
  const txid = "cc".repeat(32);
  const infos = mockFetch({
    infos: [
      {
        height: 2,
        last_result_id: 0,
        recent_blocks: [{ height: 2, hash: "a" }],
        signature: "s0",
      },
      {
        height: 2,
        last_result_id: 3,
        recent_blocks: [{ height: 2, hash: "a" }],
        signature: "s1",
      },
    ],
  });
  const cursors: number[] = [];
  const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    if (
      !url.pathname.endsWith("/receipt-stream") ||
      url.searchParams.has("start")
    )
      return infos(input, init);
    const cursor = tokenCursor(
      url.searchParams.get("page") ?? url.searchParams.get("from"),
    );
    cursors.push(cursor);
    const results =
      cursor === 0
        ? [row(1, "completed", 1), row(2, txid, 1)]
        : cursor === 2
          ? [row(3, txid, 2, 0, 1)]
          : [row(2, txid, 2), row(3, txid, 2, 0, 1)];
    return new Response(
      JSON.stringify({
        result: page(results, cursor === 0),
      }),
    );
  }) as typeof globalThis.fetch;
  const poller = new ResultsPoller({
    baseUrl: "http://test/api",
    fetch,
    retryBackoffMs: 1,
  });
  const iter = poller.events();
  poller.start();
  try {
    const first = (await iter.next()).value!;
    expect(first.kind === "tx" && first.txid).toBe("completed");
    const second = (await iter.next()).value!;
    if (second.kind !== "tx") throw new Error("expected transaction");
    expect(cursors).toEqual([0, 2, 1]);
    expect(second.txid).toBe(txid);
    expect(second.executionHeight).toBe(2n);
    expect(second.outcomes).toHaveLength(1);
    expect(second.outcomes[0]!.coordinates?.executionHeight).toBe(2n);
  } finally {
    poller.stop();
    await iter.return!();
  }
});

test("ResultsPoller: collapses one op's rows to its max-result_index result", async () => {
  // The user op and the implicit gas op share (input 0, op 0); the gas
  // op sits at a lower result_index. The poller keeps only the highest
  // — one canonical outcome, mirroring the indexer's `get_op_result`.
  const fetch = mockFetch({
    infos: [
      {
        height: 1,
        last_result_id: 0,
        recent_blocks: [{ height: 1, hash: "a" }],
        signature: "s0",
      },
      {
        height: 1,
        last_result_id: 2,
        recent_blocks: [{ height: 1, hash: "a" }],
        signature: "s1",
      },
    ],
    results: [
      { ...row(1, "txGG", 1, 0, 0), func: "release", gas: 5 },
      { ...row(2, "txGG", 1, 0, 1), func: "transfer", gas: 10 },
    ],
  });
  const poller = new ResultsPoller({ baseUrl: "http://test/api", fetch });
  const iter = poller.events();
  poller.start();

  const ev = (await iter.next()).value!;
  poller.stop();

  if (ev.kind !== "tx") throw new Error("expected tx");
  expect(ev.outcomes).toHaveLength(1);
  expect(ev.outcomes[0]!.func).toBe("transfer");
  expect(ev.outcomes[0]!.gas).toBe(10n);
});

test("same-hash finality replay signals retraction and drains reused IDs", async () => {
  const requests: URL[] = [];
  const stream = [
    {
      kind: "recovery",
      resume_token: token(80, 1),
      fork_height: 1,
      more: false,
    },
    page([row(81, "replacement", 1)], false, 1),
  ];
  const fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    requests.push(url);
    if (url.pathname.endsWith("/receipt-stream"))
      return response(stream.shift() ?? page([], false, 1, 81));
    if (url.searchParams.has("wait")) await sleep(5);
    return response({
      height: 2,
      last_result_id: 100,
      recent_blocks: [{ height: 2, hash: "unchanged" }],
      signature: "new-generation",
    });
  }) as typeof globalThis.fetch;
  const poller = new ResultsPoller({
    baseUrl: "http://test/api",
    fetch,
    from: token(100),
  });
  openPollers.push(poller);
  const iter = poller.events();
  poller.start();
  expect((await iter.next()).value).toEqual({
    kind: "reorg",
    forkHeight: 1n,
    resumeToken: token(80, 1),
  });
  expect((await iter.next()).value).toMatchObject({
    kind: "tx",
    txid: "replacement",
    id: 81,
    resumeToken: token(81, 1),
  });
  poller.stop();
  const pages = requests.filter((url) =>
    url.pathname.endsWith("/receipt-stream"),
  );
  expect(pages[0]!.searchParams.get("from")).toBe(token(100));
  expect(pages[1]!.searchParams.get("from")).toBe(token(80, 1));
});

test("ResultsPoller: ready() resolves once the node is reachable", async () => {
  const fetch = mockFetch({
    infos: [
      {
        height: 1,
        last_result_id: 0,
        recent_blocks: [{ height: 1, hash: "a" }],
        signature: "s0",
      },
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

function scriptedStream(steps: Array<unknown | (() => Response)>) {
  const requests: URLSearchParams[] = [];
  const fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/receipt-stream")) {
      requests.push(new URLSearchParams(url.search));
      const step = steps.shift();
      if (typeof step === "function") return step();
      return response(step ?? page([], false, 0, 100));
    }
    if (url.searchParams.has("wait")) await sleep(5);
    return response({
      height: 2,
      last_result_id: 100,
      recent_blocks: [],
      signature: "same",
    });
  }) as typeof globalThis.fetch;
  return { fetch, requests };
}

function startScript(
  steps: Array<unknown | (() => Response)>,
  from = token(0),
) {
  const mock = scriptedStream(steps);
  const poller = new ResultsPoller({
    baseUrl: "http://test/api",
    fetch: mock.fetch,
    from,
    retryBackoffMs: 1,
  });
  openPollers.push(poller);
  const events = poller.events();
  poller.start();
  return { ...mock, poller, events };
}

test("rollback between pages discards the pending group and preserves completed observations", async () => {
  const { events, requests, poller } = startScript([
    page([row(1, "survivor", 1), row(2, "pending", 2)], true),
    {
      kind: "recovery",
      resume_token: token(1, 1),
      fork_height: 1,
      more: false,
    },
    page([row(2, "replacement", 2, 0), row(3, "replacement", 2, 1)], false, 1),
  ]);
  expect((await events.next()).value).toMatchObject({
    kind: "tx",
    txid: "survivor",
    resumeToken: token(1),
  });
  expect((await events.next()).value).toMatchObject({
    kind: "reorg",
    resumeToken: token(1, 1),
  });
  expect((await events.next()).value).toMatchObject({
    kind: "tx",
    txid: "replacement",
    resumeToken: token(3, 1),
    outcomes: [
      { inputIndex: 0, opIndex: 0 },
      { inputIndex: 0, opIndex: 1 },
    ],
  });
  poller.stop();
  expect(
    requests.map((query) => [query.get("from"), query.get("page")]),
  ).toEqual([
    [token(0), null],
    [token(1), token(2)],
    [token(1, 1), null],
  ]);
});

test("failed continuation retries from the last completed group without duplicate delivery", async () => {
  const { events, requests, poller } = startScript([
    page([row(1, "survivor", 1), row(2, "pending", 2)], true),
    () => new Response("temporary", { status: 503 }),
    page([row(2, "pending", 2, 0), row(3, "pending", 2, 1)]),
  ]);
  expect((await events.next()).value).toMatchObject({ txid: "survivor" });
  expect((await events.next()).value).toMatchObject({
    txid: "pending",
    resumeToken: token(3),
  });
  await poller.ready();
  poller.stop();
  expect(
    requests.map((query) => [query.get("from"), query.get("page")]),
  ).toEqual([
    [token(0), null],
    [token(1), token(2)],
    [token(1), null],
  ]);
});

test("an empty continuation completes pending receipts before advancing the high-water token", async () => {
  const { events, requests, poller } = startScript([
    page([row(1, "pending", 1)], true),
    page([], false, 0, 50),
    page([], false, 0, 50),
  ]);
  expect((await events.next()).value).toMatchObject({
    txid: "pending",
    resumeToken: token(1),
  });
  await poller.ready();
  await expect.poll(() => requests.length).toBeGreaterThanOrEqual(3);
  poller.stop();
  expect(requests[2]!.get("from")).toBe(token(50));
  expect(requests[2]!.has("page")).toBe(false);
});

test("offline resume walks bounded recovery batches before reading replacements", async () => {
  const { events, requests, poller } = startScript(
    [
      {
        kind: "recovery",
        resume_token: token(90, 256),
        fork_height: 3,
        more: true,
      },
      {
        kind: "recovery",
        resume_token: token(80, 300),
        fork_height: 1,
        more: false,
      },
      page([row(81, "new", 2)], false, 300),
    ],
    token(100),
  );
  expect((await events.next()).value).toEqual({
    kind: "reorg",
    forkHeight: 3n,
    resumeToken: token(90, 256),
  });
  expect((await events.next()).value).toEqual({
    kind: "reorg",
    forkHeight: 1n,
    resumeToken: token(80, 300),
  });
  expect((await events.next()).value).toMatchObject({
    txid: "new",
    resumeToken: token(81, 300),
  });
  poller.stop();
  expect(requests.map((query) => query.get("from"))).toEqual([
    token(100),
    token(90, 256),
    token(80, 300),
  ]);
  expect(requests.some((query) => query.has("start"))).toBe(false);
});

test("failed request after recovery resumes its committed token without a second invalidation", async () => {
  const { events, requests, poller } = startScript(
    [
      {
        kind: "recovery",
        resume_token: token(0, 1),
        fork_height: 0,
        more: false,
      },
      () => new Response("temporary", { status: 503 }),
      page([row(1, "new", 1)], false, 1),
    ],
    token(100),
  );
  expect((await events.next()).value).toMatchObject({
    kind: "reorg",
    resumeToken: token(0, 1),
  });
  expect((await events.next()).value).toMatchObject({
    kind: "tx",
    txid: "new",
  });
  poller.stop();
  expect(requests.map((query) => query.get("from"))).toEqual([
    token(100),
    token(0, 1),
    token(0, 1),
  ]);
});

test.each([
  "epoch_mismatch",
  "future_generation",
  "unsupported_lineage",
  "missing_history",
])("%s requires explicit resynchronization", async (reason) => {
  const { poller, events, requests } = startScript([
    { kind: "reset_required", reason },
  ]);
  await expect(poller.ready()).rejects.toMatchObject({
    name: "ReceiptStreamError",
    reason,
  });
  await expect(events.next()).rejects.toMatchObject({ reason });
  expect(requests).toHaveLength(1);
});

test.each(["origin", "tip"] as const)(
  "bootstrap explicitly requests %s and keeps its filter",
  async (start) => {
    const mock = scriptedStream([
      { kind: "start", resume_token: token(start === "tip" ? 100 : 0) },
      page([], false, 0, 100),
    ]);
    const poller = new ResultsPoller({
      baseUrl: "http://test/api",
      fetch: mock.fetch,
      start,
      filter: { contract: "token_0_0", func: "transfer", signerId: 7 },
    });
    openPollers.push(poller);
    poller.events();
    poller.start();
    await poller.ready();
    poller.stop();
    expect(mock.requests[0]!.get("start")).toBe(start);
    expect(mock.requests[1]!.get("from")).toBe(
      token(start === "tip" ? 100 : 0),
    );
    for (const query of mock.requests) {
      expect(query.get("contract")).toBe("token_0_0");
      expect(query.get("func")).toBe("transfer");
      expect(query.get("signer_id")).toBe("7");
    }
  },
);

test("numeric-only resume is rejected rather than assigned a guessed generation", () => {
  expect(
    () =>
      new ResultsPoller({
        baseUrl: "http://test/api",
        fetch,
        from: 100 as unknown as string,
      }),
  ).toThrow(ReceiptStreamError);
});

test("unsafe receipt IDs and non-progressing continuation pages fail closed", async () => {
  for (const malformed of [
    page([row(Number.MAX_SAFE_INTEGER + 1, "bad", 1)]),
    page([], true),
  ]) {
    const { poller } = startScript([malformed]);
    await expect(poller.ready()).rejects.toMatchObject({
      reason: "invalid_response",
    });
  }
});

test("old servers do not silently fall back to unsafe numeric pagination", async () => {
  const { poller } = startScript([
    () => new Response("not found", { status: 404 }),
  ]);
  await expect(poller.ready()).rejects.toMatchObject({
    reason: "unsupported_server",
  });
});

test.each(["origin", "resume"] as const)(
  "ready before events preserves %s history and recovery",
  async (mode) => {
    let reads = 0;
    const info = {
      height: 2,
      last_result_id: 1,
      recent_blocks: [{ height: 2, hash: "same" }],
      signature: "s1",
    };
    const fetch = (async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      if (!url.pathname.endsWith("/receipt-stream")) {
        if (url.searchParams.has("wait")) await sleep(5);
        return response(info);
      }
      if (url.searchParams.has("start"))
        return response({ kind: "start", resume_token: token(0, 1) });
      reads += 1;
      const from = url.searchParams.get("from");
      if (from === token(100, 0))
        return response({
          kind: "recovery",
          resume_token: token(0, 1),
          fork_height: 1,
          more: false,
        });
      return response(
        page(
          from === token(0, 1) ? [row(1, "replacement", 2)] : [],
          false,
          1,
          1,
        ),
      );
    }) as typeof globalThis.fetch;
    const poller = new ResultsPoller({
      baseUrl: "http://test/api",
      fetch,
      ...(mode === "origin"
        ? { start: "origin" as const }
        : { from: token(100, 0) }),
    });
    openPollers.push(poller);
    poller.start();
    await poller.ready();
    await sleep(10);
    expect(reads).toBe(0);
    const iterator = poller.events();
    if (mode === "resume") {
      const recovery = (await iterator.next()).value!;
      expect(recovery).toMatchObject({
        kind: "reorg",
        forkHeight: 1n,
        resumeToken: token(0, 1),
      });
    }
    expect((await iterator.next()).value).toMatchObject({
      kind: "tx",
      txid: "replacement",
      resumeToken: token(1, 1),
    });
  },
);

test("last unsubscribe during a page request preserves undelivered progress", async () => {
  let release!: (value: Response) => void;
  let requested!: () => void;
  const started = new Promise<void>((resolve) => {
    requested = resolve;
  });
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const cursors: Array<string | null> = [];
  const fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (!url.pathname.endsWith("/receipt-stream")) {
      if (url.searchParams.has("wait")) await sleep(5);
      return response({ signature: "s1" });
    }
    cursors.push(url.searchParams.get("from"));
    if (cursors.length === 1) {
      requested();
      return pending;
    }
    return response(page([row(1, "undelivered", 1)]));
  }) as typeof globalThis.fetch;
  const poller = new ResultsPoller({
    baseUrl: "http://test/api",
    fetch,
    from: token(0),
  });
  openPollers.push(poller);
  const first = poller.events();
  poller.start();
  await started;
  await first.return!();
  release(response(page([row(1, "undelivered", 1)])));
  await poller.ready();
  const second = poller.events();
  expect((await second.next()).value).toMatchObject({
    kind: "tx",
    txid: "undelivered",
  });
  expect(cursors.slice(0, 2)).toEqual([token(0), token(0)]);
});

test("later iterators join live progress without replaying earlier events", async () => {
  let release!: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (!url.pathname.endsWith("/receipt-stream")) {
      if (url.searchParams.has("wait")) await sleep(5);
      return response({ signature: "s1" });
    }
    if (url.searchParams.get("from") === token(0))
      return response(page([row(1, "before", 1)]));
    if (url.searchParams.get("from") === token(1)) return pending;
    return response(page([], false, 0, 2));
  }) as typeof globalThis.fetch;
  const poller = new ResultsPoller({
    baseUrl: "http://test/api",
    fetch,
    from: token(0),
  });
  openPollers.push(poller);
  const first = poller.events();
  poller.start();
  expect((await first.next()).value).toMatchObject({ txid: "before" });
  const second = poller.events();
  release(response(page([row(2, "shared", 2)])));
  expect((await first.next()).value).toMatchObject({ txid: "shared" });
  expect((await second.next()).value).toMatchObject({ txid: "shared" });
});
