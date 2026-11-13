import { expect, test, vi } from "vitest";
import { signet } from "../src/chains.js";
import { Identity } from "../src/identity.js";
import { HttpTransport } from "../src/transport/http.js";
import { TransportError } from "../src/errors.js";
import type {
  ExecutionContextInfo,
  ProtocolSnapshot,
} from "../src/protocol.js";
import type { KontorTransport, OpResultRaw } from "../src/json-codec.js";
import { KontorSession } from "../src/session.js";
import { ContractAddress } from "../src/canonical/ContractAddress.js";
import { inMemoryFunding } from "../src/funding.js";

const context: ExecutionContextInfo = {
  protocol_id: "11".repeat(32),
  execution_definition: "22".repeat(32),
  application_ordinal: "9007199254740993",
  lineage: "33".repeat(32),
  bitcoin_height: "120",
  bitcoin_hash: "44".repeat(32),
  checkpoint_height: "119",
  checkpoint_hash: "55".repeat(32),
  receipt_epoch: "3",
  rollback_generation: "2",
  simulation_height: "121",
};

const identity = Identity.fromXOnly(
  "8c7fc6552af4384a13791e63bac79ff2bcfeedf143a88d6dc4b6080a8829cdc1",
  signet,
);

const recovering: ProtocolSnapshot = {
  availability: "recovering",
  chain_id: "11".repeat(32),
  certified: {
    authenticated_height: "9007199254740993",
    authenticated_decision: "22".repeat(32),
    closed_height: "9007199254740992",
    closure_id: "33".repeat(32),
    ordering_protocol_id: "44".repeat(32),
    ordering_era_id: "55".repeat(32),
  },
  canonical: null,
  installed_protocols: [],
  build: null,
};

test("protocol discovery is read-only, keeps exact heights, and preserves recovery status", async () => {
  const transport = new HttpTransport({
    chain: signet,
    identity,
    url: "http://node/api/",
    headers: { authorization: "test-token" },
    fetch: (async (url, init) => {
      expect(String(url)).toBe("http://node/api/protocol");
      expect(init?.method).toBe("GET");
      expect(init?.body).toBeUndefined();
      expect(new Headers(init?.headers).get("authorization")).toBe(
        "test-token",
      );
      return new Response(JSON.stringify({ result: recovering }));
    }) as typeof fetch,
  });
  const state = await transport.protocol();
  expect(state).toEqual(recovering);
  expect(
    BigInt(state.certified!.authenticated_height) -
      BigInt(state.certified!.closed_height),
  ).toBe(1n);
});

test("protocol discovery propagates unavailable and malformed replies", async () => {
  for (const response of [
    new Response(JSON.stringify({ error: "history unavailable" }), {
      status: 503,
    }),
    new Response("not JSON"),
  ]) {
    const transport = new HttpTransport({
      chain: signet,
      identity,
      fetch: (async () => response) as typeof fetch,
    });
    await expect(transport.protocol()).rejects.toBeInstanceOf(TransportError);
  }
});

test("contextual HTTP simulation releases funding on composition and response failures", async () => {
  const coins = [
    { txid: "11".repeat(32), vout: 0, value: 10000n, scriptPubKey: "" },
  ];
  for (const failure of ["compose", "http", "json", "none"]) {
    const funding = inMemoryFunding(coins);
    const reserve = funding.reserve.bind(funding);
    const settle = vi.fn();
    vi.spyOn(funding, "reserve").mockImplementation(async () => {
      const lease = await reserve();
      return {
        ...lease,
        settle: (delta) => {
          settle(delta);
          lease.settle(delta);
        },
      };
    });
    const fetch = vi.fn(
      async (url: string | URL | Request, init?: RequestInit) => {
        expect(String(url)).toBe(
          "http://node/api/transactions/simulate/context",
        );
        expect(init?.method).toBe("POST");
        expect(JSON.parse(init?.body as string)).toEqual({ hex: "0102" });
        if (failure === "http")
          return new Response("unavailable", { status: 503 });
        if (failure === "json") return new Response("invalid JSON");
        return new Response(
          JSON.stringify({ result: { context, operations: [] } }),
        );
      },
    );
    const transport = new HttpTransport({
      chain: signet,
      identity,
      funding,
      fetch,
      url: "http://node/api",
    });
    const compose = vi.spyOn(transport, "composeAndSign");
    if (failure === "compose") {
      compose.mockRejectedValue(new Error("composition failed"));
    } else {
      // Signing has its own tests. Isolate the HTTP boundary and reservation here.
      compose.mockResolvedValue({
        revealTx: { extract: () => new Uint8Array([1, 2]) },
      } as Awaited<ReturnType<HttpTransport["composeAndSign"]>>);
    }
    try {
      const preview = transport.simulateWithContext({
        ops: [],
        aggregate: null,
      });
      if (failure === "none") {
        expect(await preview).toEqual({ context, operations: [] });
      } else {
        await expect(preview).rejects.toThrow();
      }
      expect(fetch).toHaveBeenCalledTimes(failure === "compose" ? 0 : 1);
      expect(settle).not.toHaveBeenCalled();
      const lease = await funding.reserve();
      const available = lease.utxos;
      expect(available).toEqual(coins);
      lease.release();
    } finally {
      compose.mockRestore();
    }
  }
});

test("typed simulations preserve gas and context from one execution, without a discovery race", async () => {
  const outcomes: OpResultRaw[] = [
    {
      status: "Ok",
      gas: 21n,
      value: "42",
      func: "value",
      contract: "test_0_0",
      inputIndex: 0,
      opIndex: 0,
    },
    {
      status: "OutOfFuel",
      gas: 50n,
      func: "other",
      contract: "test_0_0",
      inputIndex: 0,
      opIndex: 1,
    },
  ];
  const protocol = vi.fn(async () => {
    throw new Error("must not fetch a later context");
  });
  const simulate = vi.fn(async () => {
    throw new Error("must not fall back to context-free results");
  });
  const simulateWithContext = vi.fn(async () => ({
    context,
    operations: outcomes,
  }));
  const transport = {
    protocol,
    simulate,
    simulateWithContext,
  } as unknown as KontorTransport;
  const session = new KontorSession({
    chain: signet,
    identity,
    transport: () => transport,
  });
  const address = new ContractAddress("test", 0n, 0n);
  const first = session.call(address, "value", "value()", BigInt);
  const second = session.call(address, "other", "other()", String);
  try {
    const single = await first.simulateWithContext();
    expect(single.context).toEqual(context);
    expect(single.result).toMatchObject({ value: 42n, gas: 21n, status: "Ok" });
    const batch = await session.bulk(first, second).simulateWithContext();
    expect(batch.context).toEqual(context);
    expect(batch.result[0]).toMatchObject({ value: 42n, gas: 21n });
    expect(batch.result[1]).toMatchObject({ status: "OutOfFuel", gas: 50n });
    expect(simulateWithContext).toHaveBeenCalledTimes(2);
    expect(protocol).not.toHaveBeenCalled();
    expect(simulate).not.toHaveBeenCalled();
    delete transport.simulateWithContext;
    await expect(first.simulateWithContext()).rejects.toBeInstanceOf(
      TransportError,
    );
    await expect(
      session.bulk(first, second).simulateWithContext(),
    ).rejects.toBeInstanceOf(TransportError);
    expect(simulate).not.toHaveBeenCalled();
  } finally {
    session.close();
  }
});
