import { afterEach, expect, test, vi } from "vitest";
import {
  ContractAddress,
  ContractError,
  Decimal,
  HolderRef,
  KontorSession,
  TransportError,
  signet,
  type KontorTransport,
  type Signing,
} from "@kontor/sdk";
import type { OpResultRaw } from "../src/json-codec.js";
import type { ChainEvent } from "../src/events.js";
import { Contract as Token } from "./__generated__/token.js";
import { Contract as CallResults } from "./__generated__/call-results.js";

const address = new ContractAddress("token", 0n, 0n);
const signing: Signing = {
  identity: {
    xOnlyPubKey: "00".repeat(32),
    address: "tb1pstub",
    holderRef: HolderRef.core(),
  },
  psbt: async () => {
    throw new Error("unexpected signing");
  },
};
const sessions: KontorSession[] = [];
afterEach(() => {
  sessions.splice(0).forEach((session) => session.close());
  vi.restoreAllMocks();
});

function setup(
  responses: Record<string, string> = {},
  outcomes: OpResultRaw[] = [],
) {
  const submit = vi.fn(async () => ({ txid: "tx-results" }));
  const transport = {
    view: vi.fn(async (_address: ContractAddress, expr: string) => {
      const name = expr.slice(0, expr.indexOf("("));
      if (!(name in responses)) throw new Error(`unexpected view: ${expr}`);
      return responses[name];
    }),
    simulate: async () => outcomes,
    inspect: async () => outcomes,
    submit,
  } as unknown as KontorTransport;
  const session = new KontorSession({
    chain: signet,
    signing,
    transport: () => transport,
  });
  sessions.push(session);
  const closed = vi.fn();
  vi.spyOn(session, "events").mockImplementation(
    async function* (): AsyncIterableIterator<ChainEvent> {
      try {
        yield {
          kind: "tx",
          txid: "tx-results",
          id: 1,
          height: 1n,
          txIndex: 0,
          outcomes,
        };
      } finally {
        closed();
      }
    },
  );
  return {
    session,
    transport,
    submit,
    closed,
    token: session.bind(Token, address),
    results: session.bind(CallResults, address),
  };
}

function outcome(
  value: string | undefined,
  status: OpResultRaw["status"] = "Ok",
  opIndex = 0,
): OpResultRaw {
  return {
    status,
    value,
    gas: 12n,
    func: "set-flag",
    contract: "token_0_0",
    inputIndex: 0,
    opIndex,
  };
}

test("outer result aliases unwrap while option and ok/err-shaped data retain their meaning", async () => {
  const responses = {
    "maybe-value": "ok(some(9007199254740993))",
    outcome: '%err("ordinary data")',
    "wrapped-outcome": 'ok(%err("ordinary data"))',
    "check-flag": "ok",
  };
  const { results } = setup(responses);
  expect(await results.maybeValue()).toBe(9007199254740993n);
  responses["maybe-value"] = "ok(some(0))";
  expect(await results.maybeValue()).toBe(0n);
  responses["maybe-value"] = "ok(none)";
  expect(await results.maybeValue()).toBeNull();
  expect(await results.checkFlag()).toBeUndefined();
  expect(await results.outcome()).toEqual({
    kind: "err",
    value: "ordinary data",
  });
  expect(await results.wrappedOutcome()).toEqual({
    kind: "err",
    value: "ordinary data",
  });
  responses["maybe-value"] = 'err(overflow("u64"))';
  await expect(results.maybeValue()).rejects.toMatchObject({
    data: { kind: "overflow", value: "u64" },
    functionName: "maybe-value",
    contract: address,
  });
});

test("transport and malformed-response errors are not treated as contract return values", async () => {
  const { results, transport } = setup({ "check-flag": "not-wave(" });
  await expect(results.checkFlag()).rejects.toThrow();
  const error = new TransportError("offline");
  vi.mocked(transport.view).mockRejectedValue(error);
  await expect(results.checkFlag()).rejects.toBe(error);
});

test("awaiting a generated write throws its structured error and closes its event stream", async () => {
  const { token, submit, closed } = setup({}, [
    outcome('err(message("insufficient funds"))', "ContractErr"),
  ]);
  const call = token
    .transfer(HolderRef.core(), Decimal.from("1"))
    .withGasLimit(123n);
  const error = await Promise.resolve(call).catch((error: unknown) => error);
  expect(error).toBeInstanceOf(ContractError);
  expect(error).toMatchObject({
    data: { kind: "message", value: "insufficient funds" },
    contract: address,
    functionName: "transfer",
  });
  expect(submit).toHaveBeenCalledOnce();
  expect(closed).toHaveBeenCalledOnce();
});

test("simulate, inspect, and submitted wait retain contract errors alongside telemetry", async () => {
  const { results, submit, closed } = setup({}, [
    outcome('err(message("rejected"))', "ContractErr"),
  ]);
  const call = results.setFlag();
  const simulation = await call.simulate();
  const inspection = await call.inspect();
  expect(submit).not.toHaveBeenCalled();
  const submitted = await call.submit();
  expect(submitted.txid).toBe("tx-results");
  const confirmed = await submitted.wait();
  for (const result of [simulation, inspection, confirmed]) {
    expect(result.status).toBe("ContractErr");
    expect(result.gas).toBe(12n);
    expect(result.value).toBeUndefined();
    expect(result.contractError).toBeInstanceOf(ContractError);
    expect(result.contractError?.data).toEqual({
      kind: "message",
      value: "rejected",
    });
  }
  expect(closed).toHaveBeenCalledOnce();
});

test("successful unit results resolve to undefined for single calls and batches", async () => {
  const { session, results } = setup({}, [
    outcome("ok"),
    outcome('%err("ordinary data")', "Ok", 1),
  ]);
  expect(await results.setFlag()).toBeUndefined();
  expect(
    await session.bulk(
      results.setFlag(),
      results.echoOutcome({ kind: "err", value: "ordinary data" }),
    ),
  ).toEqual([undefined, { kind: "err", value: "ordinary data" }]);
});

test("batches also accept successful instructions with no encoded return value", async () => {
  const { session, results } = setup({}, [
    outcome(undefined),
    outcome("ok", "Ok", 1),
  ]);
  expect(await session.bulk(session.issuance(), results.setFlag())).toEqual([
    undefined,
    undefined,
  ]);
});

test("batch diagnostics retain every slot while ordinary await throws the structured error", async () => {
  const { session, results, submit, closed } = setup({}, [
    outcome('err(message("rejected"))', "ContractErr"),
    outcome("ok", "Ok", 1),
  ]);
  const batch = session.bulk(results.setFlag(), results.setFlag());
  const simulated = await batch.simulate();
  expect(simulated[0].contractError?.data).toEqual({
    kind: "message",
    value: "rejected",
  });
  expect(simulated[1]).toMatchObject({
    status: "Ok",
    gas: 12n,
    value: undefined,
  });
  const submitted = await batch.submit();
  const confirmed = await submitted.wait();
  expect(confirmed).toEqual(simulated);
  await expect(Promise.resolve(batch)).rejects.toMatchObject({
    name: "ContractError",
    data: { kind: "message", value: "rejected" },
    functionName: "set-flag",
  });
  expect(submit).toHaveBeenCalledTimes(2);
  expect(closed).toHaveBeenCalledTimes(2);
});

test("execution failures without a WIT value still reject single calls and batches", async () => {
  const { session, results } = setup({}, [
    { ...outcome(undefined, "Trap"), error: "unreachable" },
  ]);
  await expect(Promise.resolve(results.setFlag())).rejects.toMatchObject({
    name: "ContractError",
    details: "unreachable",
  });
  await expect(
    Promise.resolve(session.bulk(results.setFlag())),
  ).rejects.toBeInstanceOf(ContractError);
});

test("structured error data preserves bigint values when rendering its message", () => {
  const data = { amount: 9007199254740993n };
  const error = new ContractError("failed", { data });
  expect(error.data).toBe(data);
  expect(error.message).toContain("9007199254740993");
});
