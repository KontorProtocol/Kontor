/**
 * Unit tests for `session.bulk(...)` → `Insts`: that a bundle's ops map
 * back onto their Insts by op index, each decoded with its own decoder.
 * The real broadcast path is covered by the live regtest suite; here a
 * mock transport feeds canned per-op outcomes.
 */
import { test, expect, afterEach } from "vitest";
import {
  type Account,
  type KontorTransport,
  ContractAddress,
  HolderRef,
  KontorSession,
  signet,
} from "@kontor/sdk";

const stubAccount: Account = {
  xOnlyPubKey: "00".repeat(32),
  address: "tb1pstub",
  holderRef: HolderRef.xOnlyPubkey("00".repeat(32)),
  signMessage: () => Promise.reject(new Error("stub")),
  signPsbt: () => Promise.reject(new Error("stub")),
};

/** Idle poller: bootstraps, then long-polls with nothing to report. */
const pollerFetch = (async (url: string) => {
  const body = url.includes("/results")
    ? { results: [], pagination: { has_more: false, next_offset: null, total_count: 0 } }
    : { last_result_id: 0, recent_blocks: [], signature: "idle" };
  if (url.includes("?wait=")) await new Promise((r) => setTimeout(r, 5));
  return new Response(JSON.stringify({ result: body }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}) as typeof fetch;

const openSessions: KontorSession[] = [];
afterEach(() => {
  for (const s of openSessions) s.close();
  openSessions.length = 0;
});

/** A session whose transport's `simulate` returns `outcomes` verbatim. */
function mockSession(simulate: KontorTransport["simulate"]): KontorSession {
  const fail = () => Promise.reject(new Error("bulk test: only simulate"));
  const transport: KontorTransport = {
    view: fail,
    inspect: fail,
    simulate,
    submit: fail,
    compose: fail,
    composeReveal: fail,
  };
  const session = new KontorSession({
    chain: signet,
    account: stubAccount,
    transport: () => transport,
    fetch: pollerFetch,
  });
  openSessions.push(session);
  return session;
}

test("bulk: simulate maps each op to its slot, decoded per-Inst", async () => {
  const session = mockSession(() =>
    Promise.resolve([
      { status: "Ok", gas: 1n, value: "42", func: "f", contract: "c_0_0", inputIndex: 0, opIndex: 0 },
      { status: "Ok", gas: 2n, value: "99", func: "g", contract: "c_0_0", inputIndex: 0, opIndex: 1 },
    ]),
  );
  const addr = new ContractAddress("c", 0n, 0n);
  const i1 = session.call(addr, "f", "f()", (w) => Number(w));
  const i2 = session.call(addr, "g", "g()", (w) => `decoded:${w}`);

  const [r1, r2] = await session.bulk(i1, i2).simulate();

  expect(r1.status).toBe("Ok");
  expect(r1.gas).toBe(1n);
  expect(r1.value).toBe(42); // i1's decoder: Number
  expect(r2.value).toBe("decoded:99"); // i2's decoder
});

test("bulk: a wrongly-ordered transport response is realigned by op index", async () => {
  // Op 1 listed before op 0 — `mapBundleOutcomes` selects by index.
  const session = mockSession(() =>
    Promise.resolve([
      { status: "Ok", gas: 2n, value: "b", func: "g", contract: "c_0_0", inputIndex: 0, opIndex: 1 },
      { status: "Ok", gas: 1n, value: "a", func: "f", contract: "c_0_0", inputIndex: 0, opIndex: 0 },
    ]),
  );
  const addr = new ContractAddress("c", 0n, 0n);
  const [r1, r2] = await session
    .bulk(session.call(addr, "f", "f()", (w) => w), session.call(addr, "g", "g()", (w) => w))
    .simulate();
  expect(r1.value).toBe("a");
  expect(r2.value).toBe("b");
});

test("bulk: rejects an empty bundle", () => {
  const session = mockSession(() => Promise.resolve([]));
  expect(() => session.bulk()).toThrow(/at least one Inst/);
});
