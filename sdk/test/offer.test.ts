/**
 * Unit tests for the marketplace offer surface — `session.openOffer`
 * and `IncomingOffer.inspect()`. The full `offer()` → `accept()`
 * round-trip is the live regtest test; here we cover the cheap,
 * transport-free guards: blob parsing and static validity.
 */
import { test, expect, afterEach } from "vitest";
import {
  type Account,
  type KontorTransport,
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

/** A session whose transport rejects every call — `openOffer` /
 *  `inspect` never touch it. */
function stubSession(): KontorSession {
  const fail = () => Promise.reject(new Error("offer test: transport unused"));
  const transport: KontorTransport = {
    view: fail,
    inspect: fail,
    simulate: fail,
    submit: fail,
    compose: fail,
    composeReveal: fail,
    broadcast: fail,
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

test("openOffer: rejects a blob that isn't JSON", () => {
  expect(() => stubSession().openOffer("not an offer")).toThrow(
    /not valid JSON/,
  );
});

test("openOffer: rejects an unrecognized blob version", () => {
  expect(() =>
    stubSession().openOffer(JSON.stringify({ v: 99 })),
  ).toThrow(/not a recognized offer/);
});

test("inspect: flags a malformed offer rather than throwing", async () => {
  // A v1 blob whose transaction fields are junk hex — inspect() should
  // report `valid: false` with a reason, not blow up.
  const blob = JSON.stringify({
    v: 1,
    attachCommit: "00",
    attachReveal: "00",
    detachInsts: { ops: [], aggregate: null },
    detachPsbt: "00",
    price: "600",
    seller: "ab".repeat(32),
  });
  const result = await stubSession().openOffer(blob).inspect();
  expect(result.valid).toBe(false);
  expect(result.problem).toBeDefined();
  // The price + seller are still surfaced even on an invalid offer.
  expect(result.price).toBe(600n);
  expect(result.seller).toBe("ab".repeat(32));
});
