/**
 * Read-only sessions — built with a bare `identity` (no `signing`), for
 * server-side / view-only use. Construction is side-effect-free (the poller
 * is lazy), so these need no network: `view` is available, but any write
 * path throws a clear error.
 */
import { test, expect } from "vitest";
import { KontorSession, Identity, signet } from "@kontor/sdk";

const XONLY =
  "8c7fc6552af4384a13791e63bac79ff2bcfeedf143a88d6dc4b6080a8829cdc1";

test("transaction metadata lookup does not start background polling", async () => {
  const requests: string[] = [];
  const session = new KontorSession({
    chain: signet,
    identity: Identity.fromXOnly(XONLY, signet),
    fetch: (async (url: RequestInfo | URL) => {
      requests.push(String(url));
      return new Response(
        JSON.stringify({
          result: {
            id: 1,
            txid: "aa",
            height: 1,
            execution_height: 1,
            tx_index: 0,
            confirmed_height: 2,
            confirmed_bitcoin_tx_index: 4,
            batch_height: 9,
          },
        }),
      );
    }) as typeof fetch,
  });
  expect((await session.transaction("aa"))?.confirmed_bitcoin_tx_index).toBe(4);
  expect(requests).toEqual([`${signet.urls.http}/transactions/aa`]);
  session.close();
});

test("read-only session: identity-only, no signer, no side effects", () => {
  const identity = Identity.fromXOnly(XONLY, signet);
  const session = new KontorSession({ chain: signet, identity });
  expect(session.signing).toBeUndefined();
  expect(session.identity.xOnlyPubKey).toBe(XONLY);
  expect(session.identity.address).toBe(identity.address);
  session.close(); // safe even though the poller never started
});

test("read-only session: registerBls throws a clear read-only error", async () => {
  const session = new KontorSession({
    chain: signet,
    identity: Identity.fromXOnly(XONLY, signet),
  });
  await expect(session.registerBls(undefined as never)).rejects.toThrow(
    /read-only/i,
  );
  session.close();
});

test("read-only session: submit() rejects without starting the poller", async () => {
  // A fetch that records if it's ever hit — the poller's only I/O. A
  // read-only submit must reject before the poller starts, so this stays false.
  let polled = false;
  const fetchSpy = ((..._args: unknown[]) => {
    polled = true;
    return Promise.reject(new Error("poller should not have run"));
  }) as unknown as typeof fetch;

  const session = new KontorSession({
    chain: signet,
    identity: Identity.fromXOnly(XONLY, signet),
    fetch: fetchSpy,
  });
  // `issuance()` is an Inst that needs no bound contract.
  await expect(session.issuance().submit()).rejects.toThrow(/read-only/i);
  expect(polled).toBe(false);
  session.close();
});

test("KontorSession: requires either signing or identity", () => {
  expect(() => new KontorSession({ chain: signet } as never)).toThrow(
    /signing.*identity/i,
  );
});
