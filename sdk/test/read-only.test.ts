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
  await expect(
    session.registerBls(undefined as never),
  ).rejects.toThrow(/read-only/i);
  session.close();
});

test("KontorSession: requires either signing or identity", () => {
  expect(() => new KontorSession({ chain: signet } as never)).toThrow(
    /signing.*identity/i,
  );
});
