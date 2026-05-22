/**
 * Unit tests for the `Attachment` runtime surface. The full
 * `to(recipient)` round-trip — chained compose, taproot signing, a
 * three-tx package broadcast — is exercised by the live regtest suite;
 * here we cover the cheap, signing-free guards: recipient validation
 * and the not-yet-implemented `sell()` terminal.
 */
import { test, expect, afterEach } from "vitest";
import {
  type Account,
  type KontorTransport,
  Attachment,
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

/** A session whose transport rejects every call — the guards under test
 *  never reach the transport. */
function stubSession(): KontorSession {
  const fail = () => Promise.reject(new Error("attach test: transport unused"));
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

/** A token-style `Attachment` against a throwaway contract address. */
function attachment(session: KontorSession): Attachment<string> {
  const addr = new ContractAddress("token", 0n, 0n);
  const decode = (w: string): string => w;
  return new Attachment(
    session,
    session.call(addr, "attach", "attach(0)", decode),
    session.call(addr, "detach", "detach()", decode),
  );
}

// secp256k1's generator point x-coordinate — a guaranteed-valid x-only
// pubkey (the WASM codec validates the curve point).
const VALID_PUBKEY =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

test("Attachment.to: rejects a malformed recipient before any network call", async () => {
  // The WASM codec validates the recipient pubkey; a bad one fails fast,
  // before the stub transport is ever reached.
  const att = attachment(stubSession());
  await expect(att.to("deadbeef")).rejects.toThrow(/invalid detach recipient/);
});

test("Attachment.to: a valid recipient passes validation, then hits the transport", async () => {
  // A valid pubkey clears `encodeRecipientOpReturn`; the rejection here
  // is the stub `compose`, proving validation let it through.
  const att = attachment(stubSession());
  await expect(att.to(VALID_PUBKEY)).rejects.toThrow(/transport unused/);
});

test("Attachment.sell: marketplace path is not implemented yet", () => {
  const att = attachment(stubSession());
  expect(() => att.sell({ price: 1000n })).toThrow(/not implemented/);
});
