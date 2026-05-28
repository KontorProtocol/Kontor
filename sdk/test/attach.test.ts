/**
 * Unit tests for the `Attachment` runtime surface. The full
 * `offer(...)` flow — chained compose, taproot signing, PSBT build —
 * is exercised by the live regtest marketplace suite; here we just
 * cover the cheap guard that the terminal is wired through to the
 * transport.
 *
 * Gifts go through `contract.transfer(recipient, amount)`, not through
 * `Attachment` — see attach.ts header.
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

// secp256k1 generator x-coordinate — a real on-curve x-only pubkey, so
// the SDK's `p2tr()` derivations succeed and the test reaches the
// transport-call site as intended.
const STUB_XONLY =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const stubAccount: Account = {
  xOnlyPubKey: STUB_XONLY,
  address: "tb1pstub",
  holderRef: HolderRef.xOnlyPubkey(STUB_XONLY),
  signMessage: () => Promise.reject(new Error("stub")),
  signPsbt: () => Promise.reject(new Error("stub")),
  signSchnorr: () => Promise.reject(new Error("stub")),
  runExclusive: (fn) => fn(),
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
    utxos: fail,
    compose: fail,
    composeAndSign: fail,
    broadcast: fail,
    submitReveal: fail,
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

test("Attachment.offer: composes the attach through the transport", async () => {
  // offer() builds the attach via transport.compose; the stub rejects
  // there, proving the terminal is wired up. The full offer round-trip
  // is the live regtest test.
  const att = attachment(stubSession());
  await expect(att.offer({ price: 1000n })).rejects.toThrow(/transport unused/);
});
