/**
 * Unit tests for `HttpTransport.view` — the read-only, account-free
 * transport operation. A mock `fetch` stands in for the indexer; these
 * pin the request shape and the Ok / Err / HTTP-error handling.
 */
import { test, expect } from "vitest";
import { HttpTransport } from "../src/transport/http.js";
import { ContractAddress } from "../src/canonical/ContractAddress.js";
import { ContractError, TransportError } from "../src/errors.js";
import { HolderRef } from "../src/canonical/HolderRef.js";
import { signet } from "../src/chains.js";
import type { Account } from "../src/account/index.js";

/** Throwaway account — `view` never signs, but the option is required. */
const stubAccount: Account = {
  xOnlyPubKey: "00".repeat(32),
  address: "tb1pstub",
  holderRef: HolderRef.xOnlyPubkey("00".repeat(32)),
  signMessage: () => Promise.reject(new Error("stub")),
  signPsbt: () => Promise.reject(new Error("stub")),
};

function transportWith(fetchImpl: typeof fetch): HttpTransport {
  return new HttpTransport({
    chain: signet,
    account: stubAccount,
    url: "http://test/api",
    fetch: fetchImpl,
  });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const token = new ContractAddress("token", 0n, 0n);

test("HttpTransport.view: posts to /contracts/{addr} and returns the Ok value", async () => {
  let seen: { url: string; init: RequestInit } | undefined;
  const t = transportWith((async (url, init) => {
    seen = { url: url as string, init: init! };
    return jsonResponse({ result: { type: "Ok", value: "some(42)" } });
  }) as typeof fetch);

  const out = await t.view(token, "balance(core)");

  expect(out).toBe("some(42)");
  expect(seen!.url).toBe("http://test/api/contracts/token_0_0");
  expect(seen!.init.method).toBe("POST");
  expect(JSON.parse(seen!.init.body as string)).toEqual({
    expr: "balance(core)",
  });
});

test("HttpTransport.view: throws ContractError on an Err result", async () => {
  const t = transportWith((async () =>
    jsonResponse({
      result: { type: "Err", message: "no such function" },
    })) as typeof fetch);

  await expect(t.view(token, "bogus()")).rejects.toBeInstanceOf(ContractError);
  await expect(t.view(token, "bogus()")).rejects.toThrow(/no such function/);
});

test("HttpTransport.view: throws TransportError on a non-2xx response", async () => {
  const t = transportWith((async () =>
    jsonResponse(
      { error: "Bad request: invalid address" },
      400,
    )) as typeof fetch);

  await expect(t.view(token, "balance(core)")).rejects.toBeInstanceOf(
    TransportError,
  );
  await expect(t.view(token, "balance(core)")).rejects.toThrow(/HTTP 400/);
});

test("HttpTransport.view: throws TransportError when the node is unreachable", async () => {
  const t = transportWith((() =>
    Promise.reject(new Error("ECONNREFUSED"))) as typeof fetch);

  await expect(t.view(token, "balance(core)")).rejects.toBeInstanceOf(
    TransportError,
  );
});

test("HttpTransport.view: throws TransportError on a non-JSON body", async () => {
  const t = transportWith(
    (async () =>
      new Response("<html>502 Bad Gateway</html>", {
        status: 200,
      })) as typeof fetch,
  );

  await expect(t.view(token, "balance(core)")).rejects.toThrow(/non-JSON/);
});
