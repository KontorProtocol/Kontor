import { expect, test } from "vitest";
import { UpgradeClient } from "../src/upgrades.js";
import { TransportError } from "../src/errors.js";

const action = { action_id: "a1", action_hex: "4b554131" };
const queued = { action_id: "a1", control_id: "c1", status: "queued" };

test("operator calls preserve exact integers and approvals without wallet signing or polling", async () => {
  const requests: { url: string; init: RequestInit }[] = [];
  const results = [
    { reference_height: "9007199254740993", nonce: "18446744073709551615" },
    action,
    queued,
  ];
  const client = new UpgradeClient({
    url: "http://node/api/",
    headers: { authorization: "test-operator" },
    fetch: (async (url, init) => {
      requests.push({ url: String(url), init: init! });
      return new Response(JSON.stringify({ result: results.shift() }));
    }) as typeof fetch,
  });
  const state = await client.state();
  expect(state.reference_height).toBe("9007199254740993");
  expect(state.nonce).toBe("18446744073709551615");
  const request = {
    expires_at: "9007199254740994",
    operation: {
      kind: "schedule" as const,
      activation_height: "9007199254742100",
      manifest_hex: "4b504d31",
    },
  };
  expect(await client.prepare(request)).toEqual(action);
  const controller = new AbortController();
  expect(await client.submit("4b554331", controller.signal)).toEqual(queued);
  expect(requests.map(({ url }) => url)).toEqual([
    "http://node/api/protocol/upgrades",
    "http://node/api/protocol/upgrades/prepare",
    "http://node/api/protocol/upgrades",
  ]);
  expect(requests[0].init.body).toBeUndefined();
  expect(JSON.parse(requests[1].init.body as string)).toEqual(request);
  expect(JSON.parse(requests[2].init.body as string)).toEqual({
    envelope_hex: "4b554331",
  });
  expect(requests[2].init.signal).toBe(controller.signal);
  expect(requests[2].init.headers).toMatchObject({
    authorization: "test-operator",
  });
});

test.each([400, 503])(
  "operator HTTP %i does not retry or regenerate approvals",
  async (status) => {
    let calls = 0;
    const client = new UpgradeClient({
      url: "http://node/api",
      fetch: (async () => {
        calls++;
        return new Response(JSON.stringify({ error: "stale approval" }), {
          status,
        });
      }) as typeof fetch,
    });
    await expect(client.submit("abcd")).rejects.toThrow(/stale approval/);
    expect(calls).toBe(1);
  },
);

test.each(["not json", "null", "{}", '{"result":null}'])(
  "operator rejects malformed response %s",
  async (body) => {
    const client = new UpgradeClient({
      url: "http://node/api",
      fetch: (async () => new Response(body)) as typeof fetch,
    });
    await expect(client.state()).rejects.toBeInstanceOf(TransportError);
  },
);

test("operator network failure is surfaced without a retry", async () => {
  let calls = 0;
  const client = new UpgradeClient({
    url: "http://node/api",
    fetch: (async () => {
      calls++;
      throw new Error("offline");
    }) as typeof fetch,
  });
  await expect(client.state()).rejects.toThrow(/offline/);
  expect(calls).toBe(1);
});
