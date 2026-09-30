import { afterEach, expect, test, vi } from "vitest";
import { ContractError, Identity, KontorSession, signet } from "@kontor/sdk";
import { Contract as Pages } from "./__generated__/pagination.js";
import { Contract as Token } from "./__generated__/token.js";

const sessions: KontorSession[] = [];
afterEach(() => sessions.splice(0).forEach((session) => session.close()));

function setup() {
  const session = new KontorSession({
    chain: signet,
    identity: Identity.fromXOnly(
      "8c7fc6552af4384a13791e63bac79ff2bcfeedf143a88d6dc4b6080a8829cdc1",
      signet,
    ),
  });
  sessions.push(session);
  const view = vi.spyOn(session, "view");
  const submit = vi.spyOn(session.transport, "submit");
  return {
    view,
    submit,
    pages: session.bind(Pages, "pages@0.0"),
    token: session.bind(Token, "token@0.0"),
  };
}

test("generated pagination preserves filters, cursor and limit through WAVE encoding", async () => {
  const { pages, view, submit } = setup();
  view
    .mockResolvedValueOnce(
      'ok({items: [1, 2], next: some("z:opaque"), count: 3})',
    )
    .mockResolvedValueOnce("ok({items: [3], next: none, count: 3})");
  const filters = ["original"];
  const call = pages.filtered(filters, "saved", 2n);
  filters.push("later mutation");
  expect(view).not.toHaveBeenCalled();
  expect(await call).toEqual({ items: [1n, 2n], next: "z:opaque", count: 3n });
  const items = [];
  for await (const item of call) items.push(item);
  expect(items).toEqual([1n, 2n, 3n]);
  expect(view.mock.calls.map(([, expr]) => expr)).toEqual([
    'filtered(["original"], some("saved"), 2)',
    'filtered(["original"], some("z:opaque"), 2)',
  ]);
  expect(submit).not.toHaveBeenCalled();
});

test("direct page results iterate without outer result unwrapping", async () => {
  const { pages, view } = setup();
  view.mockResolvedValue("{items: [4], next: none, count: 1}");
  const items = [];
  for await (const item of pages.directPage(null, 10n)) items.push(item);
  expect(items).toEqual([4n]);
  expect(view).toHaveBeenCalledOnce();
});

test("generated token iteration stops on break and keeps contract error context", async () => {
  const { token, view, submit } = setup();
  view.mockResolvedValueOnce(
    'ok({items: [{acc: signer-id(1), amt: {r0: 0, r1: 0, r2: 0, r3: 0, sign: plus}}], next: some("cursor")})',
  );
  for await (const balance of token.balances(null, 1n)) {
    expect(balance.amt.toString()).toBe("0");
    break;
  }
  expect(view).toHaveBeenCalledOnce();
  view.mockResolvedValueOnce('err(message("invalid cursor"))');
  const call = token.balances("invalid", 0n);
  let error: unknown;
  try {
    await call;
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ContractError);
  expect(error).toMatchObject({
    functionName: "balances",
    data: { kind: "message", value: "invalid cursor" },
  });
  await expect(call[Symbol.asyncIterator]().next()).rejects.toBe(error);
  expect(view).toHaveBeenCalledTimes(2);
  expect(submit).not.toHaveBeenCalled();
});
