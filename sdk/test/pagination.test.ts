import { expect, test, vi } from "vitest";
import { ContractError, PaginatedView, type CursorPage } from "@kontor/sdk";

type FetchPage = (after: string | null) => Promise<CursorPage<number>>;

test("pagination fetches lazily and only after the current page is consumed", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValueOnce({ items: [1, 2], next: "first" })
    .mockResolvedValueOnce({ items: [3], next: null });
  const iterator = new PaginatedView(fetchPage, null)[Symbol.asyncIterator]();
  expect(fetchPage).not.toHaveBeenCalled();
  expect(await iterator.next()).toEqual({ value: 1, done: false });
  expect(await iterator.next()).toEqual({ value: 2, done: false });
  expect(fetchPage.mock.calls).toEqual([[null]]);
  expect(await iterator.next()).toEqual({ value: 3, done: false });
  expect(fetchPage.mock.calls).toEqual([[null], ["first"]]);
  expect(await iterator.next()).toEqual({ value: undefined, done: true });
  expect(await iterator.next()).toEqual({ value: undefined, done: true });
  expect(fetchPage).toHaveBeenCalledTimes(2);
});

test("pagination follows opaque cursors through empty intermediate pages", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValueOnce({ items: [1], next: "z:opaque" })
    .mockResolvedValueOnce({ items: [], next: "a:opaque" })
    .mockResolvedValueOnce({ items: [2, 3], next: null });
  const items = [];
  for await (const item of new PaginatedView(fetchPage, null)) items.push(item);
  expect(items).toEqual([1, 2, 3]);
  expect(fetchPage.mock.calls).toEqual([[null], ["z:opaque"], ["a:opaque"]]);
});

test("pagination stops on an empty terminal page", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValue({ items: [], next: null });
  expect(
    await new PaginatedView(fetchPage, null)[Symbol.asyncIterator]().next(),
  ).toEqual({
    value: undefined,
    done: true,
  });
  expect(fetchPage).toHaveBeenCalledOnce();
});

test("pagination starts after the supplied cursor", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValueOnce({ items: [2], next: "second" })
    .mockResolvedValueOnce({ items: [3], next: null });
  const items = [];
  for await (const item of new PaginatedView(fetchPage, "saved"))
    items.push(item);
  expect(items).toEqual([2, 3]);
  expect(fetchPage.mock.calls).toEqual([["saved"], ["second"]]);
});

test("breaking a walk does not fetch another page", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValue({ items: [1, 2], next: "more" });
  const iterator = new PaginatedView(fetchPage, null)[Symbol.asyncIterator]();
  for await (const item of iterator) {
    expect(item).toBe(1);
    break;
  }
  expect(await iterator.next()).toEqual({ value: undefined, done: true });
  expect(fetchPage).toHaveBeenCalledOnce();
});

test("a consumer error closes the iterator without fetching another page", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValue({ items: [1], next: "more" });
  const iterator = new PaginatedView(fetchPage, null)[Symbol.asyncIterator]();
  const error = new Error("consumer failed");
  const consume = async () => {
    for await (const _item of iterator) throw error;
  };
  await expect(consume()).rejects.toBe(error);
  expect(await iterator.next()).toEqual({ value: undefined, done: true });
  expect(fetchPage).toHaveBeenCalledOnce();
});

test("pagination preserves a contract error without retrying", async () => {
  const error = new ContractError("invalid cursor", {
    data: { kind: "message", value: "invalid cursor" },
  });
  const fetchPage = vi.fn<FetchPage>().mockRejectedValue(error);
  const iterator = new PaginatedView(fetchPage, "invalid")[
    Symbol.asyncIterator
  ]();
  await expect(iterator.next()).rejects.toBe(error);
  expect(await iterator.next()).toEqual({ value: undefined, done: true });
  expect(fetchPage).toHaveBeenCalledOnce();
});

test("pagination propagates later fetch errors without replaying earlier pages", async () => {
  const error = new Error("offline");
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValueOnce({ items: [1], next: "first" })
    .mockRejectedValueOnce(error);
  const iterator = new PaginatedView(fetchPage, null)[Symbol.asyncIterator]();
  expect(await iterator.next()).toEqual({ value: 1, done: false });
  await expect(iterator.next()).rejects.toBe(error);
  expect(await iterator.next()).toEqual({ value: undefined, done: true });
  expect(fetchPage.mock.calls).toEqual([[null], ["first"]]);
});

test("pagination rejects an unchanged continuation cursor", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValueOnce({ items: [1], next: "first" })
    .mockResolvedValueOnce({ items: [1], next: "first" });
  const iterator = new PaginatedView(fetchPage, null)[Symbol.asyncIterator]();
  expect(await iterator.next()).toEqual({ value: 1, done: false });
  await expect(iterator.next()).rejects.toThrow(
    "Pagination cursor did not advance",
  );
  expect(await iterator.next()).toEqual({ value: undefined, done: true });
  expect(fetchPage).toHaveBeenCalledTimes(2);
});

test("await and concurrent iterations share the initial page request", async () => {
  const first = { items: [1], next: "first", count: 2 };
  const fetchPage = vi.fn(async (after: string | null) =>
    after === null ? first : { items: [2], next: null, count: 2 },
  );
  const call = new PaginatedView(fetchPage, null);
  const left = call[Symbol.asyncIterator]();
  const right = call[Symbol.asyncIterator]();
  expect(fetchPage).not.toHaveBeenCalled();
  const [page, a, b] = await Promise.all([call, left.next(), right.next()]);
  expect(page).toBe(first);
  expect(a.value).toBe(1);
  expect(b.value).toBe(1);
  expect(fetchPage.mock.calls).toEqual([[null]]);
  expect((await left.next()).value).toBe(2);
  expect((await right.next()).value).toBe(2);
  expect(fetchPage.mock.calls).toEqual([[null], ["first"], ["first"]]);
  expect(await call).toBe(first);
});

test("concurrent next requests serialize page fetches on one iterator", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValueOnce({ items: [1, 2], next: "first" })
    .mockResolvedValueOnce({ items: [3], next: null });
  const iterator = new PaginatedView(fetchPage, null)[Symbol.asyncIterator]();
  expect(
    await Promise.all([iterator.next(), iterator.next(), iterator.next()]),
  ).toEqual([1, 2, 3].map((value) => ({ value, done: false })));
  expect(fetchPage.mock.calls).toEqual([[null], ["first"]]);
});

test("promise chaining consumes only the first page and preserves metadata", async () => {
  const page = { items: [1] as const, next: "more", count: 20 };
  const fetchPage = vi.fn(async () => page);
  const call = new PaginatedView(fetchPage, null);
  const finalized = vi.fn();
  const caught = vi.fn();
  expect(await call.then((value) => value.count)).toBe(20);
  expect(await call.catch(caught).finally(finalized)).toBe(page);
  expect(await call.finally(finalized)).toBe(page);
  expect(caught).not.toHaveBeenCalled();
  expect(finalized).toHaveBeenCalledTimes(2);
  expect(fetchPage).toHaveBeenCalledOnce();
});

test("await, catch, finally and iteration share first-page failures without retries", async () => {
  const error = new Error("offline");
  const fetchPage = vi.fn<FetchPage>(() => {
    throw error;
  });
  const call = new PaginatedView(fetchPage, null);
  const finalized = vi.fn();
  await expect(Promise.resolve(call)).rejects.toBe(error);
  expect(await call.catch((reason) => reason)).toBe(error);
  await expect(call.finally(finalized)).rejects.toBe(error);
  await expect(call[Symbol.asyncIterator]().next()).rejects.toBe(error);
  expect(finalized).toHaveBeenCalledOnce();
  expect(fetchPage).toHaveBeenCalledOnce();
});

test("an early break does not prevent a later walk or awaiting the first page", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValueOnce({ items: [1, 2], next: "first" })
    .mockResolvedValueOnce({ items: [3], next: null });
  const call = new PaginatedView(fetchPage, null);
  for await (const item of call) {
    expect(item).toBe(1);
    break;
  }
  expect((await call).next).toBe("first");
  const items = [];
  for await (const item of call) items.push(item);
  expect(items).toEqual([1, 2, 3]);
  expect(fetchPage.mock.calls).toEqual([[null], ["first"]]);
});
