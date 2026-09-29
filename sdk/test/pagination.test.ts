import { expect, test, vi } from "vitest";
import { ContractError, paginate, type CursorPage } from "@kontor/sdk";

type FetchPage = (after: string | null) => Promise<CursorPage<number>>;

test("pagination fetches lazily and only after the current page is consumed", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValueOnce({ items: [1, 2], next: "first" })
    .mockResolvedValueOnce({ items: [3], next: null });
  const iterator = paginate(fetchPage);
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
  for await (const item of paginate(fetchPage)) items.push(item);
  expect(items).toEqual([1, 2, 3]);
  expect(fetchPage.mock.calls).toEqual([[null], ["z:opaque"], ["a:opaque"]]);
});

test("pagination stops on an empty terminal page", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValue({ items: [], next: null });
  expect(await paginate(fetchPage).next()).toEqual({
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
  for await (const item of paginate(fetchPage, { after: "saved" }))
    items.push(item);
  expect(items).toEqual([2, 3]);
  expect(fetchPage.mock.calls).toEqual([["saved"], ["second"]]);
});

test("breaking a walk does not fetch another page", async () => {
  const fetchPage = vi
    .fn<FetchPage>()
    .mockResolvedValue({ items: [1, 2], next: "more" });
  const iterator = paginate(fetchPage);
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
  const iterator = paginate(fetchPage);
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
  const iterator = paginate(fetchPage, { after: "invalid" });
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
  const iterator = paginate(fetchPage);
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
  const iterator = paginate(fetchPage);
  expect(await iterator.next()).toEqual({ value: 1, done: false });
  await expect(iterator.next()).rejects.toThrow(
    "Pagination cursor did not advance",
  );
  expect(await iterator.next()).toEqual({ value: undefined, done: true });
  expect(fetchPage).toHaveBeenCalledTimes(2);
});
