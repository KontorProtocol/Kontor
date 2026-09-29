export interface CursorPage<T> {
  readonly items: readonly T[];
  readonly next: string | null;
}

export interface PaginationOptions {
  /** Start after a previously obtained cursor; null starts at the beginning. */
  readonly after?: string | null;
}

/** Page fetches are lazy; stopping iteration does not fetch another page. */
export async function* paginate<T>(
  fetchPage: (after: string | null) => PromiseLike<CursorPage<T>>,
  options: PaginationOptions = {},
): AsyncIterableIterator<T> {
  let after = options.after ?? null;
  while (true) {
    const { items, next } = await fetchPage(after);
    // Reject a stuck continuation before yielding potentially duplicate rows.
    if (next !== null && next === after) {
      throw new Error("Pagination cursor did not advance");
    }
    yield* items;
    if (next === null) return;
    after = next;
  }
}
