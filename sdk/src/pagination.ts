export interface CursorPage<T> {
  readonly items: readonly T[];
  readonly next: string | null;
}

/** Await one page, or lazily iterate its items and subsequent pages. */
export class PaginatedView<P extends CursorPage<unknown>>
  implements Promise<P>, AsyncIterable<P["items"][number]>
{
  readonly [Symbol.toStringTag] = "Promise";
  private first?: Promise<P>;

  constructor(
    private readonly fetchPage: (after: string | null) => PromiseLike<P>,
    private readonly after: string | null,
  ) {}

  private firstPage(): Promise<P> {
    // Awaiting, chaining and iteration share the initial request and its error.
    return (this.first ??= Promise.resolve().then(() =>
      this.fetchPage(this.after),
    ));
  }

  then<TResult1 = P, TResult2 = never>(
    onfulfilled?: ((value: P) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> {
    return this.firstPage().then(onfulfilled, onrejected);
  }

  catch<TResult = never>(
    onrejected?: ((reason: any) => TResult | PromiseLike<TResult>) | null,
  ): Promise<P | TResult> {
    return this.firstPage().catch(onrejected);
  }

  finally(onfinally?: (() => void) | null): Promise<P> {
    return this.firstPage().finally(onfinally);
  }

  async *[Symbol.asyncIterator](): AsyncIterableIterator<P["items"][number]> {
    let after = this.after;
    let page = await this.firstPage();
    while (true) {
      const { items, next } = page;
      // Reject a stuck continuation before yielding potentially duplicate rows.
      if (next !== null && next === after) {
        throw new Error("Pagination cursor did not advance");
      }
      yield* items as readonly P["items"][number][];
      if (next === null) return;
      after = next;
      page = await this.fetchPage(after);
    }
  }
}
