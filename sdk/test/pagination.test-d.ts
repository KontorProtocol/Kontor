import { expectTypeOf, test } from "vitest";
import { paginate, type CursorPage } from "@kontor/sdk";
import type { Balance, Contract as Token } from "./__generated__/token.js";

test("pagination infers the item type from generated page methods", () => {
  const verify = (token: Token) => {
    const balances = paginate((after) => token.balances(after, 100n));
    expectTypeOf(balances).toEqualTypeOf<AsyncIterableIterator<Balance>>();
  };
  void verify;
});

test("pagination accepts readonly pages and a starting cursor", () => {
  const fetchPage = async (
    _after: string | null,
  ): Promise<CursorPage<number>> => ({ items: [1] as const, next: null });
  expectTypeOf(paginate(fetchPage, { after: "saved" })).toEqualTypeOf<
    AsyncIterableIterator<number>
  >();
});
