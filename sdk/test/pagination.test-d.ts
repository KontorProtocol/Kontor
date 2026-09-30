import { expectTypeOf, test } from "vitest";
import type { PaginatedView } from "@kontor/sdk";
import type {
  Balance,
  BalancePage,
  Contract as Token,
} from "./__generated__/token.js";
import type { Contract as Pages, Page } from "./__generated__/pagination.js";

test("generated page calls support awaiting a page and iterating typed items", () => {
  type Call = ReturnType<Token["balances"]>;
  expectTypeOf<Call>().toEqualTypeOf<PaginatedView<BalancePage>>();
  expectTypeOf<Call>().toExtend<Promise<BalancePage>>();
  expectTypeOf<Call>().toExtend<AsyncIterable<Balance>>();
  expectTypeOf<Awaited<Call>>().toEqualTypeOf<BalancePage>();
  const verify = async (token: Token) => {
    for await (const balance of token.balances(null, 100n)) {
      expectTypeOf(balance).toEqualTypeOf<Balance>();
    }
    expectTypeOf(
      token.balances(null, 100n).then((page) => page.next),
    ).toEqualTypeOf<Promise<string | null>>();
    expectTypeOf(token.balances(null, 100n).finally(() => {})).toEqualTypeOf<
      Promise<BalancePage>
    >();
  };
  void verify;
});

test("aliases, filters and direct page results support iteration", () => {
  expectTypeOf<ReturnType<Pages["filtered"]>>().toExtend<
    AsyncIterable<bigint>
  >();
  expectTypeOf<Awaited<ReturnType<Pages["filtered"]>>>().toEqualTypeOf<Page>();
  expectTypeOf<ReturnType<Pages["directPage"]>>().toExtend<
    AsyncIterable<bigint>
  >();
});

test("ordinary reads, writes and pagination lookalikes are not iterable", () => {
  expectTypeOf<ReturnType<Token["balance"]>>().not.toExtend<
    AsyncIterable<unknown>
  >();
  expectTypeOf<ReturnType<Token["transfer"]>>().not.toExtend<
    AsyncIterable<unknown>
  >();
  type NonPages = ReturnType<
    Pages[
      | "writePage"
      | "wrongCursor"
      | "wrongNext"
      | "noLimit"
      | "noItems"
      | "swapped"]
  >;
  expectTypeOf<Extract<NonPages, AsyncIterable<unknown>>>().toBeNever();
});
