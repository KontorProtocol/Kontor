import { expectTypeOf, test } from "vitest";
import type { Attachment, Inst, KontorSession } from "@kontor/sdk";
import type {
  BalancePage,
  Contract as Token,
  Transfer,
} from "./__generated__/token.js";
import type {
  Contract as CallResults,
  Outcome,
} from "./__generated__/call-results.js";

test("generated calls expose success types, including aliases and unit results", () => {
  expectTypeOf<Token["balances"]>().returns.toExtend<Promise<BalancePage>>();
  expectTypeOf<Token["transfer"]>().returns.toEqualTypeOf<Inst<Transfer>>();
  expectTypeOf<Token["attachment"]>().returns.toEqualTypeOf<
    Attachment<Transfer>
  >();
  expectTypeOf<CallResults["maybeValue"]>().returns.toEqualTypeOf<
    Promise<bigint | null>
  >();
  expectTypeOf<CallResults["setFlag"]>().returns.toEqualTypeOf<Inst<void>>();
  expectTypeOf<CallResults["checkFlag"]>().returns.toEqualTypeOf<
    Promise<void>
  >();
  expectTypeOf<CallResults["outcome"]>().returns.toEqualTypeOf<
    Promise<Outcome>
  >();
  expectTypeOf<CallResults["wrappedOutcome"]>().returns.toEqualTypeOf<
    Promise<Outcome>
  >();
});

test("batches retain each call's success type", () => {
  const verify = (session: KontorSession, results: CallResults) => {
    const writes = session.bulk(
      results.setFlag(),
      results.echoOutcome({ kind: "err", value: "data" }),
    );
    expectTypeOf<Awaited<typeof writes>>().toEqualTypeOf<[void, Outcome]>();
  };
  void verify;
});
