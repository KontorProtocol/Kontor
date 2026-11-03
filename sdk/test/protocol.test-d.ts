import { expectTypeOf, test } from "vitest";
import type {
  Inst,
  KontorSession,
  OpResult,
  SimulationPreview,
} from "@kontor/sdk";

test("contextual previews retain decoded single and tuple result types", () => {
  expectTypeOf<
    Awaited<ReturnType<Inst<bigint>["simulateWithContext"]>>
  >().toEqualTypeOf<SimulationPreview<OpResult<bigint>>>();
  const verify = async (
    session: KontorSession,
    first: Inst<bigint>,
    second: Inst<string>,
  ) => {
    const preview = await session.bulk(first, second).simulateWithContext();
    expectTypeOf(preview).toEqualTypeOf<
      SimulationPreview<[OpResult<bigint>, OpResult<string>]>
    >();
  };
  void verify;
});
