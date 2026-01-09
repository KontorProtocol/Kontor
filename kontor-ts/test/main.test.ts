import { expect, test } from "vitest";
import {
  serializeInst,
  deserializeInst,
  serializeOpReturnData,
  deserializeOpReturnData,
  validateWit,
} from "@kontor/kontor-ts";

test("publish", () => {
  let inst = {
    Publish: {
      gas_limit: 1000000,
      name: "foo",
      bytes: Array.from(new Uint8Array([1, 2, 3, 4])),
    },
  };
  const str = JSON.stringify(inst);
  const bs = serializeInst(str);
  let result = deserializeInst(bs);
  expect(inst).toStrictEqual(JSON.parse(result));
});

test("call", () => {
  let inst = {
    Call: {
      gas_limit: 1000000,
      contract: "foo_1_2",
      expr: "foo()",
    },
  };
  const str = JSON.stringify(inst);
  const bs = serializeInst(str);
  let result = deserializeInst(bs);
  expect(inst).toStrictEqual(JSON.parse(result));
});

test("issuance", () => {
  let inst = "Issuance";
  const str = JSON.stringify(inst);
  const bs = serializeInst(str);
  let result = deserializeInst(bs);
  expect(inst).toStrictEqual(JSON.parse(result));
});

test("op_return_data", () => {
  let inst = {
    PubKey: "eb1e64766d59b13670f8766f306e87b15874789948dd28a4376749e0270fbe19",
  };
  const str = JSON.stringify(inst);
  const bs = serializeOpReturnData(str);
  let result = deserializeOpReturnData(bs);
  expect(inst).toStrictEqual(JSON.parse(result));
});

test("validateWit valid contract", () => {
  const wit = `
package root:component;

world root {
    include kontor:built-in/built-in;
    use kontor:built-in/context.{proc-context, view-context};
    use kontor:built-in/error.{error};

    export get-value: async func(ctx: borrow<view-context>) -> string;
    export set-value: async func(ctx: borrow<proc-context>, val: string) -> result<_, error>;
}
`;
  const result = validateWit(wit);
  expect(result.tag).toBe("ok");
});

test("validateWit invalid - missing context", () => {
  const wit = `
package root:component;

world root {
    include kontor:built-in/built-in;

    export bad-func: async func(val: string) -> string;
}
`;
  const result = validateWit(wit);
  expect(result.tag).toBe("validation-errors");
  if (result.tag === "validation-errors") {
    expect(result.val.length).toBeGreaterThan(0);
    expect(result.val.some((e) => e.message.includes("context"))).toBe(true);
  }
});

test("validateWit invalid - sync export", () => {
  const wit = `
package root:component;

world root {
    include kontor:built-in/built-in;
    use kontor:built-in/context.{view-context};

    export bad-func: func(ctx: borrow<view-context>) -> string;
}
`;
  const result = validateWit(wit);
  expect(result.tag).toBe("validation-errors");
  if (result.tag === "validation-errors") {
    expect(result.val.some((e) => e.message.includes("async"))).toBe(true);
  }
});

test("validateWit parse error", () => {
  const wit = `this is not valid wit`;
  const result = validateWit(wit);
  expect(result.tag).toBe("parse-error");
});
