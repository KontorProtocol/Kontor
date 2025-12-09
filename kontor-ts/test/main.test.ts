import { expect, test } from "vitest";
import {
  serializeInst,
  deserializeInst,
  serializeOpReturnData,
  deserializeOpReturnData,
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
