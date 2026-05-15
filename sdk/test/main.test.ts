import { expect, test } from "vitest";
import {
  serializeInst,
  deserializeInst,
  serializeOpReturnData,
  deserializeOpReturnData,
  validateWit,
  witApi,
} from "@kontor/sdk";

test("publish", () => {
  let inst = {
    ops: [
      {
        payment: { SelfPay: { limit: 1000000 } },
        kind: {
          Publish: {
            name: "foo",
            bytes: Array.from(new Uint8Array([1, 2, 3, 4])),
          },
        },
      },
    ],
    aggregate: null,
  };
  const str = JSON.stringify(inst);
  const bs = serializeInst(str);
  let result = deserializeInst(bs);
  expect(inst).toStrictEqual(JSON.parse(result));
});

test("call", () => {
  let inst = {
    ops: [
      {
        payment: { SelfPay: { limit: 1000000 } },
        kind: {
          Call: {
            contract: "foo_1_2",
            expr: "foo()",
          },
        },
      },
    ],
    aggregate: null,
  };
  const str = JSON.stringify(inst);
  const bs = serializeInst(str);
  let result = deserializeInst(bs);
  expect(inst).toStrictEqual(JSON.parse(result));
});

test("call with sponsored payment in aggregate", () => {
  let inst = {
    ops: [
      {
        payment: "Sponsored",
        kind: {
          Call: {
            contract: "foo_1_2",
            expr: "foo()",
          },
        },
      },
    ],
    aggregate: {
      signers: [
        {
          identity: { Id: 1 },
          nonce: 0,
        },
      ],
      signature: Array.from(new Uint8Array(48)),
      publisher_sponsorship: 100000,
    },
  };
  const str = JSON.stringify(inst);
  const bs = serializeInst(str);
  let result = deserializeInst(bs);
  expect(inst).toStrictEqual(JSON.parse(result));
});

test("aggregate with PubKey signer claim", () => {
  let inst = {
    ops: [
      {
        payment: "Sponsored",
        kind: {
          Call: {
            contract: "foo_1_2",
            expr: "foo()",
          },
        },
      },
    ],
    aggregate: {
      signers: [
        {
          identity: {
            PubKey:
              "eb1e64766d59b13670f8766f306e87b15874789948dd28a4376749e0270fbe19",
          },
          nonce: 0,
        },
      ],
      signature: Array.from(new Uint8Array(48)),
      publisher_sponsorship: 100000,
    },
  };
  const str = JSON.stringify(inst);
  const bs = serializeInst(str);
  let result = deserializeInst(bs);
  expect(inst).toStrictEqual(JSON.parse(result));
});

test("issuance", () => {
  let inst = {
    ops: [
      {
        payment: { SelfPay: { limit: 1000000 } },
        kind: "Issuance",
      },
    ],
    aggregate: null,
  };
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

    export init: async func(ctx: borrow<proc-context>);
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

test("Wit.encodeCall renders a single bool arg", () => {
  const wit = `package test:demo;

world demo {
  export do-thing: func(flag: bool) -> string;
}`;
  const w = new witApi.Wit(wit);

  expect(w.encodeCall("do-thing", '{"flag": true}')).toBe("do-thing(true)");
  expect(w.encodeCall("do-thing", '{"flag": false}')).toBe("do-thing(false)");
});

test("Wit.encodeCall errors when function missing", () => {
  const wit = `package test:demo;

world demo {
  export do-thing: func(flag: bool) -> string;
}`;
  const w = new witApi.Wit(wit);

  expect(() => w.encodeCall("no-such-fn", '{}')).toThrow(
    /function not found/,
  );
});

test("Wit.encodeCall errors when bool arg has wrong JSON type", () => {
  const wit = `package test:demo;

world demo {
  export do-thing: func(flag: bool) -> string;
}`;
  const w = new witApi.Wit(wit);

  expect(() => w.encodeCall("do-thing", '{"flag": "yes"}')).toThrow(
    /expected JSON bool/,
  );
});

test("Wit.encodeCall renders u64 from a quoted-decimal JSON string", () => {
  // u64 values > 2^53 can't be safely held in JS Number, so the FFI uses
  // JSON strings holding decimal digits. The WAVE output is just the
  // unquoted decimal — the WIT type system carries the precision lift.
  const wit = `package test:demo;

world demo {
  export add: func(x: u64) -> u64;
}`;
  const w = new witApi.Wit(wit);

  expect(w.encodeCall("add", '{"x": "12345"}')).toBe("add(12345)");
  expect(w.encodeCall("add", '{"x": "18446744073709551615"}')).toBe(
    "add(18446744073709551615)",
  );
});

test("Wit.encodeCall errors when u64 arg isn't a string", () => {
  const wit = `package test:demo;

world demo {
  export add: func(x: u64) -> u64;
}`;
  const w = new witApi.Wit(wit);

  expect(() => w.encodeCall("add", '{"x": 12345}')).toThrow(
    /expected JSON string holding a u64 decimal/,
  );
});

test("Wit.decodeResult parses a u64 WAVE return into a quoted-decimal JSON string", () => {
  const wit = `package test:demo;

world demo {
  export add: func(x: u64) -> u64;
}`;
  const w = new witApi.Wit(wit);

  // serde_json::to_string of a JSON string includes the quotes.
  expect(w.decodeResult("add", "12345")).toBe('"12345"');
  expect(w.decodeResult("add", "18446744073709551615")).toBe(
    '"18446744073709551615"',
  );
});

test("Wit.decodeResult parses a bool WAVE return into a JSON bool", () => {
  const wit = `package test:demo;

world demo {
  export is-ready: func() -> bool;
}`;
  const w = new witApi.Wit(wit);

  expect(w.decodeResult("is-ready", "true")).toBe("true");
  expect(w.decodeResult("is-ready", "false")).toBe("false");
});

test("Wit u64 round-trips through encodeCall + decodeResult", () => {
  // Strong invariant: a value sent through encode and back through decode
  // must equal the original. This is the test that proves the FFI
  // bigint-quoting story actually preserves precision.
  const wit = `package test:demo;

world demo {
  export echo: func(x: u64) -> u64;
}`;
  const w = new witApi.Wit(wit);

  const original = "18446744073709551615"; // u64 max
  const encoded = w.encodeCall("echo", JSON.stringify({ x: original }));
  // Mimic node response: extract the literal arg from "echo(NNN)" — in a
  // real chain this'd be the WAVE return value from the contract.
  const waveResult = encoded.slice("echo(".length, -1);
  const decoded = w.decodeResult("echo", waveResult);
  expect(JSON.parse(decoded)).toBe(original);
});
