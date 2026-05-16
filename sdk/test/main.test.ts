import { expect, test } from "vitest";
import {
  serializeInst,
  deserializeInst,
  serializeOpReturnData,
  deserializeOpReturnData,
  validateWit,
  Wit,
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

// Real Kontor contracts include the built-in world (which brings in
// proc-context, view-context, error), export an `init` function, and
// declare each export as `async func(ctx: borrow<...>, ...args)`.
// wit_validator enforces this shape at Wit construction; encode_call
// skips the ctx param.
const KONTOR_HEADER = `package root:component;

world root {
    include kontor:built-in/built-in;
    use kontor:built-in/context.{proc-context, view-context};
    use kontor:built-in/error.{error};

    export init: async func(ctx: borrow<proc-context>);
`;

test("Wit.encodeCall renders a single bool arg (skipping ctx)", () => {
  const wit = `${KONTOR_HEADER}
    export set-flag: async func(ctx: borrow<proc-context>, flag: bool) -> result<_, error>;
}`;
  const w = new Wit(wit);

  expect(w.encodeCall("set-flag", '{"flag": true}')).toBe("set-flag(true)");
  expect(w.encodeCall("set-flag", '{"flag": false}')).toBe("set-flag(false)");
});

test("Wit construction rejects WIT that fails validation", () => {
  // Missing the `borrow<context>` first param — validator rejects.
  const badWit = `${KONTOR_HEADER}
    export bad-func: async func(val: string) -> string;
}`;
  const w = new Wit(badWit);
  expect(() => w.encodeCall("bad-func", '{}')).toThrow(/WIT validation/);
});

test("Wit construction rejects malformed WIT", () => {
  const w = new Wit("this is not valid wit at all");
  expect(() => w.encodeCall("anything", '{}')).toThrow(/WIT parse error/);
});

test("Wit.encodeCall errors when function missing", () => {
  const wit = `${KONTOR_HEADER}
    export set-flag: async func(ctx: borrow<proc-context>, flag: bool) -> result<_, error>;
}`;
  const w = new Wit(wit);

  expect(() => w.encodeCall("no-such-fn", "{}")).toThrow(/function not found/);
});

test("Wit.encodeCall errors when bool arg has wrong JSON type", () => {
  const wit = `${KONTOR_HEADER}
    export set-flag: async func(ctx: borrow<proc-context>, flag: bool) -> result<_, error>;
}`;
  const w = new Wit(wit);

  expect(() => w.encodeCall("set-flag", '{"flag": "yes"}')).toThrow(
    /expected JSON bool/,
  );
});

test("Wit.encodeCall renders u64 from a quoted-decimal JSON string", () => {
  // u64 values > 2^53 can't be safely held in JS Number, so the FFI uses
  // JSON strings holding decimal digits. The WAVE output is just the
  // unquoted decimal — the WIT type system carries the precision lift.
  const wit = `${KONTOR_HEADER}
    export add: async func(ctx: borrow<view-context>, x: u64) -> u64;
}`;
  const w = new Wit(wit);

  expect(w.encodeCall("add", '{"x": "12345"}')).toBe("add(12345)");
  expect(w.encodeCall("add", '{"x": "18446744073709551615"}')).toBe(
    "add(18446744073709551615)",
  );
});

test("Wit.encodeCall errors when u64 arg isn't a string", () => {
  const wit = `${KONTOR_HEADER}
    export add: async func(ctx: borrow<view-context>, x: u64) -> u64;
}`;
  const w = new Wit(wit);

  expect(() => w.encodeCall("add", '{"x": 12345}')).toThrow(
    /expected JSON string holding a u64 decimal/,
  );
});

test("Wit.decodeResult parses a u64 WAVE return into a quoted-decimal JSON string", () => {
  const wit = `${KONTOR_HEADER}
    export add: async func(ctx: borrow<view-context>, x: u64) -> u64;
}`;
  const w = new Wit(wit);

  // serde_json::to_string of a JSON string includes the quotes.
  expect(w.decodeResult("add", "12345")).toBe('"12345"');
  expect(w.decodeResult("add", "18446744073709551615")).toBe(
    '"18446744073709551615"',
  );
});

test("Wit.decodeResult parses a bool WAVE return into a JSON bool", () => {
  const wit = `${KONTOR_HEADER}
    export is-ready: async func(ctx: borrow<view-context>) -> bool;
}`;
  const w = new Wit(wit);

  expect(w.decodeResult("is-ready", "true")).toBe("true");
  expect(w.decodeResult("is-ready", "false")).toBe("false");
});

test("Wit u64 round-trips through encodeCall + decodeResult", () => {
  // Strong invariant: a value sent through encode and back through decode
  // must equal the original. This is the test that proves the FFI
  // bigint-quoting story actually preserves precision.
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, x: u64) -> u64;
}`;
  const w = new Wit(wit);

  const original = "18446744073709551615"; // u64 max
  const encoded = w.encodeCall("echo", JSON.stringify({ x: original }));
  // Mimic node response: extract the literal arg from "echo(NNN)" — in a
  // real chain this'd be the WAVE return value from the contract.
  const waveResult = encoded.slice("echo(".length, -1);
  const decoded = w.decodeResult("echo", waveResult);
  expect(JSON.parse(decoded)).toBe(original);
});

// Note: Kontor's wit_validator rejects 8/16/32-bit ints (except list<u8>),
// floats, and char as contract-level types. The codec in WitResource still
// handles them so it can serve those types as members of larger compound
// types (records, lists, etc.) in case Kontor ever lifts the restriction,
// but they're unreachable via top-level params in a valid Kontor contract.

// ─── s64 (signed bigint — quoted decimal, like u64) ──────────────────

test("Wit s64 round-trips with quoted decimal strings (max and min)", () => {
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, x: s64) -> s64;
}`;
  const w = new Wit(wit);
  const cases = ["9223372036854775807", "-9223372036854775808", "0"];
  for (const original of cases) {
    const encoded = w.encodeCall("echo", JSON.stringify({ x: original }));
    const wave = encoded.slice("echo(".length, -1);
    const decoded = w.decodeResult("echo", wave);
    expect(JSON.parse(decoded)).toBe(original);
  }
});

// ─── option<T> ────────────────────────────────────────────────────────
// Validates locked encoding shape #7: option<T> ↔ T | null (unwrapped).

test("Wit option<string> round-trips with null for none, value for some", () => {
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, x: option<string>) -> option<string>;
}`;
  const w = new Wit(wit);

  // none ↔ null
  expect(w.encodeCall("echo", '{"x": null}')).toBe('echo(none)');
  expect(w.decodeResult("echo", "none")).toBe("null");

  // some ↔ inner value directly (no wrapping)
  expect(w.encodeCall("echo", '{"x": "hello"}')).toBe('echo(some("hello"))');
  expect(w.decodeResult("echo", 'some("hello")')).toBe('"hello"');
});

test("Wit option<u64> round-trips preserving bigint-quoting", () => {
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, x: option<u64>) -> option<u64>;
}`;
  const w = new Wit(wit);

  const max = "18446744073709551615";
  const encoded = w.encodeCall("echo", JSON.stringify({ x: max }));
  expect(encoded).toBe(`echo(some(${max}))`);
  const wave = encoded.slice("echo(".length, -1);
  const decoded = w.decodeResult("echo", wave);
  expect(JSON.parse(decoded)).toBe(max);

  // none still null even for bigint inner
  expect(w.encodeCall("echo", '{"x": null}')).toBe('echo(none)');
  expect(w.decodeResult("echo", "none")).toBe("null");
});

// ─── variant ──────────────────────────────────────────────────────────
// Validates locked encoding shape #5: `{ kind: "case", value: payload }`
// for payload cases, `{ kind: "case" }` for unit cases. Adjacent tagging
// (the discriminant `kind` and the payload `value` are separate fields).

test("Wit variant round-trips: unit cases as {kind}, payload cases as {kind,value}", () => {
  const wit = `${KONTOR_HEADER}
    variant outcome {
        success(string),
        retry,
        failed(u64),
    }
    export run: async func(ctx: borrow<proc-context>, o: outcome) -> outcome;
}`;
  const w = new Wit(wit);

  // unit case (no payload)
  expect(w.encodeCall("run", '{"o": {"kind": "retry"}}')).toBe("run(retry)");
  expect(w.decodeResult("run", "retry")).toBe('{"kind":"retry"}');

  // payload case with string
  expect(w.encodeCall("run", '{"o": {"kind": "success", "value": "done"}}')).toBe(
    'run(success("done"))',
  );
  expect(w.decodeResult("run", 'success("done")')).toBe(
    '{"kind":"success","value":"done"}',
  );

  // payload case with u64 — exercises the bigint-quoting inside the variant value
  const max = "18446744073709551615";
  const encoded = w.encodeCall(
    "run",
    JSON.stringify({ o: { kind: "failed", value: max } }),
  );
  expect(encoded).toBe(`run(failed(${max}))`);
  const wave = encoded.slice("run(".length, -1);
  const decoded = JSON.parse(w.decodeResult("run", wave));
  expect(decoded).toEqual({ kind: "failed", value: max });
});

test("Wit variant rejects unknown case names", () => {
  const wit = `${KONTOR_HEADER}
    variant outcome { ok, oops }
    export run: async func(ctx: borrow<proc-context>, o: outcome) -> outcome;
}`;
  const w = new Wit(wit);
  expect(() => w.encodeCall("run", '{"o": {"kind": "nope"}}')).toThrow(
    /unknown variant case/,
  );
});

test("Wit variant rejects shape mismatches (value on unit case, missing value on payload case)", () => {
  const wit = `${KONTOR_HEADER}
    variant outcome {
        unit,
        with-payload(string),
    }
    export run: async func(ctx: borrow<proc-context>, o: outcome) -> outcome;
}`;
  const w = new Wit(wit);
  expect(() =>
    w.encodeCall("run", '{"o": {"kind": "unit", "value": "bad"}}'),
  ).toThrow(/is unit but JSON has 'value'/);
  expect(() =>
    w.encodeCall("run", '{"o": {"kind": "with-payload"}}'),
  ).toThrow(/requires 'value' field/);
});

// ─── result<T, E> ─────────────────────────────────────────────────────
// Validates locked encoding shape #6: result reuses the variant shape
// with kind "ok" / "err". Same {kind, value} structure, same codec path.

test("Wit result<string, error> decodes both arms with built-in error variant payload", () => {
  // Kontor's validator requires the err type to be the built-in `error`
  // variant ({message(string), overflow(string), ...}). This test
  // exercises result + nested variant decoding in one go.
  const wit = `${KONTOR_HEADER}
    export run: async func(ctx: borrow<proc-context>, msg: string) -> result<string, error>;
}`;
  const w = new Wit(wit);

  // ok with payload
  expect(JSON.parse(w.decodeResult("run", 'ok("done")'))).toEqual({
    kind: "ok",
    value: "done",
  });

  // err with nested variant payload
  const errDecoded = JSON.parse(w.decodeResult("run", 'err(message("boom"))'));
  expect(errDecoded).toEqual({
    kind: "err",
    value: { kind: "message", value: "boom" },
  });
});

test("Wit result<_, error> decodes ok unit case (no value field) + err variant", () => {
  const wit = `${KONTOR_HEADER}
    export run: async func(ctx: borrow<proc-context>) -> result<_, error>;
}`;
  const w = new Wit(wit);

  // ok unit case: just {kind:"ok"} — no value field per locked shape #6.
  expect(w.decodeResult("run", "ok")).toBe('{"kind":"ok"}');

  const errDecoded = JSON.parse(w.decodeResult("run", 'err(overflow("u64"))'));
  expect(errDecoded).toEqual({
    kind: "err",
    value: { kind: "overflow", value: "u64" },
  });
});

// ─── list<T> ──────────────────────────────────────────────────────────

test("Wit list<u8> round-trips as JSON array of numbers", () => {
  // list<u8> is the only u8 form allowed by Kontor's validator —
  // common for byte arrays (addresses, BLS keys, etc.).
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, bytes: list<u8>) -> list<u8>;
}`;
  const w = new Wit(wit);
  const bytes = [0, 1, 127, 255];
  const encoded = w.encodeCall("echo", JSON.stringify({ bytes }));
  expect(encoded).toBe("echo([0, 1, 127, 255])");
  const wave = encoded.slice("echo(".length, -1);
  expect(JSON.parse(w.decodeResult("echo", wave))).toEqual(bytes);
});

test("Wit list<string> round-trips with proper escaping", () => {
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, xs: list<string>) -> list<string>;
}`;
  const w = new Wit(wit);
  const xs = ["hello", 'with "quotes"', "👋"];
  const encoded = w.encodeCall("echo", JSON.stringify({ xs }));
  const wave = encoded.slice("echo(".length, -1);
  expect(JSON.parse(w.decodeResult("echo", wave))).toEqual(xs);
});

test("Wit list<u64> round-trips quoted-decimal items", () => {
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, xs: list<u64>) -> list<u64>;
}`;
  const w = new Wit(wit);
  const xs = ["0", "12345", "18446744073709551615"];
  const encoded = w.encodeCall("echo", JSON.stringify({ xs }));
  expect(encoded).toBe(`echo([${xs.join(", ")}])`);
  const wave = encoded.slice("echo(".length, -1);
  expect(JSON.parse(w.decodeResult("echo", wave))).toEqual(xs);
});

test("Wit empty list round-trips", () => {
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, xs: list<string>) -> list<string>;
}`;
  const w = new Wit(wit);
  expect(w.encodeCall("echo", '{"xs": []}')).toBe("echo([])");
  expect(JSON.parse(w.decodeResult("echo", "[]"))).toEqual([]);
});

// ─── enum ─────────────────────────────────────────────────────────────
// Enum = variant where every case is unit. JSON shape is just the case
// name as a plain string (no {kind} wrapping needed; there's no payload).

test("Wit enum round-trips as a plain JSON string", () => {
  const wit = `${KONTOR_HEADER}
    enum traffic-light { red, yellow, green }
    export step: async func(ctx: borrow<proc-context>, current: traffic-light) -> traffic-light;
}`;
  const w = new Wit(wit);
  for (const case_ of ["red", "yellow", "green"]) {
    const encoded = w.encodeCall("step", JSON.stringify({ current: case_ }));
    expect(encoded).toBe(`step(${case_})`);
    expect(w.decodeResult("step", case_)).toBe(`"${case_}"`);
  }
});

test("Wit enum rejects unknown case names", () => {
  const wit = `${KONTOR_HEADER}
    enum traffic-light { red, yellow, green }
    export step: async func(ctx: borrow<proc-context>, current: traffic-light) -> traffic-light;
}`;
  const w = new Wit(wit);
  expect(() => w.encodeCall("step", '{"current": "purple"}')).toThrow(
    /unknown enum case/,
  );
});

// Note: Kontor's wit_validator currently rejects `flags` ("not supported")
// and `tuple` ("use a named record instead") at the contract level. The
// codec handles them for compound nesting completeness but they can't be
// exercised through a top-level param in a valid Kontor contract.

// ─── string ───────────────────────────────────────────────────────────

test("Wit string round-trips, including escape characters", () => {
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, s: string) -> string;
}`;
  const w = new Wit(wit);
  const cases = ["hello", 'with "quotes"', "back\\slash", "unicode: 👋"];
  for (const original of cases) {
    const encoded = w.encodeCall("echo", JSON.stringify({ s: original }));
    const wave = encoded.slice("echo(".length, -1);
    expect(JSON.parse(w.decodeResult("echo", wave))).toBe(original);
  }
});

// ─── smoke: real Kontor contract WIT ────────────────────────────────
// Loads the actual native token contract WIT and exercises a couple of
// realistic calls end-to-end. Anything that breaks here would show up
// in production use of @kontor/sdk against a deployed token contract.

import tokenWit from "../../native-contracts/token/wit/contract.wit?raw";

test("smoke: encodeCall against real token.wit transfer (holder-ref + decimal)", () => {
  const w = new Wit(tokenWit);

  // transfer(ctx: borrow<proc-context>, dst: holder-ref, amt: decimal)
  //   holder-ref = variant { x-only-pubkey(string), signer-id(u64), core, burner, utxo(out-point) }
  //   decimal    = record { r0..r3: u64, sign: enum {plus, minus} }
  const args = {
    dst: { kind: "x-only-pubkey", value: "abc123" },
    amt: { r0: "100", r1: "0", r2: "0", r3: "0", sign: "plus" },
  };
  const wave = w.encodeCall("transfer", JSON.stringify(args));
  expect(wave).toBe(
    'transfer(x-only-pubkey("abc123"), {r0: 100, r1: 0, r2: 0, r3: 0, sign: plus})',
  );
});

test("smoke: decodeResult against real token.wit balance (option<decimal>)", () => {
  const w = new Wit(tokenWit);

  // balance returns option<decimal>. WAVE for some-decimal:
  //   some({r0: 42, r1: 0, r2: 0, r3: 0, sign: plus})
  expect(
    JSON.parse(
      w.decodeResult("balance", "some({r0: 42, r1: 0, r2: 0, r3: 0, sign: plus})"),
    ),
  ).toEqual({ r0: "42", r1: "0", r2: "0", r3: "0", sign: "plus" });

  // none case (account doesn't exist) → null
  expect(w.decodeResult("balance", "none")).toBe("null");
});

test("smoke: encodeCall against real token.wit handles holder-ref unit cases", () => {
  const w = new Wit(tokenWit);

  // transfer with dst = `core` (a unit variant case — no value field)
  const args = {
    dst: { kind: "core" },
    amt: { r0: "1", r1: "0", r2: "0", r3: "0", sign: "plus" },
  };
  const wave = w.encodeCall("transfer", JSON.stringify(args));
  expect(wave).toBe("transfer(core, {r0: 1, r1: 0, r2: 0, r3: 0, sign: plus})");
});

// ─── parse() — Resolve graph as JSON ──────────────────────────────────

test("Wit.parse returns valid JSON describing the Resolve graph", () => {
  const wit = `${KONTOR_HEADER}
    export init: ;
}`.replace("export init: ;", ""); // strip duplicate init from header
  const cleanWit = `package root:component;

world root {
    include kontor:built-in/built-in;
    use kontor:built-in/context.{proc-context, view-context};
    use kontor:built-in/error.{error};

    export init: async func(ctx: borrow<proc-context>);
    export set-flag: async func(ctx: borrow<proc-context>, flag: bool) -> result<_, error>;
}`;
  const w = new Wit(cleanWit);

  const parsed = JSON.parse(w.parse());
  // wit_parser's Resolve serializes with arenas keyed by stable names
  // (interfaces, types) and worlds keyed by id. Smoke-check the shape.
  expect(parsed).toHaveProperty("worlds");
  expect(parsed).toHaveProperty("interfaces");
  expect(parsed).toHaveProperty("types");
});

test("Wit.parse on real token.wit captures the contract's exports", () => {
  const w = new Wit(tokenWit);
  const parsed = JSON.parse(w.parse());

  // Look for the transfer export. The exact shape depends on wit-parser's
  // serialization; we just confirm transfer is somewhere in the dump.
  const blob = JSON.stringify(parsed);
  expect(blob).toContain("transfer");
  expect(blob).toContain("holder-ref");
  expect(blob).toContain("decimal");
});

test("Wit.parse propagates validation errors", () => {
  const w = new Wit("garbage");
  expect(() => w.parse()).toThrow(/WIT parse error/);
});

// ─── codegen Tier 1 ───────────────────────────────────────────────────

import { generate } from "@kontor/sdk";

test("codegen Tier 1: emits TS types + Contract interface from token.wit", () => {
  const out = generate(tokenWit);

  // Header comment
  expect(out).toContain("// Generated by kontor-codegen");

  // Should emit a Contract class (Tier 2)
  expect(out).toContain("export class Contract {");

  // Should include the transfer method, dropping ctx
  expect(out).toMatch(/async transfer\(dst: HolderRef, amt: Decimal\)/);

  // Should include the balance return type (option<decimal>) flattened to T | null
  expect(out).toMatch(
    /async balance\(acc: HolderRef\): Promise<Decimal \| null>/,
  );

  // All four canonical types are imported as classes from @kontor/sdk;
  // none of them gets a typedef in the generated module.
  expect(out).not.toMatch(/export type Decimal =/);
  expect(out).not.toMatch(/export type HolderRef =/);
  expect(out).not.toMatch(/export type Integer =/);
  expect(out).not.toMatch(/export type ContractAddress =/);
  // OutPoint is internal to HolderRef and shouldn't leak.
  expect(out).not.toMatch(/export type OutPoint =/);
  // Sign is internal to Decimal and shouldn't leak.
  expect(out).not.toMatch(/export type Sign =/);
});

test("codegen Tier 1: result<T,E> renders as discriminated union", () => {
  const out = generate(tokenWit);
  // hold returns result<transfer, error>; should render as
  // { kind: "ok"; value: ... } | { kind: "err"; value: ... }
  expect(out).toMatch(/\{ kind: "ok"; value: .+ \} \| \{ kind: "err"; value: .+ \}/);
});

test("codegen Tier 1: rejects invalid WIT", () => {
  expect(() => generate("garbage")).toThrow(/WIT parse error/);
});


// ─── codegen Tier 2: Contract class end-to-end ────────────────────────

test("codegen Tier 2: emits Contract class with transport + per-type helpers", () => {
  const out = generate(tokenWit);

  // Imports the runtime helpers + every canonical class actually used.
  // token.wit references Decimal + HolderRef but not Integer or ContractAddress.
  expect(out).toContain(
    'import { Wit, type KontorTransport, Decimal, HolderRef } from "@kontor/sdk";',
  );

  // Embeds the WIT and instantiates a Wit resource at module load.
  expect(out).toContain("const WIT = String.raw`");
  expect(out).toContain("const _wit = new Wit(WIT);");

  // Canonical types get no _encode/_decode helpers — encoders call
  // (v).toRaw(), decoders call <Class>.fromRaw(raw).
  expect(out).not.toMatch(/function _encodeDecimal\(/);
  expect(out).not.toMatch(/function _decodeDecimal\(/);
  expect(out).not.toMatch(/function _encodeHolderRef\(/);
  expect(out).not.toMatch(/function _decodeHolderRef\(/);

  // Contract class with constructor.
  expect(out).toContain("export class Contract {");
  expect(out).toContain("constructor(private transport: KontorTransport)");

  // view-context methods dispatch via simulate, proc-context via submit.
  expect(out).toMatch(
    /async balance\([^)]*\)[^{]*\{[\s\S]*?transport\.simulate/,
  );
  expect(out).toMatch(
    /async transfer\([^)]*\)[^{]*\{[\s\S]*?transport\.submit/,
  );

  // kebab function name in WIT → camelCase TS method.
  expect(out).toMatch(/async totalSupply\(/);
  // kebab param → camelCase in TS, kebab on the wire.
  expect(out).toMatch(/burnAmt:/);
  // Canonical types: args passed via `.toRaw()` rather than a helper.
  expect(out).toMatch(/"burn-amt": \(burnAmt\)\.toRaw\(\)/);
  expect(out).toMatch(/"dst": \(dst\)\.toRaw\(\)/);
  // Canonical types: results decoded via `<Class>.fromRaw(...)`.
  expect(out).toMatch(/Decimal\.fromRaw\(/);
  expect(out).toMatch(/HolderRef\.fromRaw\(/);

  // Variant encoders throw on unknown cases instead of silently
  // returning undefined (mirrors the decoder's default arm). Every
  // `switch (v.kind)` block — the variant-encoder shape — must be
  // closed by `default: throw new Error("unknown variant case: ...`.
  const variantSwitches = out.match(/switch \(v\.kind\)/g)?.length ?? 0;
  const variantDefaults =
    out.match(
      /switch \(v\.kind\) \{[\s\S]*?default: throw new Error\("unknown variant case:/g,
    )?.length ?? 0;
  expect(variantSwitches).toBeGreaterThan(0);
  expect(variantDefaults).toBe(variantSwitches);
});

// ─── numerics-api ─────────────────────────────────────────────────────
// Same arithmetic the chain uses (delegates to core/numerics from the
// shared crate). Smoke-test a few representative operations.

import { numerics } from "@kontor/sdk";

test("numerics: u64-to-decimal + decimal-to-string round-trip", () => {
  const d = numerics.u64ToDecimal(42n);
  expect(numerics.decimalToString(d)).toBe("42");
});

test("numerics: string round-trips decimal precisely", () => {
  const d = numerics.stringToDecimal("100.5");
  expect(numerics.decimalToString(d)).toBe("100.5");
});

test("numerics: add-decimal exact arithmetic", () => {
  const a = numerics.stringToDecimal("1.1");
  const b = numerics.stringToDecimal("2.2");
  const sum = numerics.addDecimal(a, b);
  expect(numerics.decimalToString(sum)).toBe("3.3");
});

test("numerics: div-decimal exposes div-by-zero error", () => {
  const a = numerics.stringToDecimal("1");
  const b = numerics.stringToDecimal("0");
  // jco wraps result<_, error> failures as a ComponentError whose
  // .payload is the variant value: { tag: "div-by-zero", val: "..." }
  try {
    numerics.divDecimal(a, b);
    throw new Error("expected divDecimal to throw");
  } catch (e: any) {
    expect(e.payload.tag).toBe("div-by-zero");
    expect(e.payload.val).toMatch(/divide by zero/);
  }
});

test("numerics: integer string round-trip with big values", () => {
  const huge = "57843975908437589027340573245";
  const i = numerics.stringToInteger(huge);
  expect(numerics.integerToString(i)).toBe(huge);
});

test("numerics: integer overflow surfaces as error", () => {
  const oversized =
    "115792089237316195423570985008687907853269984665640564039458";
  try {
    numerics.stringToInteger(oversized);
    throw new Error("expected stringToInteger to throw");
  } catch (e: any) {
    expect(e.payload.tag).toBe("overflow");
  }
});

// ─── canonical Decimal class ─────────────────────────────────────────
// Hand-written wrapper over the raw {r0,r1,r2,r3,sign} record.

import { Decimal } from "@kontor/sdk";

test("Decimal: string round-trip preserves fractional precision", () => {
  expect(Decimal.from("100.5").toString()).toBe("100.5");
  expect(Decimal.from("-3.14159").toString()).toBe("-3.14159");
});

test("Decimal: bigint constructor handles values beyond u64", () => {
  const big = 18446744073709551616n; // 2^64
  expect(Decimal.from(big).toString()).toBe("18446744073709551616");
  expect(Decimal.from(-1n).toString()).toBe("-1");
});

test("Decimal: number constructor for convenient f64 input", () => {
  expect(Decimal.from(42).toString()).toBe("42");
});

test("Decimal: arithmetic delegates to numerics (exact)", () => {
  const a = Decimal.from("1.1");
  const b = Decimal.from("2.2");
  expect(a.add(b).toString()).toBe("3.3");
  expect(b.sub(a).toString()).toBe("1.1");
  expect(a.mul(b).toString()).toBe("2.42");
  expect(Decimal.from("10").div(Decimal.from("4")).toString()).toBe("2.5");
});

test("Decimal: eq and cmp", () => {
  const a = Decimal.from("3.14");
  const b = Decimal.from("3.14");
  const c = Decimal.from("2.71");
  expect(a.eq(b)).toBe(true);
  expect(a.eq(c)).toBe(false);
  expect(a.cmp(b)).toBe("equal");
  expect(c.cmp(a)).toBe("less");
  expect(a.cmp(c)).toBe("greater");
});

test("Decimal: fromRaw / toRaw round-trip for codec interop", () => {
  const d = Decimal.from("42.5");
  const raw = d.toRaw();
  const back = Decimal.fromRaw(raw);
  expect(back.toString()).toBe("42.5");
});

// ─── canonical Integer class ─────────────────────────────────────────
// Hand-written wrapper over the raw {r0..r3, sign} record.

import { Integer } from "@kontor/sdk";

test("Integer: string round-trip preserves arbitrary-precision values", () => {
  const huge = "57843975908437589027340573245";
  expect(Integer.from(huge).toString()).toBe(huge);
  expect(Integer.from("-12345").toString()).toBe("-12345");
});

test("Integer: bigint constructor handles values beyond u64", () => {
  const big = 18446744073709551616n; // 2^64
  expect(Integer.from(big).toString()).toBe("18446744073709551616");
  expect(Integer.from(-1n).toString()).toBe("-1");
});

test("Integer: number constructor truncates fractional part", () => {
  expect(Integer.from(42).toString()).toBe("42");
  expect(Integer.from(3.7).toString()).toBe("3");
  expect(Integer.from(-2.9).toString()).toBe("-2");
});

test("Integer: arithmetic delegates to numerics (exact)", () => {
  const a = Integer.from("100");
  const b = Integer.from("7");
  expect(a.add(b).toString()).toBe("107");
  expect(a.sub(b).toString()).toBe("93");
  expect(a.mul(b).toString()).toBe("700");
  expect(a.div(b).toString()).toBe("14");
  expect(Integer.from("144").sqrt().toString()).toBe("12");
});

test("Integer: eq and cmp", () => {
  const a = Integer.from("42");
  const b = Integer.from("42");
  const c = Integer.from("17");
  expect(a.eq(b)).toBe(true);
  expect(a.eq(c)).toBe(false);
  expect(a.cmp(b)).toBe("equal");
  expect(c.cmp(a)).toBe("less");
  expect(a.cmp(c)).toBe("greater");
});

test("Integer: fromRaw / toRaw round-trip for codec interop", () => {
  const i = Integer.from("99999999999999999999");
  const raw = i.toRaw();
  const back = Integer.fromRaw(raw);
  expect(back.toString()).toBe("99999999999999999999");
});

// ─── canonical HolderRef class ───────────────────────────────────────

import { HolderRef } from "@kontor/sdk";

test("HolderRef: factories produce the expected variants", () => {
  expect(HolderRef.xOnlyPubkey("abc").kind).toBe("x-only-pubkey");
  expect(HolderRef.signerId(42n).kind).toBe("signer-id");
  expect(HolderRef.core().kind).toBe("core");
  expect(HolderRef.burner().kind).toBe("burner");
  expect(HolderRef.utxo({ txid: "deadbeef", vout: 0n }).kind).toBe("utxo");
});

test("HolderRef: toRaw quotes u64 fields and unwraps payloads", () => {
  expect(HolderRef.xOnlyPubkey("abc").toRaw()).toEqual({
    kind: "x-only-pubkey",
    value: "abc",
  });
  expect(HolderRef.signerId(42n).toRaw()).toEqual({
    kind: "signer-id",
    value: "42",
  });
  expect(HolderRef.core().toRaw()).toEqual({ kind: "core" });
  expect(HolderRef.utxo({ txid: "deadbeef", vout: 7n }).toRaw()).toEqual({
    kind: "utxo",
    value: { txid: "deadbeef", vout: "7" },
  });
});

test("HolderRef: fromRaw round-trips every variant", () => {
  const cases: ReturnType<HolderRef["toRaw"]>[] = [
    { kind: "x-only-pubkey", value: "abc" },
    { kind: "signer-id", value: "42" },
    { kind: "core" },
    { kind: "burner" },
    { kind: "utxo", value: { txid: "deadbeef", vout: "7" } },
  ];
  for (const raw of cases) {
    expect(HolderRef.fromRaw(raw).toRaw()).toEqual(raw);
  }
});

test("HolderRef: unwrap narrows on .kind", () => {
  const h = HolderRef.signerId(42n);
  const v = h.unwrap();
  if (v.kind === "signer-id") {
    expect(v.value).toBe(42n);
  } else {
    throw new Error("expected signer-id variant");
  }
});

// ─── canonical ContractAddress class ─────────────────────────────────

import { ContractAddress } from "@kontor/sdk";

test("ContractAddress: constructor + readonly fields", () => {
  const addr = new ContractAddress("foo", 100n, 3n);
  expect(addr.name).toBe("foo");
  expect(addr.height).toBe(100n);
  expect(addr.txIndex).toBe(3n);
});

test("ContractAddress: toRaw quotes u64 fields with kebab keys", () => {
  expect(new ContractAddress("foo", 100n, 3n).toRaw()).toEqual({
    name: "foo",
    height: "100",
    "tx-index": "3",
  });
});

test("ContractAddress: fromRaw decodes string-quoted bigints", () => {
  const addr = ContractAddress.fromRaw({
    name: "foo",
    height: "100",
    "tx-index": "3",
  });
  expect(addr.name).toBe("foo");
  expect(addr.height).toBe(100n);
  expect(addr.txIndex).toBe(3n);
});

test("ContractAddress: toString gives a human-readable form", () => {
  expect(new ContractAddress("foo", 100n, 3n).toString()).toBe("foo@100.3");
});

