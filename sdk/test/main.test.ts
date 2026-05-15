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
  const w = new witApi.Wit(wit);

  expect(w.encodeCall("set-flag", '{"flag": true}')).toBe("set-flag(true)");
  expect(w.encodeCall("set-flag", '{"flag": false}')).toBe("set-flag(false)");
});

test("Wit construction rejects WIT that fails validation", () => {
  // Missing the `borrow<context>` first param — validator rejects.
  const badWit = `${KONTOR_HEADER}
    export bad-func: async func(val: string) -> string;
}`;
  const w = new witApi.Wit(badWit);
  expect(() => w.encodeCall("bad-func", '{}')).toThrow(/WIT validation/);
});

test("Wit construction rejects malformed WIT", () => {
  const w = new witApi.Wit("this is not valid wit at all");
  expect(() => w.encodeCall("anything", '{}')).toThrow(/WIT parse error/);
});

test("Wit.encodeCall errors when function missing", () => {
  const wit = `${KONTOR_HEADER}
    export set-flag: async func(ctx: borrow<proc-context>, flag: bool) -> result<_, error>;
}`;
  const w = new witApi.Wit(wit);

  expect(() => w.encodeCall("no-such-fn", "{}")).toThrow(/function not found/);
});

test("Wit.encodeCall errors when bool arg has wrong JSON type", () => {
  const wit = `${KONTOR_HEADER}
    export set-flag: async func(ctx: borrow<proc-context>, flag: bool) -> result<_, error>;
}`;
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);

  expect(w.encodeCall("add", '{"x": "12345"}')).toBe("add(12345)");
  expect(w.encodeCall("add", '{"x": "18446744073709551615"}')).toBe(
    "add(18446744073709551615)",
  );
});

test("Wit.encodeCall errors when u64 arg isn't a string", () => {
  const wit = `${KONTOR_HEADER}
    export add: async func(ctx: borrow<view-context>, x: u64) -> u64;
}`;
  const w = new witApi.Wit(wit);

  expect(() => w.encodeCall("add", '{"x": 12345}')).toThrow(
    /expected JSON string holding a u64 decimal/,
  );
});

test("Wit.decodeResult parses a u64 WAVE return into a quoted-decimal JSON string", () => {
  const wit = `${KONTOR_HEADER}
    export add: async func(ctx: borrow<view-context>, x: u64) -> u64;
}`;
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);

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
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(wit);
  const xs = ["hello", 'with "quotes"', "👋"];
  const encoded = w.encodeCall("echo", JSON.stringify({ xs }));
  const wave = encoded.slice("echo(".length, -1);
  expect(JSON.parse(w.decodeResult("echo", wave))).toEqual(xs);
});

test("Wit list<u64> round-trips quoted-decimal items", () => {
  const wit = `${KONTOR_HEADER}
    export echo: async func(ctx: borrow<view-context>, xs: list<u64>) -> list<u64>;
}`;
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(wit);
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
  const w = new witApi.Wit(tokenWit);

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
  const w = new witApi.Wit(tokenWit);

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
  const w = new witApi.Wit(tokenWit);

  // transfer with dst = `core` (a unit variant case — no value field)
  const args = {
    dst: { kind: "core" },
    amt: { r0: "1", r1: "0", r2: "0", r3: "0", sign: "plus" },
  };
  const wave = w.encodeCall("transfer", JSON.stringify(args));
  expect(wave).toBe("transfer(core, {r0: 1, r1: 0, r2: 0, r3: 0, sign: plus})");
});
