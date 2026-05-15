/**
 * Type-aware JSON conversion for @kontor/sdk's Wit codec.
 *
 * The WAVE codec on the Rust side uses quoted-decimal strings for u64/s64
 * (JS Number can't safely hold > 2^53). The TS-facing types expose these
 * as `bigint` for ergonomics. These walkers bridge the two:
 *
 *   encodeJson(value, typeNode)  bigint  →  string  (just before Wit.encodeCall)
 *   decodeJson(value, typeNode)  string  →  bigint  (just after Wit.decodeResult)
 *
 * The TypeNode AST is emitted by `kontor-codegen` per function, capturing
 * just enough type info to know which paths need the conversion.
 */

/** Per-field info for record nodes. Wire keys are kebab-case (WIT names),
 *  JS keys are camelCase (idiomatic TS). The walker uses `js` to read from
 *  user-side JS values and `wire` to write to JSON sent to the codec. */
export interface FieldNode {
  js: string;
  wire: string;
  t: TypeNode;
}

export type TypeNode =
  | { k: "bigint" } // u64 or s64 — round-tripped as decimal string
  | { k: "passthrough" } // bool, smaller ints, strings, char, floats, enums
  | { k: "list"; el: TypeNode }
  | { k: "option"; el: TypeNode } // T | null
  | { k: "record"; fields: FieldNode[] }
  | { k: "variant"; cases: Record<string, TypeNode | null> } // case names stay kebab on both sides
  | {
      k: "result";
      ok: TypeNode | null;
      err: TypeNode | null;
    }
  | { k: "tuple"; els: TypeNode[] };

export function encodeJson(value: unknown, t: TypeNode): unknown {
  if (value == null && t.k === "option") return null;
  switch (t.k) {
    case "bigint":
      return (value as bigint).toString();
    case "passthrough":
      return value;
    case "list":
      return (value as unknown[]).map((v) => encodeJson(v, t.el));
    case "option":
      return value == null ? null : encodeJson(value, t.el);
    case "record": {
      const out: Record<string, unknown> = {};
      for (const f of t.fields) {
        out[f.wire] = encodeJson(
          (value as Record<string, unknown>)[f.js],
          f.t,
        );
      }
      return out;
    }
    case "variant": {
      const v = value as { kind: string; value?: unknown };
      const inner = t.cases[v.kind];
      if (inner == null) return { kind: v.kind };
      return { kind: v.kind, value: encodeJson(v.value, inner) };
    }
    case "result": {
      const v = value as { kind: "ok" | "err"; value?: unknown };
      const inner = v.kind === "ok" ? t.ok : t.err;
      if (inner == null) return { kind: v.kind };
      return { kind: v.kind, value: encodeJson(v.value, inner) };
    }
    case "tuple":
      return (value as unknown[]).map((v, i) => encodeJson(v, t.els[i]));
  }
}

export function decodeJson(value: unknown, t: TypeNode): unknown {
  if (value == null && t.k === "option") return null;
  switch (t.k) {
    case "bigint":
      return BigInt(value as string);
    case "passthrough":
      return value;
    case "list":
      return (value as unknown[]).map((v) => decodeJson(v, t.el));
    case "option":
      return value == null ? null : decodeJson(value, t.el);
    case "record": {
      const out: Record<string, unknown> = {};
      for (const f of t.fields) {
        out[f.js] = decodeJson(
          (value as Record<string, unknown>)[f.wire],
          f.t,
        );
      }
      return out;
    }
    case "variant": {
      const v = value as { kind: string; value?: unknown };
      const inner = t.cases[v.kind];
      if (inner == null) return { kind: v.kind };
      return { kind: v.kind, value: decodeJson(v.value, inner) };
    }
    case "result": {
      const v = value as { kind: "ok" | "err"; value?: unknown };
      const inner = v.kind === "ok" ? t.ok : t.err;
      if (inner == null) return { kind: v.kind };
      return { kind: v.kind, value: decodeJson(v.value, inner) };
    }
    case "tuple":
      return (value as unknown[]).map((v, i) => decodeJson(v, t.els[i]));
  }
}

/**
 * Transport that a generated `Contract` uses to dispatch encoded WAVE
 * expressions. Implementations decide the actual mechanism:
 *
 * - `simulate` for view-context calls (no chain mutation)
 * - `submit`   for proc-context calls (requires a transaction)
 *
 * The generated contract methods pick the right one based on the
 * function's context type, baked in at codegen time.
 */
export interface KontorTransport {
  simulate(wave: string): Promise<string>;
  submit(wave: string): Promise<string>;
}
