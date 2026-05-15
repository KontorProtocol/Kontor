/**
 * 256-bit signed arbitrary-precision integer. Same semantics as
 * Kontor's on-chain `integer` type — every operation delegates to the
 * shared `numerics` crate via the WASM Component, so SDK arithmetic
 * and chain arithmetic are byte-for-byte identical.
 *
 * Construct from strings for values past 2^53; `bigint` is routed
 * through string so arbitrary-size and negative values work uniformly.
 * The `number` path truncates the fractional part and is lossy past
 * 2^53.
 */
import { numerics } from "../component/kontor-sdk";

type Sign = "plus" | "minus";

/**
 * On-wire shape used at codec boundaries. u64 limb fields are quoted
 * decimal strings so the value survives `JSON.stringify` — TS bigint
 * has no JSON representation. The internal `numerics.Integer` keeps
 * bigints because jco's WASM bindings need them for i64 marshaling.
 */
type Raw = { r0: string; r1: string; r2: string; r3: string; sign: Sign };

export class Integer {
  private constructor(private readonly inner: numerics.Integer) {}

  static from(value: string | bigint | number): Integer {
    if (typeof value === "string") {
      return new Integer(numerics.stringToInteger(value));
    }
    if (typeof value === "bigint") {
      return new Integer(numerics.stringToInteger(value.toString()));
    }
    return new Integer(numerics.stringToInteger(Math.trunc(value).toString()));
  }

  /**
   * Build an Integer from the wire-shape record (u64 fields as quoted
   * decimals) that codec/decode produces. Used by codegen-emitted
   * decoders.
   */
  static fromRaw(raw: Raw): Integer {
    return new Integer({
      r0: BigInt(raw.r0),
      r1: BigInt(raw.r1),
      r2: BigInt(raw.r2),
      r3: BigInt(raw.r3),
      sign: raw.sign,
    });
  }

  /**
   * Expose the wire shape: u64 fields as quoted decimal strings so the
   * value can flow through `JSON.stringify` into the WAVE codec. Used
   * by codegen-emitted encoders.
   */
  toRaw(): Raw {
    return {
      r0: this.inner.r0.toString(),
      r1: this.inner.r1.toString(),
      r2: this.inner.r2.toString(),
      r3: this.inner.r3.toString(),
      sign: this.inner.sign,
    };
  }

  toString(): string {
    return numerics.integerToString(this.inner);
  }

  add(other: Integer): Integer {
    return new Integer(numerics.addInteger(this.inner, other.inner));
  }

  sub(other: Integer): Integer {
    return new Integer(numerics.subInteger(this.inner, other.inner));
  }

  mul(other: Integer): Integer {
    return new Integer(numerics.mulInteger(this.inner, other.inner));
  }

  div(other: Integer): Integer {
    return new Integer(numerics.divInteger(this.inner, other.inner));
  }

  sqrt(): Integer {
    return new Integer(numerics.sqrtInteger(this.inner));
  }

  eq(other: Integer): boolean {
    return numerics.eqInteger(this.inner, other.inner);
  }

  cmp(other: Integer): "less" | "equal" | "greater" {
    return numerics.cmpInteger(this.inner, other.inner);
  }
}
