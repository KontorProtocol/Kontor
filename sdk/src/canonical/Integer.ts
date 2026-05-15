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

export class Integer {
  private constructor(private readonly raw: numerics.Integer) {}

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
   * Build an Integer from the raw record that codec/decode produces.
   * Used by codegen-emitted helpers.
   */
  static fromRaw(raw: numerics.Integer): Integer {
    return new Integer(raw);
  }

  /**
   * Expose the raw on-wire shape. Used by codegen-emitted encoders to
   * package an `Integer` back into the JSON the WAVE codec accepts.
   */
  toRaw(): numerics.Integer {
    return this.raw;
  }

  toString(): string {
    return numerics.integerToString(this.raw);
  }

  add(other: Integer): Integer {
    return new Integer(numerics.addInteger(this.raw, other.raw));
  }

  sub(other: Integer): Integer {
    return new Integer(numerics.subInteger(this.raw, other.raw));
  }

  mul(other: Integer): Integer {
    return new Integer(numerics.mulInteger(this.raw, other.raw));
  }

  div(other: Integer): Integer {
    return new Integer(numerics.divInteger(this.raw, other.raw));
  }

  sqrt(): Integer {
    return new Integer(numerics.sqrtInteger(this.raw));
  }

  eq(other: Integer): boolean {
    return numerics.eqInteger(this.raw, other.raw);
  }

  cmp(other: Integer): "less" | "equal" | "greater" {
    return numerics.cmpInteger(this.raw, other.raw);
  }
}
