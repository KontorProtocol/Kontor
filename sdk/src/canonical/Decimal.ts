/**
 * 256-bit signed decimal with 18 fractional digits (10^18 scale). Same
 * semantics as Kontor's on-chain `decimal` type — every operation
 * delegates to the shared `numerics` crate via the WASM Component, so
 * SDK arithmetic and chain arithmetic are byte-for-byte identical.
 *
 * Construct from strings for arbitrary precision. The `bigint`
 * constructor stringifies first; the `number` (f64) path is convenient
 * but lossy for values that don't round-trip through f64.
 */
import { numerics } from "../component/kontor-sdk";

export class Decimal {
  private constructor(private readonly raw: numerics.Decimal) {}

  static from(value: string | bigint | number): Decimal {
    if (typeof value === "string") {
      return new Decimal(numerics.stringToDecimal(value));
    }
    if (typeof value === "bigint") {
      // Route arbitrary-size bigints through string so negative and
      // > u64 values work uniformly.
      return new Decimal(numerics.stringToDecimal(value.toString()));
    }
    return new Decimal(numerics.f64ToDecimal(value));
  }

  /**
   * Build a Decimal from the raw `{r0,r1,r2,r3,sign}` record that
   * codec/decode produces. Used by codegen-emitted helpers.
   */
  static fromRaw(raw: numerics.Decimal): Decimal {
    return new Decimal(raw);
  }

  /**
   * Expose the raw on-wire shape. Used by codegen-emitted encoders to
   * package a `Decimal` back into the JSON the WAVE codec accepts.
   */
  toRaw(): numerics.Decimal {
    return this.raw;
  }

  toString(): string {
    return numerics.decimalToString(this.raw);
  }

  add(other: Decimal): Decimal {
    return new Decimal(numerics.addDecimal(this.raw, other.raw));
  }

  sub(other: Decimal): Decimal {
    return new Decimal(numerics.subDecimal(this.raw, other.raw));
  }

  mul(other: Decimal): Decimal {
    return new Decimal(numerics.mulDecimal(this.raw, other.raw));
  }

  div(other: Decimal): Decimal {
    return new Decimal(numerics.divDecimal(this.raw, other.raw));
  }

  eq(other: Decimal): boolean {
    return numerics.eqDecimal(this.raw, other.raw);
  }

  cmp(other: Decimal): "less" | "equal" | "greater" {
    return numerics.cmpDecimal(this.raw, other.raw);
  }
}
