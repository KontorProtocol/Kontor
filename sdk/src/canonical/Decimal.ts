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

type Sign = "plus" | "minus";

/**
 * On-wire shape used at codec boundaries. u64 limb fields are quoted
 * decimal strings so the value survives `JSON.stringify` — TS bigint
 * has no JSON representation. The internal `numerics.Decimal` keeps
 * bigints because jco's WASM bindings need them for i64 marshaling.
 */
type Raw = { r0: string; r1: string; r2: string; r3: string; sign: Sign };

export class Decimal {
  private constructor(private readonly inner: numerics.Decimal) {}

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
   * Build a Decimal from the wire-shape record (u64 fields as quoted
   * decimals) that codec/decode produces. Used by codegen-emitted
   * decoders.
   */
  static fromRaw(raw: Raw): Decimal {
    return new Decimal({
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
    return numerics.decimalToString(this.inner);
  }

  add(other: Decimal): Decimal {
    return new Decimal(numerics.addDecimal(this.inner, other.inner));
  }

  sub(other: Decimal): Decimal {
    return new Decimal(numerics.subDecimal(this.inner, other.inner));
  }

  mul(other: Decimal): Decimal {
    return new Decimal(numerics.mulDecimal(this.inner, other.inner));
  }

  div(other: Decimal): Decimal {
    return new Decimal(numerics.divDecimal(this.inner, other.inner));
  }

  eq(other: Decimal): boolean {
    return numerics.eqDecimal(this.inner, other.inner);
  }

  cmp(other: Decimal): "less" | "equal" | "greater" {
    return numerics.cmpDecimal(this.inner, other.inner);
  }
}
