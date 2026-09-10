# Exact numeric primitives

Integer has a 256-bit magnitude and a separate sign. Its range is
`-(2^256 - 1)` through `2^256 - 1`. Decimal uses the same coefficient
representation with a fixed scale of `10^18`. Whole Integer values therefore
have a wider range than whole Decimal values.

Parsing and ordinary Integer arithmetic check the shared representation limit.
The former smaller Integer ceiling reserved Decimal's fractional digits even
when no Decimal conversion occurred. That ceiling is removed; an actual
Integer-to-Decimal conversion checks the scaled coefficient exactly.
This changes consensus-visible arithmetic at the old Integer boundary, while
preserving Decimal's capacity and the existing protocol voting-power limits.

## Value conversion and raw units

These are separate operations:

| Operation                | Example                                              |
| ------------------------ | ---------------------------------------------------- |
| Whole Integer to Decimal | `1` becomes `1.0`; overflow is checked after scaling |
| Decimal to whole Integer | `-1.25` becomes `-1`, truncating toward zero         |
| Decimal to raw units     | `-1.25` becomes `-1250000000000000000`               |
| Raw units to Decimal     | `1` becomes `0.000000000000000001`                   |

Rust's `Decimal::to_raw_units` / `from_raw_units` and TypeScript's
`toRawUnits` / `fromRawUnits` preserve the signed coefficient exactly.
They do not replace ordinary numeric conversion or the SDK's wire-record
`toRaw` / `fromRaw` codec adapters.

Decimal-to-Integer conversion divides the signed coefficient directly by the
scale, avoiding a decimal/string/parser round trip. Integer constants can use
`Integer::from_u128` without parsing. The ordinary Rust small-integer constructors
also construct the representation directly; their former private backend wrappers
are removed. Existing public host conversion exports remain available. Avoiding
those host calls changes metered costs, so affected contract binaries are rebuilt.

## Wide multiply/add/divide

`checked_mul_add_div_rem(multiplier, carry, divisor)` computes the quotient and
remainder of `(self * multiplier + carry) / divisor`. All inputs must be
nonnegative and the divisor positive. The numerator may need 512 bits, but the
quotient must fit Integer. The remainder is always less than the divisor, and
`quotient * divisor + remainder` equals the exact numerator.

Ordinary multiplication still rejects an oversized product. Ordinary signed
division remains available. Neither is superseded by the new nonnegative wide
operation. The core implementation is shared by the metered contract host, native
Rust, the browser component, and the native SDK bridge. The host charges 500 fuel
for the bounded wide operation, separately from guest execution.

The TypeScript `Integer.checkedMulAddDivRem` returns named `quotient` and
`remainder` values. Its browser and native backends use the same shared arithmetic;
no JavaScript arithmetic implementation is introduced. Native and WIT result
adapters only translate their respective record/tuple representations.

## Scope and validation

This facility has no reward eligibility or cleanup policy and makes no stored
layout change. Numeric scalar storage is separate work. Regression coverage
includes signed and full-range conversions, wide intermediates, final overflow,
zero/negative inputs, retained remainders, native/contract bridge behavior, and
SDK comparisons against independent BigInt calculations. Contract binaries are
rebuilt with the pinned image; browser and native SDK bindings are regenerated
from their sources.
