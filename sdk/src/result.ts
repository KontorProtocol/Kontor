/**
 * `Result<T, E>` — the TypeScript shape codegen emits for a WIT
 * `result<T, E>`. Kept as a plain discriminated union (not a class) so
 * codegen-emitted inline result types match structurally without
 * imports, and existing user code keeps working unchanged.
 *
 * The `Result` namespace value (same name, different scope — TS allows
 * type + value with the same name) provides conveniences for the
 * common patterns: type guards (`isOk` / `isErr`), unwrap (throws on
 * the wrong side), and `match` (typed fold over both arms).
 *
 *     const r: Result<Mint, Error> = await token.issuance(amt);
 *     if (Result.isOk(r)) console.log(r.value.amt);
 *     const mint = Result.unwrap(r);            // throws on err
 *     const amt = Result.match(r, {
 *       ok:  (m) => m.amt.toString(),
 *       err: (e) => "0",
 *     });
 *
 * Tests in particular benefit — assertions like
 * `if (r.kind !== "ok") throw ...; expect(r.value...)` collapse into
 * `expect(Result.unwrap(r)...)`.
 */

/** WIT `result<T, E>` shape — what codegen emits inline for variant returns. */
export type Result<T, E> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "err"; readonly value: E };

/** Conveniences for working with `Result<T, E>`. Same name as the type. */
export const Result = {
  /** Type guard: narrows `r` to the `ok` arm so `r.value` is `T`. */
  isOk<T, E>(r: Result<T, E>): r is { readonly kind: "ok"; readonly value: T } {
    return r.kind === "ok";
  },

  /** Type guard: narrows `r` to the `err` arm so `r.value` is `E`. */
  isErr<T, E>(
    r: Result<T, E>,
  ): r is { readonly kind: "err"; readonly value: E } {
    return r.kind === "err";
  },

  /**
   * Return the `ok` value or throw. Useful in tests / linear code where
   * an `err` is itself a test failure and the thrown payload (the `E`
   * value) is the right diagnostic.
   */
  unwrap<T, E>(r: Result<T, E>): T {
    if (r.kind === "ok") return r.value;
    throw new ResultUnwrapError("ok", r.value);
  },

  /** Return the `err` value or throw — mirror of `unwrap`. */
  unwrapErr<T, E>(r: Result<T, E>): E {
    if (r.kind === "err") return r.value;
    throw new ResultUnwrapError("err", r.value);
  },

  /** Typed fold: route through `ok` / `err` handlers, get back `U`. */
  match<T, E, U>(
    r: Result<T, E>,
    handlers: { ok: (v: T) => U; err: (e: E) => U },
  ): U {
    return r.kind === "ok" ? handlers.ok(r.value) : handlers.err(r.value);
  },
};

/**
 * Thrown by `Result.unwrap` / `Result.unwrapErr` when the result was on
 * the wrong side. Carries the offending payload on `.cause`-style
 * `value` so tests still surface the underlying detail.
 */
export class ResultUnwrapError extends Error {
  constructor(
    public readonly expected: "ok" | "err",
    public readonly value: unknown,
  ) {
    super(
      `Result.${expected === "ok" ? "unwrap" : "unwrapErr"}: result was on the wrong side (got ${
        expected === "ok" ? "err" : "ok"
      }: ${JSON.stringify(value)})`,
    );
    this.name = "ResultUnwrapError";
  }
}
