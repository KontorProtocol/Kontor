/**
 * Typed wrapper over Kontor's `holder-ref` variant. A HolderRef
 * identifies anything that can hold a balance or own storage entries:
 * a signer's x-only public key, a resolved signer-id, the core
 * identity, the burner sink, or a UTXO.
 *
 * Construct via the static factories — they spell out which case
 * you're producing and what payload it carries. Decode wire values
 * with `fromRaw`; re-package for the WAVE codec with `toRaw`.
 *
 * The class is canonical (shared across all generated contract
 * bindings), so an `HolderRef` returned by one binding flows
 * unchanged into a method on another.
 */

/** A UTXO reference: txid is hex, vout is the output index. */
export type OutPoint = { txid: string; vout: bigint };

type Variant =
  | { kind: "x-only-pubkey"; value: string }
  | { kind: "signer-id"; value: bigint }
  | { kind: "core" }
  | { kind: "burner" }
  | { kind: "utxo"; value: OutPoint };

type RawOutPoint = { txid: string; vout: string };

type Raw =
  | { kind: "x-only-pubkey"; value: string }
  | { kind: "signer-id"; value: string }
  | { kind: "core" }
  | { kind: "burner" }
  | { kind: "utxo"; value: RawOutPoint };

export class HolderRef {
  private constructor(private readonly variant: Variant) {}

  static xOnlyPubkey(hex: string): HolderRef {
    return new HolderRef({ kind: "x-only-pubkey", value: hex });
  }

  static signerId(id: bigint): HolderRef {
    return new HolderRef({ kind: "signer-id", value: id });
  }

  static core(): HolderRef {
    return new HolderRef({ kind: "core" });
  }

  static burner(): HolderRef {
    return new HolderRef({ kind: "burner" });
  }

  static utxo(out: OutPoint): HolderRef {
    return new HolderRef({ kind: "utxo", value: out });
  }

  static fromRaw(raw: Raw): HolderRef {
    switch (raw.kind) {
      case "x-only-pubkey":
        return HolderRef.xOnlyPubkey(raw.value);
      case "signer-id":
        return HolderRef.signerId(BigInt(raw.value));
      case "core":
        return HolderRef.core();
      case "burner":
        return HolderRef.burner();
      case "utxo":
        return HolderRef.utxo({
          txid: raw.value.txid,
          vout: BigInt(raw.value.vout),
        });
    }
  }

  toRaw(): Raw {
    const v = this.variant;
    switch (v.kind) {
      case "x-only-pubkey":
        return { kind: "x-only-pubkey", value: v.value };
      case "signer-id":
        return { kind: "signer-id", value: v.value.toString() };
      case "core":
        return { kind: "core" };
      case "burner":
        return { kind: "burner" };
      case "utxo":
        return {
          kind: "utxo",
          value: { txid: v.value.txid, vout: v.value.vout.toString() },
        };
    }
  }

  /** The variant kind, useful for cheap discrimination without unwrapping. */
  get kind(): Variant["kind"] {
    return this.variant.kind;
  }

  /**
   * Expose the underlying variant for exhaustive pattern matching.
   * `unwrap().kind` narrows TS to the right payload type.
   */
  unwrap(): Variant {
    return this.variant;
  }
}
