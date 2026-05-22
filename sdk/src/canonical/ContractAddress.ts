/**
 * Typed wrapper over Kontor's `contract-address` record. Identifies a
 * specific deployment of a contract by `(name, height, tx-index)`.
 *
 * The class is canonical (shared across all generated contract
 * bindings) so a `ContractAddress` returned by one binding flows
 * unchanged into a method on another — without canonicalization,
 * each binding would re-declare its own `ContractAddress` type and
 * TS would treat them as incompatible.
 */
type Raw = { name: string; height: string; "tx-index": string };

export class ContractAddress {
  constructor(
    public readonly name: string,
    public readonly height: bigint,
    public readonly txIndex: bigint,
  ) {}

  static fromRaw(raw: Raw): ContractAddress {
    return new ContractAddress(
      raw.name,
      BigInt(raw.height),
      BigInt(raw["tx-index"]),
    );
  }

  toRaw(): Raw {
    return {
      name: this.name,
      height: this.height.toString(),
      "tx-index": this.txIndex.toString(),
    };
  }

  toString(): string {
    return `${this.name}@${this.height}.${this.txIndex}`;
  }

  /**
   * The indexer's wire form — `name_height_txIndex` (Kontor's
   * `ContractAddress` `Display`/`FromStr`). Used in API URL paths and as
   * the `contract` field of a wire `Call`. Distinct from `toString()`,
   * which is the human-facing `name@height.txIndex`.
   */
  toWire(): string {
    return `${this.name}_${this.height}_${this.txIndex}`;
  }
}
