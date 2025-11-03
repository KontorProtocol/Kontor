import { describe, expect, it } from "vitest";
import { decode } from "cbor-x";

import { buildMintCallBytes, DEFAULT_TOKEN_CONTRACT } from "./mint";

type SerializedMintCall = {
  c: {
    c: {
      name: string;
      height: number;
      tx_index: number;
    };
    e: string;
  };
};

describe("buildMintCallBytes", () => {
  it("encodes the mint call using CBOR", () => {
    const bytes = buildMintCallBytes(123n);
    const decoded = decode(bytes) as SerializedMintCall;

    expect(decoded.c.c).toEqual({
      name: DEFAULT_TOKEN_CONTRACT.name,
      height: DEFAULT_TOKEN_CONTRACT.height,
      tx_index: DEFAULT_TOKEN_CONTRACT.tx_index,
    });
    expect(decoded.c.e).toBe(
      "mint({r0: 123, r1: 0, r2: 0, r3: 0, sign: plus})"
    );
  });

  it("supports string inputs by normalizing to integers", () => {
    const bytes = buildMintCallBytes("456");
    const decoded = decode(bytes) as SerializedMintCall;

    expect(decoded.c.e).toBe(
      "mint({r0: 456, r1: 0, r2: 0, r3: 0, sign: plus})"
    );
  });

  it("throws for negative amounts", () => {
    expect(() => buildMintCallBytes(-1)).toThrow(/non-negative/i);
  });

  it("throws for non-integer numbers", () => {
    expect(() => buildMintCallBytes(1.5)).toThrow(/integer/i);
  });

  it("allows overriding the contract metadata", () => {
    const bytes = buildMintCallBytes(1, {
      contractName: "custom",
      contractHeight: 42,
      contractTxIndex: 7,
    });
    const decoded = decode(bytes) as SerializedMintCall;

    expect(decoded.c.c).toEqual({
      name: "custom",
      height: 42,
      tx_index: 7,
    });
    expect(decoded.c.e).toBe(
      "mint({r0: 1, r1: 0, r2: 0, r3: 0, sign: plus})"
    );
  });

  it("splits large amounts across 256-bit limbs", () => {
    const value = (1n << 200n) + 5n;
    const bytes = buildMintCallBytes(value);
    const decoded = decode(bytes) as SerializedMintCall;

    expect(decoded.c.e).toBe(
      "mint({r0: 5, r1: 0, r2: 0, r3: 256, sign: plus})"
    );
  });
});

