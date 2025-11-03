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

    expect(decoded).toEqual({
      c: {
        c: {
          name: DEFAULT_TOKEN_CONTRACT.name,
          height: DEFAULT_TOKEN_CONTRACT.height,
          tx_index: DEFAULT_TOKEN_CONTRACT.tx_index,
        },
        e: "mint(123)",
      },
    });
  });

  it("supports string inputs by normalizing to integers", () => {
    const bytes = buildMintCallBytes("456");
    const decoded = decode(bytes) as SerializedMintCall;

    expect(decoded.c.e).toBe("mint(456)");
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
  });
});

