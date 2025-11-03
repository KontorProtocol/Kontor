import { encode } from "cbor-x";

export interface MintCallConfig {
  contractName?: string;
  contractHeight?: number;
  contractTxIndex?: number;
}

export const DEFAULT_TOKEN_CONTRACT = {
  name: "token",
  height: 0,
  tx_index: 0,
} as const;

const CALL_VARIANT_KEY = "c";
const CONTRACT_FIELD_KEY = "c";
const EXPR_FIELD_KEY = "e";

const ensureNonNegativeInteger = (value: bigint): bigint => {
  if (value < 0n) {
    throw new RangeError("Mint amount must be non-negative");
  }
  return value;
};

const normalizeAmount = (amount: bigint | number | string): bigint => {
  if (typeof amount === "bigint") {
    return ensureNonNegativeInteger(amount);
  }

  if (typeof amount === "number") {
    if (!Number.isInteger(amount)) {
      throw new RangeError("Mint amount must be an integer");
    }
    return ensureNonNegativeInteger(BigInt(amount));
  }

  const trimmed = amount.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new RangeError("Mint amount must contain only digits");
  }

  return ensureNonNegativeInteger(BigInt(trimmed));
};

const INTEGER_LIMB_BITS = 64n;
const INTEGER_LIMB_MASK = (1n << INTEGER_LIMB_BITS) - 1n;

const toIntegerWaveLiteral = (value: bigint): string => {
  const sign = value < 0n ? "minus" : "plus";
  const abs = value < 0n ? -value : value;

  const limbs = [
    abs & INTEGER_LIMB_MASK,
    (abs >> INTEGER_LIMB_BITS) & INTEGER_LIMB_MASK,
    (abs >> (INTEGER_LIMB_BITS * 2n)) & INTEGER_LIMB_MASK,
    (abs >> (INTEGER_LIMB_BITS * 3n)) & INTEGER_LIMB_MASK,
  ];

  const [r0, r1, r2, r3] = limbs.map((limb) => limb.toString());

  const fields = [`r0: ${r0}`, `r1: ${r1}`, `r2: ${r2}`, `r3: ${r3}`, `sign: ${sign}`];

  return `{${fields.join(", ")}}`;
};

const buildCallExpression = (amount: bigint): string => {
  return `mint(${toIntegerWaveLiteral(amount)})`;
};

export function buildMintCallBytes(
  amount: bigint | number | string,
  config?: MintCallConfig
): Uint8Array {
  const normalizedAmount = normalizeAmount(amount);

  const contract = {
    name: config?.contractName ?? DEFAULT_TOKEN_CONTRACT.name,
    height: config?.contractHeight ?? DEFAULT_TOKEN_CONTRACT.height,
    tx_index: config?.contractTxIndex ?? DEFAULT_TOKEN_CONTRACT.tx_index,
  };

  const inst = {
    [CALL_VARIANT_KEY]: {
      [CONTRACT_FIELD_KEY]: contract,
      [EXPR_FIELD_KEY]: buildCallExpression(normalizedAmount),
    },
  };

  return encode(inst);
}

