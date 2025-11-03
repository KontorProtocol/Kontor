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

const buildCallExpression = (amount: bigint): string => {
  return `mint(${amount.toString()})`;
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

