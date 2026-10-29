import type {
  ResultInfo,
  ResultRow,
  TransactionInfo,
  TransactionRow,
} from "./bindings.js";

/** Coordinates as observed by one API read, not a promise of finality. */
export interface ExecutionCoordinates {
  executionHeight: bigint;
  confirmedHeight: bigint | null;
  confirmedBitcoinTxIndex: number | null;
  batchHeight: bigint | null;
}

type ReceiptMetadata = ResultRow &
  Partial<
    Pick<
      ResultInfo,
      | "execution_height"
      | "confirmed_height"
      | "confirmed_bitcoin_tx_index"
      | "batch_height"
    >
  >;

export function executionCoordinates(
  row: ReceiptMetadata,
): ExecutionCoordinates {
  return {
    executionHeight: BigInt(row.execution_height ?? row.height),
    confirmedHeight:
      row.confirmed_height == null ? null : BigInt(row.confirmed_height),
    confirmedBitcoinTxIndex:
      row.confirmed_height == null
        ? null
        : (row.confirmed_bitcoin_tx_index ?? null),
    batchHeight: row.batch_height == null ? null : BigInt(row.batch_height),
  };
}

export function transactionInfoFromWire(
  row: TransactionRow & Partial<TransactionInfo>,
): TransactionInfo {
  return {
    ...row,
    execution_height: row.execution_height ?? row.height,
    confirmed_bitcoin_tx_index:
      row.confirmed_height == null
        ? null
        : (row.confirmed_bitcoin_tx_index ?? null),
  };
}
