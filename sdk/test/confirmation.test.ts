import { expect, test } from "vitest";
import { executionCoordinates } from "../src/confirmation.js";
import { rawToOpResult } from "../src/inst.js";
import type { ResultInfo } from "../src/bindings.js";

test("raw Bitcoin zero remains distinct from unknown and legacy filtered zero", () => {
  const row = {
    height: 1,
    tx_index: 0,
    confirmed_height: 2,
    confirmed_bitcoin_tx_index: 0,
  } as ResultInfo;
  expect(executionCoordinates(row).confirmedBitcoinTxIndex).toBe(0);
  expect(
    executionCoordinates({ ...row, confirmed_bitcoin_tx_index: null })
      .confirmedBitcoinTxIndex,
  ).toBeNull();
  expect(
    executionCoordinates({ ...row, confirmed_height: null })
      .confirmedBitcoinTxIndex,
  ).toBeNull();
});

test("receipt decoding retains persisted coordinates without inventing simulation coordinates", () => {
  const coordinates = {
    executionHeight: 1n,
    confirmedHeight: 2n,
    confirmedBitcoinTxIndex: 4,
    batchHeight: 9n,
  };
  const raw = {
    status: "Ok" as const,
    gas: 3n,
    value: "7",
    func: "read",
    contract: "fixture_1_7",
    inputIndex: 0,
    opIndex: 0,
  };
  expect(rawToOpResult({ ...raw, coordinates }, Number)).toMatchObject({
    value: 7,
    coordinates,
  });
  expect(rawToOpResult(raw, Number).coordinates).toBeUndefined();
});
