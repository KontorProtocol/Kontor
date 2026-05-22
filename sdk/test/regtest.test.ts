/**
 * Unit tests for `@kontor/sdk/regtest`'s readiness-line parsing. The real
 * `startRegtest()` spawns a Bitcoin regtest node and is exercised by the
 * live regtest suite; here we only pin the pure stdout-parsing logic.
 */
import { test, expect } from "vitest";
import { parseRegtestInfo, regtestChain } from "../src/regtest.js";

/** The `KONTOR_REGTEST_INFO` JSON payload as the binary prints it —
 *  `devFundingUtxo.value` is a plain number of satoshis on the wire. */
const INFO = {
  apiUrl: "http://localhost:32889/api",
  bitcoinRpc: "http://rpc:rpc@127.0.0.1:44745",
  devPrivateKey:
    "b02e485eed90477077e90585b3fa3b225f55a5085f0244c17315549afce0e447",
  devPublicKey:
    "3285de1e9b50e8eec053b840fb5c6b886cefcfdb729c37bba2a7e27a066f86fe",
  devAddress: "bcrt1pfj2vd8zrgmrt2tu75t7kx29ju673v3mc8peqnp676524aayl0tvq0jq7mh",
  devFundingUtxo: {
    txid: "a1b2c3d4e5f6071829303142535465768798a0b1c2d3e4f50617283940516273",
    vout: 1,
    value: 4999990000,
    scriptPubKey:
      "51204c953681c8d18d6a5f3d45f5b194597b5e8b23783875099d76aa2abdef27ded8",
  },
};

/** A realistic `kontor regtest` stdout slice — the info line in log noise. */
const READY_OUTPUT = [
  "2026-05-21T22:45:00Z  INFO indexer::reactor: Block processed height=102",
  `KONTOR_REGTEST_INFO ${JSON.stringify(INFO)}`,
  "kontor regtest devnet running — Ctrl-C to stop",
].join("\n");

test("parseRegtestInfo: returns null until the info line has appeared", () => {
  expect(parseRegtestInfo("")).toBeNull();
  expect(
    parseRegtestInfo("2026-05-21T22:45:00Z  INFO indexer::reactor: started\n"),
  ).toBeNull();
});

test("parseRegtestInfo: extracts every field, value as a bigint", () => {
  const info = parseRegtestInfo(READY_OUTPUT)!;
  expect(info.apiUrl).toBe(INFO.apiUrl);
  expect(info.bitcoinRpc).toBe(INFO.bitcoinRpc);
  expect(info.devPrivateKey).toBe(INFO.devPrivateKey);
  expect(info.devPublicKey).toBe(INFO.devPublicKey);
  expect(info.devAddress).toBe(INFO.devAddress);
  expect(info.devFundingUtxo).toEqual({
    txid: INFO.devFundingUtxo.txid,
    vout: 1,
    value: 4999990000n,
    scriptPubKey: INFO.devFundingUtxo.scriptPubKey,
  });
});

test("parseRegtestInfo: an info line still streaming in is not matched", () => {
  // The line is present but has no terminating newline yet — a chunk
  // boundary fell mid-line, so its JSON is truncated.
  const partial = `KONTOR_REGTEST_INFO ${JSON.stringify(INFO).slice(0, 40)}`;
  expect(parseRegtestInfo(partial)).toBeNull();
  expect(parseRegtestInfo(`${READY_OUTPUT}\n`)).not.toBeNull();
});

test("parseRegtestInfo: throws on a complete-but-malformed info line", () => {
  expect(() => parseRegtestInfo("KONTOR_REGTEST_INFO {not json}\n")).toThrow(
    /not valid JSON/,
  );
  const noBitcoinRpc = JSON.stringify({ ...INFO, bitcoinRpc: undefined });
  expect(() => parseRegtestInfo(`KONTOR_REGTEST_INFO ${noBitcoinRpc}\n`)).toThrow(
    /missing string field 'bitcoinRpc'/,
  );
  const noUtxo = JSON.stringify({ ...INFO, devFundingUtxo: undefined });
  expect(() => parseRegtestInfo(`KONTOR_REGTEST_INFO ${noUtxo}\n`)).toThrow(
    /devFundingUtxo/,
  );
});

test("regtestChain: builds a bcrt chain wired to the parsed endpoints", () => {
  const chain = regtestChain(parseRegtestInfo(READY_OUTPUT)!);
  expect(chain.name).toBe("regtest");
  expect(chain.network.bech32).toBe("bcrt");
  expect(chain.urls.http).toBe(INFO.apiUrl);
  expect(chain.urls.bitcoinRpc).toBe(INFO.bitcoinRpc);
});
