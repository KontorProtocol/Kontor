/**
 * Unit tests for `@kontor/sdk/regtest`'s readiness-line parsing. The real
 * `startRegtest()` spawns a Bitcoin regtest node and is exercised by the
 * live regtest suite; here we only pin the pure stdout-parsing logic.
 */
import { test, expect } from "vitest";
import { parseRegtestInfo, regtestChain } from "../src/regtest.js";

const INFO = {
  apiUrl: "http://localhost:32889/api",
  bitcoinRpc: "http://rpc:rpc@127.0.0.1:44745",
  devPrivateKey:
    "b02e485eed90477077e90585b3fa3b225f55a5085f0244c17315549afce0e447",
  devPublicKey:
    "3285de1e9b50e8eec053b840fb5c6b886cefcfdb729c37bba2a7e27a066f86fe",
  devAddress: "bcrt1pfj2vd8zrgmrt2tu75t7kx29ju673v3mc8peqnp676524aayl0tvq0jq7mh",
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

test("parseRegtestInfo: extracts every field from the JSON payload", () => {
  expect(parseRegtestInfo(READY_OUTPUT)).toEqual(INFO);
});

test("parseRegtestInfo: an info line still streaming in is not matched", () => {
  // The line is present but has no terminating newline yet — a chunk
  // boundary fell mid-line, so its JSON is truncated. Matching it would
  // resolve `startRegtest` with garbage.
  const partial = `KONTOR_REGTEST_INFO ${JSON.stringify(INFO).slice(0, 40)}`;
  expect(parseRegtestInfo(partial)).toBeNull();
  // Once the full line + newline arrive, it parses.
  expect(parseRegtestInfo(`${READY_OUTPUT}\n`)).toEqual(INFO);
});

test("parseRegtestInfo: throws on a complete-but-malformed info line", () => {
  expect(() => parseRegtestInfo("KONTOR_REGTEST_INFO {not json}\n")).toThrow(
    /not valid JSON/,
  );
  const missing = JSON.stringify({ apiUrl: INFO.apiUrl });
  expect(() => parseRegtestInfo(`KONTOR_REGTEST_INFO ${missing}\n`)).toThrow(
    /missing string field 'bitcoinRpc'/,
  );
});

test("regtestChain: builds a bcrt chain wired to the parsed endpoints", () => {
  const chain = regtestChain(parseRegtestInfo(READY_OUTPUT)!);
  expect(chain.name).toBe("regtest");
  expect(chain.network.bech32).toBe("bcrt");
  expect(chain.urls.http).toBe(INFO.apiUrl);
  expect(chain.urls.bitcoinRpc).toBe(INFO.bitcoinRpc);
});
