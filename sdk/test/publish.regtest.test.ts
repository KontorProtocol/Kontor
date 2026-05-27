/**
 * Live regtest capstone for the publish pipeline: deploy a small
 * contract from JS via `session.publish(name, bytes)`, force the
 * confirming block with `regtest.mine()`, then bind the codegen'd
 * `Counter` contract at the returned address and call its `get()`
 * view to confirm init ran (counter starts at 0).
 *
 * Proves the end-to-end path added in
 * project_contract_resource_publish_return:
 *   - init returns its own `contract` resource (`ctx.contract()`),
 *   - the host drains the resource to a `contract-address` record at
 *     the WAVE boundary,
 *   - the SDK reads the address out of the publish op's result value
 *     via `decodeContractAddressWave` and surfaces it as
 *     `Inst<ContractAddress>`'s typed return.
 *
 * Funding: identities[2] (the slot claimed for this suite).
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect, inject } from "vitest";
import { KontorSession, LocalAccount, http } from "@kontor/sdk";
import { connectRegtest } from "@kontor/sdk/regtest";

import { Contract as Counter } from "./__generated__/counter.js";
import "./regtest-context.js";

const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * Brotli-compressed counter wasm — what the indexer's `Storage`
 * expects on `insert_contract` (it decompresses on the way out via
 * `component_bytes`). Built by `test-contracts/build.sh`.
 */
const COUNTER_WASM_BR = readFileSync(
  path.join(
    here,
    "..",
    "..",
    "test-contracts",
    "target",
    "wasm32-unknown-unknown",
    "release",
    "counter.wasm.br",
  ),
);

test("session.publish deploys a contract and returns its address", async () => {
  const regtest = connectRegtest(inject("regtest"));
  const { chain } = regtest;
  const { account: publisher, fundingUtxo } = regtest.accounts[2]!;

  const session = new KontorSession({
    chain,
    account: publisher,
    transport: ({ chain, account }) =>
      http({ chain, account, utxos: [fundingUtxo] }),
  });

  try {
    await session.ready();

    // Broadcast the publish tx, force the containing block (Publish is
    // the one op whose result depends on block height — `regtest.mine()`
    // saves us the up-to-10s wait for the auto-miner's next tick), then
    // wait for the indexer to materialize the result row.
    const submitted = await session
      .publish("kontor-tested-counter", new Uint8Array(COUNTER_WASM_BR))
      .submit();
    await regtest.mine();
    const result = await submitted.wait();

    expect(result.status).toBe("Ok");
    const address = result.value;
    if (address == null) {
      throw new Error(
        `publish returned no address; result=${JSON.stringify(result)}`,
      );
    }
    expect(address.name).toBe("kontor-tested-counter");
    expect(address.height).toBeGreaterThan(0n);

    // Bind the codegen'd Counter at the freshly-deployed address and
    // confirm init ran by reading the default value.
    const counter = session.bind(Counter, address);
    const value = await counter.get();
    expect(value).toBe(0n);
  } finally {
    session.close();
  }
});
