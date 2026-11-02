import { expect, test } from "vitest";
import { ContractAddress } from "../src/canonical/ContractAddress.js";
import { signet } from "../src/chains.js";
import { Identity } from "../src/identity.js";
import { HttpTransport } from "../src/transport/http.js";

const token = new ContractAddress("token", 0n, 0n);
const identity = Identity.fromXOnly(
  "8c7fc6552af4384a13791e63bac79ff2bcfeedf143a88d6dc4b6080a8829cdc1",
  signet,
);

function transport(result: unknown) {
  return new HttpTransport({
    chain: signet,
    identity,
    url: "http://test/api",
    fetch: (async (url) => {
      expect(String(url)).toBe(
        "http://test/api/contracts/token_0_0/provenance",
      );
      return new Response(JSON.stringify({ result }));
    }) as typeof fetch,
  });
}

test("effective provenance distinguishes a protocol replacement from publication", async () => {
  const t = transport({
    entries: [],
    effective_artifact: {
      sha256: "11".repeat(32),
      published_sha256: "22".repeat(32),
      source: "protocol_native",
      protocol_id: "33".repeat(32),
      execution_definition: "44".repeat(32),
    },
  });
  expect(await t.contractProvenance(token)).toEqual({
    entries: [],
    effectiveArtifact: {
      sha256: "11".repeat(32),
      publishedSha256: "22".repeat(32),
      source: "protocol_native",
      protocolId: "33".repeat(32),
      executionDefinition: "44".repeat(32),
    },
  });
  expect(await t.provenance(token)).toEqual([]);
});

test("older nodes keep publication-log access but cannot claim effective provenance", async () => {
  const t = transport({ entries: [] });
  expect(await t.provenance(token)).toEqual([]);
  await expect(t.contractProvenance(token)).rejects.toThrow(
    "Node did not report the effective contract artifact",
  );
});
