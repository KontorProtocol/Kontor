import { expect, test } from "vitest";
import { generate, Wit } from "@kontor/sdk";
import nftWit from "../../native-contracts/nft/wit/contract.wit?raw";

const contracts = import.meta.glob<string>(
  [
    "../../native-contracts/*/wit/contract.wit",
    "../../test-contracts/*/wit/contract.wit",
  ],
  { query: "?raw", import: "default", eager: true },
);

// Exercise the component shipped by the JS build, which can lag behind Rust's
// validator even when the Rust suite and contract builds are green.
test.each(Object.entries(contracts))(
  "shipped SDK parses and generates bindings for %s",
  (_path, source) => {
    expect(JSON.parse(new Wit(source).parse())).toHaveProperty("worlds");
    expect(generate(source)).toContain(
      "export class Contract extends ContractBase",
    );
  },
);

test("NFT codegen exposes cursor arguments and list-bearing page records", () => {
  const source = generate(nftWit);
  expect(source).toMatch(
    /export type NftPage = \{[\s\S]*?items: Array<NftInfo>/,
  );
  expect(source).toMatch(
    /export type AgreementPage = \{[\s\S]*?items: Array<string>/,
  );
  expect(source).toContain(
    "listNfts(after: string | null, limit: bigint): Promise<NftPage>",
  );
});

test("NFT page calls and results preserve lists, holders, and cursors", () => {
  const wit = new Wit(nftWit);
  expect(
    wit.encodeCall(
      "list-nfts",
      JSON.stringify({ after: "nft-001", limit: "5" }),
    ),
  ).toBe('list-nfts(some("nft-001"), 5)');
  expect(
    JSON.parse(
      wit.decodeResult(
        "list-nfts",
        '{items: [{nft-id: "nft-002", owner: signer-id(7), creator: core, agreement-id: "file-002"}], next: some("nft-002")}',
      ),
    ),
  ).toEqual({
    items: [
      {
        "nft-id": "nft-002",
        owner: { kind: "signer-id", value: "7" },
        creator: { kind: "core" },
        "agreement-id": "file-002",
      },
    ],
    next: "nft-002",
  });
  expect(
    JSON.parse(wit.decodeResult("list-nfts", "{items: [], next: none}")),
  ).toEqual({ items: [], next: null });
  expect(
    JSON.parse(
      wit.decodeResult(
        "agreement-ids-by-creator",
        '{items: ["file-002"], next: some("nft-002")}',
      ),
    ),
  ).toEqual({ items: ["file-002"], next: "nft-002" });
});
