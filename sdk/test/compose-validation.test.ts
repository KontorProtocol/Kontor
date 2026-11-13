import { expect, test } from "vitest";
import { hex } from "@scure/base";
import { p2tr, Script, Transaction } from "@scure/btc-signer";

import { serializeInst } from "../src/backend/index.js";
import { signet } from "../src/chains.js";
import { Identity } from "../src/identity.js";
import { LocalKey } from "../src/local-key.js";
import { HttpTransport } from "../src/transport/http.js";
import { validateComposeResponse } from "../src/transport/compose-validation.js";
import type { Reveal } from "../src/bindings.js";

const xOnly =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const identity = Identity.fromXOnly(xOnly, signet);
const own = p2tr(hex.decode(xOnly), undefined, signet.network);
const insts = {
  ops: [
    {
      gas_limit: 50_000,
      kind: { Call: { contract: "test_0_0", expr: "get()" } },
    },
  ],
  aggregate: null,
};
const requested = "00".repeat(32);
const other = "11".repeat(32);
const supplied = [
  {
    txid: requested,
    vout: 0,
    value: 100_000n,
    scriptPubKey: hex.encode(own.script),
  },
];

function envelope(
  amount: bigint,
  keyHex = xOnly,
  instructions: unknown = insts,
) {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, amount, false);
  const script = Script.encode([
    hex.decode(keyHex),
    "CHECKSIG",
    "OP_0",
    "IF",
    new Uint8Array([0x6b, 0x6f, 0x6e]),
    bytes,
    hex.decode(signet.bitcoinNetworkMagic!),
    serializeInst(JSON.stringify(instructions)),
    "ENDIF",
  ]);
  return p2tr(hex.decode(keyHex), { script }, signet.network, true);
}

const reveal: Reveal = {
  sat_per_vbyte: 10,
  participants: [
    {
      x_only_public_key: xOnly,
      commit_insts: insts,
      sighash_type: null,
      output: null,
      commit_source: {
        Build: {
          address: identity.address,
          funding: { Ids: [`${requested}:0`] },
        },
      },
    },
  ],
  extra_inputs: [],
  extra_outputs: [{ Change: { script_pubkey: hex.encode(own.script) } }],
};

function composed(
  fundingTxid: string,
  changeScript = own.script,
  change = 9000n,
) {
  const tap = envelope(90_000n);
  const commit = new Transaction();
  commit.addInput({
    txid: fundingTxid,
    index: 0,
    witnessUtxo: { script: own.script, amount: 100_000n },
    tapInternalKey: own.tapInternalKey,
  });
  commit.addOutput({ script: tap.script, amount: 90_000n });
  commit.addOutput({ script: changeScript, amount: change });
  const child = new Transaction({ allowUnknownOutputs: true });
  child.addInput({
    txid: commit.id,
    index: 0,
    witnessUtxo: { script: tap.script, amount: 90_000n },
    tapInternalKey: own.tapInternalKey,
    tapLeafScript: tap.tapLeafScript,
    sighashType: 0x81,
  });
  child.addOutput({ script: own.script, amount: 89_000n });
  return {
    commits: [
      {
        transaction: "dummy",
        transaction_hex: hex.encode(commit.unsignedTx),
        psbt_hex: hex.encode(commit.toPSBT()),
        txid: commit.id,
        change_value: Number(change),
      },
    ],
    reveal: {
      transaction: "dummy",
      transaction_hex: hex.encode(child.unsignedTx),
      psbt_hex: hex.encode(child.toPSBT()),
      txid: child.id,
      output_info: [{ Change: { value: 89_000 } }],
    },
  };
}

test("compose response validates requested funding, leaf, outputs and fee before signing", async () => {
  let response = composed(requested);
  let callbacks = 0;
  const signing = {
    identity,
    async psbt(): Promise<Uint8Array> {
      callbacks++;
      throw new Error("recorded signer callback");
    },
  };
  const fetchImpl = (async () => ({
    ok: true,
    status: 200,
    async text() {
      return JSON.stringify({ result: response });
    },
  })) as unknown as typeof fetch;
  const transport = new HttpTransport({
    chain: signet,
    identity,
    signing,
    url: "http://dummy.invalid/api",
    fetch: fetchImpl,
  });

  await expect(transport.composeAndSign(reveal, supplied)).rejects.toThrow(
    "recorded signer callback",
  );
  expect(callbacks).toBe(1);

  callbacks = 0;
  for (const changed of [
    composed(other),
    composed(requested, envelope(90_000n).script),
    composed(requested, own.script, 1000n),
  ]) {
    response = changed;
    await expect(transport.composeAndSign(reveal, supplied)).rejects.toThrow(
      "Compose response rejected",
    );
    expect(callbacks).toBe(0);
  }
  const conflicting = composed(requested);
  Object.assign(conflicting.reveal.output_info[0]!, {
    Fixed: { value: 89_000 },
  });
  response = conflicting;
  await expect(transport.composeAndSign(reveal, supplied)).rejects.toThrow(
    "Compose response rejected",
  );
  expect(callbacks).toBe(0);

  const arrayLike = composed(requested);
  arrayLike.reveal.output_info = Object.assign(
    { 0: arrayLike.reveal.output_info[0] },
    { length: 1 },
  ) as unknown as typeof arrayLike.reveal.output_info;
  response = arrayLike;
  await expect(transport.composeAndSign(reveal, supplied)).rejects.toThrow(
    "Compose response rejected",
  );
  expect(callbacks).toBe(0);
});

test("funding settlement follows signed outpoints rather than a candidate prefix", () => {
  const response = composed(other);
  const candidates = [supplied[0]!, { ...supplied[0]!, txid: other }];
  const transport = new HttpTransport({
    chain: signet,
    identity,
    url: "http://dummy.invalid/api",
  });
  const delta = (
    transport as unknown as {
      computeFundingDelta(opts: {
        suppliedUtxos: typeof candidates;
        composed: typeof response;
        commitHexes: string[];
        revealHex: string;
      }): { spent: typeof candidates };
    }
  ).computeFundingDelta({
    suppliedUtxos: candidates,
    composed: response,
    commitHexes: [response.commits[0]!.transaction_hex],
    revealHex: response.reveal.transaction_hex,
  });
  expect(delta.spent).toEqual([candidates[1]]);
});

test("funding settlement retains only owned unspent change", () => {
  const response = composed(requested);
  const foreign = p2tr(
    hex.decode(
      Identity.fromXOnly(
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        signet,
      ).xOnlyPubKey,
    ),
    undefined,
    signet.network,
  );
  const revealTx = Transaction.fromPSBT(hex.decode(response.reveal.psbt_hex));
  revealTx.updateOutput(0, { script: foreign.script });
  response.reveal.transaction_hex = hex.encode(revealTx.unsignedTx);
  response.reveal.txid = revealTx.id;
  const transport = new HttpTransport({
    chain: signet,
    identity,
    url: "http://dummy.invalid/api",
  });
  const compute = (opts: {
    suppliedUtxos: typeof supplied;
    composed: typeof response;
    commitHexes: string[];
    revealHex: string;
  }) =>
    (
      transport as unknown as {
        computeFundingDelta(value: typeof opts): { change: typeof supplied };
      }
    ).computeFundingDelta(opts);
  const commitHex = response.commits[0]!.transaction_hex;
  const delta = compute({
    suppliedUtxos: supplied,
    composed: response,
    commitHexes: [commitHex],
    revealHex: response.reveal.transaction_hex,
  });
  expect(delta.change).toEqual([
    {
      txid: response.commits[0]!.txid,
      vout: 1,
      value: 9000n,
      scriptPubKey: hex.encode(own.script),
    },
  ]);

  const spendingReveal = Transaction.fromPSBT(
    hex.decode(response.reveal.psbt_hex),
  );
  spendingReveal.updateOutput(0, { script: foreign.script });
  spendingReveal.addInput({
    txid: response.commits[0]!.txid,
    index: 1,
    witnessUtxo: { script: own.script, amount: 9000n },
    tapInternalKey: own.tapInternalKey,
  });
  const consumed = compute({
    suppliedUtxos: supplied,
    composed: response,
    commitHexes: [commitHex],
    revealHex: hex.encode(spendingReveal.unsignedTx),
  });
  expect(consumed.change).toEqual([]);
});

test("Existing leaf binds the supplied amount and 0x81 mode", () => {
  const tap = envelope(90_000n);
  const point = `${"33".repeat(32)}:0`;
  const request: Reveal = {
    sat_per_vbyte: 10,
    participants: [
      {
        x_only_public_key: xOnly,
        commit_insts: insts,
        sighash_type: null,
        output: null,
        commit_source: {
          Existing: {
            outpoint: point,
            prevout: { value: 90_000, script_pubkey: hex.encode(tap.script) },
          },
        },
      },
    ],
    extra_inputs: [],
    extra_outputs: [{ Change: { script_pubkey: hex.encode(own.script) } }],
  };
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({
    txid: point.slice(0, 64),
    index: 0,
    witnessUtxo: { script: tap.script, amount: 90_000n },
    tapInternalKey: own.tapInternalKey,
    tapLeafScript: tap.tapLeafScript,
    sighashType: 0x81,
  });
  tx.addOutput({ script: own.script, amount: 89_000n });
  const response = {
    commits: [],
    reveal: {
      transaction: "dummy",
      transaction_hex: hex.encode(tx.unsignedTx),
      psbt_hex: hex.encode(tx.toPSBT()),
      txid: tx.id,
      output_info: [{ Change: { value: 89_000 } }],
    },
  };
  validateComposeResponse(request, response, signet, xOnly);
  tx.updateInput(0, { sighashType: 0x83 });
  response.reveal.psbt_hex = hex.encode(tx.toPSBT());
  expect(() =>
    validateComposeResponse(request, response, signet, xOnly),
  ).toThrow("changes the signing hash");
});

test("marketplace Sponsor binds the seller's exact leaf, outpoint and gas ceiling", () => {
  const seller = LocalKey.fromMnemonic({
    mnemonic:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    chain: signet,
  });
  const sellerKey = seller.identity.xOnlyPubKey;
  const sellerAmount = 10_000n;
  const sellerTap = envelope(sellerAmount, sellerKey);
  const sellerTxid = Array.from({ length: 32 }, (_, index) =>
    index.toString(16).padStart(2, "0"),
  ).join("");
  const sellerPoint = `${sellerTxid}:2`;
  const maxGas = 50_000n;
  const gas = new Uint8Array(8);
  new DataView(gas.buffer).setBigUint64(0, maxGas, true);
  const placeholder = {
    target_input_index: 1,
    target_txid: Array(32).fill(0),
    target_vout_le: Array(4).fill(0),
    target_leaf_hash: Array(32).fill(0),
    max_total_gas_le: Array(8).fill(0),
  };
  const buyerInsts = {
    ops: [{ gas_limit: Number(maxGas), kind: { SponsorBound: placeholder } }],
    aggregate: null,
  };
  const request: Reveal = {
    sat_per_vbyte: 10,
    participants: [
      {
        x_only_public_key: xOnly,
        commit_insts: buyerInsts,
        sighash_type: null,
        output: { Change: { script_pubkey: hex.encode(own.script) } },
        commit_source: {
          Build: {
            address: identity.address,
            funding: { Ids: [`${requested}:0`] },
          },
        },
      },
      {
        x_only_public_key: sellerKey,
        commit_insts: insts,
        sighash_type: 0x83,
        output: {
          Fixed: { script_pubkey: hex.encode(own.script), value: 10_000 },
        },
        commit_source: {
          Existing: {
            outpoint: sellerPoint,
            prevout: {
              value: Number(sellerAmount),
              script_pubkey: hex.encode(sellerTap.script),
            },
          },
        },
      },
    ],
    extra_inputs: [],
    extra_outputs: [],
  };
  const sponsor = {
    ...placeholder,
    target_txid: Array.from(hex.decode(sellerTxid).reverse()),
    target_vout_le: [2, 0, 0, 0],
    target_leaf_hash: Array.from(sellerTap.leaves![0]!.hash),
    max_total_gas_le: Array.from(gas),
  };
  const boundBuyerInsts = {
    ops: [{ gas_limit: Number(maxGas), kind: { SponsorBound: sponsor } }],
    aggregate: null,
  };
  const buyerTap = envelope(90_000n, xOnly, boundBuyerInsts);
  const commit = new Transaction();
  commit.addInput({
    txid: requested,
    index: 0,
    witnessUtxo: { script: own.script, amount: 100_000n },
    tapInternalKey: own.tapInternalKey,
  });
  commit.addOutput({ script: buyerTap.script, amount: 90_000n });
  commit.addOutput({ script: own.script, amount: 9000n });
  const swap = new Transaction();
  swap.addInput({
    txid: commit.id,
    index: 0,
    witnessUtxo: { script: buyerTap.script, amount: 90_000n },
    tapInternalKey: own.tapInternalKey,
    tapLeafScript: buyerTap.tapLeafScript,
    sighashType: 0x81,
  });
  swap.addInput({
    txid: sellerTxid,
    index: 2,
    witnessUtxo: { script: sellerTap.script, amount: sellerAmount },
    tapInternalKey: hex.decode(sellerKey),
    tapLeafScript: sellerTap.tapLeafScript,
    sighashType: 0x83,
  });
  swap.addOutput({ script: own.script, amount: 87_000n });
  swap.addOutput({ script: own.script, amount: 10_000n });
  const response = {
    commits: [
      {
        transaction: "dummy",
        transaction_hex: hex.encode(commit.unsignedTx),
        psbt_hex: hex.encode(commit.toPSBT()),
        txid: commit.id,
        change_value: 9000,
      },
    ],
    reveal: {
      transaction: "dummy",
      transaction_hex: hex.encode(swap.unsignedTx),
      psbt_hex: hex.encode(swap.toPSBT()),
      txid: swap.id,
      output_info: [
        { Change: { value: 87_000 } },
        { Fixed: { value: 10_000 } },
      ],
    },
  };
  expect(() =>
    validateComposeResponse(request, response, signet, xOnly, supplied),
  ).not.toThrow();

  const changed = { ...request, participants: [...request.participants] };
  changed.participants[1] = {
    ...request.participants[1]!,
    commit_insts: {
      ops: [
        {
          gas_limit: 50_001,
          kind: { Call: { contract: "test_0_0", expr: "get()" } },
        },
      ],
      aggregate: null,
    },
  };
  expect(() =>
    validateComposeResponse(changed, response, signet, xOnly, supplied),
  ).toThrow("Compose response rejected");
});

test("Sponsor binds a separately built recipient even when its commit is returned later", () => {
  const gasLimit = 50_000;
  const placeholder = {
    target_input_index: 1,
    target_txid: Array(32).fill(0),
    target_vout_le: Array(4).fill(0),
    target_leaf_hash: Array(32).fill(0),
    max_total_gas_le: Array(8).fill(0),
  };
  const sponsorInsts = {
    ops: [{ gas_limit: gasLimit, kind: { SponsorBound: placeholder } }],
    aggregate: null,
  };
  const request: Reveal = {
    sat_per_vbyte: 10,
    participants: [
      {
        x_only_public_key: xOnly,
        commit_insts: sponsorInsts,
        sighash_type: 0x81,
        output: null,
        commit_source: {
          Build: {
            address: identity.address,
            funding: { Ids: [`${requested}:0`] },
          },
        },
      },
      {
        x_only_public_key: xOnly,
        commit_insts: insts,
        sighash_type: 0x81,
        output: null,
        commit_source: {
          Build: {
            address: identity.address,
            funding: { Ids: [`${other}:0`] },
          },
        },
      },
    ],
    extra_inputs: [],
    extra_outputs: [{ Change: { script_pubkey: hex.encode(own.script) } }],
  };
  const makeCommit = (fundingTxid: string, tapScript: Uint8Array) => {
    const tx = new Transaction();
    tx.addInput({
      txid: fundingTxid,
      index: 0,
      witnessUtxo: { script: own.script, amount: 100_000n },
      tapInternalKey: own.tapInternalKey,
    });
    tx.addOutput({ script: tapScript, amount: 90_000n });
    tx.addOutput({ script: own.script, amount: 9000n });
    return {
      tx,
      response: {
        transaction: "dummy",
        transaction_hex: hex.encode(tx.unsignedTx),
        psbt_hex: hex.encode(tx.toPSBT()),
        txid: tx.id,
        change_value: 9000,
      },
    };
  };
  const targetTap = envelope(90_000n);
  const targetCommit = makeCommit(other, targetTap.script);
  const gas = new Uint8Array(8);
  new DataView(gas.buffer).setBigUint64(0, BigInt(gasLimit), true);
  const boundSponsorInsts = {
    ops: [
      {
        gas_limit: gasLimit,
        kind: {
          SponsorBound: {
            target_input_index: 1,
            target_txid: Array.from(hex.decode(targetCommit.tx.id).reverse()),
            target_vout_le: [0, 0, 0, 0],
            target_leaf_hash: Array.from(targetTap.leaves![0]!.hash),
            max_total_gas_le: Array.from(gas),
          },
        },
      },
    ],
    aggregate: null,
  };
  const sponsorTap = envelope(90_000n, xOnly, boundSponsorInsts);
  const sponsorCommit = makeCommit(requested, sponsorTap.script);
  const child = new Transaction({ allowUnknownOutputs: true });
  for (const item of [
    { commit: sponsorCommit, tap: sponsorTap },
    { commit: targetCommit, tap: targetTap },
  ]) {
    child.addInput({
      txid: item.commit.tx.id,
      index: 0,
      witnessUtxo: { script: item.tap.script, amount: 90_000n },
      tapInternalKey: own.tapInternalKey,
      tapLeafScript: item.tap.tapLeafScript,
      sighashType: 0x81,
    });
  }
  child.addOutput({ script: own.script, amount: 178_000n });
  const response = {
    commits: [sponsorCommit.response, targetCommit.response],
    reveal: {
      transaction: "dummy",
      transaction_hex: hex.encode(child.unsignedTx),
      psbt_hex: hex.encode(child.toPSBT()),
      txid: child.id,
      output_info: [{ Change: { value: 178_000 } }],
    },
  };
  const candidates = [supplied[0]!, { ...supplied[0]!, txid: other }];
  validateComposeResponse(request, response, signet, xOnly, candidates);
  response.commits.reverse();
  expect(() =>
    validateComposeResponse(request, response, signet, xOnly, candidates),
  ).toThrow("commit 0 spends unexpected funding");
});
