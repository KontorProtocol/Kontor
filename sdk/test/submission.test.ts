import { expect, test, vi } from "vitest";
import { hex } from "@scure/base";
import {
  p2tr,
  Script,
  TaprootControlBlock,
  Transaction,
} from "@scure/btc-signer";
import { sha256 } from "@scure/btc-signer/utils.js";
import { signet } from "../src/chains.js";
import { LocalKey } from "../src/local-key.js";
import { Attachment } from "../src/attach.js";
import { Offer } from "../src/offer.js";
import { ContractAddress } from "../src/canonical/ContractAddress.js";
import { KontorSession } from "../src/session.js";
import { inMemoryFunding } from "../src/funding.js";
import { HttpTransport } from "../src/transport/http.js";
import {
  PendingSubmission,
  SubmissionError,
} from "../src/transport/submission.js";
import type { BroadcastReport } from "../src/transport/submission.js";
import type { ComposeOutputs } from "../src/bindings.js";
import type { Utxo } from "../src/json-codec.js";

const signer = LocalKey.fromPrivateKey({
  privateKey: "01".padStart(64, "0"),
  chain: signet,
});
const own = p2tr(
  hex.decode(signer.identity.xOnlyPubKey),
  undefined,
  signet.network,
);
const coin = (tag: string, value = 10_000n): Utxo => ({
  txid: tag.repeat(64).slice(0, 64),
  vout: 0,
  value,
  scriptPubKey: hex.encode(own.script),
});
async function signed(
  input: Utxo,
  amounts: bigint[],
  firstScript = own.script,
) {
  const tx = new Transaction();
  tx.addInput({
    txid: input.txid,
    index: input.vout,
    witnessUtxo: { script: own.script, amount: input.value },
    tapInternalKey: own.tapInternalKey,
  });
  for (const [index, amount] of amounts.entries())
    tx.addOutput({ script: index === 0 ? firstScript : own.script, amount });
  const result = Transaction.fromPSBT(await signer.psbt(tx.toPSBT()));
  result.finalize();
  return result;
}
function report(raw: readonly string[], statuses?: boolean[]): BroadcastReport {
  const transactions = raw.map((encoded, index) => {
    const bytes = hex.decode(encoded);
    return {
      txid: Transaction.fromRaw(bytes).id,
      wtxid: hex.encode(sha256(sha256(bytes)).reverse()),
      status:
        statuses?.[index] === false
          ? ("unknown" as const)
          : ("accepted" as const),
      reason: statuses?.[index] === false ? "not_observed" : null,
    };
  });
  const n = transactions.filter((tx) => tx.status === "accepted").length;
  return {
    outcome: n === transactions.length ? "accepted" : n ? "partial" : "unknown",
    transactions,
  };
}
function prepared(tx: Transaction): {
  commitHexes: string[];
  revealTx: Transaction;
  composed: ComposeOutputs;
} {
  return {
    commitHexes: [],
    revealTx: tx,
    composed: {
      commits: [],
      reveal: {
        transaction: "fixture",
        transaction_hex: hex.encode(tx.unsignedTx),
        psbt_hex: hex.encode(tx.toPSBT()),
        txid: tx.id,
        output_info: [{ Change: { value: Number(tx.getOutput(0).amount) } }],
      },
    },
  };
}
function transport(
  source: ReturnType<typeof inMemoryFunding>,
  relay: (raw: string[], url: string) => unknown | Promise<unknown>,
) {
  return new HttpTransport({
    chain: signet,
    identity: signer.identity,
    signing: signer,
    funding: source,
    fetch: (async (url, init) =>
      new Response(
        JSON.stringify({
          result: await relay(
            JSON.parse(String(init?.body)).transactions,
            String(url),
          ),
        }),
        { status: 200 },
      )) as typeof fetch,
  });
}

test("lost response keeps the lease and exact retry shares one operation with reconciliation", async () => {
  const original = coin("a"),
    change = coin("b", 9000n);
  const source = inMemoryFunding([original]);
  const raw = [hex.encode((await signed(original, [9000n])).extract())];
  let finish!: (value: unknown) => void;
  const request = vi
    .fn()
    .mockRejectedValueOnce(new Error("lost response"))
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
  const completed = vi.fn(),
    value = { signedOffer: "preserved" };
  const pending = new PendingSubmission(
    raw,
    value,
    await source.reserve(),
    { spent: [original], change: [change] },
    request,
    completed,
  );
  await expect(pending.retry()).rejects.toBeInstanceOf(SubmissionError);
  await expect(source.reserve()).rejects.toThrow(/single-flight/);
  raw[0] = "00";
  const retry = pending.retry();
  expect(pending.reconcile()).toBe(retry);
  expect(() => pending.abandon()).toThrow(/wait/);
  await Promise.resolve();
  expect(request).toHaveBeenCalledTimes(2);
  expect(request.mock.calls[0]![1]).toEqual(request.mock.calls[1]![1]);
  finish(report(pending.transactions.map((tx) => tx.hex)));
  expect(await retry).toBe(value);
  expect(await pending.retry()).toBe(value);
  expect(completed).toHaveBeenCalledTimes(1);
  pending.abandon();
  expect((await source.reserve()).utxos).toEqual([change]);
});

test("malformed or mismatched relay evidence never settles or releases funding", async () => {
  const original = coin("a");
  const raw = [hex.encode((await signed(original, [9000n])).extract())];
  for (const response of [
    null,
    { txid: Transaction.fromRaw(hex.decode(raw[0]!)).id },
    { ...report(raw), outcome: "unknown" },
    {
      ...report(raw),
      transactions: [
        { ...report(raw).transactions[0], wtxid: "00".repeat(32) },
      ],
    },
  ]) {
    const source = inMemoryFunding([original]);
    const pending = new PendingSubmission(
      raw,
      undefined,
      await source.reserve(),
      { spent: [original], change: [] },
      async () => response,
      () => {},
    );
    await expect(pending.retry()).rejects.toBeInstanceOf(SubmissionError);
    expect(pending.status).toBe("uncertain");
    await expect(source.reserve()).rejects.toThrow(/single-flight/);
    pending.abandon();
    await expect(source.reserve()).rejects.toThrow(/no spendable/);
  }
});

test("an observation failure after partial acceptance discards stale positive change evidence", async () => {
  const input = coin("a"),
    unused = coin("c");
  const parent = await signed(input, [9000n]);
  const child = await signed({ ...coin("b", 9000n), txid: parent.id }, [8000n]);
  const raw = [hex.encode(parent.extract()), hex.encode(child.extract())];
  const source = inMemoryFunding([input, unused]);
  const request = vi
    .fn()
    .mockResolvedValueOnce(report(raw, [true, false]))
    .mockRejectedValueOnce(new Error("offline"));
  const pending = new PendingSubmission(
    raw,
    undefined,
    await source.reserve(),
    {
      spent: [input],
      change: [{ ...coin("d", 9000n), txid: parent.id }],
    },
    request,
    () => {},
  );
  await expect(pending.retry()).rejects.toBeInstanceOf(SubmissionError);
  await expect(pending.reconcile()).rejects.toBeInstanceOf(SubmissionError);
  pending.abandon();
  expect((await source.reserve()).utxos).toEqual([unused]);
});

test("preparation failure releases funding, but dropped publication errors remain recoverable", async () => {
  const input = coin("a"),
    source = inMemoryFunding([input]);
  const relay = vi
    .fn()
    .mockRejectedValueOnce(new Error("response lost"))
    .mockImplementation((raw: string[]) => report(raw));
  const http = transport(source, relay);
  await expect(
    http.submitReveal(async () => {
      throw new Error("wallet refused");
    }),
  ).rejects.toThrow(/wallet refused/);
  expect(relay).not.toHaveBeenCalled();
  expect(http.pendingSubmissions()).toHaveLength(0);
  const tx = await signed(input, [9000n]);
  const prepare = vi.fn(async () => ({
    ...prepared(tx),
    value: { offer: "signed escrow recovery" },
  }));
  await expect(http.submitReveal(prepare)).rejects.toBeInstanceOf(
    SubmissionError,
  );
  const [pending] = http.pendingSubmissions();
  expect(pending).toBeDefined();
  await expect(http.submitReveal(prepare)).rejects.toThrow(/single-flight/);
  expect(prepare).toHaveBeenCalledTimes(1);
  const recovered = await pending!.reconcile();
  expect(recovered).toMatchObject({
    result: { txid: tx.id },
    value: { offer: "signed escrow recovery" },
  });
  expect(relay.mock.calls[1]![1]).toContain("/transactions/reconcile");
  expect(http.pendingSubmissions()).toHaveLength(0);
  expect((await source.reserve()).utxos).toEqual([
    {
      txid: tx.id,
      vout: 0,
      value: 9000n,
      scriptPubKey: hex.encode(own.script),
    },
  ]);
});

test("partial abandon retires original inputs and never offers a package-consumed change output", async () => {
  const input = coin("a"),
    unused = coin("b");
  const parent = await signed(input, [4000n, 5000n]);
  const child = await signed(
    {
      txid: parent.id,
      vout: 1,
      value: 5000n,
      scriptPubKey: hex.encode(own.script),
    },
    [4000n],
  );
  const source = inMemoryFunding([input, unused]);
  const http = transport(source, (raw) => report(raw, [true, false]));
  const compose = prepared(child);
  compose.commitHexes = [hex.encode(parent.extract())];
  compose.composed.commits = [
    {
      transaction: "fixture",
      transaction_hex: hex.encode(parent.unsignedTx),
      psbt_hex: hex.encode(parent.toPSBT()),
      txid: parent.id,
      change_value: 5000,
    },
  ];
  await expect(http.submitReveal(async () => compose)).rejects.toBeInstanceOf(
    SubmissionError,
  );
  const [pending] = http.pendingSubmissions();
  expect(pending!.status).toBe("uncertain");
  pending!.abandon();
  expect(http.pendingSubmissions()).toHaveLength(0);
  expect((await source.reserve()).utxos).toEqual([unused]);
  await expect(pending!.retry()).rejects.toThrow(/abandoned/);
});

test("an uncertain Attachment.offer preserves its verified seller PSBT without signing again", async () => {
  const key = hex.decode(signer.identity.xOnlyPubKey);
  const amount = new Uint8Array(8);
  new DataView(amount.buffer).setBigUint64(0, 600n, false);
  const script = Script.encode([
    key,
    "CHECKSIG",
    "OP_0",
    "IF",
    new Uint8Array([0x6b, 0x6f, 0x6e]),
    amount,
    hex.decode(signet.bitcoinNetworkMagic!),
    new Uint8Array([1]),
    "ENDIF",
  ]);
  const escrow = p2tr(key, { script }, signet.network, true);
  const input = coin("a"),
    source = inMemoryFunding([input]);
  const tx = await signed(input, [600n, 9000n], escrow.script);
  const preparedOffer = prepared(tx);
  preparedOffer.composed.reveal.output_info = [
    {
      ChainedEnvelope: {
        value: 600,
        tap_leaf_script: {
          leafVersion: 0xc0,
          script: hex.encode(script),
          controlBlock: hex.encode(
            TaprootControlBlock.encode(escrow.tapLeafScript![0]![0]),
          ),
        },
      },
    },
    { Change: { value: 9000 } },
  ];
  const relay = vi
    .fn()
    .mockRejectedValueOnce(new Error("response lost"))
    .mockImplementation((raw: string[]) => report(raw));
  const http = transport(source, relay);
  const compose = vi
    .spyOn(http, "composeAndSign")
    .mockResolvedValue(preparedOffer);
  const signing = vi.spyOn(signer, "psbt");
  const session = new KontorSession({
    chain: signet,
    signing: signer,
    transport: () => http,
  });
  const address = new ContractAddress("token", 0n, 0n);
  const attachment = new Attachment(
    session,
    session.call(address, "attach", "attach(0)", (s) => s),
    session.call(address, "detach", "detach()", (s) => s),
  );
  try {
    await expect(attachment.offer({ price: 1000n })).rejects.toBeInstanceOf(
      SubmissionError,
    );
    const [pending] = session.transport.pendingSubmissions();
    const value = pending!.value as { value: Offer };
    expect(value.value).toBeInstanceOf(Offer);
    const encoded = value.value.serialize();
    const sellerPsbt = Transaction.fromPSBT(
      hex.decode(value.value.data.detachPsbt),
    );
    expect(sellerPsbt.getInput(1).tapScriptSig?.[0]?.[1].at(-1)).toBe(0x83);
    expect(signing).toHaveBeenCalledTimes(1);
    expect(await pending!.retry()).toBe(value);
    expect(value.value.serialize()).toBe(encoded);
    expect(signing).toHaveBeenCalledTimes(1);
    expect(compose).toHaveBeenCalledTimes(1);
    expect(http.pendingSubmissions()).toHaveLength(0);
  } finally {
    session.close();
    compose.mockRestore();
    signing.mockRestore();
  }
});
