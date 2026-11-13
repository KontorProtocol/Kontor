import { hex } from "@scure/base";
import {
  DEFAULT_SEQUENCE,
  Script,
  TaprootControlBlock,
  Transaction,
  p2tr,
} from "@scure/btc-signer";

import { serializeInst } from "../backend/index.js";
import type {
  ComposeOutputs,
  InstKind,
  Reveal,
  RevealOutput,
} from "../bindings.js";
import type { Chain } from "../chains.js";
import { TransportError } from "../errors.js";
import type { Utxo } from "../json-codec.js";

const DUST_SATS = 330n;
const DEFAULT_MAX_FEE_RATE = 100;
const FORMAT_TAG = new Uint8Array([0x6b, 0x6f, 0x6e, 0x32]);
const MAX_MONEY_SATS = 2_100_000_000_000_000n;
type SponsorFields = Extract<
  InstKind,
  { SponsorBound: unknown }
>["SponsorBound"];

function amountBytes(amount: bigint): Uint8Array {
  if (amount < 0n || amount > MAX_MONEY_SATS)
    reject("invalid format-2 previous-output amount");
  const bytes = new Uint8Array(8);
  let remaining = amount;
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function reject(reason: string): never {
  throw new TransportError(`Compose response rejected: ${reason}`, {
    docsPath: "/sdk/transport",
  });
}

function equalBytes(left: Uint8Array | undefined, right: Uint8Array): boolean {
  return left != null && hex.encode(left) === hex.encode(right);
}

function hasOnlyKeys(
  value: unknown,
  keys: string[],
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function validSats(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function outpoint(input: ReturnType<Transaction["getInput"]>): string {
  if (input.txid == null || input.index == null)
    reject("missing input outpoint");
  return `${hex.encode(input.txid)}:${input.index}`;
}

function expectedOutpoint(value: string): string {
  const match = /^([0-9a-fA-F]{64}):(0|[1-9][0-9]*)$/.exec(value);
  if (
    !match ||
    !Number.isSafeInteger(Number(match[2])) ||
    Number(match[2]) > 0xffffffff
  ) {
    reject("invalid requested outpoint");
  }
  return `${match[1]!.toLowerCase()}:${Number(match[2])}`;
}

function envelope(
  keyHex: string,
  insts: unknown,
  chain: Chain,
  amount: bigint,
) {
  const key = hex.decode(keyHex);
  const data = serializeInst(JSON.stringify(insts));
  if (data.length === 0 || data.length > 387 * 1024)
    reject("invalid envelope size");
  const chunks: Uint8Array[] = [];
  for (let offset = 0; offset < data.length; offset += 520) {
    chunks.push(data.slice(offset, offset + 520));
  }
  const magic = chain.bitcoinNetworkMagic;
  if (magic == null || !/^[0-9a-fA-F]{8}$/.test(magic))
    reject("leaf needs a valid network magic");
  const script = Script.encode([
    key,
    "CHECKSIG",
    "OP_0",
    "IF",
    FORMAT_TAG,
    amountBytes(amount),
    hex.decode(magic),
    ...chunks,
    "ENDIF",
  ]);
  if (script.length > 387 * 1024) reject("complete leaf exceeds limit");
  return p2tr(key, { script }, chain.network, true);
}

type ExpectedPrevout = { value: bigint; script: Uint8Array };

function prevout(value: {
  value: number;
  script_pubkey: string;
}): ExpectedPrevout {
  if (!Number.isSafeInteger(value.value) || value.value < 0)
    reject("invalid prevout value");
  return {
    value: BigInt(value.value),
    script: hex.decode(value.script_pubkey),
  };
}

function checkInput(
  tx: Transaction,
  index: number,
  expectedPoint: string,
  expectedPrevout: ExpectedPrevout,
  expectedKey?: Uint8Array,
  expectedSighash = 0,
): void {
  const input = tx.getInput(index);
  if (outpoint(input) !== expectedOutpoint(expectedPoint))
    reject(`input ${index} outpoint differs`);
  if (input.sequence !== DEFAULT_SEQUENCE || input.finalScriptSig?.length) {
    reject(`input ${index} changes the unsigned transaction`);
  }
  if (
    input.witnessUtxo?.amount !== expectedPrevout.value ||
    !equalBytes(input.witnessUtxo?.script, expectedPrevout.script)
  ) {
    reject(`input ${index} prevout differs`);
  }
  if (
    expectedKey == null
      ? input.tapInternalKey != null
      : !equalBytes(input.tapInternalKey, expectedKey)
  ) {
    reject(`input ${index} signing key differs`);
  }
  if (
    (expectedSighash === 0 &&
      input.sighashType != null &&
      input.sighashType !== 0) ||
    (expectedSighash !== 0 && input.sighashType !== expectedSighash)
  ) {
    reject(`input ${index} changes the signing hash`);
  }
  if (
    input.nonWitnessUtxo != null ||
    input.redeemScript != null ||
    input.witnessScript != null ||
    input.finalScriptWitness != null
  ) {
    reject(`input ${index} has unexpected signing fields`);
  }
}

function checkMetadata(
  tx: Transaction,
  response: { transaction_hex: string; txid: string },
): void {
  if (tx.version !== 2 || tx.lockTime !== 0)
    reject("unexpected transaction header");
  if (
    response.transaction_hex.toLowerCase() !== hex.encode(tx.unsignedTx) ||
    response.txid.toLowerCase() !== tx.id
  ) {
    reject("transaction metadata differs from PSBT");
  }
}

function checkFee(
  tx: Transaction,
  totalInput: bigint,
  rate: number,
  witnessBytes: number,
  sizingDelta = 0,
): void {
  const totalOutput = Array.from(
    { length: tx.outputsLength },
    (_, i) => tx.getOutput(i).amount ?? 0n,
  ).reduce((sum, value) => sum + value, 0n);
  const fee = totalInput - totalOutput;
  const vsize =
    tx.unsignedTx.length + sizingDelta + Math.ceil((2 + witnessBytes) / 4);
  if (fee < 0n || fee > BigInt(rate) * BigInt(vsize + 2) + (DUST_SATS - 1n)) {
    reject("fee exceeds the requested rate or local safety limit");
  }
}

function varIntBytes(value: number): number {
  if (value < 253) return 1;
  if (value <= 0xffff) return 3;
  return 5;
}

function outputBytes(scriptLength: number): number {
  return 8 + varIntBytes(scriptLength) + scriptLength;
}

function checkOutput(
  tx: Transaction,
  index: number,
  script: Uint8Array,
  value?: bigint,
): void {
  const output = tx.getOutput(index);
  if (
    !equalBytes(output.script, script) ||
    (value != null && output.amount !== value)
  ) {
    reject(`output ${index} differs from request`);
  }
}

function fundingFor(
  funding: Reveal["participants"][number]["commit_source"] & { Build: unknown },
  supplied: Utxo[] | undefined,
): Map<string, ExpectedPrevout> {
  const build = funding.Build as {
    funding:
      | { Ids: string[] }
      | {
          Resolved: Array<{
            outpoint: string;
            prevout: { value: number; script_pubkey: string };
          }>;
        };
  };
  const result = new Map<string, ExpectedPrevout>();
  if ("Ids" in build.funding) {
    if (supplied == null)
      reject("Build funding requires locally supplied UTXOs");
    const available = new Map(
      supplied!.map((u) => [
        expectedOutpoint(`${u.txid}:${u.vout}`),
        {
          value: u.value,
          script: hex.decode(u.scriptPubKey),
        },
      ]),
    );
    for (const id of build.funding.Ids) {
      const key = expectedOutpoint(id);
      const value = available.get(key);
      if (value == null || result.has(key))
        reject("unknown or repeated funding outpoint");
      result.set(key, value);
    }
  } else {
    for (const item of build.funding.Resolved) {
      const key = expectedOutpoint(item.outpoint);
      if (result.has(key)) reject("repeated funding outpoint");
      result.set(key, prevout(item.prevout));
    }
  }
  return result;
}

function outputLayout(reveal: Reveal): RevealOutput[] {
  let lastPaired = -1;
  for (let i = reveal.participants.length - 1; i >= 0; i--) {
    if (reveal.participants[i]!.output != null) {
      lastPaired = i;
      break;
    }
  }
  const layout: RevealOutput[] = [];
  let nextExtra = 0;
  for (let i = 0; i <= lastPaired; i++) {
    const paired = reveal.participants[i]!.output;
    if (paired != null) layout.push(paired);
    else if (nextExtra < reveal.extra_outputs.length)
      layout.push(reveal.extra_outputs[nextExtra++]!);
    else reject("participant output slot has no requested output");
  }
  while (nextExtra < reveal.extra_outputs.length)
    layout.push(reveal.extra_outputs[nextExtra++]!);
  if (layout.length === 0) layout.push({ OpReturn: { data: [0, 0, 0, 0] } });
  return layout;
}

type ExpectedCommit = { point: string; prevout: ExpectedPrevout };

function participantSource(
  reveal: Reveal,
  committed: ExpectedCommit[],
  index: number,
): ExpectedCommit {
  const source = reveal.participants[index]!.commit_source;
  if ("Existing" in source) {
    return {
      point: source.Existing.outpoint,
      prevout: prevout(source.Existing.prevout),
    };
  }
  const order = reveal.participants
    .slice(0, index)
    .filter((participant) => "Build" in participant.commit_source).length;
  return committed[order] ?? reject("unresolved Build participant");
}

function outpointBytes(point: string): { txid: number[]; vout: number[] } {
  const [txidHex, voutText] = expectedOutpoint(point).split(":");
  const txid = Array.from(hex.decode(txidHex!).reverse());
  let vout = Number(voutText);
  const bytes: number[] = [];
  for (let i = 0; i < 4; i++) {
    bytes.push(vout & 0xff);
    vout >>>= 8;
  }
  return { txid, vout: bytes };
}

function gasBytes(limit: bigint): number[] {
  if (limit < 0n || limit > 0xffff_ffff_ffff_ffffn)
    reject("Sponsor total gas overflows");
  const bytes: number[] = [];
  for (let i = 0; i < 8; i++) {
    bytes.push(Number(limit & 0xffn));
    limit >>= 8n;
  }
  return bytes;
}

function expectedInstructions(
  reveal: Reveal,
  committed: ExpectedCommit[],
  chain: Chain,
  index: number,
): Reveal["participants"][number]["commit_insts"] {
  const participant = reveal.participants[index]!;
  const sponsorOps = participant.commit_insts.ops.filter(
    (inst) => typeof inst.kind === "object" && "SponsorBound" in inst.kind,
  );
  if (participant.commit_insts.ops.some((inst) => inst.kind === "Sponsor"))
    reject("unbound Sponsor is not a launch operation");
  if (sponsorOps.length === 0) return participant.commit_insts;
  if (sponsorOps.length !== 1 || participant.commit_insts.aggregate != null)
    reject("ambiguous Sponsor instructions");
  if ((participant.sighash_type ?? 0x81) !== 0x81)
    reject("Sponsor must use ALL|ANYONECANPAY");
  const sponsor = sponsorOps[0]!;
  if (typeof sponsor.kind !== "object" || !("SponsorBound" in sponsor.kind))
    reject("invalid Sponsor kind");
  const targetIndex = sponsor.kind.SponsorBound.target_input_index;
  if (targetIndex !== index + 1 || targetIndex >= reveal.participants.length)
    reject("Sponsor target is not the next participant");
  const target = reveal.participants[targetIndex]!;
  if (
    target.commit_insts.ops.length === 0 ||
    target.commit_insts.ops.some(
      (inst) =>
        inst.kind === "Sponsor" ||
        (typeof inst.kind === "object" && "SponsorBound" in inst.kind),
    )
  )
    reject("Sponsor target has invalid instructions");
  const source = participantSource(reveal, committed, targetIndex);
  const targetTap = envelope(
    target.x_only_public_key,
    target.commit_insts,
    chain,
    source.prevout.value,
  );
  if (!equalBytes(source.prevout.script, targetTap.script))
    reject("Sponsor target prevout does not match its leaf");
  const leafHash = targetTap.leaves?.[0]?.hash;
  if (leafHash == null) reject("Sponsor target has no leaf hash");
  const point = outpointBytes(source.point);
  if (!Number.isSafeInteger(sponsor.gas_limit) || sponsor.gas_limit < 0)
    reject("invalid Sponsor gas limit");
  const maxGas = gasBytes(
    BigInt(sponsor.gas_limit) * BigInt(target.commit_insts.ops.length),
  );
  return {
    ...participant.commit_insts,
    ops: participant.commit_insts.ops.map((inst) =>
      inst === sponsor
        ? {
            ...inst,
            kind: {
              SponsorBound: {
                target_input_index: targetIndex,
                target_txid: point.txid as SponsorFields["target_txid"],
                target_vout_le: point.vout as SponsorFields["target_vout_le"],
                target_leaf_hash: Array.from(
                  leafHash,
                ) as SponsorFields["target_leaf_hash"],
                max_total_gas_le: maxGas as SponsorFields["max_total_gas_le"],
              },
            },
          }
        : inst,
    ),
  };
}

export function validateComposeResponse(
  reveal: Reveal,
  composed: ComposeOutputs,
  chain: Chain,
  ownKeyHex: string,
  suppliedUtxos?: Utxo[],
): void {
  if (
    !Array.isArray(composed.commits) ||
    !Array.isArray(composed.reveal?.output_info)
  ) {
    reject("response collections are not arrays");
  }
  for (let index = 0; index < reveal.participants.length; index++) {
    const participant = reveal.participants[index]!;
    const mode = participant.sighash_type ?? 0x81;
    if (mode !== 0x81 && mode !== 0x83)
      reject(`participant ${index} has unsupported sighash`);
    if (mode === 0x83) {
      if (participant.output == null || index === 0)
        reject("SINGLE|ANYONECANPAY needs a paired output and Sponsor");
      const prior = reveal.participants[index - 1]!;
      if (
        !prior.commit_insts.ops.some(
          (inst) =>
            typeof inst.kind === "object" &&
            "SponsorBound" in inst.kind &&
            inst.kind.SponsorBound.target_input_index === index,
        )
      )
        reject("SINGLE|ANYONECANPAY is missing its Sponsor");
    }
  }
  const rate = reveal.sat_per_vbyte ?? DEFAULT_MAX_FEE_RATE;
  if (!Number.isSafeInteger(rate) || rate <= 0)
    reject("invalid fee-rate limit");
  const ownKey = hex.decode(ownKeyHex);
  const buildIndices = reveal.participants.flatMap((participant, index) =>
    "Build" in participant.commit_source ? [index] : [],
  );
  const builds = buildIndices.map((index) => reveal.participants[index]!);
  if (composed.commits.length !== builds.length)
    reject("commit count differs from request");
  const committed: ExpectedCommit[] = [];
  const commitTxs: Transaction[] = [];
  const allFunding = new Set<string>();

  for (let i = 0; i < builds.length; i++) {
    const participant = builds[i]!;
    const build = participant.commit_source as Extract<
      typeof participant.commit_source,
      { Build: unknown }
    >;
    const expectedInputs = fundingFor(build, suppliedUtxos);
    const response = composed.commits[i]!;
    const tx = Transaction.fromPSBT(hex.decode(response.psbt_hex));
    checkMetadata(tx, response);
    if (
      tx.inputsLength === 0 ||
      tx.inputsLength > expectedInputs.size ||
      tx.outputsLength < 1 ||
      tx.outputsLength > 2
    ) {
      reject(`commit ${i} input or output count differs`);
    }
    if (!equalBytes(hex.decode(participant.x_only_public_key), ownKey)) {
      reject(`commit ${i} belongs to a different signer`);
    }
    const ownScript = p2tr(ownKey, undefined, chain.network).script;
    if (
      build.Build.address !== p2tr(ownKey, undefined, chain.network).address
    ) {
      reject(`commit ${i} change address differs from signer`);
    }
    let totalInput = 0n;
    const used = new Set<string>();
    for (let j = 0; j < tx.inputsLength; j++) {
      const input = tx.getInput(j);
      const point = outpoint(input);
      const expected = expectedInputs.get(point);
      if (expected == null || used.has(point) || allFunding.has(point))
        reject(`commit ${i} spends unexpected funding`);
      checkInput(tx, j, point, expected, ownKey);
      if (input.tapLeafScript?.length || input.tapMerkleRoot != null)
        reject(`commit ${i} has unexpected script path`);
      used.add(point);
      allFunding.add(point);
      totalInput += expected.value;
    }
    const tapValue = tx.getOutput(0).amount;
    if (tapValue == null || tapValue < DUST_SATS)
      reject(`commit ${i} has invalid tap output`);
    if (tx.outputsLength === 2) {
      if (
        !Number.isSafeInteger(response.change_value) ||
        response.change_value! < 0
      )
        reject(`commit ${i} change metadata is invalid`);
      checkOutput(tx, 1, ownScript, BigInt(response.change_value!));
    }
    if ((tx.outputsLength === 2) !== (response.change_value != null))
      reject(`commit ${i} change metadata differs`);
    checkFee(tx, totalInput, rate, 66 * tx.inputsLength);
    committed.push({
      point: `${tx.id}:0`,
      prevout: {
        value: tapValue,
        script:
          tx.getOutput(0).script ?? reject(`commit ${i} has no output script`),
      },
    });
    commitTxs.push(tx);
  }
  for (let i = 0; i < builds.length; i++) {
    const participant = builds[i]!;
    const expected = expectedInstructions(
      reveal,
      committed,
      chain,
      buildIndices[i]!,
    );
    const tap = envelope(
      participant.x_only_public_key,
      expected,
      chain,
      committed[i]!.prevout.value,
    );
    checkOutput(commitTxs[i]!, 0, tap.script);
    committed[i]!.prevout.script = tap.script;
  }

  const tx = Transaction.fromPSBT(hex.decode(composed.reveal.psbt_hex));
  checkMetadata(tx, composed.reveal);
  if (
    tx.inputsLength !==
    reveal.participants.length + reveal.extra_inputs.length
  ) {
    reject("reveal input count differs from request");
  }
  let totalInput = 0n;
  let witnessBytes = 0;
  for (let i = 0; i < reveal.participants.length; i++) {
    const participant = reveal.participants[i]!;
    const expected = participantSource(reveal, committed, i);
    const insts = expectedInstructions(reveal, committed, chain, i);
    const tap = envelope(
      participant.x_only_public_key,
      insts,
      chain,
      expected.prevout.value,
    );
    checkInput(
      tx,
      i,
      expected.point,
      expected.prevout,
      hex.decode(participant.x_only_public_key),
      participant.sighash_type ?? 0x81,
    );
    const leaf = tx.getInput(i).tapLeafScript;
    const expectedLeaf = tap.tapLeafScript?.[0];
    if (
      leaf?.length !== 1 ||
      expectedLeaf == null ||
      leaf[0]?.[1]?.at(-1) !== 0xc0 ||
      !equalBytes(
        leaf[0]?.[1]?.slice(0, -1),
        tap.leaves?.[0]?.script ?? new Uint8Array(),
      ) ||
      !equalBytes(
        leaf[0] == null ? undefined : TaprootControlBlock.encode(leaf[0][0]),
        TaprootControlBlock.encode(expectedLeaf[0]),
      )
    ) {
      reject(`reveal input ${i} does not commit to requested instructions`);
    }
    if (
      tx.getInput(i).tapMerkleRoot != null ||
      tx.getInput(i).tapScriptSig?.length
    ) {
      reject(`reveal input ${i} has unexpected signing fields`);
    }
    totalInput += expected.prevout.value;
    const scriptLength = tap.leaves![0]!.script.length;
    const controlLength = TaprootControlBlock.encode(expectedLeaf[0]).length;
    witnessBytes +=
      1 +
      1 +
      65 +
      varIntBytes(scriptLength) +
      scriptLength +
      varIntBytes(controlLength) +
      controlLength;
  }
  for (let i = 0; i < reveal.extra_inputs.length; i++) {
    const extra = reveal.extra_inputs[i]!;
    const index = reveal.participants.length + i;
    checkInput(
      tx,
      index,
      extra.outpoint,
      prevout(extra.prevout),
      reveal.participants.length
        ? hex.decode(reveal.participants[0]!.x_only_public_key)
        : undefined,
    );
    if (tx.getInput(index).tapLeafScript?.length)
      reject(`extra input ${i} changes signing path`);
    totalInput += BigInt(extra.prevout.value);
    witnessBytes += 66;
  }

  const layout = outputLayout(reveal);
  if (layout.filter((output) => "Change" in output).length > 1)
    reject("multiple change outputs requested");
  let outputIndex = 0;
  let droppedChange: Uint8Array | undefined;
  for (let i = 0; i < layout.length; i++) {
    const output = layout[i]!;
    if ("Change" in output) {
      const info = composed.reveal.output_info[outputIndex];
      if (typeof info === "object" && info != null && "Change" in info) {
        if (
          !hasOnlyKeys(info, ["Change"]) ||
          !hasOnlyKeys(info.Change, ["value"]) ||
          !validSats(info.Change.value)
        ) {
          reject("change annotation has unexpected fields");
        }
        if (outputIndex >= tx.outputsLength)
          reject("change annotation has no output");
        checkOutput(tx, outputIndex, hex.decode(output.Change.script_pubkey));
        if ((tx.getOutput(outputIndex).amount ?? 0n) < DUST_SATS)
          reject("sub-dust change output");
        if (BigInt(info.Change.value) !== tx.getOutput(outputIndex).amount) {
          reject("change annotation differs from transaction");
        }
        outputIndex++;
      } else if (
        i !== layout.length - 1 ||
        (reveal.participants.length > 1 && i < reveal.participants.length)
      ) {
        reject("requested change output is missing");
      } else {
        droppedChange = hex.decode(output.Change.script_pubkey);
      }
    } else if ("Fixed" in output) {
      checkOutput(
        tx,
        outputIndex,
        hex.decode(output.Fixed.script_pubkey),
        BigInt(output.Fixed.value),
      );
      const info = composed.reveal.output_info[outputIndex];
      if (
        typeof info !== "object" ||
        info == null ||
        !("Fixed" in info) ||
        !hasOnlyKeys(info, ["Fixed"]) ||
        !hasOnlyKeys(info.Fixed, ["value"]) ||
        !validSats(info.Fixed.value) ||
        info.Fixed.value !== output.Fixed.value
      )
        reject("fixed output annotation differs");
      outputIndex++;
    } else if ("ChainedEnvelope" in output) {
      const tap = envelope(
        output.ChainedEnvelope.internal_key,
        output.ChainedEnvelope.insts,
        chain,
        BigInt(output.ChainedEnvelope.value),
      );
      checkOutput(
        tx,
        outputIndex,
        tap.script,
        BigInt(output.ChainedEnvelope.value),
      );
      const info = composed.reveal.output_info[outputIndex];
      const leaf = tap.tapLeafScript?.[0];
      if (
        typeof info !== "object" ||
        info == null ||
        !("ChainedEnvelope" in info) ||
        leaf == null ||
        !hasOnlyKeys(info, ["ChainedEnvelope"]) ||
        !hasOnlyKeys(info.ChainedEnvelope, ["value", "tap_leaf_script"]) ||
        !validSats(info.ChainedEnvelope.value) ||
        !hasOnlyKeys(info.ChainedEnvelope.tap_leaf_script, [
          "leafVersion",
          "script",
          "controlBlock",
        ]) ||
        info.ChainedEnvelope.value !== output.ChainedEnvelope.value ||
        info.ChainedEnvelope.tap_leaf_script.leafVersion !== 0xc0 ||
        info.ChainedEnvelope.tap_leaf_script.script.toLowerCase() !==
          hex.encode(tap.leaves![0]!.script) ||
        info.ChainedEnvelope.tap_leaf_script.controlBlock.toLowerCase() !==
          hex.encode(TaprootControlBlock.encode(leaf[0]))
      ) {
        reject("chained output annotation differs");
      }
      outputIndex++;
    } else {
      checkOutput(
        tx,
        outputIndex,
        Script.encode(["RETURN", new Uint8Array(output.OpReturn.data)]),
        0n,
      );
      if (composed.reveal.output_info[outputIndex] !== "OpReturn")
        reject("OP_RETURN annotation differs");
      outputIndex++;
    }
  }
  let sizingDelta = 0;
  if (droppedChange != null) {
    sizingDelta =
      outputBytes(droppedChange.length) +
      varIntBytes(layout.length) -
      varIntBytes(tx.outputsLength);
    if (outputIndex === 0 && layout.length === 1 && tx.outputsLength === 1) {
      const fallback = Script.encode(["RETURN", new Uint8Array(4)]);
      checkOutput(tx, 0, fallback, 0n);
      if (composed.reveal.output_info[0] !== "OpReturn")
        reject("fallback output annotation differs");
      outputIndex = 1;
      sizingDelta -= outputBytes(fallback.length);
    }
  }
  if (outputIndex !== tx.outputsLength) reject("reveal has extra outputs");
  // The composer charges for a planned Change before it may drop dust.
  checkFee(tx, totalInput, rate, witnessBytes, sizingDelta);
  if (composed.reveal.output_info.length !== tx.outputsLength)
    reject("output annotations differ from transaction");
}
