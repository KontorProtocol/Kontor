/**
 * Default `KontorTransport` implementation. Four operations,
 * matching the indexer's API + Bitcoin RPC:
 *
 *   - `view(contract, wave)`   — POST to `/contracts/{address}`,
 *                                cheap read-only query.
 *   - `inspect(insts)`         — compose unsigned Bitcoin tx from
 *                                Insts, POST hex to `/transactions/inspect`.
 *                                Static analysis only.
 *   - `simulate(insts)`        — same composition, POST to
 *                                `/transactions/simulate`. Sandboxed
 *                                live execution.
 *   - `submit(insts)`          — compose the commit/reveal pair, sign
 *                                both with the account, and broadcast
 *                                them through the indexer's
 *                                `/transactions/broadcast` relay.
 *
 * Each tx-composition step is overridable through `HttpTransportOptions`
 * — power users can swap UTXO selection, fee estimation, or wait
 * policy. Defaults are sane for the common case.
 *
 * The transport is contract-agnostic: it submits whatever Insts the
 * Session hands it. Per-Inst contract addresses live inside the
 * `WireInsts` payload.
 */

import { hex } from "@scure/base";
import { p2tr, Transaction } from "@scure/btc-signer";

import type { Identity } from "../identity.js";
import type { Signing } from "../signing.js";
import type { FundingSource } from "../funding.js";
import type { Chain } from "../chains.js";
import type { ContractAddress } from "../canonical/ContractAddress.js";
import { ChainError, ContractError, TransportError } from "../errors.js";
import {
  signCommit,
  signReveal,
  verifyFinalizedTaprootTransaction,
} from "./signing.js";
import { validateComposeResponse } from "./compose-validation.js";
import { PendingSubmission, type BroadcastReport } from "./submission.js";
import { toRevealOutputs, type ExtraOutput } from "../outputs.js";
import type {
  BroadcastResult,
  KontorTransport,
  OpResultRaw,
  Utxo,
  WireInsts,
} from "../json-codec.js";
import type {
  ComposeOutputs,
  ContractProvenanceResponse,
  ErrorResponse,
  FootprintResponse,
  InspectedOp,
  OpWithResult,
  ResultResponse,
  Reveal,
  SignerResponse,
  ViewExpr,
  ViewResult,
} from "../bindings.js";
import { executionCoordinates } from "../confirmation.js";
import type { ProtocolSnapshot, SimulationReport } from "../protocol.js";
import {
  type ProvenanceEntry,
  type ContractProvenance,
  effectiveArtifactFromWire,
  provenanceEntryFromWire,
} from "../provenance.js";

export interface HttpTransportOptions {
  chain: Chain;
  /** Identity funding + signing for this transport (the P2TR address/key). */
  identity: Identity;
  /** Signing capability — the SDK calls `signing.psbt(...)` to authorize.
   *  Absent for a read-only transport (`view` works; submit/inspect/simulate
   *  throw). */
  signing?: Signing;

  /** Override the chain's HTTP endpoint. */
  url?: string;
  /** Custom fetch impl (testing, custom auth headers). */
  fetch?: typeof fetch;
  /** Static headers attached to every HTTP request. */
  headers?: Record<string, string>;

  /**
   * Where submits reserve spendable UTXOs and settle spent/change. The
   * transport retains uncertain signed submissions for recovery. Use
   * `inMemoryFunding` for optimistic chaining or `queryFunding` for
   * authoritative wallet snapshots. Omit for read-only transports;
   * `submit`/`inspect`/`simulate` then throw.
   */
  funding?: FundingSource;
  /**
   * Default Bitcoin fee rate in sat/vB. Omit (or `null`) to let the
   * indexer pick its current `fastest_fee` when composing. Static —
   * if you need per-call control, compose your own Reveal and pass
   * `sat_per_vbyte` directly.
   */
  feeRate?: number;
  /**
   * @deprecated This option is not applied. Set the cap with
   * `KontorSession.defaultGasLimit` or `Inst.withGasLimit`. Use
   * `simulateWithContext()` for an explicit estimate before choosing a cap.
   */
  gasLimit?: bigint | (() => Promise<bigint>);
  /**
   * How to wait for a submitted tx to land. Default: poll the indexer
   * every block until the tx is included and the proc result is
   * available.
   */
  wait?: {
    /** Max ms to wait. Default: 30 minutes. */
    timeoutMs?: number;
    /** Polling cadence in ms. Default: half of `chain.blockTime`. */
    pollMs?: number;
  };
}

export class HttpTransport implements KontorTransport {
  /** Indexer API base, trailing slash trimmed (so `${base}/contracts/…`). */
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly pending = new Set<PendingSubmission>();

  /** Recover unresolved submissions even if their original error was discarded. */
  pendingSubmissions(): readonly PendingSubmission[] {
    return [...this.pending];
  }

  constructor(private readonly opts: HttpTransportOptions) {
    this.baseUrl = (opts.url ?? opts.chain.urls.http).replace(/\/+$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** The signer, or a clear error on a read-only transport. */
  private requireSigning(): Signing {
    if (this.opts.signing == null) {
      throw new ChainError(
        "this is a read-only session (no signer) — only `view` is available; " +
          "construct with `signing` to submit/inspect/simulate",
        { docsPath: "/sdk/session" },
      );
    }
    return this.opts.signing;
  }

  /** The funding source, or a clear error if none was configured. */
  private funding(): FundingSource {
    if (this.opts.funding == null) {
      throw new ChainError(
        "this transport has no funding source — set `funding` on the session " +
          "(e.g. `inMemoryFunding([utxo])` or `queryFunding(fetch)`)",
        { docsPath: "/sdk/funding" },
      );
    }
    return this.opts.funding;
  }

  async view(contract: ContractAddress, wave: string): Promise<string> {
    const body: ViewExpr = { expr: wave };
    const result = await this.postJson<ViewResult>(
      `/contracts/${contract.toWire()}`,
      body,
    );
    if (result.type === "Ok") return result.value;
    // The view function itself returned an error (revert, bad expr,
    // unknown contract) — a contract-level failure, not a transport one.
    throw new ContractError(`view call on '${contract}' failed`, {
      details: result.message,
      docsPath: "/sdk/transport",
    });
  }

  async signer(identifier: string): Promise<SignerResponse | null> {
    const url = `${this.baseUrl}/signers/${identifier}`;
    let res: Response;
    try {
      res = await this.fetchImpl(url);
    } catch (cause) {
      throw new TransportError(`GET ${url} failed`, {
        cause: cause instanceof Error ? cause : undefined,
        docsPath: "/sdk/transport",
      });
    }
    if (res.status === 404) return null;
    const text = await res.text();
    if (!res.ok) {
      let detail = text;
      try {
        detail = (JSON.parse(text) as ErrorResponse).error ?? text;
      } catch {
        /* not JSON */
      }
      throw new TransportError(`GET ${url} returned HTTP ${res.status}`, {
        details: detail,
        docsPath: "/sdk/transport",
      });
    }
    return (JSON.parse(text) as ResultResponse<SignerResponse>).result;
  }

  async signerFootprint(identifier: string): Promise<FootprintResponse | null> {
    const url = `${this.baseUrl}/signers/${identifier}/footprint`;
    let res: Response;
    try {
      res = await this.fetchImpl(url);
    } catch (cause) {
      throw new TransportError(`GET ${url} failed`, {
        cause: cause instanceof Error ? cause : undefined,
        docsPath: "/sdk/transport",
      });
    }
    if (res.status === 404) return null;
    const text = await res.text();
    if (!res.ok) {
      let detail = text;
      try {
        detail = (JSON.parse(text) as ErrorResponse).error ?? text;
      } catch {
        /* not JSON */
      }
      throw new TransportError(`GET ${url} returned HTTP ${res.status}`, {
        details: detail,
        docsPath: "/sdk/transport",
      });
    }
    return (JSON.parse(text) as ResultResponse<FootprintResponse>).result;
  }

  async provenance(contract: ContractAddress): Promise<ProvenanceEntry[]> {
    return (await this.provenanceResponse(contract)).entries.map(
      provenanceEntryFromWire,
    );
  }

  async contractProvenance(
    contract: ContractAddress,
  ): Promise<ContractProvenance> {
    const response = await this.provenanceResponse(contract);
    if (!response.effective_artifact) {
      throw new TransportError(
        "Node did not report the effective contract artifact",
        {
          docsPath: "/sdk/transport",
        },
      );
    }
    return {
      entries: response.entries.map(provenanceEntryFromWire),
      effectiveArtifact: effectiveArtifactFromWire(response.effective_artifact),
    };
  }

  private async provenanceResponse(
    contract: ContractAddress,
  ): Promise<ContractProvenanceResponse> {
    const url = `${this.baseUrl}/contracts/${contract.toWire()}/provenance`;
    let res: Response;
    try {
      res = await this.fetchImpl(url);
    } catch (cause) {
      throw new TransportError(`GET ${url} failed`, {
        cause: cause instanceof Error ? cause : undefined,
        docsPath: "/sdk/transport",
      });
    }
    const text = await res.text();
    if (!res.ok) {
      let detail = text;
      try {
        detail = (JSON.parse(text) as ErrorResponse).error ?? text;
      } catch {
        /* not JSON */
      }
      throw new TransportError(`GET ${url} returned HTTP ${res.status}`, {
        details: detail,
        docsPath: "/sdk/transport",
      });
    }
    const resp = (
      JSON.parse(text) as ResultResponse<ContractProvenanceResponse>
    ).result;
    return resp;
  }

  /**
   * POST `body` as JSON to `path` under the indexer API base, unwrap the
   * `{ result }` envelope, and return the inner value. HTTP-level
   * failures — unreachable node, non-2xx status, malformed body — all
   * surface as `TransportError`.
   */
  private async postJson<T>(path: string, body: unknown): Promise<T> {
    return this.requestJson("POST", path, body);
  }

  protocol(): Promise<ProtocolSnapshot> {
    return this.requestJson("GET", "/protocol");
  }

  private async requestJson<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method,
        headers: { "content-type": "application/json", ...this.opts.headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (cause) {
      throw new TransportError(`${method} ${url} failed`, {
        cause: cause instanceof Error ? cause : undefined,
        docsPath: "/sdk/transport",
      });
    }
    const text = await res.text();
    if (!res.ok) {
      // The indexer returns `{ error }` on 4xx/5xx; fall back to the raw
      // body if it isn't that shape.
      let detail = text;
      try {
        detail = (JSON.parse(text) as ErrorResponse).error ?? text;
      } catch {
        /* not JSON — keep the raw text */
      }
      throw new TransportError(`${method} ${url} returned HTTP ${res.status}`, {
        details: detail,
        docsPath: "/sdk/transport",
      });
    }
    try {
      return (JSON.parse(text) as ResultResponse<T>).result;
    } catch (cause) {
      throw new TransportError(`${method} ${url} returned a non-JSON body`, {
        cause: cause instanceof Error ? cause : undefined,
        details: text.slice(0, 200),
        docsPath: "/sdk/transport",
      });
    }
  }

  /**
   * Combined commit + reveal. Builds any commits required by Build
   * participants, then builds the reveal PSBT. If all participants are
   * Existing, only builds the reveal.
   */
  compose(reveal: Reveal): Promise<ComposeOutputs> {
    return this.postJson<ComposeOutputs>("/transactions/compose", reveal);
  }

  /**
   * Compose a Reveal and sign all participant inputs belonging to
   * this transport's account. Pure: NO broadcast, NO tracking
   * update — callers feed the result into `submitReveal`'s prepare
   * callback, which handles broadcast + tracking under the lock.
   *
   * Public so `attach.ts` / marketplace flows can route their custom
   * Reveal shapes (ChainedEnvelope outputs, multi-participant) through
   * the same compose+sign primitive `submit` uses for the simple
   * single-Build case.
   */
  async composeAndSign(
    reveal: Reveal,
    fundingUtxos: Utxo[] | undefined,
  ): Promise<{
    /** One finalized hex per Build participant's commit, in
     *  `composed.commits` order. Empty when every input is Existing /
     *  extra_input (no commits to broadcast). Today every commit is
     *  signed by this account — a future mixed-account flow would
     *  need to skip foreign commits here. */
    commitHexes: string[];
    /** Reveal as a parsed `Transaction`. Only inputs whose
     *  `tap_internal_key` matches this account were finalized;
     *  callers extract once every input's witness is in place. */
    revealTx: Transaction;
    composed: ComposeOutputs;
  }> {
    const signing = this.requireSigning();
    const composed = await this.compose(reveal);
    validateComposeResponse(
      reveal,
      composed,
      this.opts.chain,
      signing.identity.xOnlyPubKey,
      fundingUtxos,
    );
    const commitHexes = await Promise.all(
      composed.commits.map((c) => signCommit(signing, c.psbt_hex)),
    );
    return {
      commitHexes,
      revealTx: await signReveal(signing, composed.reveal.psbt_hex),
      composed,
    };
  }

  /** Build the simple single-Build-participant Reveal used by `submit`,
   *  `inspect`, and `simulate`. The account funds + signs the commit;
   *  the reveal's paired output is Change back to the account. */
  private async buildSimpleReveal(
    insts: WireInsts,
    utxos: Utxo[],
    extraOutputs?: ExtraOutput[],
  ): Promise<Reveal> {
    const { identity } = this.opts;
    const scriptPubKeyHex = hex.encode(
      p2tr(hex.decode(identity.xOnlyPubKey), undefined, this.opts.chain.network)
        .script,
    );
    return {
      sat_per_vbyte: this.opts.feeRate ?? null,
      participants: [
        {
          x_only_public_key: identity.xOnlyPubKey,
          commit_insts: insts,
          sighash_type: null,
          // Change rides as the final extra_output (below), not a paired
          // output: rider outputs slot in front of it so Change stays
          // last. The indexer only silently drops sub-dust Change when
          // it's the final output, so a paired Change at index 0 with
          // riders appended after would turn a would-be-dropped dust
          // change into a hard compose error.
          output: null,
          commit_source: {
            Build: {
              address: identity.address,
              funding: { Ids: utxos.map((u) => `${u.txid}:${u.vout}`) },
            },
          },
        },
      ],
      extra_inputs: [],
      extra_outputs: [
        ...toRevealOutputs(extraOutputs, this.opts.chain.network),
        { Change: { script_pubkey: scriptPubKeyHex } },
      ],
    };
  }

  /**
   * Compose, sign, and broadcast `insts` through the indexer. Returns
   * the reveal txid; per-Inst results are resolved later by the
   * session's poller.
   *
   * Each submit owns a funding lease. Once publication is attempted, an
   * uncertain outcome retains that lease and exposes exact-byte recovery.
   */
  async submit(
    insts: WireInsts,
    opts?: { extraOutputs?: ExtraOutput[] },
  ): Promise<BroadcastResult> {
    const { result } = await this.submitReveal(async (utxos) => {
      const reveal = await this.buildSimpleReveal(
        insts,
        utxos,
        opts?.extraOutputs,
      );
      return this.composeAndSign(reveal, utxos);
    });
    return result;
  }

  /**
   * Preparation may return recovery data, such as a signed marketplace offer.
   * Only failures before publication release the lease. Later failures retain
   * an exact signed package in pendingSubmissions() and SubmissionError.recovery.
   */
  async submitReveal<T = undefined>(
    prepare: (utxos: Utxo[]) => Promise<{
      commitHexes: string[];
      revealTx: Transaction;
      composed: ComposeOutputs;
      value?: T;
    }>,
  ): Promise<{
    result: BroadcastResult;
    commitHexes: string[];
    revealHex: string;
    composed: ComposeOutputs;
    value?: T;
  }> {
    const lease = await this.funding().reserve();
    const taken = lease.utxos.map((utxo) => ({ ...utxo }));
    let submission: PendingSubmission<{
      result: BroadcastResult;
      commitHexes: string[];
      revealHex: string;
      composed: ComposeOutputs;
      value?: T;
    }>;
    try {
      const prepared = await prepare(taken);
      const commitHexes = [...prepared.commitHexes];
      const composed = prepared.composed;
      verifyFinalizedTaprootTransaction(prepared.revealTx);
      const revealHex = hex.encode(prepared.revealTx.extract());
      const fundingDelta = this.computeFundingDelta({
        suppliedUtxos: taken,
        composed,
        commitHexes,
        revealHex,
      });
      const value = {
        result: { txid: prepared.revealTx.id },
        commitHexes,
        revealHex,
        composed,
        value: prepared.value,
      };
      submission = new PendingSubmission(
        [...commitHexes, revealHex],
        value,
        lease,
        fundingDelta,
        (mode, raw) =>
          this.postJson<BroadcastReport>(`/transactions/${mode}`, {
            transactions: raw,
          }),
        () => {
          this.pending.delete(submission);
        },
      );
    } catch (err) {
      lease.release();
      throw err;
    }
    this.pending.add(submission);
    return submission.retry();
  }

  /**
   * Compute the spent candidates and owned change from the exact finalized
   * package. An output spent by a later package transaction is not retained
   * as funding, even if its annotation calls it Change.
   */
  private computeFundingDelta(opts: {
    suppliedUtxos: Utxo[];
    composed: ComposeOutputs;
    commitHexes: string[];
    revealHex: string;
  }): { spent: Utxo[]; change: Utxo[] } {
    const { suppliedUtxos, commitHexes, revealHex, composed } = opts;
    const ownScriptPubKey = hex.encode(
      p2tr(
        hex.decode(this.opts.identity.xOnlyPubKey),
        undefined,
        this.opts.chain.network,
      ).script,
    );
    const change: Utxo[] = [];
    const rawTransactions = [...commitHexes, revealHex].map((rawHex) =>
      Transaction.fromRaw(hex.decode(rawHex), {
        disableScriptCheck: true,
        allowUnknownOutputs: true,
        allowUnknownInputs: true,
      }),
    );
    const spentKeys = new Set<string>();
    for (const tx of rawTransactions) {
      for (let index = 0; index < tx.inputsLength; index++) {
        const input = tx.getInput(index);
        spentKeys.add(`${hex.encode(input.txid!)}:${input.index}`);
      }
    }
    const addOwnChange = (tx: Transaction, outputIndex: number): void => {
      const output = tx.getOutput(outputIndex);
      if (
        output.script == null ||
        hex.encode(output.script) !== ownScriptPubKey ||
        output.amount == null ||
        spentKeys.has(`${tx.id}:${outputIndex}`)
      )
        return;
      change.push({
        txid: tx.id,
        vout: outputIndex,
        value: output.amount,
        scriptPubKey: ownScriptPubKey,
      });
    };

    const revealChangeIdx = composed.reveal.output_info.findIndex(
      (info) => typeof info === "object" && info != null && "Change" in info,
    );
    if (revealChangeIdx >= 0) {
      addOwnChange(
        rawTransactions[rawTransactions.length - 1]!,
        revealChangeIdx,
      );
    }

    for (const [index, meta] of composed.commits.entries()) {
      if (meta.change_value != null) {
        addOwnChange(rawTransactions[index]!, 1);
      }
    }

    return {
      spent: suppliedUtxos.filter((utxo) =>
        spentKeys.has(`${utxo.txid.toLowerCase()}:${utxo.vout}`),
      ),
      change,
    };
  }

  /**
   * Relay already-signed raw transactions to the network, in dependency
   * order, as one package. The attach/detach runtime composes and signs
   * its commit/reveal txs by hand, then hands the finished package here.
   */
  broadcast(transactions: string[]): Promise<BroadcastReport> {
    return this.postJson<BroadcastReport>("/transactions/broadcast", {
      transactions,
    });
  }

  /**
   * Static analysis — the indexer parses the composed reveal without
   * executing it. One outcome per Inst; a rejected op surfaces as a
   * non-Ok `OpResultRaw` carrying its error. Takes funding to build a
   * valid reveal, but doesn't broadcast — so it `release()`s the
   * reservation rather than settling.
   */
  async inspect(insts: WireInsts): Promise<OpResultRaw[]> {
    const lease = await this.funding().reserve();
    const taken = lease.utxos.map((utxo) => ({ ...utxo }));
    try {
      const reveal = await this.buildSimpleReveal(insts, taken);
      const { revealTx } = await this.composeAndSign(reveal, taken);
      const ops = await this.postJson<InspectedOp[]>("/transactions/inspect", {
        hex: hex.encode(revealTx.extract()),
      });
      return ops.map(opWithResultToRaw);
    } finally {
      lease.release();
    }
  }

  /**
   * Sandboxed live execution — runs the composed reveal's ops against
   * current chain state in a throwaway tx, returning predicted per-Inst
   * outcomes (real gas, real results) without broadcasting. Like
   * `inspect`, it `release()`s its funding (nothing is spent).
   */
  async simulate(insts: WireInsts): Promise<OpResultRaw[]> {
    const ops = await this.simulationRequest<OpWithResult[]>(
      insts,
      "/transactions/simulate",
    );
    return ops.map(opWithResultToRaw);
  }

  async simulateWithContext(
    insts: WireInsts,
  ): Promise<SimulationReport<OpResultRaw>> {
    const report = await this.simulationRequest<SimulationReport>(
      insts,
      "/transactions/simulate/context",
    );
    return {
      context: report.context,
      operations: report.operations.map(opWithResultToRaw),
    };
  }

  private async simulationRequest<T>(
    insts: WireInsts,
    path: string,
  ): Promise<T> {
    const lease = await this.funding().reserve();
    const taken = lease.utxos.map((utxo) => ({ ...utxo }));
    try {
      const reveal = await this.buildSimpleReveal(insts, taken);
      const { revealTx } = await this.composeAndSign(reveal, taken);
      return await this.postJson<T>(path, {
        hex: hex.encode(revealTx.extract()),
      });
    } finally {
      lease.release();
    }
  }
}

/**
 * Map an indexer `OpWithResult` (from inspect / simulate) to the
 * transport's `OpResultRaw`. Three cases: a rejected op (didn't
 * materialize), a materialized + executed op (simulate — carries a
 * result row), and a materialized-only op (inspect — parsed, not run).
 */
function opWithResultToRaw(o: OpWithResult | InspectedOp): OpResultRaw {
  if (o.kind === "Rejected") {
    return {
      status: "Other",
      gas: 0n,
      error: o.error_message ?? undefined,
      func: "",
      contract: "",
      inputIndex: o.input_index,
      opIndex: o.op_index,
    };
  }
  const r = o.result;
  if (r != null) {
    return {
      ...("execution_height" in r
        ? { coordinates: executionCoordinates(r) }
        : {}),
      status: r.status,
      gas: BigInt(r.gas),
      value: r.value ?? undefined,
      error: o.error_message ?? undefined,
      func: r.func,
      contract: r.contract,
      inputIndex: r.input_index,
      opIndex: r.op_index,
    };
  }
  // Materialized but not executed (inspect): the op parsed cleanly.
  return {
    status: "Ok",
    gas: 0n,
    error: o.error_message ?? undefined,
    func: "",
    contract: "",
    inputIndex: o.op.metadata.input_index,
    opIndex: o.op.metadata.op_index,
  };
}

/**
 * Convenience factory mirroring Viem's `http()` style:
 *
 *     const transport = http({ chain: signet, identity, signing });
 */
export function http(opts: HttpTransportOptions): HttpTransport {
  return new HttpTransport(opts);
}
