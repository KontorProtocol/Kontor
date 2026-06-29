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
import { signCommit, signReveal } from "./signing.js";
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
  OpWithResult,
  ResultResponse,
  Reveal,
  SignerResponse,
  ViewExpr,
  ViewResult,
} from "../bindings.js";
import {
  type ProvenanceEntry,
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
   * Where submits get spendable UTXOs and report back spent/change. The
   * transport holds no funding state itself — see `FundingSource`
   * (`inMemoryFunding` for optimistic chaining, `queryFunding` for a
   * stateless wallet/indexer source). Omit for read-only transports;
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
   * Override automatic gas estimation. Default: simulate the call first
   * and use the reported gas + a small buffer.
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
    return resp.entries.map(provenanceEntryFromWire);
  }

  /**
   * POST `body` as JSON to `path` under the indexer API base, unwrap the
   * `{ result }` envelope, and return the inner value. HTTP-level
   * failures — unreachable node, non-2xx status, malformed body — all
   * surface as `TransportError`.
   */
  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json", ...this.opts.headers },
        body: JSON.stringify(body),
      });
    } catch (cause) {
      throw new TransportError(`POST ${url} failed`, {
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
      throw new TransportError(`POST ${url} returned HTTP ${res.status}`, {
        details: detail,
        docsPath: "/sdk/transport",
      });
    }
    try {
      return (JSON.parse(text) as ResultResponse<T>).result;
    } catch (cause) {
      throw new TransportError(`POST ${url} returned a non-JSON body`, {
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
  async composeAndSign(reveal: Reveal): Promise<{
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
   * Serialized via `lock` so concurrent callers don't race on funding
   * selection — submit 2 sees submit 1's broadcast reflected in
   * `trackedFunding` / `recentlySpent` before picking inputs.
   *
   * On success, advances `trackedFunding` to the broadcast's change
   * outputs (array mode) and records the actually-used input outpoints
   * in `recentlySpent` (callback mode's filter). On broadcast failure,
   * neither is touched — those UTXOs aren't actually spent.
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
      return this.composeAndSign(reveal);
    });
    return result;
  }

  /**
   * The blessed broadcast path for funding-spending txs. `take()` from
   * the funding source, hand the candidates to `prepare` (which shapes
   * the Reveal + compose+signs, and may inject a foreign reveal witness),
   * extract → broadcast, then `settle()` the funding source with what was
   * spent and the change created. On failure before broadcast, `release()`
   * the reservation. No lock — serialization (if any) is the funding
   * source's concern.
   */
  async submitReveal(
    prepare: (utxos: Utxo[]) => Promise<{
      commitHexes: string[];
      revealTx: Transaction;
      composed: ComposeOutputs;
    }>,
  ): Promise<{
    result: BroadcastResult;
    commitHexes: string[];
    revealHex: string;
    composed: ComposeOutputs;
  }> {
    const funding = this.funding();
    const taken = await funding.take();
    let commitHexes: string[];
    let revealHex: string;
    let composed: ComposeOutputs;
    let result: BroadcastResult;
    try {
      const prepared = await prepare(taken);
      commitHexes = prepared.commitHexes;
      composed = prepared.composed;
      revealHex = hex.encode(prepared.revealTx.extract());
      result = await this.broadcast([...commitHexes, revealHex]);
    } catch (err) {
      funding.release(taken);
      throw err;
    }
    funding.settle(
      this.computeFundingDelta({ suppliedUtxos: taken, composed, commitHexes }),
    );
    return { result, commitHexes, revealHex, composed };
  }

  /**
   * Compute what a broadcast commit/reveal package spent and what change
   * it created — fed to `FundingSource.settle`. The commit consumes a
   * prefix of `suppliedUtxos` (length = `commitTx.inputsLength` — the
   * indexer greedily picks from the head). Change is the reveal's
   * dust-floor Change output (first, for consolidation) plus each commit's
   * vout-1 change. Pure: no mutation.
   */
  private computeFundingDelta(opts: {
    suppliedUtxos: Utxo[];
    composed: ComposeOutputs;
    commitHexes: string[];
  }): { spent: Utxo[]; change: Utxo[] } {
    const { suppliedUtxos, commitHexes, composed } = opts;
    const ownScriptPubKey = hex.encode(
      p2tr(
        hex.decode(this.opts.identity.xOnlyPubKey),
        undefined,
        this.opts.chain.network,
      ).script,
    );
    const change: Utxo[] = [];

    // Reveal-change first — the dust-floor 330-sat output is what the
    // indexer's greedy selector pulls in alongside the larger commit-change
    // UTXO on the next submit, consolidating the dust naturally.
    const revealChangeIdx = composed.reveal.output_info.findIndex(
      (info) => typeof info === "object" && "Change" in info,
    );
    if (revealChangeIdx >= 0) {
      const info = composed.reveal.output_info[revealChangeIdx]!;
      if (typeof info === "object" && "Change" in info) {
        change.push({
          txid: composed.reveal.txid,
          vout: revealChangeIdx,
          value: BigInt(info.Change.value),
          scriptPubKey: ownScriptPubKey,
        });
      }
    }

    let consumed = 0;
    if (commitHexes.length === 0) {
      // No commits — `suppliedUtxos` went straight into the reveal as
      // `extra_inputs`, every one consumed.
      consumed = suppliedUtxos.length;
    } else {
      for (let i = 0; i < commitHexes.length; i++) {
        const meta = composed.commits[i]!;
        const commitTx = Transaction.fromRaw(hex.decode(commitHexes[i]!), {
          disableScriptCheck: true,
          allowUnknownOutputs: true,
          allowUnknownInputs: true,
        });
        consumed += commitTx.inputsLength;
        if (meta.change_value != null) {
          change.push({
            txid: meta.txid,
            vout: 1,
            value: BigInt(meta.change_value),
            scriptPubKey: ownScriptPubKey,
          });
        }
      }
    }

    return { spent: suppliedUtxos.slice(0, consumed), change };
  }

  /**
   * Relay already-signed raw transactions to the network, in dependency
   * order, as one package. The attach/detach runtime composes and signs
   * its commit/reveal txs by hand, then hands the finished package here.
   */
  broadcast(transactions: string[]): Promise<BroadcastResult> {
    return this.postJson<BroadcastResult>("/transactions/broadcast", {
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
    const funding = this.funding();
    const taken = await funding.take();
    try {
      const reveal = await this.buildSimpleReveal(insts, taken);
      const { revealTx } = await this.composeAndSign(reveal);
      const ops = await this.postJson<OpWithResult[]>("/transactions/inspect", {
        hex: hex.encode(revealTx.extract()),
      });
      return ops.map(opWithResultToRaw);
    } finally {
      funding.release(taken);
    }
  }

  /**
   * Sandboxed live execution — runs the composed reveal's ops against
   * current chain state in a throwaway tx, returning predicted per-Inst
   * outcomes (real gas, real results) without broadcasting. Like
   * `inspect`, it `release()`s its funding (nothing is spent).
   */
  async simulate(insts: WireInsts): Promise<OpResultRaw[]> {
    const funding = this.funding();
    const taken = await funding.take();
    try {
      const reveal = await this.buildSimpleReveal(insts, taken);
      const { revealTx } = await this.composeAndSign(reveal);
      const ops = await this.postJson<OpWithResult[]>(
        "/transactions/simulate",
        { hex: hex.encode(revealTx.extract()) },
      );
      return ops.map(opWithResultToRaw);
    } finally {
      funding.release(taken);
    }
  }
}

/**
 * Map an indexer `OpWithResult` (from inspect / simulate) to the
 * transport's `OpResultRaw`. Three cases: a rejected op (didn't
 * materialize), a materialized + executed op (simulate — carries a
 * result row), and a materialized-only op (inspect — parsed, not run).
 */
function opWithResultToRaw(o: OpWithResult): OpResultRaw {
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
