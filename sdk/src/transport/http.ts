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
import { p2tr } from "@scure/btc-signer";

import type { Account } from "../account/index.js";
import type { Chain } from "../chains.js";
import type { ContractAddress } from "../canonical/ContractAddress.js";
import { ChainError, ContractError, TransportError } from "../errors.js";
import { signCommit, signReveal } from "./signing.js";
import type {
  BroadcastResult,
  KontorTransport,
  OpResultRaw,
  Utxo,
  WireInsts,
} from "../json-codec.js";
import type {
  CommitOutputs,
  ComposeOutputs,
  ErrorResponse,
  OpWithResult,
  ResultResponse,
  Reveal,
  RevealOutputs,
  ViewExpr,
  ViewResult,
} from "../bindings.js";

export interface HttpTransportOptions {
  chain: Chain;
  account: Account;

  /** Override the chain's HTTP endpoint. */
  url?: string;
  /** Custom fetch impl (testing, custom auth headers). */
  fetch?: typeof fetch;
  /** Static headers attached to every HTTP request. */
  headers?: Record<string, string>;

  /**
   * Override automatic UTXO selection. Default: fetch the account's
   * spendable UTXOs from the indexer and pick enough to cover the tx.
   */
  utxos?: () => Promise<Utxo[]>;
  /**
   * Override automatic fee estimation. Number = fixed sats/vB; function
   * = called per-submit. Default: read from a mempool feerate endpoint.
   */
  feeRate?: number | (() => Promise<number>);
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
        body: JSON.stringify(body, bigIntReplacer),
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
   * Builds only the commits for Build participants and returns the
   * input Reveal with each Build → Existing (outpoint filled in).
   * Caller signs/broadcasts the commits, then later passes the
   * returned reveal to `composeReveal`.
   */
  composeCommit(reveal: Reveal): Promise<CommitOutputs> {
    return this.postJson<CommitOutputs>("/transactions/compose/commit", reveal);
  }

  /**
   * Builds only the reveal PSBT. All participants must be
   * CommitSource::Existing (no commits to build here).
   */
  composeReveal(reveal: Reveal): Promise<RevealOutputs> {
    return this.postJson<RevealOutputs>("/transactions/compose/reveal", reveal);
  }

  /**
   * Compose a Kontor transaction for `insts` and sign the commit +
   * reveal — the shared front half of `submit` / `inspect` / `simulate`.
   *
   * Builds a single-Build-participant Reveal: the account funds and
   * signs the commit, the commit's tap-leaf output is script-spent in
   * the reveal whose paired output is Change back to the account.
   */
  private async composeAndSign(
    insts: WireInsts,
  ): Promise<{ commitHex: string; revealHex: string }> {
    const { account } = this.opts;
    const utxos = await this.utxos();
    const scriptPubKeyHex = hex.encode(
      p2tr(hex.decode(account.xOnlyPubKey), undefined, this.opts.chain.network).script,
    );
    const reveal: Reveal = {
      sat_per_vbyte: await this.feeRate(),
      participants: [
        {
          x_only_public_key: account.xOnlyPubKey,
          commit_insts: insts,
          output: { Change: { script_pubkey: scriptPubKeyHex } },
          commit_source: {
            Build: {
              address: account.address,
              funding_utxo_ids: utxos.map((u) => `${u.txid}:${u.vout}`),
            },
          },
        },
      ],
      extra_inputs: [],
      extra_outputs: [],
    };
    const composed = await this.compose(reveal);
    return {
      commitHex: await signCommit(account, composed.commits[0]!.psbt_hex),
      revealHex: await signReveal(
        account,
        composed.reveal.psbt_hex,
        composed.reveal.commit_tap_leaf_scripts,
      ),
    };
  }

  /**
   * Compose, sign, and broadcast `insts` through the indexer. Returns
   * the reveal txid; per-Inst results are resolved later by the
   * session's poller.
   */
  async submit(insts: WireInsts): Promise<BroadcastResult> {
    const { commitHex, revealHex } = await this.composeAndSign(insts);
    return this.broadcast([commitHex, revealHex]);
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
   * non-Ok `OpResultRaw` carrying its error.
   */
  async inspect(insts: WireInsts): Promise<OpResultRaw[]> {
    const { revealHex } = await this.composeAndSign(insts);
    const ops = await this.postJson<OpWithResult[]>(
      "/transactions/inspect",
      { hex: revealHex },
    );
    return ops.map(opWithResultToRaw);
  }

  /**
   * Sandboxed live execution — runs the composed reveal's ops against
   * current chain state in a throwaway tx, returning predicted per-Inst
   * outcomes (real gas, real results) without broadcasting.
   */
  async simulate(insts: WireInsts): Promise<OpResultRaw[]> {
    const { revealHex } = await this.composeAndSign(insts);
    const ops = await this.postJson<OpWithResult[]>(
      "/transactions/simulate",
      { hex: revealHex },
    );
    return ops.map(opWithResultToRaw);
  }

  /** Caller-supplied funding UTXOs; the SDK never sources them itself. */
  async utxos(): Promise<Utxo[]> {
    if (this.opts.utxos == null) {
      throw new ChainError(
        "submit: no funding UTXOs — set a `utxos` provider on the transport",
        { docsPath: "/sdk/transport" },
      );
    }
    const utxos = await this.opts.utxos();
    if (utxos.length === 0) {
      throw new ChainError("submit: the `utxos` provider returned none", {
        docsPath: "/sdk/transport",
      });
    }
    return utxos;
  }

  /** Fee rate in sat/vB, or `null` to let the indexer pick `fastest_fee`. */
  async feeRate(): Promise<number | null> {
    const f = this.opts.feeRate;
    if (f == null) return null;
    return typeof f === "number" ? f : await f();
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
 * `JSON.stringify` replacer that serializes `bigint` as a plain JSON
 * number. ts-rs maps Rust `u64` to TS `bigint` for precision, but the
 * wire is a JSON number — bitcoind/indexer sat amounts fit comfortably
 * inside `Number.MAX_SAFE_INTEGER` (2^53 ≈ 9e15, vs total BTC supply
 * 2.1e15 sats), so the round-trip is lossless. Errors on values
 * outside that range.
 */
function bigIntReplacer(_key: string, value: unknown): unknown {
  if (typeof value !== "bigint") return value;
  if (
    value > BigInt(Number.MAX_SAFE_INTEGER) ||
    value < BigInt(Number.MIN_SAFE_INTEGER)
  ) {
    throw new TypeError(
      `cannot serialize bigint ${value} as JSON number (outside safe integer range)`,
    );
  }
  return Number(value);
}

/**
 * Convenience factory mirroring Viem's `http()` style:
 *
 *     const transport = http({ chain: signet, account });
 */
export function http(opts: HttpTransportOptions): HttpTransport {
  return new HttpTransport(opts);
}
