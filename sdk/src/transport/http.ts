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
  ComposeOutputs,
  ErrorResponse,
  OpWithResult,
  ResultResponse,
  Reveal,
  ViewExpr,
  ViewResult,
} from "../bindings.js";

/** "txid:vout" outpoint key — the unit we dedupe / filter UTXOs by. */
const keyOf = (u: { txid: string; vout: number }): string =>
  `${u.txid}:${u.vout}`;

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
   * Funding source for submits. Two modes, picked by the value's shape:
   *
   *   - `Utxo[]` — bootstrap-once. Used on the first submit only;
   *     afterwards `trackedFunding` (the change outputs of the prior
   *     submit) takes over. The array is never consulted again.
   *
   *   - `() => Promise<Utxo[]>` — wallet-managed. Called on every
   *     submit. The SDK auto-filters outpoints it just spent (so a
   *     stale wallet view that still reports them won't double-spend),
   *     but otherwise the callback's return value drives funding.
   *     Tracking via `trackedFunding` is bypassed in this mode.
   */
  utxos?: Utxo[] | (() => Promise<Utxo[]>);
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
  /**
   * Change UTXOs from the most recent successful submit. In array
   * (bootstrap) mode, after submit 1 this takes over and is the sole
   * funding source thereafter. In callback mode it's not used — the
   * callback is consulted every submit.
   *
   * `null` = no submit landed yet (or last broadcast failed); fall back
   * to `opts.utxos`.
   */
  private trackedFunding: Utxo[] | null = null;
  /**
   * Outpoints this transport has spent in successful broadcasts so far.
   * Consulted only in callback mode — a stale wallet that still reports
   * a spent UTXO gets it filtered out before compose sees it. The set
   * grows for the transport's lifetime; entries are tiny (a string per
   * outpoint), so we don't bother with expiry. `clearTracking()` wipes
   * it if the user wants a clean slate (e.g. an externally-broadcast
   * sweep mooted the prior state).
   */
  private recentlySpent: Set<string> = new Set();

  constructor(private readonly opts: HttpTransportOptions) {
    this.baseUrl = (opts.url ?? opts.chain.urls.http).replace(/\/+$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Inject additional UTXOs into the tracked pool (array/bootstrap
   * mode). Useful when fresh funding arrives mid-session — e.g. the
   * user received a payment outside the SDK and wants the next submit
   * to see it. Outpoints already in `recentlySpent` are dropped on
   * the way in. No-op in callback mode (the callback owns funding).
   */
  addUtxos(more: Utxo[]): void {
    if (typeof this.opts.utxos === "function") return;
    const fresh = more.filter((u) => !this.recentlySpent.has(keyOf(u)));
    if (fresh.length === 0) return;
    const existing = this.trackedFunding ?? [];
    const have = new Set(existing.map(keyOf));
    const add = fresh.filter((u) => !have.has(keyOf(u)));
    this.trackedFunding = [...existing, ...add];
  }

  /**
   * Wipe all transport-side funding state — `trackedFunding` and
   * `recentlySpent`. After this, behavior reverts to the bootstrap
   * state: array form re-reads `opts.utxos` on the next submit;
   * callback form's filter is empty. Call this if external action
   * (e.g. a manual sweep tx) has rendered the tracked state stale.
   */
  clearTracking(): void {
    this.trackedFunding = null;
    this.recentlySpent.clear();
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
    const { account } = this.opts;
    const composed = await this.compose(reveal);
    const commitHexes = await Promise.all(
      composed.commits.map((c) => signCommit(account, c.psbt_hex)),
    );
    return {
      commitHexes,
      revealTx: await signReveal(account, composed.reveal.psbt_hex),
      composed,
    };
  }

  /** Build the simple single-Build-participant Reveal used by `submit`,
   *  `inspect`, and `simulate`. The account funds + signs the commit;
   *  the reveal's paired output is Change back to the account. */
  private async buildSimpleReveal(
    insts: WireInsts,
    utxos: Utxo[],
  ): Promise<Reveal> {
    const { account } = this.opts;
    const scriptPubKeyHex = hex.encode(
      p2tr(hex.decode(account.xOnlyPubKey), undefined, this.opts.chain.network).script,
    );
    return {
      sat_per_vbyte: this.opts.feeRate ?? null,
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
  async submit(insts: WireInsts): Promise<BroadcastResult> {
    const { result } = await this.submitReveal(async (utxos) => {
      const reveal = await this.buildSimpleReveal(insts, utxos);
      return this.composeAndSign(reveal);
    });
    return result;
  }

  /**
   * The only blessed broadcast path for funding-state-mutating txs.
   * See `KontorTransport.submitReveal` for the full contract.
   *
   * Body runs under the account's `runExclusive` for the entire
   * critical section: read `utxos()` consistently, hand them to the
   * `prepare` callback to shape the Reveal + compose+sign (and inject
   * any foreign reveal witness), then extract → broadcast →
   * `advanceTracking` — all before the lock is released. Two
   * concurrent callers — even on separate transports binding the same
   * Account — serialize.
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
    return this.opts.account.runExclusive(async () => {
      const utxos = await this.utxos();
      const { commitHexes, revealTx, composed } = await prepare(utxos);
      const revealHex = hex.encode(revealTx.extract());
      const result = await this.broadcast([...commitHexes, revealHex]);
      this.advanceTracking({
        suppliedUtxos: utxos,
        composed,
        commitHexes,
        revealHex,
      });
      return { result, commitHexes, revealHex, composed };
    });
  }

  /**
   * Update internal funding tracking after a commit/reveal package
   * has been broadcast. The commit consumes a prefix of
   * `suppliedUtxos` (length = `commitTx.inputsLength` — the indexer
   * greedily picks from the head of the list); those go into
   * `recentlySpent` so they don't resurface from `utxos()`, and the
   * package's change outputs become `trackedFunding`.
   *
   * Called automatically by `submit`. Called by `attach.ts`'s offer
   * build after it broadcasts the attach. Implements the
   * `KontorTransport.advanceTracking` interface.
   */
  advanceTracking(opts: {
    suppliedUtxos: Utxo[];
    composed: ComposeOutputs;
    commitHexes: string[];
    revealHex: string;
  }): void {
    const { suppliedUtxos, commitHexes, composed } = opts;
    if (commitHexes.length === 0) {
      // No commits — `suppliedUtxos` went straight into the reveal as
      // `extra_inputs`, every one consumed.
      for (const u of suppliedUtxos) this.recentlySpent.add(keyOf(u));
    } else {
      // Each commit consumes a prefix of `suppliedUtxos` chosen by the
      // indexer's greedy selector. Walk commits in order, peeling
      // `inputsLength` UTXOs off the front per commit.
      let offset = 0;
      for (const commitHex of commitHexes) {
        const commitTx = Transaction.fromRaw(hex.decode(commitHex), {
          disableScriptCheck: true,
          allowUnknownOutputs: true,
          allowUnknownInputs: true,
        });
        const used = suppliedUtxos.slice(offset, offset + commitTx.inputsLength);
        for (const u of used) this.recentlySpent.add(keyOf(u));
        offset += commitTx.inputsLength;
      }
    }
    const accountScriptPubKey = hex.encode(
      p2tr(
        hex.decode(this.opts.account.xOnlyPubKey),
        undefined,
        this.opts.chain.network,
      ).script,
    );
    this.trackedFunding = extractChangeUtxos(composed, accountScriptPubKey);
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
   *
   * Held under the account's lock so concurrent submit / submitReveal
   * can't shift the funding pool out from under us mid-compose.
   * Doesn't broadcast, doesn't advance tracking — the next real
   * submit reuses the same UTXOs.
   */
  async inspect(insts: WireInsts): Promise<OpResultRaw[]> {
    return this.opts.account.runExclusive(async () => {
      const utxos = await this.utxos();
      const reveal = await this.buildSimpleReveal(insts, utxos);
      const { revealTx } = await this.composeAndSign(reveal);
      const ops = await this.postJson<OpWithResult[]>(
        "/transactions/inspect",
        { hex: hex.encode(revealTx.extract()) },
      );
      return ops.map(opWithResultToRaw);
    });
  }

  /**
   * Sandboxed live execution — runs the composed reveal's ops against
   * current chain state in a throwaway tx, returning predicted per-Inst
   * outcomes (real gas, real results) without broadcasting.
   *
   * Held under the account's lock for the same reason as `inspect`:
   * read a consistent funding snapshot, no interleave with submitReveal.
   */
  async simulate(insts: WireInsts): Promise<OpResultRaw[]> {
    return this.opts.account.runExclusive(async () => {
      const utxos = await this.utxos();
      const reveal = await this.buildSimpleReveal(insts, utxos);
      const { revealTx } = await this.composeAndSign(reveal);
      const ops = await this.postJson<OpWithResult[]>(
        "/transactions/simulate",
        { hex: hex.encode(revealTx.extract()) },
      );
      return ops.map(opWithResultToRaw);
    });
  }

  /**
   * Funding UTXOs for the next submit. Two paths, by `opts.utxos` shape:
   *
   *   - Array (bootstrap-once): use `trackedFunding` if it's set
   *     (post-submit), otherwise the bootstrap array.
   *   - Callback (wallet-managed): always call the callback; filter
   *     out any outpoints we know we've already spent.
   *
   * Inputs are returned in funding-priority order. The indexer's
   * `select_utxos_for_commit` walks the list greedily and stops once it
   * has enough, so ordering here drives selection — dust (reveal
   * Change, 330) lives at the head of `trackedFunding` for consolidation.
   *
   * Public because the attach/detach runtime composes its own reveals
   * outside of `submit` and needs the same funding source.
   */
  async utxos(): Promise<Utxo[]> {
    if (Array.isArray(this.opts.utxos)) {
      const list = this.trackedFunding ?? this.opts.utxos;
      if (list.length === 0) {
        throw new ChainError("submit: bootstrap utxos array is empty", {
          docsPath: "/sdk/transport",
        });
      }
      return list;
    }
    if (typeof this.opts.utxos === "function") {
      const supplied = await this.opts.utxos();
      const fresh = supplied.filter((u) => !this.recentlySpent.has(keyOf(u)));
      if (fresh.length === 0) {
        throw new ChainError(
          "submit: utxos() returned no unspent UTXOs (after filtering recently-spent)",
          { docsPath: "/sdk/transport" },
        );
      }
      return fresh;
    }
    throw new ChainError(
      "submit: no funding UTXOs — set a `utxos` source on the transport",
      { docsPath: "/sdk/transport" },
    );
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

/**
 * Extract the change UTXOs from a just-broadcast commit-reveal pair.
 * The indexer's `compose` response carries everything we need
 * structurally: each commit's `txid` + `change_value`, and each
 * reveal output's value embedded in its `output_info` variant. So
 * this is pure record assembly — no tx-hex parsing.
 *
 * Both change outputs pay the account's P2TR scriptPubKey by
 * construction (commit-change to the Build's address, reveal-Change
 * to the script the SDK passed in the Reveal request — both this
 * account), so we derive the scriptPubKey once from the account.
 *
 * Order matters: the reveal's Change is the 330-sat minimum-envelope
 * dust buffer, so we put it FIRST so the indexer's greedy
 * `select_utxos_for_commit` pulls it in alongside the larger
 * commit-change UTXO on the next submit, consolidating the dust
 * naturally rather than letting it accumulate.
 */
function extractChangeUtxos(
  composed: ComposeOutputs,
  accountScriptPubKey: string,
): Utxo[] {
  const out: Utxo[] = [];

  // Reveal tx: scan output_info for the Change variant.
  const revealChangeIdx = composed.reveal.output_info.findIndex(
    (info) => typeof info === "object" && "Change" in info,
  );
  if (revealChangeIdx >= 0) {
    const info = composed.reveal.output_info[revealChangeIdx]!;
    if (typeof info === "object" && "Change" in info) {
      out.push({
        txid: composed.reveal.txid,
        vout: revealChangeIdx,
        value: BigInt(info.Change.value),
        scriptPubKey: accountScriptPubKey,
      });
    }
  }

  // Commit tx: vout 0 is the tap output (consumed by the reveal we
  // just broadcast); vout 1 is change, present only when the leftover
  // after fees cleared the dust floor (signaled by non-null
  // `change_value`).
  const commit = composed.commits[0];
  if (commit != null && commit.change_value != null) {
    out.push({
      txid: commit.txid,
      vout: 1,
      value: BigInt(commit.change_value),
      scriptPubKey: accountScriptPubKey,
    });
  }

  return out;
}
