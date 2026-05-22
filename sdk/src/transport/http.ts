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
import { TaprootControlBlock, Transaction, utils as btcUtils } from "@scure/btc-signer";

import type { Account } from "../account/index.js";
import type { Chain } from "../chains.js";
import type { ContractAddress } from "../canonical/ContractAddress.js";
import { ChainError, ContractError, SignerError, TransportError } from "../errors.js";
import type {
  BroadcastResult,
  KontorTransport,
  OpResultRaw,
  WireInsts,
} from "../json-codec.js";
import type {
  ComposeOutputs,
  ComposeQuery,
  ErrorResponse,
  OpWithResult,
  ParticipantScripts,
  ResultResponse,
  RevealOutputs,
  RevealQuery,
  ViewExpr,
  ViewResult,
} from "../bindings.js";

export interface Utxo {
  txid: string;
  vout: number;
  /** Value in satoshis. */
  value: bigint;
  /** ScriptPubKey hex (for PSBT input building). */
  scriptPubKey: string;
}

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
   * Compose a Kontor transaction for `insts` — commit + (attach) reveal,
   * unsigned. `chainedInsts` carries a detach to chain after. Funding
   * UTXOs and fee rate are caller-supplied (`utxos` / `feeRate`).
   */
  async compose(
    insts: WireInsts,
    chainedInsts?: WireInsts,
  ): Promise<ComposeOutputs> {
    const { account } = this.opts;
    const utxos = await this.resolveUtxos();
    const query: ComposeQuery = {
      instructions: [
        {
          address: account.address,
          x_only_public_key: account.xOnlyPubKey,
          funding_utxo_ids: utxos.map((u) => `${u.txid}:${u.vout}`).join(","),
          insts,
          chained_insts: chainedInsts ?? null,
        },
      ],
      sat_per_vbyte: await this.resolveFeeRate(),
      envelope: null,
    };
    return this.postJson<ComposeOutputs>("/transactions/compose", query);
  }

  /** Build a reveal tx (e.g. the detach reveal) from a composed parent. */
  composeReveal(query: RevealQuery): Promise<RevealOutputs> {
    return this.postJson<RevealOutputs>(
      "/transactions/compose/reveal",
      query,
    );
  }

  /**
   * Compose a Kontor transaction for `insts` and sign the commit +
   * reveal — the shared front half of `submit` / `inspect` / `simulate`.
   */
  private async composeAndSign(
    insts: WireInsts,
  ): Promise<{ commitHex: string; revealHex: string }> {
    const composed = await this.compose(insts);
    return {
      commitHex: await this.signCommit(composed.commit_psbt_hex),
      revealHex: await this.signReveal(
        composed.reveal_psbt_hex,
        composed.per_participant,
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
    return this.postJson<BroadcastResult>("/transactions/broadcast", {
      transactions: [commitHex, revealHex],
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
  private async resolveUtxos(): Promise<Utxo[]> {
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
  private async resolveFeeRate(): Promise<number | null> {
    const f = this.opts.feeRate;
    if (f == null) return null;
    return typeof f === "number" ? f : await f();
  }

  /**
   * Sign the commit PSBT — a taproot key-path spend — and return the
   * finalized raw transaction hex.
   */
  private async signCommit(psbtHex: string): Promise<string> {
    const signed = await this.opts.account.signPsbt(hex.decode(psbtHex));
    const tx = Transaction.fromPSBT(signed);
    tx.finalize();
    return hex.encode(tx.extract());
  }

  /**
   * Sign the reveal PSBT — a taproot script-path spend. The compose
   * response carries each input's tap-leaf script separately; it must be
   * injected into the PSBT before signing, and the witness assembled by
   * hand afterwards (the Kontor reveal leaf is non-standard, so
   * `@scure/btc-signer`'s `finalize()` can't build it).
   */
  private async signReveal(
    psbtHex: string,
    participants: ParticipantScripts[],
  ): Promise<string> {
    // Prepare: inject each input's leaf script + control block.
    const prep = Transaction.fromPSBT(hex.decode(psbtHex));
    participants.forEach((p, i) => {
      const leaf = p.commit_tap_leaf_script;
      const scriptWithVersion = btcUtils.concatBytes(
        hex.decode(leaf.script),
        new Uint8Array([leaf.leafVersion]),
      );
      const controlBlock = TaprootControlBlock.decode(
        hex.decode(leaf.controlBlock),
      );
      prep.updateInput(i, { tapLeafScript: [[controlBlock, scriptWithVersion]] }, true);
    });

    const signed = await this.opts.account.signPsbt(prep.toPSBT());

    // Finalize by hand: witness = [schnorr sig, leaf script, control block].
    const tx = Transaction.fromPSBT(signed);
    participants.forEach((p, i) => {
      const sig = tx.getInput(i).tapScriptSig?.[0]?.[1];
      if (sig == null) {
        throw new SignerError(
          `submit: reveal input ${i} was not signed by the account`,
          { docsPath: "/sdk/transport" },
        );
      }
      const leaf = p.commit_tap_leaf_script;
      tx.updateInput(i, {
        finalScriptWitness: [
          sig,
          hex.decode(leaf.script),
          hex.decode(leaf.controlBlock),
        ],
      });
    });
    return hex.encode(tx.extract());
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
 *     const transport = http({ chain: signet, account });
 */
export function http(opts: HttpTransportOptions): HttpTransport {
  return new HttpTransport(opts);
}
