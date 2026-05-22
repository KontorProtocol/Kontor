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
 *   - `submit(insts)`          — compose, sign via the session's
 *                                account, broadcast via Bitcoin RPC,
 *                                poll the indexer until the tx lands
 *                                and per-Inst results are available.
 *
 * Each tx-composition step is overridable through `HttpTransportOptions`
 * — power users can swap UTXO selection, fee estimation, or wait
 * policy. Defaults are sane for the common case.
 *
 * The transport is contract-agnostic: it submits whatever Insts the
 * Session hands it. Per-Inst contract addresses live inside the
 * `WireInsts` payload.
 */

import type { Account } from "../account/index.js";
import type { Chain } from "../chains.js";
import type { ContractAddress } from "../canonical/ContractAddress.js";
import { ContractError, TransportError } from "../errors.js";
import type {
  BroadcastResult,
  KontorTransport,
  OpResultRaw,
  WireInsts,
} from "../json-codec.js";
import type {
  ErrorResponse,
  ResultResponse,
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
      `/contracts/${contractPath(contract)}`,
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

  inspect(_insts: WireInsts): Promise<OpResultRaw[]> {
    throw new TransportError("HttpTransport.inspect: not implemented", {
      docsPath: "/sdk/transport",
    });
  }

  simulate(_insts: WireInsts): Promise<OpResultRaw[]> {
    throw new TransportError("HttpTransport.simulate: not implemented", {
      docsPath: "/sdk/transport",
    });
  }

  submit(_insts: WireInsts): Promise<BroadcastResult> {
    throw new TransportError("HttpTransport.submit: not implemented", {
      docsPath: "/sdk/transport",
    });
  }
}

/**
 * The indexer's URL form for a contract address: `name_height_txIndex`
 * — Kontor's `ContractAddress` `Display`. Distinct from the SDK's
 * `toString()` (`name@height.txIndex`), which is the human/parse form.
 */
function contractPath(c: ContractAddress): string {
  return `${c.name}_${c.height}_${c.txIndex}`;
}

/**
 * Convenience factory mirroring Viem's `http()` style:
 *
 *     const transport = http({ chain: signet, account });
 */
export function http(opts: HttpTransportOptions): HttpTransport {
  return new HttpTransport(opts);
}
