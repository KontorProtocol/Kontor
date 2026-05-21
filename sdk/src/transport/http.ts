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
import { TransportError } from "../errors.js";
import type {
  BroadcastResult,
  KontorTransport,
  OpResultRaw,
  WireInsts,
} from "../json-codec.js";

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
  constructor(private readonly opts: HttpTransportOptions) {}

  view(_contract: ContractAddress, _wave: string): Promise<string> {
    throw new TransportError("HttpTransport.view: not implemented", {
      docsPath: "/sdk/transport",
    });
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
 * Convenience factory mirroring Viem's `http()` style:
 *
 *     const transport = http({ chain: signet, account });
 */
export function http(opts: HttpTransportOptions): HttpTransport {
  return new HttpTransport(opts);
}
