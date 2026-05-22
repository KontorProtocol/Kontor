/**
 * `KontorTransport` is the chain-side I/O surface consumed by
 * `KontorSession`. Four operations — three on instruction bundles plus
 * one for view-context queries:
 *
 *   - `view(contract, wave)`   — read-only query against a `view-context`
 *                                function. Single contract, single wave
 *                                expression. Returns the WAVE-encoded
 *                                result.
 *
 *   - `inspect(insts)`         — static analysis on a wire-Insts bundle.
 *                                No execution against state, just "what
 *                                does Kontor see in this bundle?"
 *                                Cheap, useful for previews.
 *
 *   - `simulate(insts)`        — sandboxed live execution. Runs the
 *                                ops against current chain state in a
 *                                throwaway transaction. Returns real
 *                                predicted per-Inst outcomes including
 *                                gas used.
 *
 *   - `submit(insts)`          — for-real broadcast. Composes the
 *                                Bitcoin tx, signs via the session's
 *                                account, submits, waits for indexer
 *                                inclusion, returns per-Inst outcomes.
 *
 * For inspect/simulate/submit the transport is responsible for any tx
 * composition — callers (Session, Inst, Insts) stay at the Insts
 * level. The indexer's underlying endpoints take Bitcoin tx hex; the
 * HttpTransport hides that.
 *
 * `WireInst` / `WireInsts` are aliases for the auto-generated wire
 * types in `bindings.d.ts` — the names collide with the SDK-level
 * `Inst<T>` / `Insts<T>` classes (rich PromiseLike wrappers with
 * decoders), so the wire shapes get the `Wire` prefix wherever they
 * appear together.
 */
import type { ContractAddress } from "./canonical/ContractAddress.js";
import type {
  ComposeOutputs,
  Inst as WireInst,
  Insts as WireInsts,
  OpStatus,
  RevealOutputs,
  RevealQuery,
} from "./bindings.js";

export type { WireInst, WireInsts, OpStatus };

/**
 * Per-Inst outcome as the transport layer surfaces it: the WAVE-encoded
 * result string (decoded by the SDK layer into the user's typed value)
 * plus telemetry (`status`, `gas`, optional `error`). `value` is absent
 * on failed ops or when the function has no return type.
 */
export interface OpResultRaw {
  status: OpStatus;
  gas: bigint;
  error?: string;
  /** WAVE-encoded result. Absent on non-Ok status / void-return Insts. */
  value?: string;
  /** The function this op invoked (e.g. `transfer`). */
  func: string;
  /** Contract the op ran on, wire form (`name_height_txIndex`). */
  contract: string;
  /**
   * The op's position in the broadcast tx — Bitcoin input index and
   * op index within that input. For a single-Inst `submit` the user's
   * op is `(0, 0)`; `wait()` selects on these.
   */
  inputIndex: number | null;
  opIndex: number | null;
}

/**
 * Per-Inst outcome at the SDK level: same shape as `OpResultRaw` but
 * the `value` field is the typed value, produced by the Inst's
 * decoder. Returned by `inst.submit()` / `.simulate()` / `.inspect()`
 * for callers who want telemetry; `await inst` returns the unwrapped
 * `T` and throws on non-Ok status.
 */
export interface OpResult<T> {
  status: OpStatus;
  gas: bigint;
  error?: string;
  value?: T;
}

/** Result of broadcasting a tx — just the txid. The per-Inst outcomes
 * are surfaced later, asynchronously, by the session's results poller
 * (the tx may take minutes to land). Keeping `submit` broadcast-only
 * is what makes the submit/wait split possible at the SDK level. */
export interface BroadcastResult {
  txid: string;
}

export interface KontorTransport {
  /**
   * View-context call. The indexer runs `wave` against `contract`
   * with no state mutation and returns the WAVE-encoded result.
   * Not bundled, not signed, not broadcast — just an RPC.
   */
  view(contract: ContractAddress, wave: string): Promise<string>;

  /**
   * Static analysis on a wire-Insts bundle. Does not execute against
   * chain state — just parses what Kontor would extract. Returns
   * per-Inst outcomes directly (no broadcast, synchronous).
   */
  inspect(insts: WireInsts): Promise<OpResultRaw[]>;

  /**
   * Sandboxed live execution. Runs the bundle's ops against current
   * chain state in a throwaway transaction and returns real predicted
   * outcomes directly (no broadcast). More expensive than `inspect`
   * but accurate.
   */
  simulate(insts: WireInsts): Promise<OpResultRaw[]>;

  /**
   * For-real broadcast. Composes the Bitcoin tx, signs via the
   * session's account, broadcasts to the mempool, and returns the
   * txid. Does NOT wait for inclusion — per-Inst outcomes are
   * resolved later by the session's results poller. This keeps
   * `submit` fast and lets callers see the txid before the tx lands.
   */
  submit(insts: WireInsts): Promise<BroadcastResult>;

  /**
   * Compose a Kontor transaction — the commit + the (attach) reveal —
   * unsigned. `chainedInsts`, when given, carries a detach to chain
   * after: it sizes the commit to fund the detach and returns the
   * detach's tap-leaf script. Used by the attach/detach runtime; the
   * detach reveal itself is built later via `composeReveal`.
   */
  compose(insts: WireInsts, chainedInsts?: WireInsts): Promise<ComposeOutputs>;

  /**
   * Build a reveal transaction from an already-composed parent — e.g.
   * the detach reveal, which spends the attach reveal's escrow output.
   * The `RevealQuery` is assembled by the caller (the attach/detach
   * runtime), since its content depends on who is detaching and where.
   */
  composeReveal(query: RevealQuery): Promise<RevealOutputs>;

  /**
   * Broadcast already-signed raw transactions — in dependency order
   * (commit, reveal, …) — as one package. Used by the attach/detach
   * runtime, which builds and signs its txs by hand rather than going
   * through `submit`.
   */
  broadcast(transactions: string[]): Promise<BroadcastResult>;
}
