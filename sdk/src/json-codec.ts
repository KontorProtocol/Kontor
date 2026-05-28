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
import type { Transaction } from "@scure/btc-signer";

import type { ContractAddress } from "./canonical/ContractAddress.js";
import type {
  ComposeOutputs,
  Inst as WireInst,
  Insts as WireInsts,
  OpStatus,
  Reveal,
  SignerResponse,
} from "./bindings.js";

export type { WireInst, WireInsts, OpStatus };

/**
 * A funding UTXO a Build participant can spend in its commit tx. Higher-
 * level flows fetch these via `KontorTransport.utxos()` and feed them
 * into `CommitSource.Build.funding_utxo_ids`.
 */
export interface Utxo {
  txid: string;
  vout: number;
  /** Value in satoshis. */
  value: bigint;
  /** ScriptPubKey hex (for PSBT input building). */
  scriptPubKey: string;
}

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
   * Look up a signer by `identifier` — numeric `signer_id`, 64-char
   * x-only pubkey hex, or 192-char BLS pubkey hex. Returns the
   * registry row (`signer_id`, `x_only_pubkey`, `bls_pubkey`,
   * `next_nonce`). `null` when no row exists. Used by the aggregate
   * flow to source the contributor's current `next_nonce`.
   */
  signer(identifier: string): Promise<SignerResponse | null>;

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
   * Caller-supplied funding UTXOs for `Build` participants whose source
   * comes from this transport's account. Higher-level flows (attach,
   * marketplace) call this when constructing a `Reveal` so they can
   * populate `CommitSource::Build.funding_utxo_ids` without each call
   * site implementing UTXO selection itself.
   */
  utxos(): Promise<Utxo[]>;

  /**
   * Combined compose: build any commits required by Build participants,
   * then build the reveal PSBT. All-Existing Reveals skip commit building.
   * Used by the attach/detach runtime to assemble the full commit/reveal
   * package in one call.
   */
  compose(reveal: Reveal): Promise<ComposeOutputs>;

  /**
   * Broadcast already-signed raw transactions — in dependency order
   * (commit, reveal, …) — as one package. Used by the attach/detach
   * runtime, which builds its txs (e.g. the seller's pre-signed detach
   * PSBT, the buyer's swap reveal) outside the generic `submit` path.
   */
  broadcast(transactions: string[]): Promise<BroadcastResult>;

  /**
   * Compose a Reveal and sign all participant inputs that belong to
   * this transport's account, returning the prepared package. Pure:
   * does NOT broadcast and does NOT update funding tracking. Callers
   * that will broadcast (now or later) should also call
   * `advanceTracking` so subsequent `utxos()` reflects the spent
   * inputs + change outputs.
   *
   * `submit` is the simple-Reveal shorthand (single Build participant
   * with Change). Higher-level flows (attach: ChainedEnvelope +
   * Change; marketplace: multi-participant) build their own Reveal
   * and route through this.
   *
   * Returns the reveal as a parsed `Transaction` (NOT an extracted-tx
   * hex) because only inputs owned by this transport's account are
   * finalized — foreign inputs (e.g. a seller's pre-signed escrow on
   * a marketplace swap) are left untouched for the caller to fill in
   * before extracting. Common single-owner callers do
   * `hex.encode(revealTx.extract())` immediately; mixed-signer
   * callers inject the foreign witness first.
   */
  composeAndSign(reveal: Reveal): Promise<{
    commitHexes: string[];
    revealTx: Transaction;
    composed: ComposeOutputs;
  }>;

  /**
   * The only blessed broadcast path for funding-state-mutating txs.
   * Holds the account's lock for the full body, so two concurrent
   * callers — even on separate transports binding the same Account
   * — serialize naturally. No race on `utxos()`, the broadcast, or
   * the tracking update.
   *
   * The `prepare` callback runs *inside* the lock with a consistent
   * snapshot of `utxos()`. It owns the Reveal shape, the
   * compose+sign work (via `composeAndSign`), and any foreign-witness
   * injection on `revealTx` before this method extracts. Returning
   * `{commitHexes, revealTx, composed}` hands the prepared package
   * back; `submitReveal` extracts the reveal, broadcasts
   * `[...commitHexes, revealHex]` as a Bitcoin package, and advances
   * funding tracking — all atomically.
   *
   * Multi-commit (0..N) is supported in the API shape; today every
   * SDK flow has 0 or 1 commits (`revoke` is the no-commit case).
   *
   * Adding a new submission flow? Route it through here. The
   * `broadcast` / `advanceTracking` primitives exist on the
   * interface but using them directly bypasses the lock — only
   * read-only methods (`view`) are safe outside.
   */
  submitReveal(
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
  }>;

  /**
   * After broadcasting a commit/reveal package that this transport
   * prepared via `composeAndSign`, advance the funding tracker so its
   * spent inputs are filtered out of `utxos()` and its change outputs
   * become the new pool. Called automatically by `submitReveal` —
   * direct callers bypass the account's lock, so don't.
   *
   * Optional — implementations that don't track funding (e.g. test
   * mocks) may leave it undefined.
   */
  advanceTracking?(opts: {
    suppliedUtxos: Utxo[];
    composed: ComposeOutputs;
    commitHexes: string[];
    revealHex: string;
  }): void;
}
