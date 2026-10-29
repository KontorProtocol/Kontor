/**
 * Chain-event types for `session.events()` — the indexer-following
 * API. A consumer iterating `session.events(...)` receives a stream
 * of `ChainEvent`s reconstructed by the SDK's results poller from the
 * indexer's REST surface.
 *
 * Two event kinds:
 *
 *   - `tx`     — a transaction was processed; carries its per-Inst
 *                outcomes. Persist its opaque `resumeToken` atomically with
 *                derived effects and pass it as `EventsOptions.from`.
 *   - `reorg`  — a chain reorg was detected. Everything strictly above
 *                `forkHeight` is invalidated; the consumer must revert
 *                derived state for those heights, then continues from
 *                the post-reorg events that follow.
 *
 * `reorg` events come from the node's durable rollback journal, including
 * finality replay with unchanged Bitcoin hashes. Persist the recovery token
 * atomically with the corresponding retraction of derived effects.
 */

import type { OpResultRaw } from "./json-codec.js";
import type { ExecutionCoordinates } from "./confirmation.js";

export type ChainEvent =
  | (ExecutionCoordinates & {
      kind: "tx";
      /**
       * Cursor id for this event — the underlying `contract_results`
       * row id. It can be reused after rollback and is not a resume token.
       */
      id: number;
      resumeToken: string;
      /** @deprecated Alias of executionHeight, not Bitcoin confirmation height. */
      height: bigint;
      /** @deprecated Legacy filtered ordinal; use confirmedBitcoinTxIndex. */
      txIndex: number | null;
      txid: string;
      /** Per-Inst outcomes, raw (WAVE-encoded values + telemetry). */
      outcomes: OpResultRaw[];
    })
  | {
      kind: "reorg";
      resumeToken: string;
      /**
       * Surviving execution height. Heights strictly greater than this
       * have been rolled back; the consumer reverts derived state
       * for those heights before processing subsequent events.
       */
      forkHeight: bigint;
    };

export interface EventsFilter {
  /** Only emit events for this contract (`<name>@<height>.<txIndex>`). */
  contract?: string;
  /** Only emit events for this function name. */
  func?: string;
  /** Only emit events for this signer id. */
  signerId?: number;
}

export interface EventsOptions {
  /**
   * Resume after an observed tx or reorg event's opaque token, on the same
   * node and with the same filter. Numeric-only cursors require resynchronization.
   */
  from?: string;
  /** Start a new stream at origin or the current tip (default); excludes from. */
  start?: "origin" | "tip";
  /** Server-side filter — narrows what the poller fetches. */
  filter?: EventsFilter;
}
