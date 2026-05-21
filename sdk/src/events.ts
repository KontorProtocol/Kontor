/**
 * Chain-event types for `session.events()` — the indexer-following
 * API. A consumer iterating `session.events(...)` receives a stream
 * of `ChainEvent`s reconstructed by the SDK's results poller from the
 * indexer's REST surface.
 *
 * Two event kinds:
 *
 *   - `tx`     — a transaction was processed; carries its per-Inst
 *                outcomes. The `id` is the cursor — persist it and
 *                pass it back as `EventsOptions.from` to resume.
 *   - `reorg`  — a chain reorg was detected. Everything strictly above
 *                `forkHeight` is invalidated; the consumer must revert
 *                derived state for those heights, then continues from
 *                the post-reorg events that follow.
 *
 * `reorg` events are synthesized client-side by the poller (it detects
 * the fork by comparing the indexer's recent block hashes against its
 * local cache). There is no server-side reorg record — the signal is
 * canonical-chain state differing from what the SDK last saw.
 */

import type { OpResultRaw } from "./json-codec.js";

export type ChainEvent =
  | {
      kind: "tx";
      /**
       * Cursor id for this event — the underlying `contract_results`
       * row id. Monotonic. Persist it; pass as `EventsOptions.from`
       * to resume the stream after this event.
       */
      id: number;
      height: bigint;
      txIndex: number;
      txid: string;
      /** Per-Inst outcomes, raw (WAVE-encoded values + telemetry). */
      outcomes: OpResultRaw[];
    }
  | {
      kind: "reorg";
      /**
       * Common-ancestor height. Heights strictly greater than this
       * have been rolled back — the consumer reverts derived state
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
   * Resume the stream after this cursor id (a prior `tx` event's
   * `id`). Omit to start from the current chain tip.
   */
  from?: number;
  /** Server-side filter — narrows what the poller fetches. */
  filter?: EventsFilter;
}
