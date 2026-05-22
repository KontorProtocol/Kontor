/**
 * `ResultsPoller` — the SDK's indexer-following loop, and the
 * `BlockHashCache` it leans on for reorg detection.
 *
 * The indexer is followed entirely over its REST surface — no
 * websocket, no server-side event log:
 *
 *   - `GET /api?wait=&since=` — long-poll heartbeat. The request hangs
 *     until `Info.signature` moves (a block / batch / rollback) or the
 *     timeout elapses.
 *   - `GET /api/results?cursor=` — forward, id-cursored drain of
 *     `contract_results`. `cursor` is the last row id consumed.
 *   - `GET /api/blocks/{height}` — single block, for the deep-reorg
 *     walk-down.
 *
 * Each long-poll wake runs reorg detection by comparing the indexer's
 * `recent_blocks` against the local `BlockHashCache`; a divergence is
 * synthesized into a `reorg` ChainEvent (there is no server-side reorg
 * record). Then, if `last_result_id` advanced, results are drained and
 * grouped per transaction into `tx` ChainEvents.
 *
 * The poller is a per-session singleton: multiple `events()` iterators
 * share one polling loop, each getting its own fan-out queue.
 */

import type { BlockRow, Info, PaginatedResponse, ResultRow } from "./bindings.js";
import type { ChainEvent, EventsFilter } from "./events.js";
import { DeepReorgError, TransportError } from "./errors.js";
import type { OpResultRaw } from "./json-codec.js";

/** Local block-hash cache depth — mirrors the indexer's `HASH_CACHE_SIZE`. */
const HASH_CACHE_SIZE = 50;
/** Long-poll budget — at or below the indexer's `MAX_WAIT_MS` cap. */
const LONG_POLL_MS = 25_000;
/** Page size when draining `/api/results`. */
const DRAIN_PAGE_LIMIT = 200;
/** Bootstrap (`getInfo`) attempts before the poller calls the node unreachable. */
const BOOTSTRAP_ATTEMPTS = 5;
/** Base retry backoff (ms) — bootstrap and post-bootstrap transient errors. */
const DEFAULT_RETRY_BACKOFF_MS = 500;
/** Ceiling on the (linearly-growing) transient-error backoff. */
const MAX_RETRY_BACKOFF_MS = 10_000;

/**
 * Bounded `height → hash` map. Mirrors
 * `core/indexer/src/bitcoin_follower/poller/mod.rs::BlockHashCache`:
 * the SDK following Kontor, as Kontor follows Bitcoin.
 */
export class BlockHashCache {
  private readonly hashes = new Map<number, string>();
  /** Insertion order, for capacity eviction (oldest-inserted first). */
  private readonly order: number[] = [];

  constructor(private readonly capacity: number) {}

  /** Record `height → hash`. A height already present is left as-is. */
  insert(height: number, hash: string): void {
    if (this.hashes.has(height)) return;
    if (this.order.length >= this.capacity) {
      const oldest = this.order.shift();
      if (oldest !== undefined) this.hashes.delete(oldest);
    }
    this.hashes.set(height, hash);
    this.order.push(height);
  }

  get(height: number): string | undefined {
    return this.hashes.get(height);
  }

  /** Drop every entry strictly above `height` — post-reorg cleanup. */
  truncateAbove(height: number): void {
    for (let i = this.order.length - 1; i >= 0; i--) {
      const h = this.order[i]!;
      if (h > height) {
        this.order.splice(i, 1);
        this.hashes.delete(h);
      }
    }
  }

  /** Lowest cached height, or `undefined` when empty. */
  minHeight(): number | undefined {
    let min: number | undefined;
    for (const h of this.order) {
      if (min === undefined || h < min) min = h;
    }
    return min;
  }
}

export interface PollerOptions {
  /** Indexer HTTP API base, e.g. `https://signet.kontor.network:35001/api`. */
  baseUrl: string;
  /** `fetch` implementation (injectable for tests). */
  fetch: typeof fetch;
  /**
   * Resume cursor — a prior `tx` event's `id`. Omitted: start at the
   * current chain tip (no history replay).
   */
  from?: number;
  /** Server-side filter narrowing the `/api/results` drain. */
  filter?: EventsFilter;
  /** Base retry backoff in ms (bootstrap + transient errors). Default 500. */
  retryBackoffMs?: number;
}

/** One `events()` iterator's fan-out queue. */
interface Consumer {
  queue: ChainEvent[];
  /** Resolver for a `next()` currently parked on an empty queue. */
  wake: (() => void) | null;
  done: boolean;
}

export class ResultsPoller {
  private readonly cache = new BlockHashCache(HASH_CACHE_SIZE);
  private readonly consumers = new Set<Consumer>();
  /** Last `contract_results` row id consumed. */
  private cursor: number;
  /** Whether `from` was omitted — if so, jump `cursor` to the tip on bootstrap. */
  private readonly seekToTip: boolean;
  /** Latest `Info.signature`, fed back as the long-poll `?since=`. */
  private signature = "";
  private running = false;
  /** Set when the loop dies (e.g. `DeepReorgError`); re-thrown to consumers. */
  private fatal: Error | null = null;
  /** Base retry backoff (ms). */
  private readonly backoff: number;
  /** Resolves on the first successful poll; rejects if bootstrap fails. */
  private readonly readyPromise: Promise<void>;
  private readyResolve!: () => void;
  private readyReject!: (e: Error) => void;

  constructor(private readonly opts: PollerOptions) {
    this.cursor = opts.from ?? 0;
    this.seekToTip = opts.from === undefined;
    this.backoff = opts.retryBackoffMs ?? DEFAULT_RETRY_BACKOFF_MS;
    this.readyPromise = new Promise<void>((res, rej) => {
      this.readyResolve = res;
      this.readyReject = rej;
    });
    // Pre-attach a no-op catch so an unobserved bootstrap failure isn't
    // reported as an unhandled rejection — `ready()` callers still see it.
    this.readyPromise.catch(() => {});
  }

  /**
   * Resolves once the poller's first poll succeeds — confirming the
   * indexer URL is reachable and the node is up. Rejects if the
   * bootstrap poll fails every `BOOTSTRAP_ATTEMPTS` try. `session.ready()`
   * awaits this as a connectivity / config check.
   */
  ready(): Promise<void> {
    return this.readyPromise;
  }

  /** Start the polling loop (idempotent). */
  start(): void {
    if (this.running) return;
    this.running = true;
    void this.loop().catch((e: unknown) => {
      this.fatal = e instanceof Error ? e : new Error(String(e));
      this.wakeAll();
    });
  }

  /** Stop the loop and close every `events()` iterator. */
  stop(): void {
    this.running = false;
    for (const c of this.consumers) c.done = true;
    this.wakeAll();
  }

  /**
   * A fresh async iterator over `ChainEvent`s. Multiple iterators share
   * this poller's single loop; each gets its own buffered queue.
   */
  events(): AsyncIterableIterator<ChainEvent> {
    const consumer: Consumer = { queue: [], wake: null, done: false };
    this.consumers.add(consumer);
    const poller = this;
    return {
      [Symbol.asyncIterator]() {
        return this;
      },
      async next(): Promise<IteratorResult<ChainEvent>> {
        for (;;) {
          const ev = consumer.queue.shift();
          if (ev !== undefined) return { value: ev, done: false };
          if (poller.fatal) throw poller.fatal;
          if (consumer.done) return { value: undefined, done: true };
          await new Promise<void>((r) => {
            consumer.wake = r;
          });
        }
      },
      async return(): Promise<IteratorResult<ChainEvent>> {
        poller.consumers.delete(consumer);
        consumer.done = true;
        return { value: undefined, done: true };
      },
    };
  }

  // ── loop ─────────────────────────────────────────────────────────

  private async loop(): Promise<void> {
    try {
      await this.bootstrap();
    } catch (e) {
      // Bootstrap exhausted its retries — the node is unreachable or
      // misconfigured. Terminal: fail `ready()` and every consumer.
      const err = e instanceof Error ? e : new Error(String(e));
      this.fatal = err;
      this.readyReject(err);
      this.wakeAll();
      return;
    }
    this.readyResolve();

    let failures = 0;
    while (this.running) {
      try {
        const info = await this.longPoll();
        if (!this.running) break;
        await this.detectReorg(info.recent_blocks);
        this.seed(info);
        if (info.last_result_id > this.cursor) {
          await this.drainResults(info.last_result_id);
        }
        failures = 0;
      } catch (e) {
        // A reorg past the cache is unrecoverable; everything else
        // (network blip, node restart) is transient — back off and
        // retry, since an always-on poller must survive these.
        if (e instanceof DeepReorgError) throw e;
        failures += 1;
        await this.sleep(Math.min(this.backoff * failures, MAX_RETRY_BACKOFF_MS));
      }
    }
  }

  /**
   * First poll, with retry — seeds the cache, anchors the cursor,
   * drains any backlog. Doubles as the connectivity check: if every
   * attempt fails, the caller treats the node as unreachable.
   */
  private async bootstrap(): Promise<void> {
    let lastErr: Error = new Error("indexer unreachable");
    for (let attempt = 1; attempt <= BOOTSTRAP_ATTEMPTS; attempt++) {
      try {
        const info = await this.getInfo();
        this.seed(info);
        if (this.seekToTip) this.cursor = info.last_result_id;
        if (info.last_result_id > this.cursor) {
          await this.drainResults(info.last_result_id);
        }
        return;
      } catch (e) {
        lastErr = e instanceof Error ? e : new Error(String(e));
        if (attempt < BOOTSTRAP_ATTEMPTS) {
          await this.sleep(this.backoff * attempt);
        }
      }
    }
    throw lastErr;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }

  /** Fold `Info` into local state: cache + signature. */
  private seed(info: Info): void {
    for (const b of info.recent_blocks) this.cache.insert(b.height, b.hash);
    this.signature = info.signature;
  }

  // ── reorg detection ──────────────────────────────────────────────

  /**
   * Compare the indexer's `recent_blocks` against the cache. On a
   * divergence, emit one `reorg` event and truncate the cache to the
   * fork point. Fast path scans the (descending) `recent_blocks`
   * window; if every cached height there disagrees, the slow path
   * walks `/api/blocks/{h}` down to the fork.
   */
  private async detectReorg(recent: ReadonlyArray<Info["recent_blocks"][number]>): Promise<void> {
    const diverged = recent.some((b) => {
      const cached = this.cache.get(b.height);
      return cached !== undefined && cached !== b.hash;
    });
    if (!diverged) return;

    // `recent` is height-descending, so the first agreement is the
    // highest height that still matches — the fork point.
    let forkHeight: number | undefined;
    for (const b of recent) {
      if (this.cache.get(b.height) === b.hash) {
        forkHeight = b.height;
        break;
      }
    }
    if (forkHeight === undefined) {
      forkHeight = await this.slowPathFork(recent);
    }
    this.cache.truncateAbove(forkHeight);
    this.emit({ kind: "reorg", forkHeight: BigInt(forkHeight) });
  }

  /**
   * Every height in the `recent_blocks` window disagreed — walk down
   * one block at a time until a cached hash matches. Throws
   * `DeepReorgError` if the walk falls below the cache.
   */
  private async slowPathFork(
    recent: ReadonlyArray<Info["recent_blocks"][number]>,
  ): Promise<number> {
    const windowMin = Math.min(...recent.map((b) => b.height));
    for (let h = windowMin - 1; h >= 0; h--) {
      const cached = this.cache.get(h);
      if (cached === undefined) {
        throw new DeepReorgError(
          `reorg deeper than the ${HASH_CACHE_SIZE}-block cache`,
          { details: `walked down to height ${h} with no cached hash` },
        );
      }
      const block = await this.getBlock(h);
      if (block.hash === cached) return h;
    }
    throw new DeepReorgError("reorg past the base of the local cache");
  }

  // ── results drain ────────────────────────────────────────────────

  /**
   * Drain `/api/results` forward from `cursor` up to `upTo`, grouping
   * consecutive same-`txid` rows into one `tx` event each. A tx's op
   * results are inserted with consecutive ids, so a group never
   * interleaves — though it may span a page boundary.
   */
  private async drainResults(upTo: number): Promise<void> {
    let cursor = this.cursor;
    let pending: ResultRow[] = [];
    while (cursor < upTo) {
      const page = await this.getResults(cursor);
      if (page.results.length === 0) break;
      for (const row of page.results) {
        if (pending.length > 0 && pending[0]!.txid !== row.txid) {
          this.emitTx(pending);
          pending = [];
        }
        pending.push(row);
        cursor = row.id;
      }
      if (!page.pagination.has_more) break;
    }
    if (pending.length > 0) this.emitTx(pending);
    this.cursor = cursor;
  }

  /** Group of same-`txid` result rows → one `tx` ChainEvent. */
  private emitTx(rows: ResultRow[]): void {
    const last = rows[rows.length - 1]!;
    // Results with no txid (shouldn't occur for contract calls) carry
    // no transaction to surface — skip the group.
    if (last.txid == null) return;
    const outcomes: OpResultRaw[] = rows.map((r) => ({
      status: r.status,
      gas: BigInt(r.gas),
      value: r.value ?? undefined,
    }));
    this.emit({
      kind: "tx",
      id: last.id,
      height: BigInt(last.height),
      txIndex: last.tx_index ?? 0,
      txid: last.txid,
      outcomes,
    });
  }

  // ── fan-out ──────────────────────────────────────────────────────

  private emit(event: ChainEvent): void {
    for (const c of this.consumers) {
      c.queue.push(event);
      if (c.wake) {
        c.wake();
        c.wake = null;
      }
    }
  }

  private wakeAll(): void {
    for (const c of this.consumers) {
      if (c.wake) {
        c.wake();
        c.wake = null;
      }
    }
  }

  // ── HTTP ─────────────────────────────────────────────────────────

  private async fetchResult<T>(path: string): Promise<T> {
    let res: Response;
    try {
      res = await this.opts.fetch(`${this.opts.baseUrl}${path}`);
    } catch (e) {
      throw new TransportError("indexer poll request failed", {
        cause: e instanceof Error ? e : undefined,
        details: path,
      });
    }
    if (!res.ok) {
      throw new TransportError(`indexer poll returned ${res.status}`, {
        details: path,
      });
    }
    const body = (await res.json()) as { result: T };
    return body.result;
  }

  private getInfo(): Promise<Info> {
    // The indexer serves the info endpoint at the API base exactly
    // (`/api`); `/api/` 404s. So this path is empty, not "/".
    return this.fetchResult<Info>("");
  }

  private longPoll(): Promise<Info> {
    const sig = encodeURIComponent(this.signature);
    return this.fetchResult<Info>(`?wait=${LONG_POLL_MS}&since=${sig}`);
  }

  private getBlock(height: number): Promise<BlockRow> {
    return this.fetchResult<BlockRow>(`/blocks/${height}`);
  }

  private getResults(cursor: number): Promise<PaginatedResponse<ResultRow>> {
    const params = new URLSearchParams({
      cursor: String(cursor),
      order: "asc",
      limit: String(DRAIN_PAGE_LIMIT),
    });
    const f = this.opts.filter;
    if (f?.contract) params.set("contract", f.contract);
    if (f?.func) params.set("func", f.func);
    if (f?.signerId !== undefined) params.set("signer_id", String(f.signerId));
    return this.fetchResult<PaginatedResponse<ResultRow>>(`/results?${params}`);
  }
}
