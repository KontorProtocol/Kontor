/** Ordered receipt observations with durable rollback recovery and opaque resume tokens. */
import type {
  Info,
  ReceiptStreamResponse,
  ResultInfo,
  StreamReceipt,
  TransactionInfo,
} from "./bindings.js";
import {
  executionCoordinates,
  transactionInfoFromWire,
} from "./confirmation.js";
import type { ChainEvent, EventsOptions } from "./events.js";
import { ReceiptStreamError, TransportError } from "./errors.js";
import type { OpResultRaw } from "./json-codec.js";

const LONG_POLL_MS = 25_000;
const DRAIN_PAGE_LIMIT = 200;
const BOOTSTRAP_ATTEMPTS = 5;
const DEFAULT_RETRY_BACKOFF_MS = 500;
const MAX_RETRY_BACKOFF_MS = 10_000;

export interface PollerOptions extends EventsOptions {
  baseUrl: string;
  fetch: typeof fetch;
  retryBackoffMs?: number;
}

interface Consumer {
  queue: ChainEvent[];
  wake: (() => void) | null;
  done: boolean;
}

export class ResultsPoller {
  private readonly consumers = new Set<Consumer>();
  private completedToken: string | undefined;
  private signature = "";
  private running = false;
  private subscriberWake: (() => void) | undefined;
  private fatal: Error | null = null;
  private readonly backoff: number;
  private readonly readyPromise: Promise<void>;
  private readyResolve!: () => void;
  private readyReject!: (e: Error) => void;

  constructor(private readonly opts: PollerOptions) {
    if (
      opts.from !== undefined &&
      (typeof opts.from !== "string" || !opts.from)
    ) {
      throw new ReceiptStreamError(
        "invalid_request",
        "Resume requires an opaque receipt token; numeric cursors require explicit resynchronization",
      );
    }
    if (opts.from !== undefined && opts.start !== undefined) {
      throw new ReceiptStreamError(
        "invalid_request",
        "Specify a resume token or a start mode, not both",
      );
    }
    this.opts = { ...opts, filter: opts.filter && { ...opts.filter } };
    this.completedToken = opts.from;
    this.backoff = opts.retryBackoffMs ?? DEFAULT_RETRY_BACKOFF_MS;
    this.readyPromise = new Promise((res, rej) => {
      this.readyResolve = res;
      this.readyReject = rej;
    });
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
    this.subscriberWake?.();
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
    this.subscriberWake?.();
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

  private async loop(): Promise<void> {
    try {
      await this.bootstrap();
    } catch (e) {
      const error = e instanceof Error ? e : new Error(String(e));
      this.fatal = error;
      this.readyReject(error);
      this.wakeAll();
      return;
    }
    this.readyResolve();
    let failures = 0;
    while (this.running) {
      try {
        const resuming = this.consumers.size === 0;
        if (resuming) {
          await new Promise<void>((resolve) => {
            this.subscriberWake = resolve;
          });
          this.subscriberWake = undefined;
        }
        if (!this.running) break;
        const info =
          failures > 0 || resuming
            ? await this.getInfo()
            : await this.longPoll();
        if (!this.running) break;
        // Rollback may keep both the height and maximum result ID unchanged.
        await this.drainResults();
        this.signature = info.signature;
        failures = 0;
      } catch (e) {
        if (e instanceof ReceiptStreamError) throw e;
        failures += 1;
        await this.sleep(
          Math.min(this.backoff * failures, MAX_RETRY_BACKOFF_MS),
        );
      }
    }
  }

  private async bootstrap(): Promise<void> {
    let lastError: Error = new Error("indexer unreachable");
    for (let attempt = 1; attempt <= BOOTSTRAP_ATTEMPTS; attempt++) {
      try {
        const info = await this.getInfo();
        if (this.completedToken === undefined) {
          const response = await this.getStream(
            new URLSearchParams({ start: this.opts.start ?? "tip" }),
          );
          if (response.kind !== "start") throw this.invalidResponse();
          this.completedToken = this.requireToken(response.resume_token);
        }
        await this.drainResults();
        this.signature = info.signature;
        return;
      } catch (e) {
        if (e instanceof ReceiptStreamError) throw e;
        lastError = e instanceof Error ? e : new Error(String(e));
        if (attempt < BOOTSTRAP_ATTEMPTS)
          await this.sleep(this.backoff * attempt);
      }
    }
    throw lastError;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private invalidResponse(): ReceiptStreamError {
    return new ReceiptStreamError(
      "invalid_response",
      "Invalid receipt stream response",
    );
  }

  private requireToken(token: unknown): string {
    if (typeof token !== "string" || token.length === 0 || token.length > 192)
      throw this.invalidResponse();
    return token;
  }

  private completeGroup(group: StreamReceipt[]): void {
    const last = group[group.length - 1]!;
    this.emitTx(
      group.map((entry) => entry.receipt),
      last.resume_token,
    );
    this.completedToken = last.resume_token;
  }

  private async drainResults(): Promise<void> {
    let pending: StreamReceipt[] = [];
    let pageToken: string | undefined;
    let previousId: number | undefined;
    while (this.running && this.consumers.size > 0) {
      const params = new URLSearchParams({
        from: this.completedToken!,
        limit: String(DRAIN_PAGE_LIMIT),
      });
      if (pageToken !== undefined) params.set("page", pageToken);
      const response = await this.getStream(params);
      if (!this.running || this.consumers.size === 0) return;
      if (response.kind === "recovery") {
        const resumeToken = this.requireToken(response.resume_token);
        if (
          !Number.isSafeInteger(response.fork_height) ||
          response.fork_height < 0 ||
          resumeToken === this.completedToken
        )
          throw this.invalidResponse();
        pending = [];
        pageToken = undefined;
        previousId = undefined;
        this.emit({
          kind: "reorg",
          forkHeight: BigInt(response.fork_height),
          resumeToken,
        });
        this.completedToken = resumeToken;
        continue;
      }
      if (
        response.kind !== "page" ||
        !Array.isArray(response.receipts) ||
        typeof response.has_more !== "boolean"
      )
        throw this.invalidResponse();
      const nextToken = this.requireToken(response.next_token);
      if (
        response.has_more &&
        (response.receipts.length === 0 || nextToken === pageToken)
      )
        throw this.invalidResponse();
      for (const entry of response.receipts) {
        const row = entry.receipt;
        this.requireToken(entry.resume_token);
        if (
          !row ||
          !Number.isSafeInteger(row.id) ||
          row.id <= 0 ||
          (previousId !== undefined && row.id <= previousId)
        )
          throw this.invalidResponse();
        if (pending.length > 0 && pending[0]!.receipt.txid !== row.txid) {
          this.completeGroup(pending);
          pending = [];
        }
        pending.push(entry);
        previousId = row.id;
      }
      if (!response.has_more) {
        // An empty continuation still completes a group buffered from its prior page.
        if (pending.length > 0) this.completeGroup(pending);
        this.completedToken = nextToken;
        return;
      }
      pageToken = nextToken;
    }
  }

  /** Group of same-`txid` result rows → one `tx` ChainEvent. */
  private emitTx(rows: ResultInfo[], resumeToken: string): void {
    const last = rows[rows.length - 1]!;
    // Results with no txid (shouldn't occur for contract calls) carry
    // no transaction to surface — skip the group.
    if (last.txid == null) return;
    const executionHeight = last.execution_height ?? last.height;
    if (
      rows.some(
        (row) => (row.execution_height ?? row.height) !== executionHeight,
      )
    ) {
      // Retry from the last completed transaction. Collapsing duplicate op keys
      // first would hide receipts from different executions across page reads.
      throw new TransportError(
        "Transaction execution changed while reading receipts",
      );
    }
    // One transaction can span pages read on either side of a confirmation or
    // reorg. Use the final page's metadata consistently for the emitted group.
    const coordinates = executionCoordinates(last);
    // Collapse each (input_index, op_index) to its highest-`result_index`
    // row — the op's canonical result, mirroring the indexer's
    // `get_op_result`. Drops intermediate sub-results and the implicit
    // gas op (which shares the user op's indices at a lower
    // `result_index`).
    const canonical = new Map<string, ResultInfo>();
    for (const r of rows) {
      const key = `${r.input_index}:${r.op_index}`;
      const prev = canonical.get(key);
      if (prev === undefined || r.result_index > prev.result_index) {
        canonical.set(key, r);
      }
    }
    const outcomes: OpResultRaw[] = [...canonical.values()]
      .sort(
        (a, b) =>
          (a.input_index ?? 0) - (b.input_index ?? 0) ||
          (a.op_index ?? 0) - (b.op_index ?? 0),
      )
      .map((r) => ({
        status: r.status,
        gas: BigInt(r.gas),
        value: r.value ?? undefined,
        func: r.func,
        contract: r.contract,
        inputIndex: r.input_index,
        opIndex: r.op_index,
        coordinates: { ...coordinates },
      }));
    this.emit({
      kind: "tx",
      resumeToken,
      id: last.id,
      height: BigInt(last.height),
      txIndex: last.tx_index ?? null,
      ...coordinates,
      txid: last.txid,
      outcomes,
    });
  }

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

  private async fetchResponse(path: string): Promise<Response> {
    let res: Response;
    try {
      res = await this.opts.fetch(`${this.opts.baseUrl}${path}`);
    } catch (e) {
      throw new TransportError("indexer poll request failed", {
        cause: e instanceof Error ? e : undefined,
        details: path,
      });
    }
    return res;
  }

  private async readResult<T>(res: Response, path: string): Promise<T> {
    if (!res.ok) {
      throw new TransportError(`indexer poll returned ${res.status}`, {
        details: path,
      });
    }
    const body = (await res.json()) as { result: T };
    return body.result;
  }

  private async fetchResult<T>(path: string): Promise<T> {
    return this.readResult<T>(await this.fetchResponse(path), path);
  }

  /** Fresh metadata without starting the event loop. A missing transaction is null. */
  async transaction(txid: string): Promise<TransactionInfo | null> {
    const path = `/transactions/${encodeURIComponent(txid)}`;
    const response = await this.fetchResponse(path);
    if (response.status === 404) return null;
    return transactionInfoFromWire(
      await this.readResult<TransactionInfo>(response, path),
    );
  }

  private getInfo(): Promise<Info> {
    return this.fetchResult<Info>("");
  }

  private longPoll(): Promise<Info> {
    return this.fetchResult<Info>(
      `?wait=${LONG_POLL_MS}&since=${encodeURIComponent(this.signature)}`,
    );
  }

  private async getStream(
    params: URLSearchParams,
  ): Promise<ReceiptStreamResponse> {
    const filter = this.opts.filter;
    if (filter?.contract !== undefined) params.set("contract", filter.contract);
    if (filter?.func !== undefined) params.set("func", filter.func);
    if (filter?.signerId !== undefined)
      params.set("signer_id", String(filter.signerId));
    const path = `/receipt-stream?${params}`;
    const response = await this.fetchResponse(path);
    if (response.status === 404)
      throw new ReceiptStreamError(
        "unsupported_server",
        "This node does not support durable receipt streams",
      );
    if (response.status === 400 || response.status === 422)
      throw new ReceiptStreamError(
        "invalid_request",
        "The node rejected the receipt resume token or stream options",
      );
    const result = await this.readResult<ReceiptStreamResponse>(response, path);
    if (!result || typeof result !== "object") throw this.invalidResponse();
    if (result.kind === "reset_required") {
      throw new ReceiptStreamError(
        result.reason,
        "Receipt history requires explicit resynchronization",
      );
    }
    return result;
  }
}
