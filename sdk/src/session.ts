/**
 * `KontorSession` is the execution surface for the SDK. Bind a chain
 * and account once; instantiate Contract classes against deployments
 * via `bind(ContractClass, address)`; execute Insts (single, bulk, or
 * aggregate) through the session.
 *
 *     const session = new KontorSession({ chain: signet, account });
 *     const token = session.bind(Token, "token@0.0");
 *
 *     // View — Promise<T> directly, hits transport.view (no tx)
 *     const balance = await token.balance(account.holderRef);
 *
 *     // Proc single — await the Inst fires submit; throws on non-Ok
 *     await token.transfer(dst, amt);
 *
 *     // Proc bulk — N Insts in one tx, results tuple-typed
 *     const [r1, r2] = await session.bulk(
 *       token.transfer(dst1, amt1),
 *       staking.delegate(validator),
 *     );
 *
 *     // Aggregate (contributor)
 *     const fragment = await token.transfer(dst, amt).signForAggregate(account);
 *     // out-of-band: send fragment.serialize() to the aggregator
 *
 *     // Aggregate (aggregator)
 *     const bundle = session.combineAggregate(fragments);
 *     const results = await bundle;
 *
 * For tests, pass a custom `transport` factory to swap the default
 * HttpTransport for a mock implementation.
 */

import { ContractAddress } from "./canonical/ContractAddress.js";
import type { Account } from "./account/index.js";
import type { Chain } from "./chains.js";
import { Inst, type InstDecoder, type PaymentIntent } from "./inst.js";
import { Insts } from "./insts.js";
import type { AggregateFragment } from "./aggregate.js";
import type { ChainEvent, EventsOptions } from "./events.js";
import { HttpTransport } from "./transport/http.js";
import type { KontorTransport } from "./json-codec.js";

export interface KontorSessionOptions {
  chain: Chain;
  account: Account;
  /**
   * Override the default `HttpTransport`. Useful for tests (swap in a
   * mock) or for custom backends that proxy through a different
   * protocol.
   */
  transport?: (opts: { chain: Chain; account: Account }) => KontorTransport;
  /**
   * Default payment commitment for proc `Inst`s built via `call(...)`.
   * Overridable per-Inst with `inst.pay(...)`. When omitted, defaults
   * to `SelfPay` with a provisional limit — the transport refines the
   * actual gas at submit time; this is the signer's ceiling.
   */
  defaultPayment?: PaymentIntent;
}

/**
 * Provisional default `SelfPay` ceiling when `KontorSessionOptions`
 * doesn't specify one. Tunable; the transport estimates real gas at
 * submit time, so this is just the cap the signer authorizes.
 */
const DEFAULT_PAYMENT: PaymentIntent = { kind: "SelfPay", limit: 100_000n };

/**
 * Unwrap the `T` from each `Inst<T>` in a tuple, producing a tuple of
 * the same shape. Used by `bulk(...)` so per-Inst result types stay
 * accurate at the call site.
 */
type InstResults<Ts extends readonly Inst<unknown>[]> = {
  [K in keyof Ts]: Ts[K] extends Inst<infer U> ? U : never;
};

export class KontorSession {
  readonly chain: Chain;
  readonly account: Account;
  /** Public so `Inst<T>` / `Insts<T>` can route through it directly. */
  readonly transport: KontorTransport;
  /** Default payment for proc `Inst`s; see `KontorSessionOptions`. */
  readonly defaultPayment: PaymentIntent;

  constructor(opts: KontorSessionOptions) {
    this.chain = opts.chain;
    this.account = opts.account;
    this.defaultPayment = opts.defaultPayment ?? DEFAULT_PAYMENT;
    const make =
      opts.transport ??
      (({ chain, account }) => new HttpTransport({ chain, account }));
    this.transport = make({ chain: opts.chain, account: opts.account });
  }

  /**
   * Build a proc-context `Call` `Inst`. Codegen-emitted proc methods
   * are one-liners delegating here — this is the narrow facade that
   * keeps generated code free of `Inst` / `InstKind` internals and of
   * payment policy. The Inst carries the session's `defaultPayment`;
   * override per-call with `inst.pay(...)`.
   */
  call<T>(
    contract: ContractAddress,
    fnName: string,
    expr: string,
    decode: InstDecoder<T>,
  ): Inst<T> {
    return new Inst<T>(
      this,
      this.defaultPayment,
      { kind: "Call", contract, fnName, expr },
      decode,
    );
  }

  /**
   * Instantiate a generated Contract class against a specific
   * deployment. The returned Contract's methods produce either
   * `Inst`s (proc) or `Promise<T>`s (view), bound to this session.
   *
   * `address` accepts a raw `ContractAddress` or its string form
   * (`<name>@<height>.<txIndex>`).
   */
  bind<C>(
    Ctor: new (session: KontorSession, address: ContractAddress) => C,
    address: ContractAddress | string,
  ): C {
    const addr =
      typeof address === "string" ? parseContractAddress(address) : address;
    return new Ctor(this, addr);
  }

  /**
   * View-context call: read-only query against a contract. Codegen
   * routes view-context methods through here. Returns the raw WAVE
   * result string; per-method decoders sit in the generated code.
   */
  view(contract: ContractAddress, wave: string): Promise<string> {
    return this.transport.view(contract, wave);
  }

  /**
   * Bundle multiple Insts into one `Insts` for broadcast as a single
   * Bitcoin tx. Returns an `Insts<[A, B, ...]>` whose `await` yields a
   * tuple of typed results in the same order as the inputs.
   */
  bulk<Ts extends readonly Inst<unknown>[]>(
    ..._insts: Ts
  ): Insts<InstResults<Ts>> {
    throw new Error("KontorSession.bulk: not implemented");
  }

  /**
   * Build an `Insts` bundle from collected `AggregateFragment`s. The
   * aggregator verifies each fragment locally first (callers should
   * `fragment.verify()` before passing in), then this method assembles
   * the multi-signer bundle and prepares it for broadcast.
   */
  combineAggregate(
    _fragments: readonly AggregateFragment[],
  ): Insts<unknown[]> {
    throw new Error("KontorSession.combineAggregate: not implemented");
  }

  /**
   * Follow chain events — the indexer-following API. Returns an async
   * iterator over `ChainEvent`s (tx outcomes + reorg signals),
   * reconstructed by the session's results poller from the indexer's
   * REST surface (`/api/` long-poll + `/api/results` cursor drain +
   * `/api/blocks/{h}` for reorg walk-down).
   *
   * Pass `from` to resume from a persisted cursor; `filter` to narrow
   * server-side to specific contracts / funcs / signers.
   *
   *     for await (const event of session.events({ from: cursor })) {
   *       if (event.kind === "reorg") {
   *         await store.revertAbove(event.forkHeight);
   *       } else {
   *         await store.apply(event);
   *         await store.checkpoint(event.id);
   *       }
   *     }
   *
   * The poller is a per-session singleton — multiple `events()`
   * iterators (and `wait()` calls) share one polling loop.
   */
  events(_opts?: EventsOptions): AsyncIterableIterator<ChainEvent> {
    throw new Error("KontorSession.events: not implemented");
  }
}

function parseContractAddress(s: string): ContractAddress {
  const m = s.match(/^([^@]+)@(\d+)\.(\d+)$/);
  if (m == null) {
    throw new Error(
      `invalid contract address '${s}'; expected '<name>@<height>.<txIndex>'`,
    );
  }
  return new ContractAddress(m[1]!, BigInt(m[2]!), BigInt(m[3]!));
}
