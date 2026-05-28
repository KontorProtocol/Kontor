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
import { BlsKey, buildRegistrationProof } from "./bls.js";
import type { Chain } from "./chains.js";
import { hex } from "@scure/base";

import type {
  AggregateInfo,
  AggregateSigner,
  Inst as WireInst,
} from "./bindings.js";
import { blsAggregateSignatures } from "./component/kontor-sdk.js";
import { ContractError, SignerError } from "./errors.js";
import { Inst, type InstDecoder, wireInstToInst } from "./inst.js";
import { Insts } from "./insts.js";
import { IncomingOffer, type OfferData } from "./offer.js";
import type { AggregateFragment } from "./aggregate.js";
import type { ChainEvent, EventsOptions } from "./events.js";
import { ResultsPoller } from "./poller.js";
import { HttpTransport } from "./transport/http.js";
import type { KontorTransport } from "./json-codec.js";

export interface KontorSessionOptions {
  chain: Chain;
  account: Account;
  /**
   * Override the default `HttpTransport`. Useful for tests (swap in a
   * mock) or for custom backends that proxy through a different
   * protocol. `feeRate` mirrors `KontorSessionOptions.feeRate` so a
   * custom transport can honor the session-level default.
   */
  transport?: (opts: {
    chain: Chain;
    account: Account;
    feeRate: number | null;
  }) => KontorTransport;
  /**
   * `fetch` implementation for the results poller. Inject a mock in
   * tests; defaults to `globalThis.fetch`.
   */
  fetch?: typeof fetch;
  /**
   * Default gas cap for proc `Inst`s built via `call(...)`.
   * Overridable per-Inst with `inst.withGasLimit(...)`. When omitted,
   * defaults to a provisional ceiling — the transport refines the
   * actual gas at submit time; this is the signer's authorized cap.
   */
  defaultGasLimit?: bigint;
  /**
   * Results-poller configuration. The poller starts in the constructor
   * — it follows the chain for `events()` / `wait()` and doubles as a
   * connectivity check (see `ready()`). `from` resumes a persisted
   * cursor; `filter` narrows the stream. Omit for "follow from the tip".
   */
  events?: EventsOptions;
  /**
   * Default Bitcoin fee rate in sat/vB, applied to every Reveal the
   * SDK composes (single submits, attach/offer/revoke/accept). Omit to
   * let the indexer pick its current `fastest_fee`. Power users wanting
   * a per-call override can compose their own Reveal via
   * `transport.composeAndSign` + `transport.submitReveal`.
   */
  feeRate?: number;
}

/**
 * Provisional default self-pay ceiling when `KontorSessionOptions`
 * doesn't specify one. Tunable; the transport estimates real gas at
 * submit time, so this is just the cap the signer authorizes.
 */
const DEFAULT_GAS_LIMIT: bigint = 100_000n;

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
  /** Default gas cap for proc `Inst`s; see `KontorSessionOptions`. */
  readonly defaultGasLimit: bigint;
  /** Default sat/vB for every Reveal the SDK composes; `null` = let the
   *  indexer pick its current `fastest_fee`. */
  readonly feeRate: number | null;
  /**
   * The session's results poller — one shared loop, started here in the
   * constructor. Backs `events()` and (later) `inst.submit().wait()`.
   */
  private readonly poller: ResultsPoller;

  constructor(opts: KontorSessionOptions) {
    this.chain = opts.chain;
    this.account = opts.account;
    this.defaultGasLimit = opts.defaultGasLimit ?? DEFAULT_GAS_LIMIT;
    this.feeRate = opts.feeRate ?? null;
    const make =
      opts.transport ??
      (({ chain, account, feeRate }) =>
        new HttpTransport({ chain, account, feeRate: feeRate ?? undefined }));
    this.transport = make({
      chain: opts.chain,
      account: opts.account,
      feeRate: this.feeRate,
    });
    this.poller = new ResultsPoller({
      baseUrl: opts.chain.urls.http,
      fetch: opts.fetch ?? globalThis.fetch.bind(globalThis),
      from: opts.events?.from,
      filter: opts.events?.filter,
    });
    this.poller.start();
  }

  /**
   * Build a proc-context `Call` `Inst`. Codegen-emitted proc methods
   * are one-liners delegating here — this is the narrow facade that
   * keeps generated code free of `Inst` / `InstKind` internals and of
   * gas-cap policy. The Inst carries the session's `defaultGasLimit`;
   * override per-call with `inst.withGasLimit(...)`.
   */
  call<T>(
    contract: ContractAddress,
    fnName: string,
    expr: string,
    decode: InstDecoder<T>,
  ): Inst<T> {
    return new Inst<T>(
      this,
      this.defaultGasLimit,
      { kind: "Call", contract, fnName, expr },
      decode,
    );
  }

  /**
   * Build a `Publish` Inst that deploys `bytes` under `name`.
   *
   * Resolves to the new contract's `ContractAddress` once the publish
   * lands on chain. The address comes back as init's return value —
   * every contract's `init` returns its own `contract` resource (see
   * project_contract_resource_publish_return), which the host drains
   * to a `contract-address` record at the WAVE boundary so the SDK
   * reads it through the same standard result-row pipeline as any
   * Call return.
   *
   * The publish op needs a containing Bitcoin block to resolve its
   * address (the address is `name@<height>.<txIndex>`), so a freshly
   * broadcast publish may not surface a result for up to one block
   * confirmation (the regtest `mine()` helper short-circuits that
   * latency for tests).
   */
  publish(name: string, bytes: Uint8Array): Inst<ContractAddress> {
    return new Inst<ContractAddress>(
      this,
      this.defaultGasLimit,
      { kind: "Publish", name, bytes },
      decodeContractAddressWave,
    );
  }

  /**
   * Register the BLS public key behind `blsKey` for this session's
   * account, broadcasting + waiting for confirmation. After this
   * resolves, the indexer's signer entry for this account carries
   * `bls_pubkey` and the account can participate in BLS-aggregate
   * flows.
   *
   * Single high-level call rather than "build the Inst, submit it" —
   * the intermediate `Inst<void>` can't be safely returned across an
   * `async` boundary because awaiting `Promise<Inst<void>>` would
   * chain into the Inst's own PromiseLike submit semantics. Aggregate
   * flows that want the Inst (without broadcasting) will get a
   * different non-thenable handle when that work lands.
   */
  async registerBls(blsKey: BlsKey): Promise<void> {
    const proof = await buildRegistrationProof(this.account, blsKey);
    const inst = new Inst<void>(
      this,
      this.defaultGasLimit,
      {
        kind: "RegisterBlsKey",
        blsPubkey: proof.blsPubkey,
        schnorrSig: proof.schnorrSig,
        blsSig: proof.blsSig,
      },
      () => undefined,
    );
    await inst;
  }

  /**
   * Build an `Issuance` Inst — credits the signer with native tokens.
   * System-paid: bypasses gas accounting, so a freshly-funded account
   * can self-issue without an existing balance. Returns no value.
   */
  issuance(): Inst<void> {
    return new Inst<void>(
      this,
      this.defaultGasLimit,
      { kind: "Issuance" },
      () => undefined,
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
   * Rehydrate a marketplace offer blob (`Offer.serialize()`) into an
   * `IncomingOffer` — the buyer's handle, with `inspect()` / `accept()`.
   * Needs no contact with the seller.
   */
  openOffer(blob: string): IncomingOffer {
    let data: OfferData;
    try {
      data = JSON.parse(blob) as OfferData;
    } catch (cause) {
      throw new ContractError("openOffer: blob is not valid JSON", {
        cause: cause instanceof Error ? cause : undefined,
        docsPath: "/sdk/offer",
      });
    }
    if (data == null || data.v !== 1) {
      throw new ContractError("openOffer: not a recognized offer blob", {
        docsPath: "/sdk/offer",
      });
    }
    return new IncomingOffer(this, data);
  }

  /**
   * Bundle multiple Insts into one `Insts` for broadcast as a single
   * Bitcoin tx. Returns an `Insts<[A, B, ...]>` whose `await` yields a
   * tuple of typed results in the same order as the inputs.
   */
  bulk<Ts extends readonly Inst<unknown>[]>(
    ...insts: Ts
  ): Insts<InstResults<Ts>> {
    if (insts.length === 0) {
      throw new Error("KontorSession.bulk: at least one Inst is required");
    }
    return new Insts<InstResults<Ts>>(this, insts, null);
  }

  /**
   * Build a broadcastable `Insts<unknown[]>` from a set of
   * `AggregateFragment`s collected from contributors. Callers should
   * `fragment.verify()` each fragment before passing it in — this
   * method trusts the inputs cryptographically and only sanity-checks
   * that the bundle isn't empty.
   *
   * Combines every per-op BLS signature into one 48-byte aggregate
   * via the kontor-sdk wasm (`blst::AggregateSignature::aggregate`)
   * and embeds it in `Insts.aggregate.signature`. Each fragment
   * supplies one op + one `AggregateSigner` entry, in the same order
   * as `fragments`.
   *
   * The returned bundle has `Inst<unknown>` slots — contributor
   * result types don't survive the serialization boundary, so the
   * aggregator's `wait()` returns the raw WAVE strings.
   */
  combineAggregate(
    fragments: readonly AggregateFragment[],
  ): Insts<unknown[]> {
    if (fragments.length === 0) {
      throw new SignerError(
        "combineAggregate: requires at least one fragment",
        { docsPath: "/sdk/aggregate" },
      );
    }
    const sigs = fragments.map((f) => hex.decode(f.data.signature));
    const aggregatedSig = blsAggregateSignatures(sigs);

    const signers: AggregateSigner[] = fragments.map((f) => ({
      identity: { XOnlyPubkey: f.data.signerXOnlyPubKey },
      nonce: Number(f.data.nonce),
      sponsored: f.data.sponsored,
    }));
    const aggregate: AggregateInfo = {
      signers,
      signature: [...aggregatedSig],
    };

    // Wrap each fragment's wire Inst as an Inst<unknown> for the
    // bundle. The decoder is identity — the aggregator doesn't know
    // contributor result types, so `wait()` surfaces raw WAVE strings.
    const insts: Inst<unknown>[] = fragments.map((f) =>
      wireInstToInst(this, f.data.inst),
    );

    return new Insts<unknown[]>(this, insts, aggregate);
  }

  /**
   * Follow chain events — the indexer-following API. Returns a fresh
   * async iterator over `ChainEvent`s (tx outcomes + reorg signals),
   * attached to the session's already-running poller. Multiple
   * iterators share that one loop.
   *
   *     for await (const event of session.events()) {
   *       if (event.kind === "reorg") {
   *         await store.revertAbove(event.forkHeight);
   *       } else {
   *         await store.apply(event);
   *         await store.checkpoint(event.id);
   *       }
   *     }
   *
   * The poller's resume cursor + filter are set once, at construction,
   * via `KontorSessionOptions.events` — not per call.
   */
  events(): AsyncIterableIterator<ChainEvent> {
    return this.poller.events();
  }

  /**
   * Resolves once the session's poller has reached the indexer — a
   * connectivity / config check. Rejects if the node is unreachable
   * after the poller's bootstrap retries.
   */
  ready(): Promise<void> {
    return this.poller.ready();
  }

  /**
   * Stop the background poller. A `KontorSession` owns a polling loop
   * from construction, so call this once done with the session — e.g.
   * to let a Node process exit cleanly.
   */
  close(): void {
    this.poller.stop();
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

/**
 * Decode a `contract-address` WAVE record into a `ContractAddress`.
 * The shape is `{name: "<n>", height: <u64>, tx-index: <u64>}` — what
 * `to_wave_expr(ContractAddress)` produces on the indexer side.
 *
 * A small custom regex parser rather than a full built-in WIT codec:
 * publish is the only built-in (non-contract) return that the SDK
 * decodes, the format is rigid, and bringing the built-in WIT into
 * the bundle just for this would be wildly over-built. If more
 * built-in returns appear, switch this to a real WIT codec instance.
 */
function decodeContractAddressWave(wave: string): ContractAddress {
  const m = wave.match(
    /^\{\s*name:\s*"([^"]*)"\s*,\s*height:\s*(\d+)\s*,\s*tx-index:\s*(\d+)\s*\}$/,
  );
  if (m == null) {
    throw new Error(
      `expected contract-address WAVE record, got: ${wave}`,
    );
  }
  return new ContractAddress(m[1]!, BigInt(m[2]!), BigInt(m[3]!));
}
