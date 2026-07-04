/**
 * `KontorSession` is the execution surface for the SDK. Bind a chain
 * and account once; instantiate Contract classes against deployments
 * via `bind(ContractClass, address)`; execute Insts (single, bulk, or
 * aggregate) through the session.
 *
 *     const session = new KontorSession({ chain: signet, signing });
 *     const token = session.bind(Token, "token@0.0");
 *
 *     // View — Promise<T> directly, hits transport.view (no tx)
 *     const balance = await token.balance(session.identity.holderRef);
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
 *     const fragment = await token.transfer(dst, amt).signForAggregate(blsKey);
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
import type { BuildProvenance, ProvenanceEntry } from "./provenance.js";
import { canSignSchnorr, type Signing } from "./signing.js";
import type { Identity } from "./identity.js";
import type { FundingSource } from "./funding.js";
import { BlsKey, buildRegistrationProof } from "./bls.js";
import type { Chain } from "./chains.js";
import { hex } from "@scure/base";

import type {
  AggregateInfo,
  AggregateSigner,
  FootprintResponse,
  Inst as WireInst,
} from "./bindings.js";
import { blsAggregateSignatures } from "./backend/index.js";
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
  /**
   * The signing capability for this session. Carries its own `identity`
   * (so identity and key can't be mismatched). Omit for a **read-only**
   * session — pass `identity` instead. A read-only session can `view`
   * (and is safe to build on a server / in an RSC); `submit` / `inspect`
   * / `simulate` / `registerBls` throw.
   */
  signing?: Signing;
  /**
   * Identity for a read-only session, when no `signing` is given. Ignored
   * if `signing` is present (its `signing.identity` wins). A plain
   * serializable value — no key material — so it's safe server-side.
   */
  identity?: Identity;
  /**
   * Where the default transport gets spendable UTXOs (and reports back
   * spent/change). Use `inMemoryFunding([utxo])` for optimistic chaining
   * or `queryFunding(fetch)` for a stateless wallet/indexer source. Omit
   * for read-only sessions (submit/inspect/simulate then throw). Ignored
   * when a custom `transport` is supplied — that factory owns funding.
   */
  funding?: FundingSource;
  /**
   * Override the default `HttpTransport`. Useful for tests (swap in a
   * mock) or for custom backends that proxy through a different
   * protocol. `feeRate` mirrors `KontorSessionOptions.feeRate` so a
   * custom transport can honor the session-level default.
   */
  transport?: (opts: {
    chain: Chain;
    identity: Identity;
    /** Absent for a read-only session. */
    signing: Signing | undefined;
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
  /** The signing capability bound to this session, or `undefined` for a
   *  read-only session. */
  readonly signing: Signing | undefined;
  /** Who this session acts as — from `signing.identity` or the read-only
   *  `identity` option. */
  readonly identity: Identity;
  /** Public so `Inst<T>` / `Insts<T>` can route through it directly. */
  readonly transport: KontorTransport;
  /** Default gas cap for proc `Inst`s; see `KontorSessionOptions`. */
  readonly defaultGasLimit: bigint;
  /** Default sat/vB for every Reveal the SDK composes; `null` = let the
   *  indexer pick its current `fastest_fee`. */
  readonly feeRate: number | null;
  /**
   * The session's results poller — one shared loop. Started lazily on the
   * first `events()` / `ready()` (and thus `submit().wait()`), so just
   * constructing a session has no side effects and a read-only / view-only
   * session never starts a loop. `close()` stops it.
   */
  private readonly poller: ResultsPoller;

  constructor(opts: KontorSessionOptions) {
    const identity = opts.signing?.identity ?? opts.identity;
    if (identity == null) {
      throw new SignerError(
        "KontorSession requires `signing` (read+write) or `identity` (read-only)",
        { docsPath: "/sdk/session" },
      );
    }
    this.chain = opts.chain;
    this.signing = opts.signing;
    this.identity = identity;
    this.defaultGasLimit = opts.defaultGasLimit ?? DEFAULT_GAS_LIMIT;
    this.feeRate = opts.feeRate ?? null;
    const make =
      opts.transport ??
      (({ chain, identity, signing, feeRate }) =>
        new HttpTransport({
          chain,
          identity,
          signing,
          funding: opts.funding,
          feeRate: feeRate ?? undefined,
        }));
    this.transport = make({
      chain: opts.chain,
      identity: this.identity,
      signing: opts.signing,
      feeRate: this.feeRate,
    });
    this.poller = new ResultsPoller({
      baseUrl: opts.chain.urls.http,
      fetch: opts.fetch ?? globalThis.fetch.bind(globalThis),
      from: opts.events?.from,
      filter: opts.events?.filter,
    });
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
  publish(
    name: string,
    bytes: Uint8Array,
    provenance: BuildProvenance,
  ): Inst<ContractAddress> {
    return new Inst<ContractAddress>(
      this,
      this.defaultGasLimit,
      { kind: "Publish", name, bytes, provenance },
      decodeContractAddressWave,
    );
  }

  /**
   * Append a new build-provenance claim to a contract's provenance log.
   * Only the contract's publisher may do this (the reactor enforces it);
   * use it when the source moves (repo renamed/migrated) or to correct a
   * claim. Broadcasts + waits for confirmation. Returns no value.
   */
  async updateProvenance(
    contract: ContractAddress,
    provenance: BuildProvenance,
  ): Promise<void> {
    const inst = new Inst<void>(
      this,
      this.defaultGasLimit,
      { kind: "UpdateProvenance", contract, provenance },
      () => undefined,
    );
    await inst;
  }

  /**
   * Read a contract's append-only build-provenance log (oldest first; the
   * last entry is the current claim). Empty if the contract has none.
   */
  getProvenance(contract: ContractAddress): Promise<ProvenanceEntry[]> {
    return this.transport.provenance(contract);
  }

  /**
   * Read a signer's storage-deposit footprint — the token deposit they
   * collateralize (their floor) and live bytes held, broken down by contract.
   * `identifier` is a signer_id, x-only pubkey hex, or BLS pubkey hex. `null`
   * if no such signer; a signer with no deposited storage returns zeroed totals.
   */
  getFootprint(identifier: string): Promise<FootprintResponse | null> {
    return this.transport.signerFootprint(identifier);
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
    const signing = this.signing;
    if (signing == null || !canSignSchnorr(signing)) {
      throw new SignerError(
        "registerBls requires a seed-holding (BLS-capable) signer — a " +
          "read-only or browser-wallet session can't produce the Taproot↔BLS " +
          "binding signature",
        { docsPath: "/sdk/bls" },
      );
    }
    const proof = await buildRegistrationProof(signing, blsKey);
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
  combineAggregate(fragments: readonly AggregateFragment[]): Insts<unknown[]> {
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
   * Throw if this session can't broadcast (read-only — built with a bare
   * `identity`, no `signing`). The submit paths call this *before*
   * `events()`, so a read-only `submit()` fails without the side effect of
   * starting the background poller. Keeps a read-only session genuinely
   * side-effect-free / server-safe even if `submit` is called by mistake.
   */
  assertWritable(): void {
    if (this.signing == null) {
      throw new SignerError(
        "submit requires a signer — this is a read-only session (construct " +
          "with `signing`)",
        { docsPath: "/sdk/session" },
      );
    }
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
    this.poller.start(); // idempotent — lazy-starts the loop on first use
    return this.poller.events();
  }

  /**
   * Resolves once the session's poller has reached the indexer — a
   * connectivity / config check. Rejects if the node is unreachable
   * after the poller's bootstrap retries.
   */
  ready(): Promise<void> {
    this.poller.start(); // idempotent — lazy-starts the loop on first use
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
    throw new Error(`expected contract-address WAVE record, got: ${wave}`);
  }
  return new ContractAddress(m[1]!, BigInt(m[2]!), BigInt(m[3]!));
}
