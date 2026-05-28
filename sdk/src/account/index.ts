/**
 * `Account` is a *signer* — anything that can produce a signature for
 * an arbitrary message or a Bitcoin PSBT. Whether the key lives
 * in-process (`LocalAccount`) or in an external wallet
 * (`WalletAccount`) is an implementation detail.
 *
 * Concrete implementations live in `./local.ts` and `./wallet.ts`.
 *
 * Why a single interface instead of a discriminated union: every
 * caller treats the two account flavors identically (call signMessage
 * / signPsbt, use the address + xOnlyPubKey). The old SDK's
 * `JsonRpcAccount | LocalAccount` discrimination existed for Viem
 * compatibility but added a `type` field nobody branched on.
 */

import type { HolderRef } from "../canonical/HolderRef.js";

/**
 * Per-input sighash for `signPsbt`. The `Account` interface speaks
 * these neutral names rather than raw Bitcoin sighash bytes, so a
 * `WalletAccount` never has to surface `@scure/btc-signer` types
 * across the wallet boundary.
 *
 * - `default` — taproot's implicit sighash; commits to every input and
 *   output of the transaction.
 * - `all` — `SIGHASH_ALL`.
 * - `single-anyonecanpay` — `SIGHASH_SINGLE | ANYONECANPAY`: commits to
 *   only this input and the output at its index, leaving the rest of
 *   the transaction open for others to complete. The marketplace
 *   seller signs the detach input this way.
 */
export type SighashKind = "default" | "all" | "single-anyonecanpay";

/** One input to sign, and the sighash to sign it under. */
export interface SignInput {
  /** Input index within the PSBT. */
  index: number;
  /** Sighash for this input; omitted means `default`. */
  sighash?: SighashKind;
}

export interface SignPsbtOptions {
  /**
   * Which inputs to sign, and under which sighash. Omit to sign every
   * input that belongs to this account, each under `default`.
   */
  inputs?: SignInput[];
}

export interface Account {
  /** Taproot x-only public key, lowercase hex. */
  readonly xOnlyPubKey: string;
  /** Bech32m-encoded P2TR address for this account on its bound chain. */
  readonly address: string;
  /**
   * Canonical `HolderRef` for this account (the `x-only-pubkey`
   * variant). Cached so callers can pass it directly into contract
   * methods without reconstructing.
   */
  readonly holderRef: HolderRef;

  /**
   * Sign an arbitrary message (BIP-322 for taproot accounts).
   * Returns the signature as base64 — the standard wire format that
   * sats-connect-style wallets emit.
   */
  signMessage(message: string | Uint8Array): Promise<string>;

  /**
   * Sign a PSBT. With `opts.inputs`, only those inputs are signed, each
   * under its requested sighash; otherwise every input that belongs to
   * this account is signed under `default`.
   *
   * Returns the signed PSBT bytes. Implementations don't broadcast —
   * that's the transport's job.
   */
  signPsbt(psbt: Uint8Array, opts?: SignPsbtOptions): Promise<Uint8Array>;

  /**
   * Serialize broadcast-mutating sequences that read or update this
   * account's funding state. The transport's `submitReveal`,
   * `inspect`, and `simulate` paths all route through here so two
   * concurrent flows — even on separate transports binding the same
   * Account — won't race on funding selection or change tracking.
   *
   * The body runs with no other locked body in flight; queued callers
   * resume in FIFO order. Re-entry from within a held body deadlocks
   * — don't call `runExclusive` from inside a `prepare` callback or
   * any other locked critical section.
   */
  runExclusive<T>(fn: () => Promise<T>): Promise<T>;
}
