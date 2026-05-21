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
   * Sign a PSBT in-place. If `signInputs` is provided, only those
   * input indices are signed; otherwise the implementation signs every
   * input that belongs to this account.
   *
   * Returns the signed PSBT bytes. Implementations don't broadcast —
   * that's `transport.broadcastTransaction(...)`'s job.
   */
  signPsbt(psbt: Uint8Array, signInputs?: number[]): Promise<Uint8Array>;
}
