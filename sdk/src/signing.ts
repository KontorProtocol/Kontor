/**
 * `Signing` — the capability to authorize an account's actions, kept
 * deliberately separate from the account's identity. A `Signing` is *not*
 * an entity (that's `Identity`); it's the small set of operations the SDK
 * calls into whenever a workflow needs a signature.
 *
 * It carries its own `Identity`: that binding is what makes it impossible
 * to pair a signer with the wrong identity. Implementations:
 *   - `LocalKey` (in-process key; exposes `schnorr` → BLS-capable)
 *   - browser-wallet adapters (PSBT delegation; no `schnorr`)
 */

import type { Identity } from "./identity.js";

/**
 * Per-input sighash for `psbt`. Neutral names rather than raw Bitcoin
 * sighash bytes, so a wallet adapter never has to surface
 * `@scure/btc-signer` types across the wallet boundary.
 *
 * - `default` — taproot's implicit sighash; commits to every input/output.
 * - `all` — `SIGHASH_ALL`.
 * - `single-anyonecanpay` — `SIGHASH_SINGLE | ANYONECANPAY`: commits to
 *   only this input and the output at its index. The marketplace seller
 *   signs the detach input this way.
 */
export type SighashKind = "default" | "all" | "single-anyonecanpay";

/** One input to sign, and the sighash to sign it under. */
export interface SignInput {
  index: number;
  /** Sighash for this input; omitted means `default`. */
  sighash?: SighashKind;
}

export interface SignPsbtOptions {
  /** Which inputs to sign, and under which sighash. Omit to sign every
   *  input that belongs to this identity, each under `default`. */
  inputs?: SignInput[];
}

export interface Signing {
  /** The identity this capability signs for — the binding. */
  readonly identity: Identity;

  /**
   * Sign a PSBT. With `opts.inputs`, only those inputs are signed, each
   * under its requested sighash; otherwise every input belonging to this
   * identity is signed under `default`. Returns the signed PSBT bytes —
   * never finalizes or broadcasts (that's the SDK's job).
   */
  psbt(psbt: Uint8Array, opts?: SignPsbtOptions): Promise<Uint8Array>;

  /**
   * BIP-340 Schnorr-sign a raw 32-byte digest. Present only on
   * seed/key-holding signers — required for the Taproot↔BLS registration
   * binding (`buildRegistrationProof` / `session.registerBls`). Browser
   * wallets don't expose raw Schnorr-over-digest, so wallet `Signing`s
   * omit it. This is **not** BIP-322 message signing.
   */
  schnorr?(digest: Uint8Array): Promise<Uint8Array>;

  /**
   * Sign an arbitrary message (BIP-322 for taproot). Optional — present
   * on wallet signers, absent where unimplemented. Returns base64.
   */
  message?(message: string | Uint8Array): Promise<string>;
}

/** Narrow a `Signing` to one that can produce raw Schnorr signatures
 *  (i.e. is BLS-capable). */
export function canSignSchnorr(
  signing: Signing,
): signing is Signing & { schnorr(digest: Uint8Array): Promise<Uint8Array> } {
  return typeof signing.schnorr === "function";
}
