/**
 * `Identity` — who an account is, as a plain serializable value: the
 * x-only Taproot pubkey, its P2TR address on the bound chain, and the
 * canonical `HolderRef`. No key material; safe to construct on a server
 * and pass to read-only flows (`view`, `compose`, `simulate`).
 *
 * A `Signing` (see `./signing.ts`) carries its own `Identity` — that's
 * the binding that makes identity and key impossible to mismatch. A bare
 * `Identity` (no signing) is used for read-only sessions and for naming
 * recipients.
 */

import { hex } from "@scure/base";
import { p2tr } from "@scure/btc-signer";

import { HolderRef } from "./canonical/HolderRef.js";
import { SignerError } from "./errors.js";
import type { Chain } from "./chains.js";

export interface Identity {
  /** Taproot x-only public key, lowercase hex. */
  readonly xOnlyPubKey: string;
  /** Bech32m-encoded P2TR address for this identity on its bound chain. */
  readonly address: string;
  /** Canonical `HolderRef` (the `x-only-pubkey` variant). */
  readonly holderRef: HolderRef;
}

// Type + value of the same name: `Identity` is both the interface above
// and this namespace of constructors.
export const Identity = {
  /** Build an `Identity` from an x-only pubkey, deriving its P2TR address
   *  on `chain`. Used for read-only sessions and naming recipients. */
  fromXOnly(xOnlyPubKey: string, chain: Chain): Identity {
    const lower = xOnlyPubKey.toLowerCase().replace(/^0x/, "");
    const payment = p2tr(hex.decode(lower), undefined, chain.network);
    if (payment.address == null) {
      throw new SignerError(
        "Identity.fromXOnly: could not derive a P2TR address",
      );
    }
    return {
      xOnlyPubKey: lower,
      address: payment.address,
      holderRef: HolderRef.xOnlyPubkey(lower),
    };
  },
};
