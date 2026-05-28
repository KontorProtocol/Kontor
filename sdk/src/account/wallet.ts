/**
 * Account backed by an external browser wallet (Xverse, Leather,
 * OKX, etc.) via sats-connect. Signing happens in the wallet's
 * sandbox — the SDK never sees the private key.
 *
 * Use this when building browser frontends. For backend services and
 * tests, use `LocalAccount`.
 *
 * The sats-connect API is RPC-style: each `signMessage` / `signPsbt`
 * call dispatches a request to the connected wallet, which prompts
 * the user. The wallet's response includes the signature bytes; we
 * unmarshal them back into the same `Uint8Array` shape `LocalAccount`
 * produces, so callers can stay agnostic.
 */

import { HolderRef } from "../canonical/HolderRef.js";
import { SignerError } from "../errors.js";
import type { Account, SignPsbtOptions } from "./index.js";
import { AccountLock } from "./lock.js";
import type { Chain } from "../chains.js";

export interface ConnectOptions {
  chain: Chain;
  /**
   * Optional preferred wallet identifier (e.g. `"xverse"`,
   * `"leather"`). If omitted, sats-connect shows the wallet picker.
   */
  walletId?: string;
}

export class WalletAccount implements Account {
  readonly xOnlyPubKey: string;
  readonly address: string;
  readonly holderRef: HolderRef;
  private readonly lock = new AccountLock();

  private constructor(xOnlyPubKey: string, address: string) {
    this.xOnlyPubKey = xOnlyPubKey;
    this.address = address;
    this.holderRef = HolderRef.xOnlyPubkey(xOnlyPubKey);
  }

  /**
   * Trigger the wallet's connect flow (the user picks a wallet and
   * approves access). Resolves to a `WalletAccount` bound to the
   * payment address the wallet exposes.
   */
  static connect(_opts: ConnectOptions): Promise<WalletAccount> {
    throw new SignerError("WalletAccount.connect: not implemented", {
      docsPath: "/sdk/account/wallet",
    });
  }

  signMessage(_message: string | Uint8Array): Promise<string> {
    throw new SignerError("WalletAccount.signMessage: not implemented");
  }

  signPsbt(_psbt: Uint8Array, _opts?: SignPsbtOptions): Promise<Uint8Array> {
    throw new SignerError("WalletAccount.signPsbt: not implemented");
  }

  runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    return this.lock.runExclusive(fn);
  }
}
