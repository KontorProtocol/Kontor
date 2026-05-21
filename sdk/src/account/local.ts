/**
 * In-process signer. Holds a private key directly, signs without
 * leaving the SDK. Use this for backend services, CLIs, and tests.
 *
 * Three construction paths:
 *   - `LocalAccount.fromPrivateKey({ privateKey, chain })`
 *   - `LocalAccount.fromHdKey({ hdKey, chain, path? })`
 *   - `LocalAccount.fromMnemonic({ mnemonic, chain, passphrase?, ... })`
 *
 * All three converge on the same shape: a 32-byte secp256k1 secret,
 * the x-only taproot pubkey, and the bech32m address. Signing uses
 * `@scure/btc-signer` (BIP-340 schnorr) — same code Bitcoin Core
 * verifies against, no custom crypto.
 *
 * For browser / wallet-mediated signing, use `WalletAccount` instead.
 */

import { HolderRef } from "../canonical/HolderRef.js";
import { SignerError } from "../errors.js";
import type { Account } from "./index.js";
import type { Chain } from "../chains.js";

export interface FromPrivateKeyOptions {
  /** 32-byte secp256k1 secret, hex string or Uint8Array. */
  privateKey: string | Uint8Array;
  chain: Chain;
}

export interface FromMnemonicOptions {
  /** BIP-39 mnemonic phrase. */
  mnemonic: string;
  chain: Chain;
  /** Optional BIP-39 passphrase. */
  passphrase?: string;
  /** BIP-86 account index (default 0). */
  accountIndex?: number;
  /** BIP-86 address index (default 0). */
  addressIndex?: number;
  /** External (0) vs change (1) chain (default 0). */
  changeIndex?: 0 | 1;
}

export class LocalAccount implements Account {
  readonly xOnlyPubKey: string;
  readonly address: string;
  readonly holderRef: HolderRef;

  private constructor(
    readonly privateKey: Uint8Array,
    xOnlyPubKey: string,
    address: string,
  ) {
    this.xOnlyPubKey = xOnlyPubKey;
    this.address = address;
    this.holderRef = HolderRef.xOnlyPubkey(xOnlyPubKey);
  }

  /**
   * Build an account from a raw private key. The key is held in
   * memory for the lifetime of the instance.
   */
  static fromPrivateKey(_opts: FromPrivateKeyOptions): LocalAccount {
    throw new SignerError("LocalAccount.fromPrivateKey: not implemented", {
      docsPath: "/sdk/account",
    });
  }

  /**
   * Build an account from a BIP-39 mnemonic, deriving the key via the
   * BIP-86 (P2TR) path `m/86'/coinType'/account'/change/address`.
   * `coinType` is taken from the chain (0 for mainnet, 1 for everything
   * else).
   */
  static fromMnemonic(_opts: FromMnemonicOptions): LocalAccount {
    throw new SignerError("LocalAccount.fromMnemonic: not implemented", {
      docsPath: "/sdk/account",
    });
  }

  signMessage(_message: string | Uint8Array): Promise<string> {
    throw new SignerError("LocalAccount.signMessage: not implemented");
  }

  signPsbt(_psbt: Uint8Array, _signInputs?: number[]): Promise<Uint8Array> {
    throw new SignerError("LocalAccount.signPsbt: not implemented");
  }
}
