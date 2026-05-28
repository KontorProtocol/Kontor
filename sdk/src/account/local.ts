/**
 * In-process signer. Holds a secp256k1 private key directly and signs
 * without it leaving the SDK — use it for backend services, CLIs,
 * tests, and the regtest devnet's pre-funded dev key.
 *
 * Three constructors, all converging on the same shape: a 32-byte
 * secret, the BIP-340 x-only taproot pubkey, and the bech32m P2TR
 * address for the bound chain.
 *
 *   - `LocalAccount.fromPrivateKey({ privateKey, chain })`
 *   - `LocalAccount.fromHdKey({ hdKey, chain, ... })`
 *   - `LocalAccount.fromMnemonic({ mnemonic, chain, ... })`
 *
 * HD derivation is BIP-86 — `m/86'/coin'/account'/change/address` —
 * with coin type 0 for mainnet and 1 for every test network. Address
 * encoding and PSBT signing run through `@scure/btc-signer`, the same
 * primitives Bitcoin Core verifies against; no custom crypto here.
 *
 * For browser / wallet-mediated signing, use `WalletAccount` instead.
 */

import { hex } from "@scure/base";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { SigHash, Transaction, p2tr, utils as btcUtils } from "@scure/btc-signer";

import { HolderRef } from "../canonical/HolderRef.js";
import { SignerError } from "../errors.js";
import type { Account, SighashKind, SignPsbtOptions } from "./index.js";
import { AccountLock } from "./lock.js";
import type { BitcoinNetwork, Chain } from "../chains.js";

/** `SighashKind` → the `@scure/btc-signer` sighash flag. `default` is
 *  absent: a default-sighash input gets no explicit `sighashType`. */
const SCURE_SIGHASH: Record<Exclude<SighashKind, "default">, SigHash> = {
  all: SigHash.ALL,
  "single-anyonecanpay": SigHash.SINGLE_ANYONECANPAY,
};

/** BIP-86 path components beyond purpose and coin type. */
export interface Bip86Indices {
  /** Account index — the `account'` component. Default 0. */
  accountIndex?: number;
  /** External (0) vs change (1) chain. Default 0. */
  changeIndex?: 0 | 1;
  /** Address index — the final component. Default 0. */
  addressIndex?: number;
}

export interface FromPrivateKeyOptions {
  /** 32-byte secp256k1 secret, hex string or `Uint8Array`. */
  privateKey: string | Uint8Array;
  chain: Chain;
}

export interface FromHdKeyOptions extends Bip86Indices {
  /** A `@scure/bip32` HD node — must carry a private key. */
  hdKey: HDKey;
  chain: Chain;
  /**
   * Full derivation path override. When set, the `*Index` options are
   * ignored; when omitted, the BIP-86 path is built from them plus the
   * chain's coin type.
   */
  path?: string;
}

export interface FromMnemonicOptions extends Bip86Indices {
  /** BIP-39 mnemonic phrase. */
  mnemonic: string;
  chain: Chain;
  /** Optional BIP-39 passphrase ("25th word"). */
  passphrase?: string;
}

export class LocalAccount implements Account {
  readonly xOnlyPubKey: string;
  readonly address: string;
  readonly holderRef: HolderRef;
  private readonly lock = new AccountLock();

  private constructor(
    /** Raw 32-byte secp256k1 secret. Held for the instance's lifetime. */
    readonly privateKey: Uint8Array,
    network: BitcoinNetwork,
  ) {
    const xOnly = btcUtils.pubSchnorr(privateKey);
    const payment = p2tr(xOnly, undefined, network);
    if (payment.address == null) {
      throw new SignerError("LocalAccount: could not derive a P2TR address");
    }
    this.xOnlyPubKey = hex.encode(xOnly);
    this.address = payment.address;
    this.holderRef = HolderRef.xOnlyPubkey(this.xOnlyPubKey);
  }

  /**
   * Build an account from a raw 32-byte private key. The key is held in
   * memory for the lifetime of the instance.
   */
  static fromPrivateKey(opts: FromPrivateKeyOptions): LocalAccount {
    const key =
      typeof opts.privateKey === "string"
        ? hexToBytes(opts.privateKey)
        : opts.privateKey;
    if (key.length !== 32) {
      throw new SignerError(
        `private key must be 32 bytes, got ${key.length}`,
        { docsPath: "/sdk/account" },
      );
    }
    return new LocalAccount(key, opts.chain.network);
  }

  /**
   * Build an account from a `@scure/bip32` HD node, deriving the BIP-86
   * (P2TR) child key. The node must be private (a master seed node or
   * an xprv) — an xpub-only node has no private key to sign with.
   */
  static fromHdKey(opts: FromHdKeyOptions): LocalAccount {
    const path = opts.path ?? bip86Path(opts.chain, opts);
    const node = opts.hdKey.derive(path);
    if (node.privateKey == null) {
      throw new SignerError(
        "fromHdKey: the derived node has no private key — derive from a " +
          "master seed or an xprv, not an xpub",
        { docsPath: "/sdk/account" },
      );
    }
    return new LocalAccount(node.privateKey, opts.chain.network);
  }

  /**
   * Build an account from a BIP-39 mnemonic, deriving the key via the
   * BIP-86 path `m/86'/coin'/account'/change/address`. `coin` is taken
   * from the chain — 0 for mainnet, 1 for every test network.
   */
  static fromMnemonic(opts: FromMnemonicOptions): LocalAccount {
    if (!validateMnemonic(opts.mnemonic, wordlist)) {
      throw new SignerError("fromMnemonic: invalid BIP-39 mnemonic", {
        docsPath: "/sdk/account",
      });
    }
    const seed = mnemonicToSeedSync(opts.mnemonic, opts.passphrase);
    return LocalAccount.fromHdKey({
      hdKey: HDKey.fromMasterSeed(seed),
      chain: opts.chain,
      accountIndex: opts.accountIndex,
      changeIndex: opts.changeIndex,
      addressIndex: opts.addressIndex,
    });
  }

  signMessage(_message: string | Uint8Array): Promise<string> {
    return Promise.reject(
      new SignerError(
        "LocalAccount.signMessage: not yet implemented — BIP-322 message " +
          "signing lands with the wallet/auth work, not the contract-call path",
        { docsPath: "/sdk/account" },
      ),
    );
  }

  signPsbt(psbt: Uint8Array, opts?: SignPsbtOptions): Promise<Uint8Array> {
    let tx: Transaction;
    try {
      tx = Transaction.fromPSBT(psbt);
    } catch (cause) {
      return Promise.reject(
        new SignerError("signPsbt: input is not a valid PSBT", {
          cause: cause instanceof Error ? cause : undefined,
        }),
      );
    }
    try {
      if (opts?.inputs == null) {
        // Whole-PSBT, default sighash — every input this key can sign.
        tx.sign(this.privateKey);
      } else {
        for (const { index, sighash } of opts.inputs) {
          if (sighash == null || sighash === "default") {
            tx.signIdx(this.privateKey, index);
          } else {
            // A non-default sighash must be pinned on the input before
            // signing, and passed as the allowed set so scure accepts it.
            const flag = SCURE_SIGHASH[sighash];
            tx.updateInput(index, { sighashType: flag });
            tx.signIdx(this.privateKey, index, [flag]);
          }
        }
      }
    } catch (cause) {
      return Promise.reject(
        new SignerError("signPsbt: signing failed", {
          cause: cause instanceof Error ? cause : undefined,
        }),
      );
    }
    return Promise.resolve(tx.toPSBT());
  }

  runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    return this.lock.runExclusive(fn);
  }
}

const BIP86_PURPOSE = 86;

/** BIP-44 coin type: 0 for Bitcoin mainnet, 1 for every test network. */
function coinType(chain: Chain): 0 | 1 {
  return chain.network.bech32 === "bc" ? 0 : 1;
}

/** Build the BIP-86 P2TR derivation path for `chain` and `idx`. */
function bip86Path(chain: Chain, idx: Bip86Indices): string {
  const account = idx.accountIndex ?? 0;
  const change = idx.changeIndex ?? 0;
  const address = idx.addressIndex ?? 0;
  return `m/${BIP86_PURPOSE}'/${coinType(chain)}'/${account}'/${change}/${address}`;
}

/** Decode a hex private key (optionally `0x`-prefixed) to bytes. */
function hexToBytes(s: string): Uint8Array {
  try {
    return hex.decode(s.startsWith("0x") ? s.slice(2) : s);
  } catch (cause) {
    throw new SignerError("private key is not valid hex", {
      cause: cause instanceof Error ? cause : undefined,
    });
  }
}
