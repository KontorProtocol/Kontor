/**
 * In-process signer. Holds a secp256k1 private key directly and signs
 * without it leaving the SDK — use it for backend services, CLIs, tests,
 * and the regtest devnet's pre-funded dev key.
 *
 * A `LocalKey` is a `Signing` that carries its own `Identity`. Because it
 * holds the seed it also exposes `schnorr` (so it's BLS-capable). Three
 * constructors, all converging on the same shape:
 *
 *   - `LocalKey.fromPrivateKey({ privateKey, chain })`
 *   - `LocalKey.fromHdKey({ hdKey, chain, ... })`
 *   - `LocalKey.fromMnemonic({ mnemonic, chain, ... })`
 *
 * HD derivation is BIP-86 — `m/86'/coin'/account'/change/address` — with
 * coin type 0 for mainnet and 1 for every test network. Address encoding
 * and PSBT signing run through `@scure/btc-signer`.
 *
 * For browser / wallet-mediated signing, use a `@kontor/sdk/wallets/*`
 * adapter instead.
 */

import { hex } from "@scure/base";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { SigHash, Transaction, p2tr, utils as btcUtils } from "@scure/btc-signer";
import { signSchnorr } from "@scure/btc-signer/utils.js";

import { HolderRef } from "./canonical/HolderRef.js";
import { SignerError } from "./errors.js";
import type { Identity } from "./identity.js";
import type { Signing, SighashKind, SignPsbtOptions } from "./signing.js";
import type { BitcoinNetwork, Chain } from "./chains.js";

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

export class LocalKey implements Signing {
  readonly identity: Identity;

  private constructor(
    /** Raw 32-byte secp256k1 secret. Held for the instance's lifetime. */
    readonly privateKey: Uint8Array,
    network: BitcoinNetwork,
  ) {
    const xOnly = btcUtils.pubSchnorr(privateKey);
    const payment = p2tr(xOnly, undefined, network);
    if (payment.address == null) {
      throw new SignerError("LocalKey: could not derive a P2TR address");
    }
    const xOnlyHex = hex.encode(xOnly);
    this.identity = {
      xOnlyPubKey: xOnlyHex,
      address: payment.address,
      holderRef: HolderRef.xOnlyPubkey(xOnlyHex),
    };
  }

  /**
   * Build a signer from a raw 32-byte private key. The key is held in
   * memory for the lifetime of the instance.
   */
  static fromPrivateKey(opts: FromPrivateKeyOptions): LocalKey {
    const key =
      typeof opts.privateKey === "string"
        ? hexToBytes(opts.privateKey)
        : opts.privateKey;
    if (key.length !== 32) {
      throw new SignerError(`private key must be 32 bytes, got ${key.length}`, {
        docsPath: "/sdk/account",
      });
    }
    return new LocalKey(key, opts.chain.network);
  }

  /**
   * Build a signer from a `@scure/bip32` HD node, deriving the BIP-86
   * (P2TR) child key. The node must be private (a master seed node or an
   * xprv) — an xpub-only node has no private key to sign with.
   */
  static fromHdKey(opts: FromHdKeyOptions): LocalKey {
    const path = opts.path ?? bip86Path(opts.chain, opts);
    const node = opts.hdKey.derive(path);
    if (node.privateKey == null) {
      throw new SignerError(
        "fromHdKey: the derived node has no private key — derive from a " +
          "master seed or an xprv, not an xpub",
        { docsPath: "/sdk/account" },
      );
    }
    return new LocalKey(node.privateKey, opts.chain.network);
  }

  /**
   * Build a signer from a BIP-39 mnemonic, deriving the key via the
   * BIP-86 path `m/86'/coin'/account'/change/address`. `coin` is taken
   * from the chain — 0 for mainnet, 1 for every test network.
   */
  static fromMnemonic(opts: FromMnemonicOptions): LocalKey {
    if (!validateMnemonic(opts.mnemonic, wordlist)) {
      throw new SignerError("fromMnemonic: invalid BIP-39 mnemonic", {
        docsPath: "/sdk/account",
      });
    }
    const seed = mnemonicToSeedSync(opts.mnemonic, opts.passphrase);
    return LocalKey.fromHdKey({
      hdKey: HDKey.fromMasterSeed(seed),
      chain: opts.chain,
      accountIndex: opts.accountIndex,
      changeIndex: opts.changeIndex,
      addressIndex: opts.addressIndex,
    });
  }

  psbt(psbt: Uint8Array, opts?: SignPsbtOptions): Promise<Uint8Array> {
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

  schnorr(digest: Uint8Array): Promise<Uint8Array> {
    if (digest.length !== 32) {
      return Promise.reject(
        new SignerError(`signSchnorr: digest must be 32 bytes, got ${digest.length}`),
      );
    }
    // Deterministic schnorr (no aux rand) — matches the indexer-side
    // `RegistrationProof::new` so the resulting signature is byte-for-byte
    // the shape the chain verifier expects.
    return Promise.resolve(signSchnorr(digest, this.privateKey));
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
