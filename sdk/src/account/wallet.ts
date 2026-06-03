/**
 * Account backed by an external browser wallet (Xverse, Leather, OKX,
 * Magic Eden, Phantom, UniSat, …) reached through a sats-connect-style
 * provider. Signing happens in the wallet's sandbox — the SDK never sees
 * the private key.
 *
 * The provider is an injected `request(method, params)` function (the
 * shape `sats-connect`'s `request` exports). Pass sats-connect's `request`
 * in real apps; tests pass a fake. The SDK does not depend on sats-connect
 * — it only speaks this small request contract, so any conforming provider
 * (a future bespoke adapter, a mock) drops in unchanged.
 *
 * Bitcoin identity model: Kontor identities are x-only **Taproot (P2TR)**
 * keys, so `WalletAccount` binds to the wallet's P2TR address and signs
 * Taproot inputs with it. The user funds that Taproot address (the compose
 * pipeline builds Taproot-only reveal inputs today). BLS is *not* available
 * on a wallet account — it's a seed-holding-only capability, so this
 * implements the base `Account`, not `BlsCapableAccount`.
 */

import { base64, hex } from "@scure/base";
import { SigHash, Transaction } from "@scure/btc-signer";

import { HolderRef } from "../canonical/HolderRef.js";
import { SignerError } from "../errors.js";
import type { Account, SighashKind, SignInput, SignPsbtOptions } from "./index.js";
import { AccountLock } from "./lock.js";
import type { Chain } from "../chains.js";

/** A sats-connect-style RPC response envelope. */
export type WalletRpcResponse =
  | { status: "success"; result: unknown }
  | { status: "error"; error?: { code?: number | string; message?: string } };

/**
 * A sats-connect-style request function. In apps, pass `request` imported
 * from `sats-connect`; in tests, pass a fake that conforms to this shape.
 */
export type WalletRequest = (
  method: string,
  params?: unknown,
) => Promise<WalletRpcResponse>;

export interface ConnectOptions {
  chain: Chain;
  /** sats-connect's `request` (or any conforming provider function). */
  request: WalletRequest;
  /** Prompt shown to the user during the connect request. */
  message?: string;
}

/** `SighashKind` → the numeric sighash sats-connect's `allowedSignHash` wants.
 *  `default` is absent — a default-sighash call omits `allowedSignHash`. */
const SIGHASH_NUMBER: Record<Exclude<SighashKind, "default">, number> = {
  all: SigHash.ALL,
  "single-anyonecanpay": SigHash.SINGLE_ANYONECANPAY,
};

interface AddressEntry {
  address: string;
  publicKey: string;
  addressType?: string;
  purpose?: string;
}

export class WalletAccount implements Account {
  readonly xOnlyPubKey: string;
  readonly address: string;
  readonly holderRef: HolderRef;
  private readonly lock = new AccountLock();

  private constructor(
    private readonly request: WalletRequest,
    xOnlyPubKey: string,
    address: string,
  ) {
    this.xOnlyPubKey = xOnlyPubKey;
    this.address = address;
    this.holderRef = HolderRef.xOnlyPubkey(xOnlyPubKey);
  }

  /**
   * Trigger the wallet's connect flow and bind to its Taproot (P2TR)
   * address. The wallet prompts the user; on approval we read the P2TR
   * address and its x-only public key — Kontor's identity.
   */
  static async connect(opts: ConnectOptions): Promise<WalletAccount> {
    const result = unwrap(
      await opts.request("getAccounts", {
        purposes: ["payment", "ordinals"],
        message: opts.message ?? "Connect your Kontor account",
      }),
      "getAccounts",
    );

    const entries = asAddressEntries(result);
    const taproot = pickTaprootAddress(entries);
    if (taproot == null) {
      throw new SignerError(
        "WalletAccount.connect: the wallet exposed no Taproot (p2tr) address — " +
          "Kontor requires a P2TR identity",
        { docsPath: "/sdk/account/wallet" },
      );
    }

    const hrp = opts.chain.network.bech32;
    if (!taproot.address.startsWith(`${hrp}1p`)) {
      throw new SignerError(
        `WalletAccount.connect: wallet returned a "${taproot.address.slice(0, 6)}…" ` +
          `address, but this session is bound to the "${hrp}" network`,
        { docsPath: "/sdk/account/wallet" },
      );
    }

    return new WalletAccount(
      opts.request,
      normalizeXOnly(taproot.publicKey),
      taproot.address,
    );
  }

  async signMessage(message: string | Uint8Array): Promise<string> {
    const msg = typeof message === "string" ? message : hex.encode(message);
    const result = unwrap(
      await this.request("signMessage", { address: this.address, message: msg }),
      "signMessage",
    ) as { signature?: string };
    if (typeof result.signature !== "string") {
      throw new SignerError("WalletAccount.signMessage: wallet returned no signature");
    }
    return result.signature;
  }

  async signPsbt(psbt: Uint8Array, opts?: SignPsbtOptions): Promise<Uint8Array> {
    if (opts?.inputs == null) {
      // The SDK's signCommit/signReveal always pass an explicit inputs spec
      // (sats-connect-style wallets require one), so we never have to walk
      // the PSBT to discover owned inputs.
      throw new SignerError(
        "WalletAccount.signPsbt requires an explicit `inputs` spec",
        { docsPath: "/sdk/account/wallet" },
      );
    }

    const kind = resolveSighashKind(opts.inputs);

    // Pin the sighash onto the PSBT inputs (like LocalAccount does), not just
    // on sats-connect's `allowedSignHash`. Some wallets derive the sighash to
    // sign with from PSBT_IN_SIGHASH_TYPE, not from allowedSignHash; without
    // the field they'd sign a non-default input (e.g. a SIGHASH_SINGLE|
    // ANYONECANPAY marketplace detach) with the default taproot sighash and
    // produce an invalid signature. Setting both covers either mechanism.
    let outgoing = psbt;
    if (kind !== "default") {
      const flag = SIGHASH_NUMBER[kind];
      const tx = Transaction.fromPSBT(psbt);
      for (const i of opts.inputs) tx.updateInput(i.index, { sighashType: flag });
      outgoing = tx.toPSBT();
    }

    const params: Record<string, unknown> = {
      psbt: base64.encode(outgoing),
      signInputs: { [this.address]: opts.inputs.map((i) => i.index) },
      broadcast: false,
    };
    if (kind !== "default") params.allowedSignHash = SIGHASH_NUMBER[kind];

    const result = unwrap(
      await this.request("signPsbt", params),
      "signPsbt",
    ) as { psbt?: string };
    if (typeof result.psbt !== "string") {
      throw new SignerError("WalletAccount.signPsbt: wallet returned no signed PSBT");
    }
    return base64.decode(result.psbt);
  }

  runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    return this.lock.runExclusive(fn);
  }
}

/** Pull `result` out of the RPC envelope, or throw on a rejection. */
function unwrap(res: WalletRpcResponse, method: string): unknown {
  if (res.status === "success") return res.result;
  const detail = res.error?.message ? `: ${res.error.message}` : "";
  throw new SignerError(`WalletAccount: wallet rejected "${method}"${detail}`, {
    docsPath: "/sdk/account/wallet",
  });
}

/** Normalize the `getAccounts` result into a flat address array. Wallets
 *  return either the array directly or under an `addresses` key. */
function asAddressEntries(result: unknown): AddressEntry[] {
  if (Array.isArray(result)) return result as AddressEntry[];
  const wrapped = (result as { addresses?: AddressEntry[] }).addresses;
  return Array.isArray(wrapped) ? wrapped : [];
}

/** The wallet's Taproot address — preferring the `payment` purpose (where a
 *  taproot-native wallet keeps spendable funds) over `ordinals`. */
function pickTaprootAddress(entries: AddressEntry[]): AddressEntry | undefined {
  const p2tr = entries.filter(
    (e) => e.addressType === "p2tr" || /^(bc|tb|bcrt)1p/.test(e.address),
  );
  return p2tr.find((e) => e.purpose === "payment") ?? p2tr[0];
}

/** A wallet may return the 32-byte x-only key or a 33-byte compressed key;
 *  Kontor's identity is the 32-byte x-only form. */
function normalizeXOnly(publicKey: string): string {
  const h = publicKey.toLowerCase().replace(/^0x/, "");
  if (h.length === 64) return h;
  if (h.length === 66) return h.slice(2); // drop the 02/03 compression prefix byte
  throw new SignerError(
    `WalletAccount: unexpected public key length (${h.length} hex chars)`,
    { docsPath: "/sdk/account/wallet" },
  );
}

/** sats-connect carries a single per-request `allowedSignHash`, so every
 *  input in one call must share a sighash. Our flows do (each party signs
 *  its own inputs under one sighash); a mix is a programming error. */
function resolveSighashKind(inputs: SignInput[]): SighashKind {
  const kinds = new Set(inputs.map((i) => i.sighash ?? "default"));
  if (kinds.size > 1) {
    throw new SignerError(
      "WalletAccount.signPsbt: one signPsbt call can't mix sighash types — " +
        "sats-connect's allowedSignHash is per-request",
      { docsPath: "/sdk/account/wallet" },
    );
  }
  const [kind] = kinds as Set<SighashKind>;
  return kind;
}
