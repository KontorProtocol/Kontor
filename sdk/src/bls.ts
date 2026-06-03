/**
 * BLS12-381 key material (min_sig scheme) for the Kontor validator-
 * registration flow. Thin TS shell around the `kontor-sdk` wasm
 * component — keygen, derivation, and signing all happen in Rust via
 * the same `blst` instance the indexer's reactor uses, so the bytes
 * any `BlsKey` produces are exactly the bytes the chain verifier
 * accepts.
 *
 *   - `BlsKey.generate()`     — random, sourced from `crypto.getRandomValues`
 *   - `BlsKey.fromSeed(...)`  — deterministic, EIP-2333 at the Kontor path
 *   - `BlsKey.fromSecret(...)` — wrap an existing 32-byte secret
 *
 * `signBls(msg)` produces a 48-byte compressed-G1 signature under
 * `KONTOR_BLS_DST` (the indexer-side hash-to-curve domain). The
 * pubkey is 96 bytes (compressed G2).
 */

import { hex } from "@scure/base";
import { utils as btcUtils } from "@scure/btc-signer";
import { sha256 } from "@scure/btc-signer/utils.js";

import type { BlsCapableAccount } from "./account/index.js";
import {
  blsPubkeyFromSecret,
  blsSecretFromSeedEip2333,
  blsSecretKeyGen,
  blsSign,
} from "./component/kontor-sdk.js";
import type { Chain } from "./chains.js";
import { SignerError } from "./errors.js";

/** Minimum input keying material for `blst::key_gen` per the IETF BLS spec. */
const KEY_GEN_IKM_BYTES = 32;
/** Compressed G2 BLS pubkey length (min_sig scheme). */
const BLS_PUBKEY_BYTES = 96;
/** Compressed G1 BLS signature length (min_sig scheme). */
const BLS_SIG_BYTES = 48;
/** Scalar size of a BLS12-381 secret key. */
const BLS_SECRET_BYTES = 32;

/**
 * Kontor BLS derivation path: `m / 12381 / <coin_type> / 0 / 0`, with
 * coin_type 0 for Bitcoin mainnet and 1 for every testnet (matches
 * BIP-44 / EIP-2334 convention, and the indexer's
 * `bls_crypto::bls_derivation_path`).
 */
export function blsDerivationPath(chain: Chain): Uint32Array {
  const coinType = chain.network.bech32 === "bc" ? 0 : 1;
  return new Uint32Array([12381, coinType, 0, 0]);
}

export class BlsKey {
  private constructor(
    /** 32-byte BLS scalar secret. */
    readonly secret: Uint8Array,
    /** 96-byte compressed G2 public key. */
    readonly pubkey: Uint8Array,
  ) {}

  /**
   * Fresh random key. Pulls `KEY_GEN_IKM_BYTES` of entropy from
   * `crypto.getRandomValues` and feeds it to the IETF KeyGen function
   * (HKDF-based) so the resulting scalar is always in-range.
   */
  static generate(): BlsKey {
    const ikm = new Uint8Array(KEY_GEN_IKM_BYTES);
    if (typeof globalThis.crypto?.getRandomValues !== "function") {
      throw new SignerError(
        "BlsKey.generate: globalThis.crypto.getRandomValues is unavailable",
        { docsPath: "/sdk/bls" },
      );
    }
    globalThis.crypto.getRandomValues(ikm);
    const secret = blsSecretKeyGen(ikm);
    return new BlsKey(secret, blsPubkeyFromSecret(secret));
  }

  /**
   * Deterministically derive from a BIP-39 seed via EIP-2333 at the
   * Kontor BLS path for `chain`. Same input → same key, matching the
   * Rust binary's pre-create identity pool.
   */
  static fromSeed(seed: Uint8Array, chain: Chain): BlsKey {
    const secret = blsSecretFromSeedEip2333(seed, blsDerivationPath(chain));
    return new BlsKey(secret, blsPubkeyFromSecret(secret));
  }

  /**
   * Wrap an existing 32-byte BLS secret (recovered from storage, an
   * HD-derivation done outside the SDK, etc.). Throws if the bytes
   * aren't a valid in-range scalar.
   */
  static fromSecret(secret: Uint8Array): BlsKey {
    if (secret.length !== BLS_SECRET_BYTES) {
      throw new SignerError(
        `BlsKey.fromSecret: secret must be ${BLS_SECRET_BYTES} bytes, got ${secret.length}`,
        { docsPath: "/sdk/bls" },
      );
    }
    // blsPubkeyFromSecret throws on out-of-range / malformed scalars,
    // so calling it doubles as validation.
    return new BlsKey(secret, blsPubkeyFromSecret(secret));
  }

  /**
   * BLS-sign `message` under `KONTOR_BLS_DST`. Hash-to-curve happens
   * inside blst — pass the raw bytes the indexer-side verifier expects
   * (e.g. `KONTOR-OP-V1 ++ postcard(...)` for aggregate ops, or
   * `KONTOR_BLS_TO_XONLY_V1 || xonly_pubkey` for the registration
   * proof). Returns a 48-byte compressed G1 signature.
   */
  signBls(message: Uint8Array): Uint8Array {
    return blsSign(this.secret, message);
  }
}

export { BLS_PUBKEY_BYTES, BLS_SECRET_BYTES, BLS_SIG_BYTES };

/** Protocol prefix the schnorr binding signs (`KONTOR_XONLY_TO_BLS_V1`). */
const SCHNORR_BINDING_PREFIX = new TextEncoder().encode("KONTOR_XONLY_TO_BLS_V1");
/** Protocol prefix the BLS binding signs (`KONTOR_BLS_TO_XONLY_V1`). */
const BLS_BINDING_PREFIX = new TextEncoder().encode("KONTOR_BLS_TO_XONLY_V1");

/**
 * Construct the bidirectional binding proof a wallet submits to claim
 * a BLS pubkey for its x-only identity. Internal — `session.registerBls`
 * is the user-facing surface. Mirrors `bls_crypto::RegistrationProof::new`
 * byte-for-byte:
 *
 *   - Schnorr direction: account-key signs `sha256("KONTOR_XONLY_TO_BLS_V1" || bls_pubkey)`
 *   - BLS direction:    bls-key signs `"KONTOR_BLS_TO_XONLY_V1" || xonly_pubkey`
 *     (blst hashes-to-curve internally under `KONTOR_BLS_DST`).
 *
 * Returns the three byte buffers `Inst.RegisterBlsKey` carries on the
 * wire — no separate proof type leaks out of the SDK; callers consume
 * via the generated `Inst.RegisterBlsKey` shape from `bindings`.
 */
export async function buildRegistrationProof(
  account: BlsCapableAccount,
  blsKey: BlsKey,
): Promise<{ blsPubkey: Uint8Array; schnorrSig: Uint8Array; blsSig: Uint8Array }> {
  const schnorrMsg = sha256(
    btcUtils.concatBytes(SCHNORR_BINDING_PREFIX, blsKey.pubkey),
  );
  const schnorrSig = await account.signSchnorr(schnorrMsg);

  const xonly = hex.decode(account.xOnlyPubKey);
  const blsMsg = btcUtils.concatBytes(BLS_BINDING_PREFIX, xonly);
  const blsSig = blsKey.signBls(blsMsg);

  return { blsPubkey: blsKey.pubkey, schnorrSig, blsSig };
}
