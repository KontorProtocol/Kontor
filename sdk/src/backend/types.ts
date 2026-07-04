/**
 * `KontorBackend` — the contract every backend implementation must
 * satisfy.
 *
 * This is the exact on-device runtime surface the SDK consumes from the
 * Rust core: BLS key material + signing, `Inst` (de)serialization, the
 * `Wit` WAVE codec, and `numerics` arithmetic. The web/Node backend
 * (`backend.web.ts`) fulfils it with the jco WASM component; the planned
 * React Native backend (`backend.native.ts`, `@kontor/sdk-native`) will
 * fulfil the *same* shape with a native module built from the same Rust
 * crate — see the mobile plan.
 *
 * Dev-time-only helpers (`Wit.parse()`, `validateWit`) are deliberately
 * absent: they run on the developer machine (codegen / CLI), never
 * on-device, so they stay bound to the WASM component at their call sites
 * and are not part of this backend contract.
 *
 * Types are sourced from the jco-generated component declarations so this
 * interface stays in lockstep with the Rust world definition
 * (`core/kontor-sdk/wit/root.wit`).
 */
import type { Wit as ComponentWit } from "../component/interfaces/root-component-wit-codec.js";
import type * as ComponentNumerics from "../component/interfaces/root-component-numerics.js";

/** The numerics namespace surface (Integer/Decimal ops + record types). */
export type NumericsApi = typeof ComponentNumerics;

/**
 * The runtime slice of the `Wit` codec a backend must expose. Every
 * generated contract instantiates one per WIT document and calls
 * `encodeCall` / `decodeResult` on it (see `contract-base.ts`). `parse`
 * is codegen-only and not required on-device.
 */
export type WitCodec = Pick<ComponentWit, "encodeCall" | "decodeResult">;

/** Constructs a per-contract WAVE codec from a WIT source string. */
export type WitConstructor = new (text: string) => WitCodec;

export interface KontorBackend {
  /** Per-WIT WAVE codec constructor (`new Wit(witText)`). */
  witCodec: { Wit: WitConstructor };

  /** Canonical 256-bit Integer / Decimal arithmetic. */
  numerics: NumericsApi;

  /** Canonical `Inst` JSON → bytes. */
  serializeInst(jsonStr: string): Uint8Array;
  /** Canonical `Inst` bytes → JSON. */
  deserializeInst(bytes: Uint8Array): string;

  /** HKDF-based BLS KeyGen from ≥32 bytes of IKM. */
  blsSecretKeyGen(ikm: Uint8Array): Uint8Array;
  /** Deterministic EIP-2333 derivation along `path`. */
  blsSecretFromSeedEip2333(seed: Uint8Array, path: Uint32Array): Uint8Array;
  /** 96-byte compressed G2 pubkey (min_sig). */
  blsPubkeyFromSecret(secret: Uint8Array): Uint8Array;
  /** 48-byte compressed G1 signature under `KONTOR_BLS_DST`. */
  blsSign(secret: Uint8Array, message: Uint8Array): Uint8Array;
  /** Single-signature verify; `false` on well-formed non-verifying sig. */
  blsVerify(
    pubkey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): boolean;

  /** Per-op contributor signing message (`"KONTOR-OP-V1" ++ postcard(...)`). */
  aggregateSigningMessage(
    claimJson: string,
    nonce: bigint,
    sponsored: boolean,
    instJson: string,
  ): Uint8Array;
  /** Combine per-op signatures into one 48-byte aggregate signature. */
  blsAggregateSignatures(signatures: Array<Uint8Array>): Uint8Array;
}
