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

/** The full jco component module — the reference implementation's shape. */
type Component = typeof import("../component/kontor-sdk.js");

/**
 * The backend contract. Free-function signatures are lifted straight off
 * the jco component (so they can never drift from the Rust world; only
 * the *name list* below is hand-kept): `Inst` JSON ↔ canonical bytes,
 * HKDF BLS KeyGen (≥32-byte IKM), EIP-2333 derivation, min_sig
 * pubkey/sign/verify under `KONTOR_BLS_DST`, the per-op contributor
 * signing message (`"KONTOR-OP-V1" ++ postcard(...)`) and signature
 * aggregation. `witCodec`/`numerics` are namespaces, narrowed above to
 * their runtime slices.
 */
export interface KontorBackend
  extends Pick<
    Component,
    | "serializeInst"
    | "deserializeInst"
    | "blsSecretKeyGen"
    | "blsSecretFromSeedEip2333"
    | "blsPubkeyFromSecret"
    | "blsSign"
    | "blsVerify"
    | "aggregateSigningMessage"
    | "blsAggregateSignatures"
  > {
  /** Per-WIT WAVE codec constructor (`new Wit(witText)`). */
  witCodec: { Wit: WitConstructor };

  /** Canonical 256-bit Integer / Decimal arithmetic. */
  numerics: NumericsApi;
}
