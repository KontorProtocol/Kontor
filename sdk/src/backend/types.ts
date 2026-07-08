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
 * Component value exports that are NOT part of the on-device runtime
 * contract. `validateWit` is dev-time-only (WIT validation on a build
 * machine); `witCodec` is subtracted here so it can be re-added below
 * narrowed to its runtime methods (dropping the codegen-only `Wit.parse`).
 * This is the ONLY hand-kept list — and it shrinks, not grows, as the world
 * evolves.
 */
type DevOnly = "validateWit" | "witCodec";

/**
 * The on-device runtime surface every backend must satisfy — derived by
 * SUBTRACTION from the jco component (`Omit`), not a hand-kept allow-list.
 * `typeof import(...)` yields only the component's value exports (the BLS
 * suite, `Inst` (de)serialization, `numerics`, the codecs), so every new
 * runtime export the Rust world (`core/kontor-sdk/wit/root.wit`) gains
 * AUTOMATICALLY joins this contract. The payoff: the moment the component
 * grows a function, `const _conforms: KontorBackend = native` in
 * `backend.native.ts` stops compiling until `kontor-sdk-native` exposes it
 * too — you can't silently ship a native module that's missing something.
 * Only `DevOnly` (small, stable) is maintained by hand.
 */
export type KontorBackend = Omit<Component, DevOnly> & {
  /** Per-WIT WAVE codec constructor (`new Wit(witText)`), runtime methods only. */
  witCodec: { Wit: WitConstructor };
};
