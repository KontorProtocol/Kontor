/**
 * Web / Node backend — the jco-transpiled WASM component.
 *
 * This is the default `KontorBackend` implementation: every symbol is a
 * direct re-export of `src/component/kontor-sdk.js` (the Rust→WASM
 * component). It carries the full runtime surface the SDK consumes —
 * BLS, Inst (de)serialization, the `Wit` WAVE codec, and `numerics`.
 *
 * The React Native build swaps `./index.ts` for `./backend.native.ts`,
 * which exposes this same surface backed by a native module instead of
 * WASM (Hermes/JSC has no `WebAssembly`). See the `react-native`
 * conditional export in package.json and `backend.native.ts`.
 *
 * Dev-time-only helpers (`Wit.parse()`, `validateWit`) are intentionally
 * NOT part of this backend surface: they run on the developer machine
 * (codegen / CLI), never on-device, so they stay bound to the WASM
 * component directly at their call sites.
 */
import * as component from "../component/kontor-sdk.js";
import type { KontorBackend } from "./types.js";

export {
  witCodec,
  numerics,
  serializeInst,
  deserializeInst,
  blsSecretKeyGen,
  blsSecretFromSeedEip2333,
  blsPubkeyFromSecret,
  blsSign,
  blsVerify,
  aggregateSigningMessage,
  blsAggregateSignatures,
} from "../component/kontor-sdk.js";

// Compile-time proof that the WASM component satisfies the backend
// contract. If the Rust world (`root.wit`) drifts from `KontorBackend`,
// this assignment stops type-checking — the native backend must match
// the same shape.
const _conforms: KontorBackend = component;
void _conforms;
