/**
 * React Native backend — the `@kontor/sdk-native` native module.
 *
 * Fulfils the same `KontorBackend` contract as `backend.web.ts`, but
 * backed by a native library (uniffi bindings over `core/kontor-mobile`,
 * exposed to JS through a JSI Turbo Module) instead of the WASM component,
 * because Hermes/JSC has no `WebAssembly`.
 *
 * This file is NOT part of the web/Node build: it is excluded from the
 * default vite/dts pass (it imports `@kontor/sdk-native`, a peer that only
 * exists in a mobile app). The React Native bundle (`KONTOR_TARGET=native`
 * vite pass) aliases `./backend/index` to this module. It is type-checked
 * and exercised in the mobile CI, where `@kontor/sdk-native` is built.
 *
 * Dev-time helpers (`Wit.parse`, `validateWit`) are absent by contract —
 * see `types.ts`.
 */
import * as native from "@kontor/sdk-native";

import type { KontorBackend } from "./types.js";

// Compile-time proof the native module satisfies the same contract as the
// WASM backend. Verified in the mobile CI (where the module is built).
const _conforms: KontorBackend = native;
void _conforms;

export const {
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
} = native;
