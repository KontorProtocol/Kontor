/**
 * React Native stub for the dev-time WASM component surface.
 *
 * `codegen.ts` (and `index.ts`'s `validateWit` re-export) import the jco
 * component directly for tooling that only ever runs on a developer
 * machine — never on-device. On React Native there is no `WebAssembly`,
 * so the native vite pass aliases `./component/kontor-sdk.js` to this stub
 * to keep the bundle free of the WASM loader.
 *
 * These symbols throw if called at runtime on a device. That is correct:
 * WIT codegen / validation is a build-time concern. The on-device runtime
 * codec comes from the native backend (`backend.native.ts`), not here.
 */
const NOT_ON_DEVICE =
  "This API is dev-time only (WIT codegen/validation) and is not available " +
  "on React Native. Run codegen on your build machine via @kontor/sdk on Node.";

export const witCodec = {
  Wit: class {
    constructor() {
      throw new Error(NOT_ON_DEVICE);
    }
  },
};

export function validateWit(): never {
  throw new Error(NOT_ON_DEVICE);
}
