/**
 * Backend selection point.
 *
 * All SDK runtime code imports the crypto / codec / numerics primitives
 * from here rather than reaching into `../component/kontor-sdk.js`
 * directly, so the WASM boundary can be swapped for a platform-native
 * one without touching call sites.
 *
 * Default resolves to the WASM component (`backend.web`). React Native /
 * Metro resolves this module to `backend.native` via the `react-native`
 * conditional export in package.json, which is backed by the
 * `@kontor/sdk-native` module instead of `WebAssembly`.
 */
export * from "./backend.web.js";
