/**
 * `@kontor/sdk-native` — the React Native (JSI) backend for `@kontor/sdk`.
 *
 * Re-shapes the uniffi-generated bindings for `core/kontor-mobile`
 * (`./generated/kontor_mobile`, produced by `uniffi-bindgen-react-native`
 * — see `ubrn.config.yaml`) into the exact `KontorBackend` surface the SDK
 * expects, so `sdk/src/backend/backend.native.ts` can `export * from` here.
 *
 * Three impedance mismatches with the WASM (jco) backend are absorbed here
 * so the SDK sees an identical shape on both platforms:
 *   1. bytes    — native uses `ArrayBuffer`, the SDK contract uses `Uint8Array`.
 *   2. sign     — native `Sign` enum ↔ the `"plus" | "minus"` string union.
 *      ordering — native `Ordering` enum ↔ `"less" | "equal" | "greater"`.
 *   3. path     — native `number[]` ← the SDK's `Uint32Array`.
 *
 * The compile-time proof that this satisfies the contract lives in the SDK
 * (`backend.native.ts`: `const _conforms: KontorBackend = native`) and is
 * verified by the mobile CI.
 */
import installer from "./generated/spec/NativeKontorMobile";
import * as gen from "./generated/kontor_mobile";

// Install the Rust crate into the JS runtime (registers the JSI host
// functions the generated FFI reads from `globalThis.NativeKontorMobile`),
// then run the binding self-checks (uniffi contract-version + per-fn
// checksums). Both are idempotent, so re-evaluating this module (e.g. a
// metro reload) is safe. Without this, every `gen.*` call would throw.
installer.installRustCrate();
gen.default.initialize();

// ─── byte conversions (ArrayBuffer ↔ Uint8Array) ─────────────────────
const toU8 = (ab: ArrayBuffer): Uint8Array => new Uint8Array(ab);
// The native bindings want an exact, standalone `ArrayBuffer`. A `Uint8Array`
// that exactly owns a plain ArrayBuffer can hand it over as-is (the FFI only
// reads from it); a view into a larger buffer or a SharedArrayBuffer gets
// copied into a fresh one.
const toAB = (u8: Uint8Array): ArrayBuffer => {
  if (
    u8.byteOffset === 0 &&
    u8.byteLength === u8.buffer.byteLength &&
    u8.buffer instanceof ArrayBuffer
  ) {
    return u8.buffer;
  }
  const ab = new ArrayBuffer(u8.byteLength);
  new Uint8Array(ab).set(u8);
  return ab;
};

// ─── numerics: enum ↔ string-union, and the {r0..r3, sign} record ────
type Sign = "plus" | "minus";
type Ordering = "less" | "equal" | "greater";
/** The jco-shaped numeric record the SDK's Integer/Decimal wrappers hold. */
type Num = { r0: bigint; r1: bigint; r2: bigint; r3: bigint; sign: Sign };

const signToNative = (s: Sign): gen.Sign =>
  s === "plus" ? gen.Sign.Plus : gen.Sign.Minus;
const signToStr = (s: gen.Sign): Sign =>
  s === gen.Sign.Plus ? "plus" : "minus";
const ordToStr = (o: gen.Ordering): Ordering =>
  o === gen.Ordering.Less ? "less" : o === gen.Ordering.Equal ? "equal" : "greater";

// gen.Integer and gen.Decimal are the same shape ({r0..r3: bigint, sign}),
// so one pair of converters serves both.
const toNativeNum = (r: Num): gen.Integer => ({
  r0: r.r0,
  r1: r.r1,
  r2: r.r2,
  r3: r.r3,
  sign: signToNative(r.sign),
});
const fromNativeNum = (r: gen.Integer): Num => ({
  r0: r.r0,
  r1: r.r1,
  r2: r.r2,
  r3: r.r3,
  sign: signToStr(r.sign),
});

// ─── numerics namespace (jco-shaped, all 25 ops) ─────────────────────
export const numerics = {
  u64ToInteger: (i: bigint): Num => fromNativeNum(gen.u64ToInteger(i)),
  s64ToInteger: (i: bigint): Num => fromNativeNum(gen.s64ToInteger(i)),
  stringToInteger: (s: string): Num => fromNativeNum(gen.stringToInteger(s)),
  integerToString: (i: Num): string => gen.integerToString(toNativeNum(i)),
  eqInteger: (a: Num, b: Num): boolean =>
    gen.eqInteger(toNativeNum(a), toNativeNum(b)),
  cmpInteger: (a: Num, b: Num): Ordering =>
    ordToStr(gen.cmpInteger(toNativeNum(a), toNativeNum(b))),
  addInteger: (a: Num, b: Num): Num =>
    fromNativeNum(gen.addInteger(toNativeNum(a), toNativeNum(b))),
  subInteger: (a: Num, b: Num): Num =>
    fromNativeNum(gen.subInteger(toNativeNum(a), toNativeNum(b))),
  mulInteger: (a: Num, b: Num): Num =>
    fromNativeNum(gen.mulInteger(toNativeNum(a), toNativeNum(b))),
  divInteger: (a: Num, b: Num): Num =>
    fromNativeNum(gen.divInteger(toNativeNum(a), toNativeNum(b))),
  sqrtInteger: (i: Num): Num => fromNativeNum(gen.sqrtInteger(toNativeNum(i))),
  integerToDecimal: (i: Num): Num =>
    fromNativeNum(gen.integerToDecimal(toNativeNum(i))),
  decimalToInteger: (d: Num): Num =>
    fromNativeNum(gen.decimalToInteger(toNativeNum(d))),
  u64ToDecimal: (i: bigint): Num => fromNativeNum(gen.u64ToDecimal(i)),
  s64ToDecimal: (i: bigint): Num => fromNativeNum(gen.s64ToDecimal(i)),
  f64ToDecimal: (f: number): Num => fromNativeNum(gen.f64ToDecimal(f)),
  stringToDecimal: (s: string): Num => fromNativeNum(gen.stringToDecimal(s)),
  decimalToString: (d: Num): string => gen.decimalToString(toNativeNum(d)),
  eqDecimal: (a: Num, b: Num): boolean =>
    gen.eqDecimal(toNativeNum(a), toNativeNum(b)),
  cmpDecimal: (a: Num, b: Num): Ordering =>
    ordToStr(gen.cmpDecimal(toNativeNum(a), toNativeNum(b))),
  addDecimal: (a: Num, b: Num): Num =>
    fromNativeNum(gen.addDecimal(toNativeNum(a), toNativeNum(b))),
  subDecimal: (a: Num, b: Num): Num =>
    fromNativeNum(gen.subDecimal(toNativeNum(a), toNativeNum(b))),
  mulDecimal: (a: Num, b: Num): Num =>
    fromNativeNum(gen.mulDecimal(toNativeNum(a), toNativeNum(b))),
  divDecimal: (a: Num, b: Num): Num =>
    fromNativeNum(gen.divDecimal(toNativeNum(a), toNativeNum(b))),
  log10Decimal: (a: Num): Num => fromNativeNum(gen.log10Decimal(toNativeNum(a))),
};

// ─── Wit codec ───────────────────────────────────────────────────────
// The native `Wit` object is a drop-in: `new Wit(text)` + `encodeCall` /
// `decodeResult` match the SDK's `WitCodec` exactly. `parse()` is dev-time
// only and intentionally absent on-device.
export const witCodec = { Wit: gen.Wit };

// ─── free functions (bytes: ArrayBuffer ↔ Uint8Array) ────────────────
export const serializeInst = (jsonStr: string): Uint8Array =>
  toU8(gen.serializeInst(jsonStr));
export const deserializeInst = (bytes: Uint8Array): string =>
  gen.deserializeInst(toAB(bytes));

export const blsSecretKeyGen = (ikm: Uint8Array): Uint8Array =>
  toU8(gen.blsSecretKeyGen(toAB(ikm)));
export const blsSecretFromSeedEip2333 = (
  seed: Uint8Array,
  path: Uint32Array,
): Uint8Array =>
  toU8(gen.blsSecretFromSeedEip2333(toAB(seed), Array.from(path)));
export const blsPubkeyFromSecret = (secret: Uint8Array): Uint8Array =>
  toU8(gen.blsPubkeyFromSecret(toAB(secret)));
export const blsSign = (secret: Uint8Array, message: Uint8Array): Uint8Array =>
  toU8(gen.blsSign(toAB(secret), toAB(message)));
export const blsVerify = (
  pubkey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean => gen.blsVerify(toAB(pubkey), toAB(message), toAB(signature));

export const aggregateSigningMessage = (
  claimJson: string,
  nonce: bigint,
  sponsored: boolean,
  instJson: string,
): Uint8Array =>
  toU8(gen.aggregateSigningMessage(claimJson, nonce, sponsored, instJson));
export const blsAggregateSignatures = (
  signatures: Array<Uint8Array>,
): Uint8Array => toU8(gen.blsAggregateSignatures(signatures.map(toAB)));
