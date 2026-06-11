// world root:component/root
export interface ValidationError {
  message: string,
  location: string,
}
export type ValidationResult = ValidationResultOk | ValidationResultParseError | ValidationResultValidationErrors;
export interface ValidationResultOk {
  tag: 'ok',
}
export interface ValidationResultParseError {
  tag: 'parse-error',
  val: string,
}
export interface ValidationResultValidationErrors {
  tag: 'validation-errors',
  val: Array<ValidationError>,
}
export type * as KontorBuiltInNumbers from './interfaces/kontor-built-in-numbers.js'; // import kontor:built-in/numbers
export * as witCodec from './interfaces/root-component-wit-codec.js'; // export root:component/wit-codec
export * as numerics from './interfaces/root-component-numerics.js'; // export root:component/numerics
export function serializeInst(jsonStr: string): Uint8Array;
export function deserializeInst(bytes: Uint8Array): string;
export function blsSecretKeyGen(ikm: Uint8Array): Uint8Array;
export function blsSecretFromSeedEip2333(seed: Uint8Array, path: Uint32Array): Uint8Array;
export function blsPubkeyFromSecret(secret: Uint8Array): Uint8Array;
export function blsSign(secret: Uint8Array, message: Uint8Array): Uint8Array;
export function blsVerify(pubkey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
export function aggregateSigningMessage(claimJson: string, nonce: bigint, sponsored: boolean, instJson: string): Uint8Array;
export function blsAggregateSignatures(signatures: Array<Uint8Array>): Uint8Array;
export function validateWit(witContent: string): ValidationResult;
export type Result<T, E> = { tag: 'ok', val: T } | { tag: 'err', val: E };
