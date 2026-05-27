// world root:component/root
export type SignerRef = SignerRefSignerId | SignerRefXOnlyPubkey;
export interface SignerRefSignerId {
  tag: 'signer-id',
  val: bigint,
}
export interface SignerRefXOnlyPubkey {
  tag: 'x-only-pubkey',
  val: string,
}
export interface OpReturnEntry {
  inputIndex: number,
  recipient: SignerRef,
}
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
export * as witCodec from './interfaces/root-component-wit-codec.js'; // export root:component/wit-codec
export * as numerics from './interfaces/root-component-numerics.js'; // export root:component/numerics
export function serializeInst(jsonStr: string): Uint8Array;
export function deserializeInst(bytes: Uint8Array): string;
export function encodeOpReturn(entries: Array<OpReturnEntry>): Uint8Array;
export function decodeOpReturn(bytes: Uint8Array): Array<OpReturnEntry>;
export function validateWit(witContent: string): ValidationResult;
export type Result<T, E> = { tag: 'ok', val: T } | { tag: 'err', val: E };
