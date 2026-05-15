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
export function serializeInst(jsonStr: string): Uint8Array;
export function deserializeInst(bytes: Uint8Array): string;
export function serializeOpReturnData(jsonStr: string): Uint8Array;
export function deserializeOpReturnData(bytes: Uint8Array): string;
export function validateWit(witContent: string): ValidationResult;
