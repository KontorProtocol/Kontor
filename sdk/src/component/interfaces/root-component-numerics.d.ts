/** @module Interface root:component/numerics **/
export function u64ToInteger(i: bigint): Integer;
export function s64ToInteger(i: bigint): Integer;
export function stringToInteger(s: string): Integer;
export function integerToString(i: Integer): string;
export function eqInteger(a: Integer, b: Integer): boolean;
export function cmpInteger(a: Integer, b: Integer): Ordering;
export function addInteger(a: Integer, b: Integer): Integer;
export function subInteger(a: Integer, b: Integer): Integer;
export function mulInteger(a: Integer, b: Integer): Integer;
export function divInteger(a: Integer, b: Integer): Integer;
export function sqrtInteger(i: Integer): Integer;
export function integerToDecimal(i: Integer): Decimal;
export function decimalToInteger(d: Decimal): Integer;
export function u64ToDecimal(i: bigint): Decimal;
export function s64ToDecimal(i: bigint): Decimal;
export function f64ToDecimal(f: number): Decimal;
export function stringToDecimal(s: string): Decimal;
export function decimalToString(d: Decimal): string;
export function eqDecimal(a: Decimal, b: Decimal): boolean;
export function cmpDecimal(a: Decimal, b: Decimal): Ordering;
export function addDecimal(a: Decimal, b: Decimal): Decimal;
export function subDecimal(a: Decimal, b: Decimal): Decimal;
export function mulDecimal(a: Decimal, b: Decimal): Decimal;
export function divDecimal(a: Decimal, b: Decimal): Decimal;
export function log10Decimal(a: Decimal): Decimal;
export type Sign = import('./kontor-built-in-numbers.js').Sign;
export type Ordering = import('./kontor-built-in-numbers.js').Ordering;
export type Integer = import('./kontor-built-in-numbers.js').Integer;
export type Decimal = import('./kontor-built-in-numbers.js').Decimal;
export type NumericsError = NumericsErrorMessage | NumericsErrorOverflow | NumericsErrorDivByZero | NumericsErrorSyntax | NumericsErrorValidation;
export interface NumericsErrorMessage {
  tag: 'message',
  val: string,
}
export interface NumericsErrorOverflow {
  tag: 'overflow',
  val: string,
}
export interface NumericsErrorDivByZero {
  tag: 'div-by-zero',
  val: string,
}
export interface NumericsErrorSyntax {
  tag: 'syntax',
  val: string,
}
export interface NumericsErrorValidation {
  tag: 'validation',
  val: string,
}
