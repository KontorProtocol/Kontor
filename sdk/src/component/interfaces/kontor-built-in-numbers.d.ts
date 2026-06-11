/** @module Interface kontor:built-in/numbers **/
/**
 * # Variants
 * 
 * ## `"plus"`
 * 
 * ## `"minus"`
 */
export type Sign = 'plus' | 'minus';
/**
 * # Variants
 * 
 * ## `"less"`
 * 
 * ## `"equal"`
 * 
 * ## `"greater"`
 */
export type Ordering = 'less' | 'equal' | 'greater';
export interface Integer {
  r0: bigint,
  r1: bigint,
  r2: bigint,
  r3: bigint,
  sign: Sign,
}
export interface Decimal {
  r0: bigint,
  r1: bigint,
  r2: bigint,
  r3: bigint,
  sign: Sign,
}
