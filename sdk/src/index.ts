// Public API. We deliberately don't re-export jco's `witCodec` namespace
// since its only export is the `Wit` resource, which we expose directly.
import { witCodec } from "./component/kontor-sdk.js";
export const Wit = witCodec.Wit;
export type Wit = InstanceType<typeof witCodec.Wit>;

export {
  numerics,
  serializeInst,
  deserializeInst,
  serializeOpReturnData,
  deserializeOpReturnData,
  validateWit,
} from "./component/kontor-sdk.js";
export type {
  ValidationError,
  ValidationResult,
  ValidationResultOk,
  ValidationResultParseError,
  ValidationResultValidationErrors,
} from "./component/kontor-sdk.js";

export type * from "./bindings";
export { generate } from "./codegen";
export type { KontorTransport } from "./json-codec";
// Client-layer types referenced by codegen output. Full client-layer
// exports (values: KontorSession, Account, ...) land with the runtime
// implementation; codegen only needs the types.
export type { KontorSession } from "./session";
export type { Inst } from "./inst";
export { Decimal } from "./canonical/Decimal";
export { Integer } from "./canonical/Integer";
export { HolderRef } from "./canonical/HolderRef";
export type { OutPoint } from "./canonical/HolderRef";
export { ContractAddress } from "./canonical/ContractAddress";
