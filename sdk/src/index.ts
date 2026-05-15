// Public API. We deliberately don't re-export jco's `witCodec` namespace
// since its only export is the `Wit` resource, which we expose directly.
import { witCodec } from "./component/kontor-sdk";
export const Wit = witCodec.Wit;
export type Wit = InstanceType<typeof witCodec.Wit>;

export {
  numerics,
  serializeInst,
  deserializeInst,
  serializeOpReturnData,
  deserializeOpReturnData,
  validateWit,
} from "./component/kontor-sdk";
export type {
  ValidationError,
  ValidationResult,
  ValidationResultOk,
  ValidationResultParseError,
  ValidationResultValidationErrors,
} from "./component/kontor-sdk";

export type * from "./bindings";
export { generate } from "./codegen";
export type { KontorTransport } from "./json-codec";
