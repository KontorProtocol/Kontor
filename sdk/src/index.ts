// Public API. We deliberately don't re-export jco's `witCodec` namespace
// since its only export is the `Wit` resource, which we expose directly.
import { witCodec } from "./component/kontor-sdk.js";
export const Wit = witCodec.Wit;
export type Wit = InstanceType<typeof witCodec.Wit>;

export {
  numerics,
  serializeInst,
  deserializeInst,
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
// Client layer. Codegen output references KontorSession / Inst; callers
// (and the e2e test) also need the chain config + the Account type.
// The full client-layer export pass — Account impls, transport, errors,
// aggregate — lands with the runtime implementation (work item #13).
export { KontorSession } from "./session";
export { Result, ResultUnwrapError } from "./result";
export type { Inst } from "./inst";
export { ContractBase } from "./contract-base";
export type { BuildProvenance, Forge, Platform, Source } from "./provenance";
export { Attachment } from "./attach";
export { Offer, IncomingOffer } from "./offer";
export type { OfferData, OfferInspection } from "./offer";
export type { ExtraOutput } from "./outputs";
export { HttpTransport, http } from "./transport/http";
export type { HttpTransportOptions } from "./transport/http";
export type { Utxo } from "./json-codec";
export { signet } from "./chains";
export type { Chain } from "./chains";
export { Identity } from "./identity";
export type {
  Signing,
  SighashKind,
  SignInput,
  SignPsbtOptions,
} from "./signing";
export { canSignSchnorr } from "./signing";
export type { FundingSource } from "./funding";
export { inMemoryFunding, queryFunding } from "./funding";
export { LocalKey } from "./local-key";
export { BlsKey, blsDerivationPath } from "./bls";
export type {
  Bip86Indices,
  FromHdKeyOptions,
  FromMnemonicOptions,
  FromPrivateKeyOptions,
} from "./local-key";
export { Decimal } from "./canonical/Decimal";
export { Integer } from "./canonical/Integer";
export { HolderRef } from "./canonical/HolderRef";
export type { OutPoint } from "./canonical/HolderRef";
export { ContractAddress } from "./canonical/ContractAddress";
