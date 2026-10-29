// Public API. We deliberately don't re-export jco's `witCodec` namespace
// since its only export is the `Wit` resource, which we expose directly.
// Runtime primitives come from the pluggable backend (`./backend`, WASM
// on web/Node, a native module on React Native); see backend/index.ts.
import { witCodec } from "./backend/index.js";
export const Wit = witCodec.Wit;
export type Wit = InstanceType<typeof witCodec.Wit>;

export { numerics, serializeInst, deserializeInst } from "./backend/index.js";
// `validateWit` is a dev-time/tooling helper (WIT validation), not part
// of the on-device runtime backend — keep it bound to the WASM component.
export { validateWit } from "./component/kontor-sdk.js";
export type {
  ValidationError,
  ValidationResult,
  ValidationResultOk,
  ValidationResultParseError,
  ValidationResultValidationErrors,
} from "./component/kontor-sdk.js";

export type * from "./bindings.js";
export { generate } from "./codegen.js";
export type { KontorTransport } from "./json-codec.js";
// Client layer. Codegen output references KontorSession / Inst; callers
// (and the e2e test) also need the chain config + the Account type.
// The full client-layer export pass — Account impls, transport, errors,
// aggregate — lands with the runtime implementation (work item #13).
export { KontorSession } from "./session.js";
export { PaginatedView } from "./pagination.js";
export type { CursorPage } from "./pagination.js";
export { Result, ResultUnwrapError } from "./result.js";
export {
  BaseError,
  ChainError,
  ContractError,
  DeepReorgError,
  SignerError,
  TransportError,
} from "./errors.js";
export type { BaseErrorOptions, ContractErrorOptions } from "./errors.js";
export type { Inst } from "./inst.js";
export { ContractBase } from "./contract-base.js";
export type {
  BuildProvenance,
  Forge,
  Platform,
  ProvenanceEntry,
  Source,
} from "./provenance.js";
export { Attachment } from "./attach.js";
export { Offer, IncomingOffer } from "./offer.js";
export type { OfferData, OfferInspection } from "./offer.js";
export type { ExtraOutput } from "./outputs.js";
export { HttpTransport, http } from "./transport/http.js";
export type { HttpTransportOptions } from "./transport/http.js";
export type { TransactionInfo, ResultInfo, InspectedOp } from "./bindings.js";
export type { ExecutionCoordinates } from "./confirmation.js";
export type { ChainEvent, EventsFilter, EventsOptions } from "./events.js";
export type { Utxo } from "./json-codec.js";
export { signet } from "./chains.js";
export type { Chain } from "./chains.js";
export { Identity } from "./identity.js";
export type {
  Signing,
  SighashKind,
  SignInput,
  SignPsbtOptions,
} from "./signing.js";
export { canSignSchnorr } from "./signing.js";
export type { FundingSource } from "./funding.js";
export { inMemoryFunding, queryFunding } from "./funding.js";
export { LocalKey } from "./local-key.js";
export { BlsKey, blsDerivationPath } from "./bls.js";
export type {
  Bip86Indices,
  FromHdKeyOptions,
  FromMnemonicOptions,
  FromPrivateKeyOptions,
} from "./local-key.js";
export { Decimal } from "./canonical/Decimal.js";
export { Integer } from "./canonical/Integer.js";
export { HolderRef } from "./canonical/HolderRef.js";
export type { OutPoint } from "./canonical/HolderRef.js";
export { ContractAddress } from "./canonical/ContractAddress.js";
