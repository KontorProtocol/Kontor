import type { OpWithResult } from "./bindings.js";

/** Heights and ordinals are decimal strings, including values beyond 2^53. */
export interface ExecutionContextInfo {
  protocol_id: string | null;
  execution_definition: string;
  application_ordinal: string | null;
  lineage: string | null;
  bitcoin_height: string | null;
  bitcoin_hash: string | null;
  checkpoint_height: string | null;
  checkpoint_hash: string | null;
  receipt_epoch: string;
  rollback_generation: string;
  simulation_height: string | null;
}

/** Local prediction at a fabricated next block, not a future inclusion guarantee. */
export interface SimulationReport<T = OpWithResult> {
  context: ExecutionContextInfo;
  operations: T[];
}

/** Decoded outcomes and gas usage apply only to this simulation's context. */
export interface SimulationPreview<T> {
  context: ExecutionContextInfo;
  result: T;
}

export interface ProtocolDescriptor {
  protocol_id: string;
  protocol_number: string;
  predecessor: string;
  execution_definition: string;
  consensus_definition: string;
  certificate_codec: number;
  transaction_formats: number[];
  host_abis: number[];
  input_state_schema: number;
  output_state_schema: number;
  migration_definition: string;
  native_contracts_root: string;
  installed: boolean;
}

/** Diagnostic snapshot. Lineage and closure identifiers are not certified state roots. */
export interface ProtocolSnapshot {
  availability:
    | "uninitialized"
    | "history_unavailable"
    | "recovering"
    | "unsupported"
    | "ready";
  chain_id: string | null;
  certified: {
    authenticated_height: string;
    authenticated_decision: string | null;
    closed_height: string;
    closure_id: string | null;
    ordering_protocol_id: string | null;
    ordering_era_id: string | null;
  } | null;
  canonical: {
    protocol: ProtocolDescriptor;
    application_ordinal: string;
    lineage: string;
    storage_height: string;
  } | null;
  installed_protocols: ProtocolDescriptor[];
  build: {
    target: string;
    profile: string;
    compiler_sha256: string;
    source_inputs_sha256: string;
    lock_sha256: string;
    consensus_runtime_definition: string;
  } | null;
}
