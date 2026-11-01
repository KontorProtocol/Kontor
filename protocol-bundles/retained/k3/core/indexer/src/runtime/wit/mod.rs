mod facades;
pub(crate) mod resources;

pub use resources::{
    Contract, CoreContext, FallContext, FileDescriptor, HasContractId, Holder, Keys, ProcContext,
    ProcStorage, Proof, Signer, StorageRows, Transaction, ViewContext, ViewStorage,
    prover_challenge_key,
};

macro_rules! bindings { ($path:literal) => { wasmtime::component::bindgen!({
    path: $path,
    anyhow: true,
    wasmtime_crate: crate::runtime::lowering::bindings,
    with: {
        "kontor:built-in/context.signer": Signer,
        "kontor:built-in/context.view-context": ViewContext,
        "kontor:built-in/context.proc-context": ProcContext,
        "kontor:built-in/context.fall-context": FallContext,
        "kontor:built-in/context.core-context": CoreContext,
        "kontor:built-in/context.view-storage": ViewStorage,
        "kontor:built-in/context.proc-storage": ProcStorage,
        "kontor:built-in/context.keys": Keys,
        "kontor:built-in/context.storage-rows": StorageRows,
        "kontor:built-in/context.holder": Holder,
        "kontor:built-in/context.contract": Contract,
        "kontor:built-in/context.transaction": Transaction,
        "kontor:built-in/file-registry.proof": Proof,
        // Types-only interfaces come from the shared `built-in-types` crate —
        // generated once there, aliased here (and, in a later stage, in the
        // contracts) instead of regenerated. The facade provides the
        // Host/add_to_linker module shape wasmtime expects of an interface.
        "kontor:built-in/file-registry-types": facades::file_registry_types,
        "kontor:built-in/numbers-types": facades::numbers_types,
        "kontor:built-in/error": facades::error,
        "kontor:built-in/context-types": facades::context_types,
        "kontor:built-in/pagination": facades::pagination,
    },
    additional_derives: [stdlib::Wavey, serde::Deserialize],
    imports: {
        // Drops need async host I/O but no Store access. STORE would select the
        // concurrent destructor API even with synchronous WIT.
        default: async | store | trappable,
        "kontor:built-in/context.[drop]signer": async | trappable,
        "kontor:built-in/context.[drop]view-context": async | trappable,
        "kontor:built-in/context.[drop]proc-context": async | trappable,
        "kontor:built-in/context.[drop]fall-context": async | trappable,
        "kontor:built-in/context.[drop]core-context": async | trappable,
        "kontor:built-in/context.[drop]view-storage": async | trappable,
        "kontor:built-in/context.[drop]proc-storage": async | trappable,
        "kontor:built-in/context.[drop]keys": async | trappable,
        "kontor:built-in/context.[drop]storage-rows": async | trappable,
        "kontor:built-in/context.[drop]holder": async | trappable,
        "kontor:built-in/context.[drop]contract": async | trappable,
        "kontor:built-in/context.[drop]transaction": async | trappable,
        "kontor:built-in/file-registry.[drop]proof": async | trappable,
    }
}); }; }
#[cfg(not(kontor_retained))]
bindings!("src/runtime/wit");
#[cfg(kontor_retained)]
bindings!("../../core/indexer/src/runtime/wit");
