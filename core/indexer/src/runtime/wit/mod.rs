mod resources;

pub use resources::{
    CoreContext, FallContext, FileDescriptor, HasContractId, Keys, ProcContext, ProcStorage, Proof,
    Signer, Transaction, ViewContext, ViewStorage,
};

wasmtime::component::bindgen!({
    path: "src/runtime/wit",
    with: {
        "kontor:built-in/context.signer": Signer,
        "kontor:built-in/context.view-context": ViewContext,
        "kontor:built-in/context.proc-context": ProcContext,
        "kontor:built-in/context.fall-context": FallContext,
        "kontor:built-in/context.core-context": CoreContext,
        "kontor:built-in/context.view-storage": ViewStorage,
        "kontor:built-in/context.proc-storage": ProcStorage,
        "kontor:built-in/context.keys": Keys,
        "kontor:built-in/context.transaction": Transaction,
        "kontor:built-in/file-ledger.file-descriptor": FileDescriptor,
        "kontor:built-in/file-ledger.proof": Proof,
    },
    additional_derives: [stdlib::Wavey],
    imports: {
        // async func in wits automatically makes them "async | store"
        // but we still need this here from implicit built-ins like resource drops.
        default:  async | store | trappable,
    }
});
