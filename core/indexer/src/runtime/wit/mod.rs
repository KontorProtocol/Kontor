mod resources;

pub use resources::{
    CoreContext, FallContext, HasContractId, Keys, ProcContext, ProcStorage, Signer, Transaction,
    ViewContext, ViewStorage,
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
    },
    additional_derives: [stdlib::Wavey],
    imports: {
        "kontor:built-in/context": async | store | trappable,
        "kontor:built-in/crypto": async | store | trappable,
        "kontor:built-in/foreign": async | store | trappable,
        "kontor:built-in/numbers": async | store | trappable,
        default: async | trappable,
    }
});
