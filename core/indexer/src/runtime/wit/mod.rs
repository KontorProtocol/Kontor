mod resources;

pub use resources::{
    FallContext, HasContractId, ProcContext, ProcStorage, Signer, ViewContext, ViewStorage,
};

wasmtime::component::bindgen!({
    world: "contract",
    path: "src/runtime/wit",
    with: {
        "kontor:built-in/storage/view-storage": ViewStorage,
        "kontor:built-in/storage/proc-storage": ProcStorage,
        "kontor:built-in/context/signer": Signer,
        "kontor:built-in/context/view-context": ViewContext,
        "kontor:built-in/context/proc-context": ProcContext,
        "kontor:built-in/context/fall-context": FallContext,
    },
    async: true,
    trappable_imports: true,
});
