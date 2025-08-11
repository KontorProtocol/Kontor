mod resources;

pub use resources::{FallContext, HasContractId, ProcContext, Signer, ViewContext};

wasmtime::component::bindgen!({
    world: "contract",
    path: "src/runtime/wit",
    with: {
        "kontor:built-in/context/signer": Signer,
        "kontor:built-in/context/view-context": ViewContext,
        "kontor:built-in/context/proc-context": ProcContext,
        "kontor:built-in/context/fall-context": FallContext,
    },
    async: true,
    trappable_imports: true,
});
