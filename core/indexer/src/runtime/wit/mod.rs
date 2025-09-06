mod resources;

pub use resources::{FallContext, HasContractId, Keys, ProcContext, Signer, ViewContext};

wasmtime::component::bindgen!({
    world: "contract",
    path: "src/runtime/wit",
    with: {
        "kontor:built-in/context/signer": Signer,
        "kontor:built-in/context/view-context": ViewContext,
        "kontor:built-in/context/proc-context": ProcContext,
        "kontor:built-in/context/fall-context": FallContext,
        "kontor:built-in/context/keys": Keys,
    },
    additional_derives: [PartialEq, Eq, stdlib::Wavey],
    imports: {
        default: async | trappable,
    }
});
