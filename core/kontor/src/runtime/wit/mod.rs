pub use crate::runtime::foreign::Foreign;

wasmtime::component::bindgen!({
    world: "contract",
    path: "src/runtime/wit",
    with: {
        "kontor:built-in/foreign/foreign": Foreign,
    },
    async: true,
    trappable_imports: true,
});
