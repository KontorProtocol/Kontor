wasmtime::component::bindgen!({
    world: "contract",
    path: "src/runtime/wit",
    with: {
    },
    async: true,
    trappable_imports: true,
});
