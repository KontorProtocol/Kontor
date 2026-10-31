"""Review tripwire for the node and proof's explicit guest-capability settings."""

import re


DISABLED = {"wasm_component_model_async", "wasm_component_model_more_async_builtins",
            "wasm_component_model_async_stackful", "wasm_component_model_threading",
            "wasm_component_model_error_context", "wasm_shared_everything_threads",
            "wasm_stack_switching", "concurrency_support", "wasm_threads"}


def settings(source):
    calls = re.findall(r"\.([a-z_]+)\(\s*(true|false)\s*\)", source)
    selected = [(name, value) for name, value in calls if name in DISABLED]
    if len(selected) != len(DISABLED) or dict(selected) != dict.fromkeys(DISABLED, "false"):
        raise RuntimeError("guest capability settings differ from the synchronous baseline")
    return dict(selected)


def verify(root):
    source = (root / "core/indexer/src/runtime/mod.rs").read_text()
    facade = re.search(r"pub fn new_engine\(\) -> Result<Engine>\s*\{([^}]+)\}", source)
    if (not facade or facade[1].strip() != "engine::new_engine()"
            or "use crate::protocol::v1::engine;" not in source):
        raise RuntimeError("node engine does not delegate to retained P1 configuration")
    node = (root / "core/indexer/src/protocol/v1/engine.rs").read_text()
    proof = (root / "protocol-bundles/proof/vm.rs").read_text()
    if settings(node) != settings(proof):
        raise RuntimeError("node and proof capability settings differ")
